# TLS Client

> **Audience:** Net stack hackers, crypto reviewers
>
> **Execution context:** Kernel — runs in the calling process's context
> on top of a TCP socket; never on the IRQ RX path
>
> **Maturity:** active — TLS 1.2 client (RSA + ECDHE-ECDSA web roots)
> lands end-to-end; `wget https://` and the browser fetch over it

## Overview

`kernel/net/tls.{h,cpp}` is the in-kernel TLS 1.2 client. It drives a
full handshake against a real server over a TCP socket, encrypts and
decrypts the record layer, validates the server's certificate chain
against an embedded root store, and hands a plaintext byte stream to the
HTTP client above it. The HTTPS path is what `wget https://`, the
browser, and the install fetchers use.

This page was originally a roadmap for work that has since landed; it now
documents the shipped client and its known limits.

## When to Use / When to Read

- You are adding an HTTPS-capable caller and need the handshake / socket
  entry points.
- You are extending cert verification (new signature algorithm, new root,
  deeper chains) and need the current GAP list.
- You hit a TLS handshake failure and need to know which limits fail
  closed.

## Layered Composition

```
[ HTTP client (kernel/net/http.cpp) ]
        |
[ TLS socket (kernel/net/tls_socket.{h,cpp}) ]   TlsSocketConnect / Handshake / Read / Write
        |
[ TLS 1.2 state machine (kernel/net/tls.cpp) ]   Connection / ConnectionStart
        |
[ X.509 chain verifier (kernel/net/x509_verify.cpp) ]
[ EC verify (kernel/net/ec.cpp), RSA / BigInt / ASN.1 (kernel/crypto/) ]
        |
[ TCP socket (SYS_SOCKET_OP) ]
```

## Key APIs and Types

- `net::tls::Connection` + `net::tls::ConnectionStart` (`tls.h:380`) —
  the handshake state machine. `State` (`tls.h:272`) walks ClientHello →
  server flight → ClientKeyExchange + ChangeCipherSpec + Finished →
  server CCS + Finished → Established. SNI is emitted from the hostname
  passed to `ConnectionStart`.
- `net::tls::TlsSocketConnect` / `TlsSocketHandshake` / read / write
  (`tls_socket.{h,cpp}`) — the socket-backed wrapper most callers use.
  `TlsSocketSetVerifier` installs the chain verifier (see Known Limits).
- `net::x509_verify::TrustAnchorVerifies` + `IssuerSigns` — RFC 5280
  chain building with issuer/subject DN equality short-circuiting before
  a signature verify.
- `IsUsableIssuer(cert, certs_below)` — the RFC 5280 §6.1.4(n) /
  §6.1.3(a)(4) issuer gate. Every certificate used to SIGN another
  (the supplied intermediate; the trust anchor) must carry
  basicConstraints **cA = TRUE**, must not carry a keyUsage that omits
  **keyCertSign**, and must satisfy its own pathLenConstraint.
  basicConstraints **absent** means "not a CA" — fail closed. Without
  this gate an ordinary end-entity certificate (issued to anyone who
  controls one domain) can be presented as an intermediate and used to
  mint a trusted chain for any hostname: the Basic Constraints bypass.
- `DecodeExtensionSeq()` / `ParseExtensionsFromTbs()` — the
  extension-block policy the gate rests on. Its governing idea: a
  certificate must have exactly **one** valid encoding, so no two parsers
  can read it differently.
  - Extension state is three separate facts (**seen**, syntactically
    **valid**, decoded **value**), and the extnID is marked seen *before*
    its value is parsed, so a malformed first copy still blocks a
    well-formed duplicate. Duplicate detection is generic — every
    extnID, bounded at 32.
  - Canonical DER throughout the subtree: minimal lengths, canonical OID
    arcs, no high-tag-number form, every `extnValue` holding exactly one
    inner element with nothing trailing or truncated. A DEFAULT value
    must be omitted, never written out (`cA FALSE`, `critical FALSE`,
    version v1 are all refused).
  - The TBS tail must be exactly `issuerUniqueID [1]?,
    subjectUniqueID [2]?, extensions [3]?` — in order, each at most once,
    `[1]`/`[2]` needing v2/v3 and `[3]` needing v3, non-empty, and
    closing out the TBS. A primitive `0x83` is refused rather than
    skipped: skipping it made the certificate parse as having no
    extensions, which re-enabled the CN fallback. `[1]`/`[2]` are
    IMPLICIT BIT STRINGs, so their **content** is validated too
    (unused-bit count ≤ 7, zero when there are no data octets, and the
    unused trailing bits actually zero) — the tag alone is not the field.
  - Each subjectAltName `GeneralName` is validated against its own
    content rules, not merely recognised by tag: `rfc822Name` / `dNSName`
    / `uniformResourceIdentifier` must be non-empty 7-bit IA5,
    `iPAddress` exactly 4 or 16 octets, `registeredID` a non-empty
    canonical OID.
  - `keyUsage` is a **NAMED** BIT STRING, so X.690 §11.2.2 additionally
    forbids encoding its trailing zero bits: keyCertSign is spelled
    `03 02 02 04` and only that way, never `03 02 00 04` or
    `03 03 00 04 00`. Several spellings of the value that decides whether
    a certificate may sign other certificates would be several chances
    for two parsers to disagree. `issuerUniqueID` / `subjectUniqueID` are
    plain BIT STRINGs and keep the looser rule.
  - An unrecognised **critical** extension (RFC 5280 §6.1.4(k)) rejects
    the certificate.
  A certificate that breaks any of these fails in `ParseOne()`, so it can
  never be promoted to an issuer by any caller. Vectors:
  `net/x509_ext_vectors.h`, generated by
  `tools/test/gen-x509-ext-vectors.py` and verified byte-for-byte by
  `tools/test/check-x509-ext-vectors.sh`. Audit the embedded anchors (or
  a live chain) with `tools/test/x509-embedded-extensions.py`.

  These rules only ever narrow what connects, so measure any new one
  against real chains before landing it:

  ```sh
  openssl s_client -showcerts -connect github.com:443 </dev/null > chain.pem
  python3 tools/test/x509-embedded-extensions.py --der chain.pem
  ```

  Last run 2026-07-26: **10/10** certificates accepted across the
  example.com, github.com and www.google.com chains. Treat this as
  compatibility *evidence*, not as a specification. A rejection here is a
  signal to investigate which of two things happened:

  - the certificate really is invalid or non-canonical — then the
    rejection is correct and stays, however common the shape is in the
    wild; or
  - the rule is stricter than the standard requires, or refuses a
    structure we could validate — then fix the rule.

  The standards and the fail-closed posture are what decide; this sample
  only tells you where to look.
- Hostname matching takes the CN **only when subjectAltName is absent**
  (RFC 6125 §6.4.4). A SAN that is present but names no DNS host still
  suppresses the CN.
- Embedded root store (`x509_verify.cpp:1063`–`1209`) — DigiCert, Amazon,
  GlobalSign, GoDaddy/AffirmTrust, and ISRG (Let's Encrypt, incl. the
  RSA-4096 ISRG Root X1) roots, plus P-384 ECDSA roots (DigiCert Global
  Root G3, ISRG Root X2).
- `net::ec` (`ec.cpp`) — ECDSA verify over NIST P-256 / P-384,
  verify-only / fail-closed.

## Crypto primitives reused

| Need | Have |
| --- | --- |
| SHA-256 / SHA-384 / HMAC | `kernel/crypto/sha256.h`, `sha384.{h,cpp}`, `hmac.h` |
| AES-128-GCM AEAD | `kernel/crypto/aes_gcm.{h,cpp}` |
| TLS PRF (P_SHA256) | `net::tls::TlsPrfSha256` |
| RSA PKCS#1 v1.5 verify | `kernel/crypto/rsa.{h,cpp}` |
| BigInt (4096-bit) | `kernel/crypto/bigint.{h,cpp}` |
| ASN.1 / X.509 DER | `kernel/crypto/asn1.{h,cpp}`, `x509.{h,cpp}` |
| ECDSA P-256 / P-384 | `kernel/net/ec.{h,cpp}` |
| TCP socket | `SYS_SOCKET_OP` |

## Rust vs C++ split

The five untrusted byte-walkers — record header, handshake header,
ServerHello body, Certificate-message body, ServerHelloDone body — are
implemented in the `duetos_tls` Rust crate
(`kernel/net/tls_rust/src/lib.rs`, `no_std`, FFI-walled). They are
**live**, not dead: the C++ wrappers in `tls.cpp` (`TlsPeekRecord`,
`TlsPeekHandshake`, `TlsParseServerHello`, `TlsParseCertificateLeaf`,
`TlsParseServerHelloDone`, `tls.cpp:268` onward) delegate straight to
`duetos_tls_*` and translate the FFI structs back into the `tls.h`
shapes. The C++ side owns the public API, the handshake state machine,
the crypto, and the cert chain; the Rust crate owns only the
bounds-checked parsing of peer-controlled lengths. See
[Rust Subsystems](../tooling/Rust-Subsystems.md).

## Capability / Privilege Surface

TLS is reached through the TCP socket path, gated by `kCapNet` (see
[Network Stack](Network-Stack.md#capability-surface)). It adds no
capability of its own.

## Boot self-tests

Each layer pins a known-answer vector at boot (grep the serial transcript):

- `[bigint] PASS` (incl. RSA-4096), `[asn1] PASS`, `[rsa] PASS`,
  `[x509] PASS`, `[aes-gcm] PASS`.
- `[ec-selftest] PASS (P-256+P-384, 4 pos / 4 neg)`.
- `[x509-verify-selftest] PASS (… basicConstraints+keyUsage issuer gate;
  …)` — parses every embedded anchor and self-signature-verifies one
  representative per signature family (1 RSA + 1 ECDSA); a full
  per-anchor public-key verify is too costly under TCG (a single P-384
  verify is tens of seconds). It also asserts the issuer gate: the real
  CA:FALSE leaf fixtures are refused as issuers, the CA fixtures are
  accepted, and the pathlen:0 intermediate refuses a deeper path. Then
  38 extension-block vectors and 19 whole-TBS vectors pin the block
  policy — duplicates (including when the first copy is the malformed
  one), trailing bytes, a truncated inner SEQUENCE, a BER BOOLEAN, an
  explicit DEFAULT FALSE, a non-minimal length or OID arc, a second or
  primitive `[3]`, a bad TBS tail field, v1/v2-with-extensions, an empty
  Extensions SEQUENCE, and an unrecognised critical extension all reject
  *and* leave the certificate unusable as an issuer, while an unknown
  non-critical extension is ignored and an ordinary CA block stays
  usable. `SanSuppressionChecks()` pins the SAN-suppresses-CN rule
  through `HostMatches()` itself.
  Hosted mirror: `tests/host/test_x509_verify.cpp` (gates every PR).
- `[tls] PASS (prf + cke + record-aead + transcript + finished +
  srv-fin verify)`.

## Known Limits / GAPs

Sourced from live `// GAP:` markers — re-derive with
`git grep -nE "// GAP:" kernel/net/x509_verify.cpp kernel/net/ec.cpp kernel/net/tls_socket.cpp`.

- **Cert signature algorithms fail closed beyond the web baseline.**
  - `x509_verify.cpp:379` — P-521 (and other non-P-256/P-384 curves) not
    supported.
  - `x509_verify.cpp:488` — sha1WithRSA / RSA-PSS not supported.
  - `x509_verify.cpp:553` — ecdsa-with-SHA1 / SHA-512 / Ed25519 not
    supported.
  - `x509_verify.cpp:627` — RSA-PSS / Ed25519 / sha1WithRSA not
    supported.
- **Chain depth capped at 2** — an intermediate signed by another
  intermediate is not followed. (Grep `// GAP: deeper chains`.)
- **Only three extensions are decoded** — basicConstraints, keyUsage and
  subjectAltName. Because an unrecognised *critical* extension now
  rejects the certificate (RFC 5280 §6.1.4(k)), the practical limit is
  that a chain marking name constraints, policy constraints or
  extendedKeyUsage **critical** fails closed rather than connecting. That
  is the safe direction, but it is a real interop limit: widen the set by
  *implementing* an extension, never by ignoring it. Unknown
  **non**-critical extensions (SKI, AKI, certificatePolicies, AIA, SCTs)
  are ignored as §4.2 directs. Dump a failing chain's extensions with
  `tools/test/x509-embedded-extensions.py --der chain.pem`.
- **Only the first 16 subjectAltName dNSName entries are retained** — a
  hostname past that point will not match (fails closed).
- **Structured subjectAltName GeneralNames are refused, not skipped.**
  `otherName [0]`, `x400Address [3]`, `directoryName [4]` and
  `ediPartyName [5]` carry nested schemas the verifier does not
  implement, so a certificate whose SAN contains one fails closed rather
  than having that entry waved through unvalidated. `directoryName` is
  the one that appears in the wild; implement its schema before
  accepting it. Same reasoning as the critical-extension rule: do not
  admit a structure you have not checked.
- **At most 32 extensions per certificate** — the duplicate-detection
  table is bounded, and a 33rd extension is refused rather than parsed
  with an incomplete duplicate check.
- **Compressed EC points rejected** (`ec.cpp:415`) — SEC1 0x02/0x03
  forms fail closed; only 0x04 uncompressed is accepted.
- **No cert verifier installed by default for non-browser callers**
  (`tls_socket.cpp:174`) — a caller that never calls
  `TlsSocketSetVerifier` gets a connection whose chain is **not**
  validated. Browser / `wget` callers install the verifier; embed-it-and-
  forget callers must do the same.
- **TLS 1.2 only; RSA + ECDHE-ECDSA web suites.** No TLS 1.3, no session
  resumption, no OCSP / CRL revocation, no constant-time hardening of the
  asymmetric paths. The hostname check is exact CN / SAN match.

## Troubleshooting

- **Handshake fails at ServerHello** — the server offered a cipher suite
  the client doesn't implement (anything outside the RSA + ECDHE-ECDSA
  AES-128-GCM baseline). Check the server's offered suites.
- **Chain verification fails on a site other browsers accept** — most
  often an unsupported signature algorithm above (RSA-PSS, P-521,
  Ed25519) or a chain deeper than 2. These fail closed by design.
- **HTTPS "connects" but trusts anything** — the caller never installed a
  verifier (`tls_socket.cpp:174`). Call `TlsSocketSetVerifier`.

## Related Pages

- [Network Stack](Network-Stack.md) — TCP / IP / DNS / HTTP that TLS sits
  between.
- [Live Internet](Live-Internet.md) — the end-to-end fetch over HTTP /
  HTTPS.
- [Rust Subsystems](../tooling/Rust-Subsystems.md) — the `duetos_tls`
  parser crate.
- `kernel/crypto/*.h` — primitives TLS reuses.
