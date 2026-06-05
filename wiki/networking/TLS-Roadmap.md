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
- `net::x509_verify::TrustAnchorVerifies` (`x509_verify.cpp:723`) +
  `IssuerSigns` (`x509_verify.cpp:607`) — RFC 5280 chain building with
  issuer/subject DN equality short-circuiting before a signature verify.
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
- `[x509-verify-selftest] PASS` — parses every embedded anchor and
  self-signature-verifies one representative per signature family (1 RSA
  + 1 ECDSA); a full per-anchor public-key verify is too costly under
  TCG (a single P-384 verify is tens of seconds).
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
- **Chain depth capped at 2** (`x509_verify.cpp:777`) — an intermediate
  signed by another intermediate is not followed.
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
