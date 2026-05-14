# TLS Roadmap

> **Status:** Tier 1 primitives complete. Every wire-level
> helper a TLS_RSA_WITH_AES_128_GCM_SHA256 client needs is
> implemented and self-tested at boot (see `[tls] PASS` line
> in the serial transcript). What's left is the thin
> Connection-state-machine glue that drives the helpers in
> order against a real socket, plus the wininet/winhttp
> HTTPS wiring that flips today's "fallback body" to "real
> TLS GET".
>
> The Tier 2/3 sections below remain forward-looking — TLS 1.3,
> ECDH/ECDSA, real cert chain validation against a bundled root
> store, and constant-time hardening are still future work.

## Why TLS is the blocker

End-user installs almost universally come from HTTPS sources:
GitHub releases, vendor CDNs, package mirrors. DuetOS today has:

- **Working TCP / IP / DNS / DHCP** — `wininet` and `mini_browser`
  smokes reach `www.google.com` over plain HTTP under QEMU SLIRP
  ([Live Internet](Live-Internet.md)).
- **Working filesystem write** — `SYS_FILE_CREATE` / `SYS_FILE_WRITE`
  route to FAT32, and as of the LoadLibraryEx / ZIP / mkdir
  slices, the whole "extract a zip to /Program Files/<app>/" path
  is achievable end-to-end.
- **Crypto primitives** — `kernel/crypto/`: SHA-1, SHA-256, HMAC,
  PBKDF2, AES (128/192/256), AES key-wrap, an internal PRF.

What's **missing**:

1. **TLS state machine** — ClientHello / ServerHello / Certificate /
   ServerKeyExchange / ClientKeyExchange / ChangeCipherSpec /
   Finished. The whole RFC 5246 (TLS 1.2) and/or RFC 8446 (TLS
   1.3) handshake.
2. **Asymmetric crypto** — RSA (PKCS#1 v1.5 + PSS) and ECDSA P-256.
   The crypto folder has no asymmetric ops today.
3. **X.509 / ASN.1 DER parsing** — certificate validation.
   No ASN.1 parser in tree.
4. **Trust store** — a bundled root-CA cert set. Either ship
   Mozilla's NSS root list (~150 KB pem) or a curated minimum.
5. **HMAC-DRBG / CSPRNG entropy source** — for client randoms
   and (TLS 1.3) ephemeral key generation. The existing
   `util/random.h` `RandomU64` is a starting point but its
   entropy source needs auditing for CSPRNG fitness.

## Scope tiers

The full surface is ~3–5 weeks of work. To make incremental
progress, slice it into tiers each of which lands real,
testable functionality:

### Tier 1 — TLS-1.2-only, RSA-only cipher suite (PARTIAL)

**Shipped this session** (every line a boot self-test):

- `crypto/bigint.{h,cpp}` — 128-limb (4096-bit) BigInt with
  `Add/Sub/Mul/Mod/ModExp`, BE byte round-trip. `[bigint] PASS`.
- `crypto/asn1.{h,cpp}` — DER reader (INTEGER, BIT STRING,
  OCTET STRING, NULL, OID, UTF8/Printable/IA5String, UTCTime,
  GeneralizedTime, SEQUENCE, SET) with `IntegerToBytesBE` and
  `OidEquals`. `[asn1] PASS`.
- `crypto/rsa.{h,cpp}` — `RsaPublicKey` + `RsaPkcs1V15Verify` +
  `Pkcs1V15UnwrapAndMatch`. SHA-256 + SHA-1 DigestInfo
  prefixes baked in. `[rsa] PASS`.
- `crypto/x509.{h,cpp}` — Certificate parser exposing
  `tbs`, `sig_algo`, `signature`, `subject_rsa`, and the
  validity-time byte slices. `[x509] PASS`.
- `crypto/aes_gcm.{h,cpp}` — AES-128-GCM AEAD encrypt +
  decrypt, validated against NIST SP 800-38D vectors v1 + v2
  with round-trip + tamper detection. `[aes-gcm] PASS`.
- `net/tls.{h,cpp}` — TLS 1.2 client primitives:
  - `TlsPrfSha256` (RFC 5246 §5 P_SHA256, expands to any length)
  - `TlsMasterSecret`, `TlsKeyBlock`, `TlsFinishedVerifyData`
  - `TlsBuildClientHelloBody`, `TlsWrapRecord`,
    `TlsWrapHandshake`
  - `TlsPeekRecord`, `TlsPeekHandshake`
  - `TlsParseServerHello`, `TlsParseCertificateLeaf`,
    `TlsParseServerHelloDone`
  - `Pkcs1V15Type2Pad`, `TlsBuildClientKeyExchangeBody`
  - `TlsEncryptRecord`, `TlsDecryptRecord` (TLS 1.2 GCM
    framing with seq-bound nonces + AAD)
  - `Transcript` (running SHA-256 with non-destructive
    snapshot), `TlsBuildEncryptedFinished`,
    `TlsVerifyEncryptedServerFinished`.
  `[tls] PASS (prf + cke + record-aead + transcript +
  finished + srv-fin verify)`.

**Still to ship to close Tier 1:**

- TLS Connection state machine (Init → SentClientHello →
  RecvServerHello → RecvCertificate → RecvServerHelloDone →
  SentClientKeyEx → SentClientCCS → SentClientFin →
  RecvServerCCS → RecvServerFin → Established) — pure
  composition of the helpers above, ~200 lines.
- Wire to wininet/winhttp: replace the "fallback body" path
  with a `Tls{Open,Read,Write,Close}` call sequence over the
  existing kernel socket pool.
- SNI extension support — required by most modern servers.
  Currently we omit the extensions block entirely.
- Server cert validation: today we trust ANY cert. Tier 1
  doesn't need full chain validation, but at least matching
  the leaf cert's CN against the hostname is a sane minimum.

Estimated remaining effort: ~3-5 days for state machine + wiring.

### Tier 2 — TLS 1.3 + ECDSA + ECDH

Adds:
- BigInt arithmetic (the AES path is u8[]; everything in TLS
  1.3 is big integers).
- P-256 ECDH + ECDSA verify.
- HKDF (uses existing HMAC).
- TLS 1.3 state machine — single-RTT handshake, no
  ChangeCipherSpec, key schedule via HKDF.
- AEAD ChaCha20-Poly1305 (for the suites where it's preferred).

Estimated effort: 2–3 additional weeks on top of Tier 1.

### Tier 3 — Production-grade hardening

- Constant-time arithmetic throughout (RSA, ECDH side-channel
  resistance).
- Cert revocation (OCSP stapling check, CRL fallback).
- Session resumption (TLS 1.3 PSK).
- Certificate-Transparency log verification.
- Trust-store update path (signed root-cert bundle).

This tier is what makes the stack appropriate for daily-driver
use rather than experimental.

## Existing primitives we can reuse

| Need                     | Have                                                                        | Gap                                                           |
| ------------------------ | --------------------------------------------------------------------------- | ------------------------------------------------------------- |
| SHA-256                  | `kernel/crypto/sha256.h`                                                    | None — drop-in ready                                          |
| HMAC-SHA256              | `kernel/crypto/hmac.h`                                                      | None                                                          |
| AES-128/256-CBC          | `kernel/crypto/aes.h`                                                       | Need AES-GCM mode (a wrapper around AES + GHASH multiplier)   |
| TLS PRF                  | `kernel/crypto/prf.h`                                                       | Exists already — needs an audit pass to confirm RFC 5246 §5   |
| RSA verify               | —                                                                           | Need: modular exponentiation, PKCS#1 v1.5 padding check       |
| ASN.1 / X.509            | —                                                                           | Need: bounded DER walker, X.509 v3 fields                     |
| Big-int                  | —                                                                           | Need: u32-limb add/sub/mul/mod/exp (no allocation)            |
| TCP socket               | `kernel/net/tcp/`, `SYS_SOCKET_OP`                                          | None — TLS sits on top                                        |
| CSPRNG                   | `util/random.h` (`RandomU64`)                                               | Need: audit entropy source, possibly add HMAC-DRBG wrapper    |

## API shape (proposed)

User-facing: live alongside `winhttp` / `wininet` and switch
on URL scheme. A PE that requests `https://...` gets a TLS-
wrapped socket transparently.

Kernel-side:
```cpp
namespace duetos::net::tls
{
struct TlsConfig {
    const u8* trust_anchors;   // PEM-or-DER cert bundle
    u64 trust_anchors_len;
    const char* sni_hostname;  // for SNI extension
};

struct TlsConn;
TlsConn* TlsClientOpen(u32 socket_fd, const TlsConfig& cfg);
i64 TlsRead(TlsConn*, void* dst, u64 cap);
i64 TlsWrite(TlsConn*, const void* src, u64 len);
void TlsClose(TlsConn*);
} // namespace
```

Userland: a new syscall pair (`SYS_TLS_OPEN`, `SYS_TLS_IO`) plus
`wininet`'s HTTPS path stops returning the fallback body and
starts wrapping the underlying `ws2_32` socket in `TlsConn`.

## Self-test plan

1. **ASN.1 round-trip**: parse a hand-built DER blob with known
   structure (one INTEGER, one OCTET STRING) and confirm field
   values.
2. **X.509 of a real cert**: bundle a known issuer cert at build
   time, parse it, verify the subject CN matches the expected
   string.
3. **RSA verify of a known signature**: hand-built {message,
   signature, public-key} triple, confirm verify succeeds and
   that flipping one signature bit makes it fail.
4. **End-to-end live**: under QEMU SLIRP, `TlsClientOpen` to a
   known endpoint (e.g. `https://example.com`), `TlsWrite` an
   HTTP/1.1 GET, `TlsRead` 4 KB, log the status line. Same
   shape `mini_browser` already uses for plain HTTP — flip
   the URL scheme to https.

## Why we are not implementing TLS this session

The crypto primitives are in tree but **RSA, big-int, and
ASN.1 are not**. Each is a 2-3 day implementation. The TLS
state machine on top is another week-plus. Reasonable to
budget Tier 1 as its own multi-session arc rather than a single
half-day landing.

## Dependencies for the next session

- Pick BigInt representation (u32 limbs vs u64). u32 keeps the
  per-multiply inner loop in registers on x86_64; u64 is fewer
  ops but each is full-width.
- Decide on built-in trust anchors. For v0 a single cert (the
  one signing example.com or a CDN we'll test against) is
  enough to prove the whole pipeline.
- Decide on TLS 1.2 vs 1.3 first. 1.2 + RSA-only is the smaller
  initial bite; 1.3 is the future-proof one but assumes ECDH +
  HKDF + the new key schedule are also in place.

## Related pages

- [Live Internet](Live-Internet.md) — what the HTTP smoke
  already does end-to-end.
- [Network Stack](Network-Stack.md) — TCP / IP / DNS that TLS
  sits on top of.
- `kernel/crypto/*.h` — primitives that TLS reuses.
