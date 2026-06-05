# Kernel Crypto Primitives

> **Audience:** Kernel hackers, security reviewers
>
> **Execution context:** Kernel — pure C++, stateless, no allocator calls
> on the hot path
>
> **Maturity:** v0 — all primitives KAT-verified at boot; constant-time
> review pending for AES/Poly1305

## Overview

DuetOS keeps its kernel-side crypto in two places:

- [`kernel/crypto/`](../../kernel/crypto/) — block ciphers, hashes,
  HMAC, PBKDF2, PRF. The bedrock primitives.
- [`kernel/security/`](../../kernel/security/) — anything that *uses*
  crypto: Argon2id KDF, BLAKE2b, ChaCha20-Poly1305 AEAD, password
  hashing, persistence envelope encryption.

The split is by abstraction, not by access: a security TU can call
into `kernel/crypto/` directly, and the storage layer can call
`security/chacha20_poly1305` directly. The two trees stay clean of each
other (no `kernel/crypto/` file `#include`s a `kernel/security/` header).

Everything in this tree is **freestanding** — no kernel heap, no IPC,
no log allocations on the hot path. The only side effect a primitive
has is writing its output buffer. That keeps them callable from
contexts that can't afford to sleep or fail (e.g. the boot self-test,
the panic-time persistence flush).

## Primitive Inventory

### Block Ciphers, Hashes, HMAC

| Primitive | Header | Sizes | Use site |
|-----------|--------|-------|----------|
| AES-128 / AES-256 | [`crypto/aes.h`](../../kernel/crypto/aes.h) | 16-byte block, 10/14 rounds | AES-Key-Wrap unwrap, 802.11 CCMP/GCMP, future TLS |
| AES Key Wrap (RFC 3394) | [`crypto/aes_keywrap.h`](../../kernel/crypto/aes_keywrap.h) | 8-byte semi-blocks | 802.11i EAPOL-Key M3 GTK/IGTK delivery |
| SHA-1 | [`crypto/sha1.h`](../../kernel/crypto/sha1.h) | 20-byte digest, 64-byte block | HMAC-SHA1, PBKDF2 (WPA2 only — legacy) |
| SHA-256 | [`crypto/sha256.h`](../../kernel/crypto/sha256.h) | 32-byte digest, 64-byte block | HMAC-SHA256, modern AKMs, Argon2id `H` |
| HMAC-SHA1 / HMAC-SHA256 | [`crypto/hmac.h`](../../kernel/crypto/hmac.h) | per underlying hash | PBKDF2, EAPOL MIC, WPA3-SAE PMK |
| PBKDF2 | [`crypto/pbkdf2.h`](../../kernel/crypto/pbkdf2.h) | 4096 iters (WPA2 locked); configurable for password hash V1 | WPA2 PMK derivation, password hash V1 |
| 802.11 PRF / KDF-Hash | [`crypto/prf.h`](../../kernel/crypto/prf.h) | SHA-1 PRF-384 → 48 B PTK; SHA-256 KDF variant | 4-way handshake PTK derivation, EAPOL MIC key, WPA3-suite AKMs |
| SHA-384 | [`crypto/sha384.h`](../../kernel/crypto/sha384.h) | 48-byte digest, 128-byte block | Suite-B / future TLS-1.2-GCM-SHA384, RSA-PSS over SHA-384 |
| HKDF (RFC 5869) | [`crypto/hkdf.h`](../../kernel/crypto/hkdf.h) | extract + expand over HMAC-SHA256 | Key-schedule derivation for future TLS / key separation |

### AEAD: AES-GCM

| Primitive | Header | Sizes | Use site |
|-----------|--------|-------|----------|
| AES-GCM | [`crypto/aes_gcm.h`](../../kernel/crypto/aes_gcm.h) | 128/256-bit key, 12-byte nonce, 16-byte tag | 802.11 GCMP, future TLS AEAD |

### Public-Key: RSA, big-integer, ASN.1, X.509

| Primitive | Header | Sizes | Use site |
|-----------|--------|-------|----------|
| Big-integer | [`crypto/bigint.h`](../../kernel/crypto/bigint.h) | up to RSA-4096 modulus (test vector `bigint_rsa4096_vector.h`) | RSA modexp backing store |
| RSA (PKCS#1) | [`crypto/rsa.h`](../../kernel/crypto/rsa.h) | 2048 / 4096-bit | Signature verification for X.509 chains, future TLS |
| ASN.1 DER | [`crypto/asn1.h`](../../kernel/crypto/asn1.h) | TLV parse | X.509 certificate decode |
| X.509 | [`crypto/x509.h`](../../kernel/crypto/x509.h) | DER certificate parse + RSA signature check | Certificate-chain verification (future TLS / image signing) |

### Modern: BLAKE2b, ChaCha20-Poly1305, Argon2id

| Primitive | Header | Sizes | Use site |
|-----------|--------|-------|----------|
| BLAKE2b | [`security/blake2b.h`](../../kernel/security/blake2b.h) | 1–64 byte output, 128-byte block | Argon2id `H` / `H'`, future content-addressed storage |
| ChaCha20-Poly1305 AEAD | [`security/chacha20_poly1305.h`](../../kernel/security/chacha20_poly1305.h) | 32-byte key, 12-byte nonce, 16-byte tag | Persistence envelope for the sealed account + role tables |
| Argon2id (RFC 9106) | [`security/argon2id.h`](../../kernel/security/argon2id.h) | memory 8–1024 KiB, time ≥ 1, parallelism ≥ 1, output 4–64 B | Password hash V2, persistence KEK derivation |

## Selection Guide

| Need | Use |
|------|-----|
| Stretch a low-entropy password into a KEK | Argon2id |
| Hash a password for a verifier file | Password hash V2 (Argon2id under the hood) |
| MAC an arbitrary-length message | HMAC-SHA256 |
| Derive a session key from a shared secret | KDF-SHA256 (`prf.h`) |
| Encrypt + authenticate a small blob (≤ MiB-class) | ChaCha20-Poly1305 |
| Encrypt a fixed-size data block (no MAC) | AES-CTR-mode (compose AES + counter) — currently inline, no helper |
| Hash any binary blob | SHA-256, or BLAKE2b if you need variable output length |
| Verify an 802.11 group key | AES Key Wrap unwrap |

The two **don't-do-it** rules:

- Do not use SHA-1 outside the WPA2 legacy compatibility paths. The
  presence of SHA-1 in this tree is for spec compliance, not because
  any new code should reach for it.
- Do not write a new PRNG. Random comes from
  [`kernel/util/random.h`](../../kernel/util/random.h), seeded by
  virtio-rng (when present), RDRAND, and entropy mixed in from the
  HPET reads + driver IRQ timing.

## Known-Answer Tests at Boot

Every primitive ships with a `*SelfTest()` whose KAT vectors come from
the spec's test appendix:

| Primitive | Vector source |
|-----------|--------------|
| AES | FIPS 197 Appendix C |
| AES Key Wrap | RFC 3394 §4 |
| SHA-1 / SHA-256 | FIPS 180-4 |
| HMAC-SHA-1 / -SHA-256 | RFC 2202 / RFC 4231 |
| PBKDF2-HMAC-SHA256 | RFC 7914 §11 |
| SHA-384 | FIPS 180-4 |
| HKDF | RFC 5869 §A |
| AES-GCM | NIST SP 800-38D test vectors |
| RSA / X.509 | self-signed test cert + `bigint_rsa4096_vector.h` modexp vector |
| BLAKE2b | RFC 7693 §A.1 |
| ChaCha20-Poly1305 | RFC 8439 §2.6.2 / §2.8.2 |
| Argon2id | RFC 9106 §6 |

All KATs run from the boot self-test orchestrator. A KAT failure fires
`kBootSelftestFail` with the primitive's tag and panics — there is no
recovery path for "AES-256 isn't AES-256."

## Threading and Locking

- All primitives are **stateless** at the call surface. The state lives
  on the caller's stack (`AesCtx`, `Sha256State`, etc.). Multiple CPUs
  can be encrypting in parallel without coordination as long as each
  has its own context.
- No allocator calls on the hot path. The caller provides the output
  buffer.
- No `KLOG` calls on the hot path. A failure case (e.g. Argon2id memory
  spec out of range) returns `Err{ErrorCode::Invalid}` and lets the
  caller decide whether to log.

## Side-Channel Posture

The primitives are written with constant-time intent — no
table-lookup-by-key for AES, BLAKE2b uses no key-dependent branching —
but DuetOS does not yet ship side-channel sanitisers or a power-side
test bench. Treat constant-time as a **design intent**, not a verified
property. The Roadmap entry is
[`crypto/constant-time-audit`](../reference/Roadmap.md).

## Capability Gates

The primitives themselves carry no capability gate — they are pure
arithmetic. Operations *built on* the primitives carry gates at the
syscall layer; see
[Auth and Login](../security/Auth-and-Login.md) for the password-hash
verification path and [Capabilities](../security/Capabilities.md) for
the cap table.

## Known Limits / GAPs

- **No elliptic-curve crypto.** RSA is the only asymmetric primitive in
  the tree; Ed25519 / X25519 / Curve25519 land with the first TLS slice.
- **PBKDF2 is locked to 4096 iters in the WPA2 path.** That is the
  spec; if you want stronger stretch for password storage, use
  Argon2id (V2 password hash) instead.
- **Constant-time review is intent-only.** No formal audit yet.

## Troubleshooting

- **Boot panics with `kBootSelftestFail` and a primitive tag.** A KAT
  vector mismatched — the build is miscompiled or a primitive was edited
  without updating its vector. There is no recovery path; fix the
  primitive or the vector. Check the failing tag against the
  Known-Answer-Tests table to find which `*SelfTest()` tripped.
- **`Err{ErrorCode::Invalid}` from a KDF call.** A spec parameter is out
  of range (Argon2id memory/time/parallelism, HKDF output length). The
  primitives don't log — inspect the caller's parameters.

## Related Pages

- [Auth and Login](../security/Auth-and-Login.md) — password hashing,
  account table, login flow
- [Persistence (secrets at rest)](../security/Persistence.md) —
  ChaCha20-Poly1305 envelope, Argon2id KEK
- [Network Stack](../networking/Network-Stack.md) — 802.11 PRF, EAPOL
  key wrap consumers
- [Capabilities](../security/Capabilities.md) — gates on crypto-using
  syscalls
- [Roadmap](../reference/Roadmap.md) — TLS, public-key, constant-time
  audit
