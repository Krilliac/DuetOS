# Crypto graduates to OS core + password-hash module v0

_Type: Decision + Pattern + Observation._
_Status: Active. Crypto modules moved out of `kernel/net/wireless/crypto/` to `kernel/crypto/`; new password-hash primitive lays groundwork for the eventual `auth.cpp` overhaul._
_Last updated: 2026-05-03._

## What landed

### 1. Crypto graduates to OS core

All crypto primitives moved from
`kernel/net/wireless/crypto/` → `kernel/crypto/`:

- `aes.{h,cpp}` — AES-128 / AES-256 block cipher (FIPS 197).
- `aes_keywrap.{h,cpp}` — RFC 3394 wrap / unwrap.
- `hmac.{h,cpp}` — HMAC-SHA1 / HMAC-SHA256 (RFC 2104 / 6234).
- `md5.{h,cpp}` — MD5 (RFC 1321; legacy interop only).
- `pbkdf2.{h,cpp}` — PBKDF2-HMAC-SHA1 + **new** PBKDF2-HMAC-SHA256
  (RFC 2898).
- `prf.{h,cpp}` — IEEE 802.11 PRF + KDF-SHA256.
- `sha1.{h,cpp}` — SHA-1 (FIPS 180-4).
- `sha256.{h,cpp}` — SHA-256 (FIPS 180-4).

Namespace renamed `duetos::net::wireless::crypto` → `duetos::crypto`.
All call sites updated to fully-qualified `duetos::crypto::X(...)`
(no alias redirect — greenfield project, no public ABI to preserve).

Consumer changes:
- `kernel/core/main.cpp` — boot self-test FQNs + include paths.
- `kernel/net/wireless/eapol.cpp` / `fourway.cpp` / `mlme.cpp` /
  `test/fake_ap.cpp` — `crypto::X` → `duetos::crypto::X`.
- `kernel/fs/gpt.cpp` — already used the unrelated `util::Crc32`,
  no crypto dependency.
- KASSERT subsystem labels updated (`net/wireless/crypto/...` →
  `crypto/...`) in the moved TUs.

The crypto subdirectory is now a peer of `kernel/util/`,
`kernel/security/`, `kernel/sync/`, etc. The 802.11 stack still
owns the *wireless-specific* modules (`net/wireless/eapol.cpp`,
`fourway.cpp`, `mlme.cpp`, `wifi_diag.{h,cpp}`, beacon parser,
loopback test) but no longer owns its primitives — those serve
the whole OS.

### 2. PBKDF2-HMAC-SHA256

`kernel/crypto/pbkdf2.{h,cpp}` gained `Pbkdf2HmacSha256` alongside
the existing `Pbkdf2HmacSha1`. Same shape as the SHA-1 form. The
SHA-1 form stays only because WPA2-Personal locks it; **all new
code MUST use the SHA-256 form**.

Boot KAT covers two RFC 7914 §11 vectors:
- `P="passwd"`, `S="salt"`, `c=1`, `dkLen=64` — exercises the
  multi-block dispatch (64 / 32 = 2 blocks).
- `P="Password"`, `S="NaCl"`, `c=80000`, `dkLen=64` — exercises
  the inner iteration loop at production cost.

### 3. Password-hash module — `kernel/security/password_hash.{h,cpp}`

Layered on PBKDF2-HMAC-SHA256 + the kernel entropy pool. Public
surface:

```cpp
struct PasswordHashRecord {
    PasswordAlgorithm algorithm;     // Pbkdf2HmacSha256 = 1
    u32 iterations;
    u8  salt[16];                    // kPasswordSaltBytes
    u8  hash[32];                    // kPasswordHashBytes
};  // packed 56 bytes, on-disk format

void PasswordHashCreate(const char* pw, u32 pw_len, PasswordHashRecord* out);
void PasswordHashCreateExplicit(const char* pw, u32 pw_len,
                                const u8 salt[16], u32 iterations,
                                PasswordHashRecord* out);
bool PasswordHashVerify(const char* pw, u32 pw_len, const PasswordHashRecord& rec);

bool ConstantTimeEqual(const u8* a, const u8* b, u32 len);
```

Key design choices:

- **Algorithm**: PBKDF2-HMAC-SHA256. Smallest reviewable
  construction that meets the v0 bar; Argon2 / scrypt is a future
  slice that grows `PasswordAlgorithm::Argon2id` alongside the
  existing case.
- **Salt**: 16 bytes, fresh per hash, drawn via
  `duetos::core::RandomFillBytes` from the kernel entropy pool.
  The salt is what makes two hashes of the same password produce
  different records — boot KAT verifies that property.
- **Iterations**: configurable per-hash so future cost increases
  don't break previously-stored records. Default
  `kPasswordDefaultIterations = 100000` (about 50 ms on a modern
  x86 core — invisible at human-typing speed, expensive at
  brute-force speed). `Verify` rejects iteration counts of 0 or
  >10 000 000 so a corrupt on-disk record can't make the kernel
  spin for hours.
- **Output**: 32 bytes (full SHA-256 digest, no truncation).
- **Storage**: packed `PasswordHashRecord` is 56 bytes total —
  static_assert locks the size. Once a user-table-on-disk format
  lands, this struct serialises directly. No string MCF parsing
  in v0.
- **ConstantTimeEqual**: OR-accumulates byte differences across
  the whole buffer with no early-out, so timing attackers can't
  infer how many leading bytes matched. Public so other auth
  surfaces (token compare, MAC compare) can reuse it.

Boot self-test (`PasswordHashSelfTest`) covers:

- `ConstantTimeEqual` true-positive + true-negative (last-byte
  difference, single-byte prefix).
- Deterministic-salt KAT for `PasswordHashCreateExplicit` —
  asserts the chained `Pbkdf2HmacSha256` returns the locked-in
  expected output. Implementation itself is verified by
  `Pbkdf2SelfTest`'s RFC 7914 vectors; this catches a
  chaining/parameter bug between the password layer and the KDF.
- `PasswordHashVerify` accepts the correct password.
- `Verify` rejects wrong password.
- `Verify` rejects tampered hash (one bit flipped).
- `Verify` rejects tampered salt.
- `Verify` rejects unknown algorithm enum value (fail-closed).
- `Verify` rejects 0-iter record (fail-closed).
- Random-salt path produces distinct records for the same
  password, both of which self-verify (asserts entropy pool
  feeding the salt is alive + deterministic chaining works for
  random salts too).

### 4. Why this lays groundwork for `auth.cpp`

`kernel/security/auth.{h,cpp}` today carries hard-coded
cleartext credentials (`admin/admin`, `guest`). The transition
to hashed passwords is a one-call swap once a user table exists:

- `AuthLoginAttempt(user, password)` → currently does a
  cleartext `strcmp`. Becomes `PasswordHashVerify(password,
  password_len, user.stored_record)`.
- New-user creation calls `PasswordHashCreate` and stores the
  resulting `PasswordHashRecord`.
- The user table itself (with rows of name + role +
  `PasswordHashRecord`) is the next bounded slice. Until that
  lands the password-hash module sits as a self-tested primitive
  with no live caller — the boot KAT keeps it honest.

## Verification

- **Boot self-tests**: KAT vectors panic on mismatch.
  `Pbkdf2SelfTest` covers RFC 6070 (SHA-1) + RFC 7914 (SHA-256).
  `PasswordHashSelfTest` covers the chaining + verify
  fail-closed cases.
- **Host check**: `/tmp/pbkdf2_sha256_check.cpp` standalone
  harness compiles `kernel/crypto/{sha1,sha256,hmac,pbkdf2}.cpp`
  against a `panic.h` shim and runs `Pbkdf2SelfTest()`. Confirmed
  PASS before pushing. The deterministic password-hash KAT
  fixture was extracted from the host run (computed by the
  RFC-7914-validated Pbkdf2HmacSha256) and locked into the
  module.
- **Build flavors**: `x86_64-release` and `x86_64-debug-fast`
  build clean with zero warnings.

## Files

- `kernel/crypto/*` — 16 files, moved from `kernel/net/wireless/crypto/*`.
- `kernel/crypto/pbkdf2.{h,cpp}` — added `Pbkdf2HmacSha256` + 2
  RFC 7914 KAT vectors (~50 LOC delta).
- `kernel/security/password_hash.{h,cpp}` — new module (~210 LOC).
- `kernel/core/main.cpp` — namespace updates + 1 new self-test +
  1 new include.
- `kernel/net/wireless/eapol.cpp`, `fourway.cpp`, `mlme.cpp`,
  `test/fake_ap.cpp` — `crypto::X` → `duetos::crypto::X`.

Total: 16 file moves + 2 new files + 6 files lightly edited.

## Follow-up not in this slice

1. **User table on disk**. Persistent storage for accounts (name +
   role + PasswordHashRecord) so credentials survive reboot. The
   existing `kernel/security/auth.{h,cpp}` is in-memory + hard-
   coded; once a user table lands, swap `strcmp` for
   `PasswordHashVerify`. ~150 LOC + a FAT32-write integration.
2. **Argon2id** as `PasswordAlgorithm::Argon2id`. Stronger than
   PBKDF2 but ~1500 LOC + its own KAT vectors. Land when there's
   a real-world reason (e.g. a power-user complaining about GPU
   crackers).
3. **Account-management shell commands** (`useradd`, `userdel`,
   `passwd`) wired to the new module. Today these don't exist;
   credentials live in a hardcoded array.
