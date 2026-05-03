# Crypto graduates to OS core + password-hash module v0

_Type: Decision + Pattern + Observation._
_Status: Active. Crypto modules moved out of `kernel/net/wireless/crypto/` to `kernel/crypto/`; password-hash primitive in place; **`auth.cpp` now consumes it** — the in-memory account table stores `PasswordHashRecord` per row and every verify path runs PBKDF2-HMAC-SHA256 + constant-time compare. User-table-on-disk is the next bounded slice._
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

### 4. `auth.cpp` overhaul — landed

`kernel/security/auth.{h,cpp}` previously stored a salted
iterated FNV-1a/64 of each password in 16 fixed-size in-memory
account rows. As of this slice it stores a
`duetos::security::PasswordHashRecord` per row instead — the
same 56-byte shape that will eventually serialise to disk — and
every verify path runs PBKDF2-HMAC-SHA256 (100 000 iterations
over a 16-byte random salt) followed by a constant-time
compare. The FNV constants (`kFnvOffset`, `kFnvPrime`,
`kHashIterations`) were file-private and have been deleted; no
external caller knew about them so the API surface is
unchanged.

Concrete changes:

- **`Account` struct** now holds `bool has_password` + a
  `PasswordHashRecord record`. The 8-byte salt + `u64 hash`
  pair is gone.
- **`SetAccountPassword(Account*, const char*)`** is the single
  internal helper that mutates a slot's credentials. Empty
  password → `has_password=false`, record zeroed (the guest
  account uses this). Non-empty → `PasswordHashCreate` derives
  a fresh record from the kernel entropy pool.
- **`VerifyPasswordOnAccount(Account*, const char*)`** always
  runs `PasswordHashVerify` against either the stored record or
  a file-private decoy record (empty-password accounts), so the
  wall-clock cost of "wrong password" matches "no password set,
  caller supplied a non-empty password". The PBKDF2 result is
  discarded for the no-password case; only an empty supplied
  password authenticates that case.
- **`AuthVerify` for unknown user** burns an equivalent PBKDF2
  cycle against the same decoy record and returns false, so an
  unknown username doesn't respond faster than a bad password
  against a real user.
- **`AuthSelfTest`** retains the four original assertions plus
  two new ones: a non-empty password is rejected for the
  empty-password guest, and `AccountView::has_password` reports
  the right value for both seeded accounts. Total ~6 PBKDF2
  derivations at 100 000 iterations each (~300 ms boot delta on
  a modern x86 core); acceptable for v0.

Init ordering: `AuthInit` calls `PasswordHashCreate`, which
draws salt bytes via `RandomFillBytes`. `kernel/core/main.cpp`
already runs `RandomInit` (line 593) well before `AuthInit`
(line 1454); the auth header documents this ordering
requirement so a future reorganiser doesn't accidentally invert
it.

What stays out of scope:

- **User-table-on-disk** is the next bounded slice. Until that
  lands, runtime-added accounts still disappear on reboot and
  `AuthInit` re-derives the seeded admin record from PBKDF2 +
  fresh entropy on every boot.
- **Argon2id** still pending — the `PasswordAlgorithm` enum has
  the case wired but the algorithm itself is a future module.

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
- `kernel/security/auth.{h,cpp}` — Account row now embeds a
  `PasswordHashRecord` instead of `salt[8] + u64 hash`; FNV/64
  constants removed; `AuthVerify` runs `PasswordHashVerify`
  through a decoy-record fallback for unknown users +
  no-password accounts.
- `kernel/core/main.cpp` — namespace updates + 1 new self-test +
  1 new include.
- `kernel/net/wireless/eapol.cpp`, `fourway.cpp`, `mlme.cpp`,
  `test/fake_ap.cpp` — `crypto::X` → `duetos::crypto::X`.

## Follow-up not in this slice

1. **User table on disk**. Persistent storage for accounts (name +
   role + PasswordHashRecord) so credentials survive reboot. With
   the in-memory `auth.cpp` already speaking `PasswordHashRecord`,
   the on-disk slice is now a serialise/deserialise plus a
   FAT32-write integration — no further cryptographic work.
2. **Argon2id** as `PasswordAlgorithm::Argon2id`. Stronger than
   PBKDF2 but ~1500 LOC + its own KAT vectors. Land when there's
   a real-world reason (e.g. a power-user complaining about GPU
   crackers).
3. **Account-management shell commands** (`useradd`, `userdel`,
   `passwd`) already exist in `kernel/shell/shell_security.cpp`
   and now transparently produce / verify
   `PasswordHashRecord`-backed accounts via the unchanged
   `Auth*` API. No further wiring needed.
