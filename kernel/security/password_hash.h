#pragma once

#include "util/types.h"

/*
 * DuetOS — account password hashing.
 *
 * Backing primitive for `kernel/security/auth.{h,cpp}`. Every
 * password stored or verified by the account subsystem flows
 * through `PasswordHashCreate` / `PasswordHashVerify`. The pair is
 * KAT-driven and fail-closed — Verify rejects unknown algorithm
 * codes and unreasonable iteration counts so a corrupt on-disk
 * record can never make the kernel spin or accept a bogus hash.
 *
 * Construction:
 *   - Algorithm: PBKDF2-HMAC-SHA256.
 *   - Salt: 16 random bytes from the kernel entropy pool
 *           (`util/random.h::RandomFillBytes`).
 *   - Iterations: configurable per hash so future cost increases
 *     don't break previously-stored hashes. Default 100 000 — a
 *     reasonable v0 floor that's slow enough on commodity x86 to
 *     deter brute force while staying invisible at human-typing
 *     speed (~50 ms on a modern core).
 *   - Output: 32 bytes (full SHA-256 digest).
 *
 * The full record (salt + iterations + hash) is what gets stored
 * for an account. Verification recomputes the PBKDF2 with the
 * stored salt + iterations and compares the result to the stored
 * hash byte-for-byte using a CONSTANT-TIME comparison so that
 * timing attackers can't infer how many leading bytes matched.
 *
 * Why PBKDF2 and not Argon2 / scrypt:
 *   - PBKDF2 is the smallest reviewable construction that meets
 *     the v0 bar — a few hundred lines of plain C++ on top of
 *     primitives already in the tree.
 *   - Argon2 / scrypt are stronger but each is ~1500 LOC + their
 *     own KAT vectors. They're a future slice — `password_hash.h`
 *     will grow `Algorithm::Argon2id` alongside `Algorithm::Pbkdf2Sha256`
 *     and the stored record's `algorithm` field tells `Verify`
 *     which path to walk.
 *
 * Why HMAC-SHA256 specifically:
 *   - HMAC has a clean security proof from the underlying hash.
 *   - SHA-256 is in the OS core already (the WPA2 stack uses it).
 *   - SHA-1 (which WPA2 also uses) has known collision attacks;
 *     password hashing is a forward-looking primitive, so v0
 *     starts on SHA-256.
 *
 * Storage format (binary, fixed-size — no MCF/PHC string parsing
 * yet, that's a follow-on once the user table itself goes on disk):
 *
 *   struct PasswordHashRecord {
 *     u32 algorithm;     // 1 = PBKDF2-HMAC-SHA256
 *     u32 iterations;
 *     u8  salt[16];
 *     u8  hash[32];
 *   };  // total 56 bytes
 */

namespace duetos::security
{

inline constexpr u32 kPasswordSaltBytes = 16;
inline constexpr u32 kPasswordHashBytes = 32;
// OWASP 2023 floor for PBKDF2-HMAC-SHA256 is 600 000. We sit at
// that floor to harden the v0 hashes against offline cracking with
// modern GPU hardware. Verify on a modern x86_64 core: ~300 ms.
// The emulator path stays at kPasswordEmulatorIterations (below)
// so QEMU boot self-tests don't multiply by 6×.
//
// This number is a runtime cost knob, not an ABI — stored records
// carry their own iteration count, so bumping the default only
// affects newly-created hashes. Older records still verify with
// whatever count they were created with.
inline constexpr u32 kPasswordDefaultIterations = 600'000u;
// Under TCG / KVM / any VMM, the kernel boots ~10× slower per
// instruction and (in this build) without SIMD acceleration. With
// the production iteration count, seeding `admin` + `guest` plus
// the auth + brute-force self-tests fires ~10× PBKDF2(100 000)
// during boot — which costs ~3-6 wall-seconds each on TCG without
// SSE, summing to a multi-minute boot delay before the kernel
// reaches its first interactive prompt. Using a much smaller
// count under emulation keeps the algorithm exercised + the
// self-tests valid (the produced hash is still PBKDF2-HMAC-SHA256
// against the seeded salt) while shrinking the per-call cost
// 100×. Bare metal stays on the full count — IsEmulator() is the
// runtime gate.
inline constexpr u32 kPasswordEmulatorIterations = 1'000u;
u32 PasswordDefaultIterations();

enum class PasswordAlgorithm : u32
{
    Pbkdf2HmacSha256 = 1,
    Argon2id = 2, // RFC 9106; implementation lives in security/argon2id.{h,cpp}
};

struct PasswordHashRecord
{
    PasswordAlgorithm algorithm;
    u32 iterations;
    u8 salt[kPasswordSaltBytes];
    u8 hash[kPasswordHashBytes];
};

static_assert(sizeof(PasswordHashRecord) == 56, "PasswordHashRecord on-disk size locked at 56 bytes");

// ---------------------------------------------------------------------
// V2 record — algorithm-tagged, room for Argon2id params.
//
// V1 (PasswordHashRecord above) is what the in-memory auth table
// currently stores. V2 is the on-disk format the persistence layer
// will write. The two coexist during the migration window: V1
// records round up to V2 on the next successful verify
// (kernel/security/persistence.cpp — pending), so the on-disk
// table strengthens silently as users log in.
//
// V2 layout:
//   - version: 2 (this struct's format ABI)
//   - algorithm: PasswordAlgorithm enum
//   - salt: 16 bytes, same shape as V1
//   - hash: 32 bytes (PBKDF2 digest OR Argon2id tag)
//   - params: union, member selected by `algorithm`
//
// Total: 72 bytes. Sized to fit either KDF's parameters; locked
// here so the on-disk format doesn't drift once persistence
// lands. See wiki/security/Persistence.md for the full design.
// ---------------------------------------------------------------------

struct Pbkdf2Params
{
    u32 iterations;
    u32 reserved[3]; // sized to match Argon2idParams; zero on write
};

struct Argon2idParams
{
    u32 memory_kib;  // memory cost (e.g. 65536 for 64 MiB target)
    u32 time_cost;   // number of passes (e.g. 3)
    u32 parallelism; // lanes (e.g. 1)
    u32 reserved;    // sized to match Pbkdf2Params; zero on write
};

struct PasswordHashRecordV2
{
    u32 version; // = kPasswordRecordV2Version
    PasswordAlgorithm algorithm;
    u8 salt[kPasswordSaltBytes];
    u8 hash[kPasswordHashBytes];
    union
    {
        Pbkdf2Params pbkdf2;
        Argon2idParams argon2id;
    } params;
};

inline constexpr u32 kPasswordRecordV2Version = 2;

static_assert(sizeof(PasswordHashRecordV2) == 72, "PasswordHashRecordV2 on-disk size locked at 72 bytes");
static_assert(sizeof(Pbkdf2Params) == sizeof(Argon2idParams),
              "Pbkdf2Params and Argon2idParams must be same size for the union");

/// Constant-time byte equality. Returns true iff the two buffers
/// are byte-identical, taking time proportional only to `len`.
/// Public so other auth surfaces (token compare, MAC compare) can
/// reuse it.
bool ConstantTimeEqual(const u8* a, const u8* b, u32 len);

/// Hash `password` (UTF-8 bytes; we don't care about Unicode
/// normalisation in v0 — bytes-as-typed is the comparison
/// invariant) with a freshly-drawn random salt and the default
/// iteration count. Writes the full record to `*out`.
///
/// The kernel entropy pool MUST be initialised before calling
/// (i.e. `RandomInit()` has run and the pool is seeded from
/// RDSEED / RDRAND / TSC). Calling this from early boot before
/// RandomInit is a programmer error — DEBUG_ASSERTs.
void PasswordHashCreate(const char* password, u32 password_len, PasswordHashRecord* out);

/// Like `PasswordHashCreate` but with explicit iterations + salt.
/// The free-form constructor is useful for tests, for migrating
/// older records that used different costs, and for the boot KAT.
void PasswordHashCreateExplicit(const char* password, u32 password_len, const u8 salt[kPasswordSaltBytes],
                                u32 iterations, PasswordHashRecord* out);

/// Verify `password` against a stored record. Returns true iff
/// PBKDF2-HMAC-SHA256(password, record.salt, record.iterations)
/// equals `record.hash` byte-for-byte (constant-time compare).
/// Returns false for any unsupported algorithm.
bool PasswordHashVerify(const char* password, u32 password_len, const PasswordHashRecord& record);

void PasswordHashSelfTest();

// ---------------------------------------------------------------------
// V2 verify — algorithm-tagged dispatch.
//
// Reads `record.algorithm` and runs the matching KDF. Both arms
// are wired:
//   - PBKDF2-HMAC-SHA256 — identical to the V1 verify above.
//   - Argon2id (RFC 9106) — via security/argon2id.h; the per-record
//     params triple (memory_kib, time_cost, parallelism) lives in
//     `params.argon2id` and is what governs the cost of a verify.
//
// `PasswordHashCreateV2` defaults to Argon2id for new records. The
// PBKDF2 arm is retained for lazy migration of existing V1/V2-PBKDF2
// records: a successful PBKDF2 verify against the user's plaintext
// password can drive a `PasswordHashCreateV2` to re-hash under
// Argon2id, and the resulting record overwrites the stored one
// (transparent upgrade to a stronger KDF on next login).
// ---------------------------------------------------------------------

/// Verify `password` against a V2 record. Dispatches on
/// `record.algorithm`. Returns false for unknown algorithms or
/// out-of-range KDF parameters.
bool PasswordHashVerifyV2(const char* password, u32 password_len, const PasswordHashRecordV2& record);

/// Re-hash `password` with the current default algorithm
/// (Argon2id) and a fresh salt. Used by callers seeding new
/// records and by the lazy-migration path. Falls back to PBKDF2
/// only if Argon2id derivation fails (KMalloc exhaustion); the
/// fallback is logged at WARN.
void PasswordHashCreateV2(const char* password, u32 password_len, PasswordHashRecordV2* out);

/// V2 KAT — exercises the algorithm dispatch for both the PBKDF2
/// path (matches the V1 KAT byte-for-byte) and the Argon2id round-
/// trip (a freshly-created Argon2id record verifies against its
/// own plaintext and rejects a wrong password). Panics on
/// regression.
void PasswordHashV2SelfTest();

} // namespace duetos::security
