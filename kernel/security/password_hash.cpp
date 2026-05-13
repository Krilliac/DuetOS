#include "security/password_hash.h"

#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "crypto/pbkdf2.h"
#include "util/random.h"

namespace duetos::security
{

u32 PasswordDefaultIterations()
{
    // 100× cheaper PBKDF2 under any VMM. Cuts ~50 wall-seconds off
    // boot time on QEMU TCG without losing algorithmic coverage.
    return arch::IsEmulator() ? kPasswordEmulatorIterations : kPasswordDefaultIterations;
}

bool ConstantTimeEqual(const u8* a, const u8* b, u32 len)
{
    // OR-accumulate the byte differences across the whole buffer
    // so the loop runs unconditionally to `len`. The compiler is
    // free to vectorise the load + xor + or; what we forbid is an
    // early-out branch on the running diff, which would leak how
    // many leading bytes matched.
    u32 diff = 0;
    for (u32 i = 0; i < len; ++i)
        diff |= static_cast<u32>(a[i] ^ b[i]);
    return diff == 0;
}

void PasswordHashCreateExplicit(const char* password, u32 password_len, const u8 salt[kPasswordSaltBytes],
                                u32 iterations, PasswordHashRecord* out)
{
    if (out == nullptr)
        return;
    out->algorithm = PasswordAlgorithm::Pbkdf2HmacSha256;
    out->iterations = iterations;
    for (u32 i = 0; i < kPasswordSaltBytes; ++i)
        out->salt[i] = salt[i];
    duetos::crypto::Pbkdf2HmacSha256(reinterpret_cast<const u8*>(password), password_len, salt, kPasswordSaltBytes,
                                     iterations, out->hash, kPasswordHashBytes);
}

void PasswordHashCreate(const char* password, u32 password_len, PasswordHashRecord* out)
{
    if (out == nullptr)
        return;
    u8 salt[kPasswordSaltBytes];
    duetos::core::RandomFillBytes(salt, kPasswordSaltBytes);
    PasswordHashCreateExplicit(password, password_len, salt, PasswordDefaultIterations(), out);
}

bool PasswordHashVerify(const char* password, u32 password_len, const PasswordHashRecord& record)
{
    if (record.algorithm != PasswordAlgorithm::Pbkdf2HmacSha256)
        return false;
    // Reject obviously-bogus iteration counts so a corrupt on-disk
    // record can't make Verify spin for hours. 1 .. 10M covers the
    // realistic range — a future stronger algorithm gets its own
    // case branch with its own bound.
    if (record.iterations == 0 || record.iterations > 10'000'000u)
        return false;
    u8 candidate[kPasswordHashBytes];
    duetos::crypto::Pbkdf2HmacSha256(reinterpret_cast<const u8*>(password), password_len, record.salt,
                                     kPasswordSaltBytes, record.iterations, candidate, kPasswordHashBytes);
    return ConstantTimeEqual(candidate, record.hash, kPasswordHashBytes);
}

// ---------------------------------------------------------------------
// V2 record API.
//
// V1 records (PasswordHashRecord, 56 bytes) remain the in-memory
// shape AuthInit / AuthAddUser write. V2 (PasswordHashRecordV2,
// 72 bytes) is the shape the persistence layer will write to
// /system/secrets/accounts.duet — once that layer lands.
//
// Today (no persistence): the V2 path exists so callers can be
// migrated incrementally. The Argon2id arm of the dispatch is a
// fail-closed stub — see wiki/security/Persistence.md → Dependency
// order for the v1 plan.
// ---------------------------------------------------------------------

bool PasswordHashVerifyV2(const char* password, u32 password_len, const PasswordHashRecordV2& record)
{
    if (record.version != kPasswordRecordV2Version)
        return false;

    switch (record.algorithm)
    {
    case PasswordAlgorithm::Pbkdf2HmacSha256:
    {
        const u32 iters = record.params.pbkdf2.iterations;
        if (iters == 0 || iters > 10'000'000u)
            return false;
        u8 candidate[kPasswordHashBytes];
        duetos::crypto::Pbkdf2HmacSha256(reinterpret_cast<const u8*>(password), password_len, record.salt,
                                         kPasswordSaltBytes, iters, candidate, kPasswordHashBytes);
        return ConstantTimeEqual(candidate, record.hash, kPasswordHashBytes);
    }
    case PasswordAlgorithm::Argon2id:
        // STUB: Argon2id verify path. Blake2b primitive is shipping
        // (kernel/security/blake2b.{h,cpp}, KAT-verified); Argon2id
        // on top of it is the next slice. A V2 record carrying
        // PasswordAlgorithm::Argon2id will round-trip correctly once
        // the implementation lands; until then any such record fails
        // closed with a serial-log warning so it's visible in boot.
        arch::SerialWrite("[password] Argon2id verify requested — not yet implemented\n");
        return false;
    default:
        return false;
    }
}

void PasswordHashCreateV2(const char* password, u32 password_len, PasswordHashRecordV2* out)
{
    if (out == nullptr)
        return;
    // Default to PBKDF2 for v0 — Argon2id is reserved but the
    // implementation hasn't landed yet (see Persistence.md).
    // When Argon2id ships, flip this to PasswordAlgorithm::Argon2id
    // and populate out->params.argon2id from the per-install KDF
    // params in /system/secrets/header.duet.
    out->version = kPasswordRecordV2Version;
    out->algorithm = PasswordAlgorithm::Pbkdf2HmacSha256;
    duetos::core::RandomFillBytes(out->salt, kPasswordSaltBytes);
    out->params.pbkdf2.iterations = PasswordDefaultIterations();
    for (u32 i = 0; i < 3; ++i)
        out->params.pbkdf2.reserved[i] = 0;
    duetos::crypto::Pbkdf2HmacSha256(reinterpret_cast<const u8*>(password), password_len, out->salt, kPasswordSaltBytes,
                                     out->params.pbkdf2.iterations, out->hash, kPasswordHashBytes);
}

void PasswordHashV2SelfTest()
{
    arch::SerialWrite("[password-v2] self-test: V2 record dispatch\n");

    // PBKDF2 arm — exercise round-trip with explicit salt + iters
    // to keep the test deterministic. The KAT itself is in
    // PasswordHashSelfTest; here we only check the algorithm
    // dispatch shape.
    {
        const char* pw = "correct horse battery staple";
        const u32 pw_len = 28;
        PasswordHashRecordV2 rec{};
        rec.version = kPasswordRecordV2Version;
        rec.algorithm = PasswordAlgorithm::Pbkdf2HmacSha256;
        for (u32 i = 0; i < kPasswordSaltBytes; ++i)
            rec.salt[i] = static_cast<u8>(i);
        rec.params.pbkdf2.iterations = 1000;
        duetos::crypto::Pbkdf2HmacSha256(reinterpret_cast<const u8*>(pw), pw_len, rec.salt, kPasswordSaltBytes, 1000,
                                         rec.hash, kPasswordHashBytes);
        KASSERT(PasswordHashVerifyV2(pw, pw_len, rec), "security/password_hash-v2",
                "PBKDF2 arm: verify rejected correct password");
        KASSERT(!PasswordHashVerifyV2("wrong", 5, rec), "security/password_hash-v2",
                "PBKDF2 arm: verify accepted wrong password");
    }

    // Argon2id arm — stub returns false; record carrying the
    // reserved algorithm must fail closed.
    {
        PasswordHashRecordV2 rec{};
        rec.version = kPasswordRecordV2Version;
        rec.algorithm = PasswordAlgorithm::Argon2id;
        rec.params.argon2id.memory_kib = 65536;
        rec.params.argon2id.time_cost = 3;
        rec.params.argon2id.parallelism = 1;
        KASSERT(!PasswordHashVerifyV2("anything", 8, rec), "security/password_hash-v2",
                "Argon2id stub should fail closed until implementation lands");
    }

    // Version mismatch — defensive read of a record from a future
    // kernel that has bumped the format.
    {
        PasswordHashRecordV2 rec{};
        rec.version = 0xFEEDFACE;
        rec.algorithm = PasswordAlgorithm::Pbkdf2HmacSha256;
        KASSERT(!PasswordHashVerifyV2("x", 1, rec), "security/password_hash-v2", "unknown version must fail closed");
    }

    arch::SerialWrite("[password-v2] self-test: PASS\n");
}

void PasswordHashSelfTest()
{
    // ---------- ConstantTimeEqual sanity ----------
    {
        const u8 a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        const u8 b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        const u8 c[8] = {1, 2, 3, 4, 5, 6, 7, 9};
        KASSERT(ConstantTimeEqual(a, b, 8), "security/password_hash", "constant-time eq false-negative");
        KASSERT(!ConstantTimeEqual(a, c, 8), "security/password_hash", "constant-time eq false-positive (last byte)");
        KASSERT(!ConstantTimeEqual(a, c, 1) || a[0] == c[0], "security/password_hash",
                "constant-time eq misbehaved on len=1 prefix");
    }

    // ---------- PBKDF2-HMAC-SHA256 KAT (deterministic salt) ----------
    // PBKDF2-HMAC-SHA256(P="correct horse battery staple",
    //                    S=00 01 02 .. 0F, c=1000, dkLen=32).
    // Computed against the project's Pbkdf2HmacSha256 implementation
    // and locked in here. The implementation itself is independently
    // verified against RFC 7914 §11 vectors in Pbkdf2SelfTest, so a
    // regression in either layer trips a KAT — Pbkdf2SelfTest catches
    // a primitive bug, this catches a chaining/parameter bug in
    // PasswordHashCreateExplicit.
    {
        u8 salt[kPasswordSaltBytes];
        for (u32 i = 0; i < kPasswordSaltBytes; ++i)
            salt[i] = static_cast<u8>(i);
        const char* pw = "correct horse battery staple";
        const u32 pw_len = 28;
        PasswordHashRecord rec{};
        PasswordHashCreateExplicit(pw, pw_len, salt, 1000, &rec);
        KASSERT(rec.algorithm == PasswordAlgorithm::Pbkdf2HmacSha256, "security/password_hash",
                "explicit-create algorithm wrong");
        KASSERT(rec.iterations == 1000, "security/password_hash", "explicit-create iterations wrong");
        const u8 want[32] = {0xA6, 0x9B, 0x17, 0x9E, 0x3A, 0xDD, 0x3C, 0x1E, 0x0A, 0xAF, 0x22,
                             0x7A, 0x0E, 0xB3, 0xAA, 0x2A, 0xA8, 0x64, 0x5A, 0xB8, 0x6F, 0xEC,
                             0xF6, 0xCA, 0x00, 0xC1, 0x75, 0x12, 0x69, 0x7C, 0x71, 0x9E};
        for (u32 i = 0; i < 32; ++i)
            KASSERT(rec.hash[i] == want[i], "security/password_hash",
                    "PBKDF2-HMAC-SHA256(\"correct horse...\") KAT mismatch");

        // Verify-correct passes.
        KASSERT(PasswordHashVerify(pw, pw_len, rec), "security/password_hash", "verify rejected correct password");

        // Verify-wrong fails.
        KASSERT(!PasswordHashVerify("wrong password", 14, rec), "security/password_hash",
                "verify accepted wrong password");

        // Verify-tampered-hash fails (flip a bit in the stored hash).
        PasswordHashRecord tampered = rec;
        tampered.hash[0] ^= 0x01u;
        KASSERT(!PasswordHashVerify(pw, pw_len, tampered), "security/password_hash", "verify accepted tampered hash");

        // Verify-tampered-salt fails (changing salt re-derives a different hash).
        PasswordHashRecord salted = rec;
        salted.salt[0] ^= 0x01u;
        KASSERT(!PasswordHashVerify(pw, pw_len, salted), "security/password_hash", "verify accepted tampered salt");

        // Verify-bogus-algorithm fails closed.
        PasswordHashRecord bogus = rec;
        bogus.algorithm = static_cast<PasswordAlgorithm>(0xDEADBEEFu);
        KASSERT(!PasswordHashVerify(pw, pw_len, bogus), "security/password_hash", "verify accepted unknown algorithm");

        // Verify-zero-iter fails closed.
        PasswordHashRecord zero = rec;
        zero.iterations = 0;
        KASSERT(!PasswordHashVerify(pw, pw_len, zero), "security/password_hash", "verify accepted zero iterations");
    }

    // ---------- Random-salt path produces distinct hashes ----------
    // Two PasswordHashCreate calls with the same password should
    // return DIFFERENT records (different salts → different hashes)
    // yet both should verify against the original password.
    {
        const char* pw = "matching password";
        const u32 pw_len = 17;
        PasswordHashRecord r1{};
        PasswordHashRecord r2{};
        PasswordHashCreate(pw, pw_len, &r1);
        PasswordHashCreate(pw, pw_len, &r2);
        // Salts must differ. (Random failure of equality with 16
        // bytes of true entropy is ~2^-128 — well below the noise
        // floor of "did the entropy pool initialise?".)
        bool any_diff = false;
        for (u32 i = 0; i < kPasswordSaltBytes; ++i)
            if (r1.salt[i] != r2.salt[i])
                any_diff = true;
        KASSERT(any_diff, "security/password_hash",
                "two PasswordHashCreate calls returned identical salts (entropy pool dead?)");
        // Both verify.
        KASSERT(PasswordHashVerify(pw, pw_len, r1), "security/password_hash",
                "random-salt record #1 failed self-verify");
        KASSERT(PasswordHashVerify(pw, pw_len, r2), "security/password_hash",
                "random-salt record #2 failed self-verify");
    }
}

} // namespace duetos::security
