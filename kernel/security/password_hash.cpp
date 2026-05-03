#include "security/password_hash.h"

#include "core/panic.h"
#include "crypto/pbkdf2.h"
#include "util/random.h"

namespace duetos::security
{

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
    PasswordHashCreateExplicit(password, password_len, salt, kPasswordDefaultIterations, out);
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
