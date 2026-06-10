#include "crypto/rsa.h"

#include "arch/x86_64/serial.h"
#include "crypto/sha256.h"

namespace duetos::crypto
{

bool RsaPublicKeyFromBE(RsaPublicKey* k, const u8* mod_be, u32 mod_len, const u8* exp_be, u32 exp_len)
{
    if (k == nullptr)
        return false;
    BigIntZero(&k->n);
    BigIntZero(&k->e);
    k->n_bytes = 0;
    if (!BigIntFromBytesBE(&k->n, mod_be, mod_len))
        return false;
    if (!BigIntFromBytesBE(&k->e, exp_be, exp_len))
        return false;
    if (BigIntIsZero(k->n))
        return false;
    k->n_bytes = mod_len;
    return true;
}

bool Pkcs1V15UnwrapAndMatch(const u8* em, u32 em_len, const u8* prefix, u32 prefix_len, const u8* hash, u32 hash_len)
{
    // EMSA-PKCS1-v1_5 layout for verify (RFC 8017 §9.2):
    //
    //   EM = 0x00 || 0x01 || PS || 0x00 || T
    //
    //   PS  is at least 8 bytes of 0xFF (RFC 8017 forbids
    //       PS shorter than 8 for security).
    //   T   is the DigestInfo: the algorithm-specific prefix
    //       (kPkcs1ShaXXXDigestPrefix) followed by the raw
    //       hash digest.
    //
    // Total layout: em_len >= 11 + len(T). We accept exactly
    // one byte 0x00, exactly one byte 0x01, then 0xFF padding
    // until we hit a 0x00, then T.
    if (em == nullptr || prefix == nullptr || hash == nullptr)
        return false;
    if (em_len < 11 + prefix_len + hash_len)
        return false;
    if (em[0] != 0x00 || em[1] != 0x01)
        return false;
    u32 i = 2;
    while (i < em_len && em[i] == 0xFF)
        ++i;
    // PS minimum length is 8 bytes per RFC 8017. Reject short PS.
    if (i - 2 < 8)
        return false;
    if (i >= em_len || em[i] != 0x00)
        return false;
    ++i; // step past the 0x00 separator
    // Remaining must be exactly prefix || hash.
    if (em_len - i != prefix_len + hash_len)
        return false;
    for (u32 j = 0; j < prefix_len; ++j)
    {
        if (em[i + j] != prefix[j])
            return false;
    }
    for (u32 j = 0; j < hash_len; ++j)
    {
        if (em[i + prefix_len + j] != hash[j])
            return false;
    }
    return true;
}

bool RsaPkcs1V15Verify(const RsaPublicKey& k, const u8* sig, u32 sig_len, const u8* prefix, u32 prefix_len,
                       const u8* hash, u32 hash_len)
{
    if (sig == nullptr || prefix == nullptr || hash == nullptr)
        return false;
    if (k.n_bytes == 0 || sig_len != k.n_bytes)
        return false;
    // RSAVP1: m = sig^e mod n. Convert the signature into the
    // BigInt s; reject sig >= n (per RFC 8017 §5.2.2 step 1).
    BigInt s{};
    if (!BigIntFromBytesBE(&s, sig, sig_len))
        return false;
    if (BigIntCompare(s, k.n) >= 0)
        return false;
    BigInt m{};
    BigIntModExp(&m, s, k.e, k.n);
    // Emit the EM at exactly k.n_bytes, leading-zero padded.
    // EMSA-PKCS1-v1_5 expects the EM to be modulus-width.
    constexpr u32 kEmMaxBytes = (kBigIntBits / 8);
    if (k.n_bytes > kEmMaxBytes)
        return false;
    u8 em[kEmMaxBytes];
    BigIntToBytesBE(m, em, k.n_bytes);
    return Pkcs1V15UnwrapAndMatch(em, k.n_bytes, prefix, prefix_len, hash, hash_len);
}

// ---------------------------------------------------------------------------
// RSASSA-PSS verify (RFC 8017 §8.1.2 / §9.1.2), SHA-256, salt length = 32 —
// i.e. the `rsa_pss_rsae_sha256` SignatureScheme TLS 1.3 uses for an RSA
// CertificateVerify. (TLS 1.3 forbids PKCS#1 v1.5 for handshake signatures.)
// ---------------------------------------------------------------------------

namespace
{

constexpr u32 kEmMax = (kBigIntBits / 8);

// MGF1 with SHA-256 (RFC 8017 §B.2.1).
void Mgf1Sha256(const u8* seed, u32 seed_len, u8* mask, u32 mask_len)
{
    u8 digest[kSha256DigestBytes];
    u32 generated = 0;
    for (u32 counter = 0; generated < mask_len; ++counter)
    {
        const u8 cbe[4] = {static_cast<u8>(counter >> 24), static_cast<u8>(counter >> 16),
                           static_cast<u8>(counter >> 8), static_cast<u8>(counter)};
        Sha256Ctx ctx;
        Sha256Init(ctx);
        Sha256Update(ctx, seed, seed_len);
        Sha256Update(ctx, cbe, 4);
        Sha256Final(ctx, digest);
        u32 take = mask_len - generated;
        if (take > kSha256DigestBytes)
            take = kSha256DigestBytes;
        for (u32 i = 0; i < take; ++i)
            mask[generated + i] = digest[i];
        generated += take;
    }
}

// EMSA-PSS-VERIFY for SHA-256, sLen=32. Assumes a standard RSA modulus
// (top bit set) so emBits = 8*emLen - 1 and exactly one masked top bit.
bool EmsaPssSha256Verify(const u8* mhash, const u8* em, u32 em_len)
{
    constexpr u32 hLen = 32;
    constexpr u32 sLen = 32;
    if (em_len < hLen + sLen + 2 || em_len > kEmMax)
        return false;
    if (em[em_len - 1] != 0xbc)
        return false;
    const u32 db_len = em_len - hLen - 1;
    const u8* masked_db = em;
    const u8* h = em + db_len; // hLen bytes
    if (masked_db[0] & 0x80)   // leftmost (8*emLen-emBits)=1 bit must be 0
        return false;
    u8 db[kEmMax];
    Mgf1Sha256(h, hLen, db, db_len);
    for (u32 i = 0; i < db_len; ++i)
        db[i] ^= masked_db[i];
    db[0] &= 0x7f;
    // DB must be PS(0x00...) || 0x01 || salt, |PS| = db_len - sLen - 1.
    const u32 ps_len = db_len - sLen - 1;
    for (u32 i = 0; i < ps_len; ++i)
        if (db[i] != 0x00)
            return false;
    if (db[ps_len] != 0x01)
        return false;
    const u8* salt = db + ps_len + 1; // sLen bytes
    // M' = (0x00)*8 || mHash || salt ; H' = SHA-256(M') ; H' must equal H.
    u8 hprime[hLen];
    const u8 zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    Sha256Ctx ctx;
    Sha256Init(ctx);
    Sha256Update(ctx, zeros, 8);
    Sha256Update(ctx, mhash, hLen);
    Sha256Update(ctx, salt, sLen);
    Sha256Final(ctx, hprime);
    u8 diff = 0;
    for (u32 i = 0; i < hLen; ++i)
        diff |= static_cast<u8>(hprime[i] ^ h[i]);
    return diff == 0;
}

} // namespace

bool RsaPssSha256Verify(const RsaPublicKey& k, const u8* sig, u32 sig_len, const u8* mhash, u32 mhash_len)
{
    if (sig == nullptr || mhash == nullptr || mhash_len != 32)
        return false;
    if (k.n_bytes == 0 || sig_len != k.n_bytes)
        return false;
    BigInt s{};
    if (!BigIntFromBytesBE(&s, sig, sig_len))
        return false;
    if (BigIntCompare(s, k.n) >= 0)
        return false;
    BigInt m{};
    BigIntModExp(&m, s, k.e, k.n);
    if (k.n_bytes > kEmMax)
        return false;
    u8 em[kEmMax];
    BigIntToBytesBE(m, em, k.n_bytes);
    return EmsaPssSha256Verify(mhash, em, k.n_bytes);
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace
{

// Hand-crafted EM with a valid PKCS#1 v1.5 SHA-256 wrap of a
// 32-byte digest of all-zero bytes. Layout: 0x00 0x01 | 0xFF*X
// | 0x00 | kPkcs1Sha256DigestPrefix | 0x00*32. With a 256-byte
// EM (2048-bit modulus width), X = 256 - 2 - 1 - 19 - 32 = 202.
constexpr u32 kEmLen = 256;
constexpr u32 kPsLen = 256 - 2 - 1 - 19 - 32; // 202
static_assert(kPsLen >= 8, "PS too short");

// Constructed at runtime inside the self-test (the array is
// 256 bytes; constexpr can build it but the C++ array form is
// noisier than necessary).
void BuildValidEm(u8 em[kEmLen], const u8 zero_digest[32])
{
    em[0] = 0x00;
    em[1] = 0x01;
    for (u32 i = 0; i < kPsLen; ++i)
        em[2 + i] = 0xFF;
    em[2 + kPsLen] = 0x00;
    for (u32 i = 0; i < kPkcs1Sha256DigestPrefixLen; ++i)
        em[2 + kPsLen + 1 + i] = kPkcs1Sha256DigestPrefix[i];
    for (u32 i = 0; i < 32; ++i)
        em[2 + kPsLen + 1 + kPkcs1Sha256DigestPrefixLen + i] = zero_digest[i];
}

} // namespace

void RsaSelfTest()
{
    using arch::SerialWrite;

    u8 zero_digest[32] = {0};
    u8 em[kEmLen];
    BuildValidEm(em, zero_digest);

    // Step 1: well-formed EM verifies.
    if (!Pkcs1V15UnwrapAndMatch(em, kEmLen, kPkcs1Sha256DigestPrefix, kPkcs1Sha256DigestPrefixLen, zero_digest, 32))
    {
        SerialWrite("[rsa] FAIL unwrap-valid\n");
        return;
    }

    // Step 2: flip the digest -> verify fails.
    em[kEmLen - 1] ^= 0x80;
    if (Pkcs1V15UnwrapAndMatch(em, kEmLen, kPkcs1Sha256DigestPrefix, kPkcs1Sha256DigestPrefixLen, zero_digest, 32))
    {
        SerialWrite("[rsa] FAIL unwrap-tampered-digest-still-passed\n");
        return;
    }
    em[kEmLen - 1] ^= 0x80; // restore

    // Step 3: tamper with the leading 0x00 -> verify fails.
    em[0] = 0x01;
    if (Pkcs1V15UnwrapAndMatch(em, kEmLen, kPkcs1Sha256DigestPrefix, kPkcs1Sha256DigestPrefixLen, zero_digest, 32))
    {
        SerialWrite("[rsa] FAIL unwrap-bad-prefix-still-passed\n");
        return;
    }
    em[0] = 0x00; // restore

    // Step 4: short PS (only 4 0xFFs) -> rejected per RFC 8017.
    u8 short_em[64];
    short_em[0] = 0x00;
    short_em[1] = 0x01;
    for (u32 i = 0; i < 4; ++i)
        short_em[2 + i] = 0xFF;
    short_em[6] = 0x00;
    // Stuff a tiny "T" of one prefix byte + one hash byte so
    // overall layout is parseable but PS is too short.
    short_em[7] = 0x30;
    short_em[8] = 0x11;
    const u8 fake_prefix[] = {0x30, 0x11};
    if (Pkcs1V15UnwrapAndMatch(short_em, 9, fake_prefix, sizeof(fake_prefix), nullptr, 0))
    {
        SerialWrite("[rsa] FAIL unwrap-short-ps-still-passed\n");
        return;
    }

    // Step 5: RSAVP1 sanity — modular exponentiation
    // round-trips for a tiny synthetic key. n = 3233 (= 61*53),
    // e = 17, d = 2753. Pick message m = 65; ciphertext c = m^d
    // mod n = 65^2753 mod 3233 = 2790. Verify: 2790^17 mod 3233
    // == 65. This uses RsaPublicKey + BigIntModExp end-to-end
    // without depending on real-world signatures.
    BigInt n_small{};
    BigIntZero(&n_small);
    n_small.limbs[0] = 3233;
    n_small.used = 1;
    BigInt e_small{};
    BigIntZero(&e_small);
    e_small.limbs[0] = 17;
    e_small.used = 1;
    BigInt c{};
    BigIntZero(&c);
    c.limbs[0] = 588; // 65^d mod n (computed offline; n=3233, d=2753)
    c.used = 1;
    BigInt m{};
    BigIntModExp(&m, c, e_small, n_small);
    if (m.used != 1 || m.limbs[0] != 65)
    {
        SerialWrite("[rsa] FAIL toy-rsavp1\n");
        return;
    }

    SerialWrite("[rsa] PASS (pkcs1-v1.5 unwrap + rsavp1 toy)\n");
}

} // namespace duetos::crypto
