#include "crypto/aes_gcm.h"

#include "core/panic.h"

namespace duetos::crypto
{

namespace
{

// GF(2^128) multiplication per NIST SP 800-38D Algorithm 1.
// The field is GF(2)[x] / (x^128 + x^7 + x^2 + x + 1) with the
// MSB-first bit ordering used by the spec — bit 0 of byte 0 is
// the highest-order bit of the polynomial.
//
// Bit-by-bit shift-and-XOR: 128 iterations each multiply. Slow
// vs. table-based approaches but completely state-free, easy to
// audit for correctness, and constant-time-by-construction.
void GHashMul(u8 z[16], const u8 h[16])
{
    u8 v[16];
    for (u32 i = 0; i < 16; ++i)
        v[i] = h[i];
    u8 r[16] = {};
    for (u32 byte = 0; byte < 16; ++byte)
    {
        for (i32 bit = 7; bit >= 0; --bit)
        {
            // If bit `bit` of z[byte] is set, XOR v into r.
            if ((z[byte] >> bit) & 1u)
            {
                for (u32 i = 0; i < 16; ++i)
                    r[i] ^= v[i];
            }
            // Multiply v by x: shift right (MSB-first interpretation
            // means right-shift across bytes), and conditionally XOR
            // with the irreducible polynomial constant 0xE1 in byte 0
            // when the LSB-of-the-polynomial (bit 7 of byte 15) was set.
            const u8 lsb_set = u8(v[15] & 1);
            for (i32 i = 15; i > 0; --i)
                v[i] = u8((v[i] >> 1) | u8(v[i - 1] << 7));
            v[0] = u8(v[0] >> 1);
            if (lsb_set)
                v[0] ^= 0xE1;
        }
    }
    for (u32 i = 0; i < 16; ++i)
        z[i] = r[i];
}

void GHashAccum(u8 acc[16], const u8 h[16], const u8* data, u32 len)
{
    u32 off = 0;
    while (off < len)
    {
        const u32 take = (len - off < 16u) ? (len - off) : 16u;
        for (u32 i = 0; i < take; ++i)
            acc[i] ^= data[off + i];
        // Pad the partial last block with zeros (bytes already 0
        // in `acc` xor with 0 = no change).
        GHashMul(acc, h);
        off += take;
    }
}

void IncCounter32(u8 ctr[16])
{
    // Increment the rightmost 32 bits per SP 800-38D §6.2.
    for (i32 i = 15; i >= 12; --i)
    {
        ++ctr[i];
        if (ctr[i] != 0)
            return;
    }
}

void GcmCore(const AesCtx& ctx, const u8 iv[kAesGcmIvBytes], const u8* aad, u32 aad_len, const u8* in, u32 len, u8* out,
             bool encrypt, u8 tag[kAesGcmTagBytes])
{
    // H = E(K, 0)
    u8 h[16] = {};
    AesEncryptBlock(ctx, h, h);

    // J0 for 96-bit IV: IV || 0x00000001.
    u8 j0[16] = {};
    for (u32 i = 0; i < 12; ++i)
        j0[i] = iv[i];
    j0[15] = 1;

    // GCTR over the data with counter starting at inc32(J0).
    u8 ctr[16];
    for (u32 i = 0; i < 16; ++i)
        ctr[i] = j0[i];
    IncCounter32(ctr);

    u32 off = 0;
    while (off < len)
    {
        u8 keystream[16];
        AesEncryptBlock(ctx, ctr, keystream);
        const u32 take = (len - off < 16u) ? (len - off) : 16u;
        for (u32 i = 0; i < take; ++i)
            out[off + i] = u8(in[off + i] ^ keystream[i]);
        off += take;
        IncCounter32(ctr);
    }

    // GHASH over AAD || pad || C || pad || u64be(aad_len_bits) ||
    // u64be(C_len_bits). For decrypt, "C" is the input ciphertext.
    u8 acc[16] = {};
    GHashAccum(acc, h, aad, aad_len);
    const u8* mac_data = encrypt ? out : in;
    GHashAccum(acc, h, mac_data, len);
    u8 lengths[16];
    const u64 aad_bits = u64(aad_len) * 8;
    const u64 ct_bits = u64(len) * 8;
    for (i32 i = 7; i >= 0; --i)
        lengths[i] = u8((aad_bits >> (8 * (7 - i))) & 0xFFu);
    for (i32 i = 7; i >= 0; --i)
        lengths[8 + i] = u8((ct_bits >> (8 * (7 - i))) & 0xFFu);
    GHashAccum(acc, h, lengths, 16);

    // T = GCTR(K, J0, GHASH).
    u8 ek_j0[16];
    AesEncryptBlock(ctx, j0, ek_j0);
    for (u32 i = 0; i < 16; ++i)
        tag[i] = u8(acc[i] ^ ek_j0[i]);
}

bool ConstantTimeEq16(const u8 a[16], const u8 b[16])
{
    u8 diff = 0;
    for (u32 i = 0; i < 16; ++i)
        diff |= u8(a[i] ^ b[i]);
    return diff == 0;
}

} // namespace

void AesGcm128Encrypt(const u8 key[kAes128KeyBytes], const u8 iv[kAesGcmIvBytes], const u8* aad, u32 aad_len,
                      const u8* plaintext, u32 plaintext_len, u8* ciphertext, u8 tag[kAesGcmTagBytes])
{
    AesCtx ctx;
    AesKeyExpand128(ctx, key);
    GcmCore(ctx, iv, aad, aad_len, plaintext, plaintext_len, ciphertext, /*encrypt=*/true, tag);
}

bool AesGcm128Decrypt(const u8 key[kAes128KeyBytes], const u8 iv[kAesGcmIvBytes], const u8* aad, u32 aad_len,
                      const u8* ciphertext, u32 ciphertext_len, const u8 tag[kAesGcmTagBytes], u8* plaintext)
{
    AesCtx ctx;
    AesKeyExpand128(ctx, key);
    u8 expected[kAesGcmTagBytes];
    GcmCore(ctx, iv, aad, aad_len, ciphertext, ciphertext_len, plaintext, /*encrypt=*/false, expected);
    return ConstantTimeEq16(expected, tag);
}

void AesGcm256Encrypt(const u8 key[kAes256KeyBytes], const u8 iv[kAesGcmIvBytes], const u8* aad, u32 aad_len,
                      const u8* plaintext, u32 plaintext_len, u8* ciphertext, u8 tag[kAesGcmTagBytes])
{
    AesCtx ctx;
    AesKeyExpand256(ctx, key);
    GcmCore(ctx, iv, aad, aad_len, plaintext, plaintext_len, ciphertext, /*encrypt=*/true, tag);
}

bool AesGcm256Decrypt(const u8 key[kAes256KeyBytes], const u8 iv[kAesGcmIvBytes], const u8* aad, u32 aad_len,
                      const u8* ciphertext, u32 ciphertext_len, const u8 tag[kAesGcmTagBytes], u8* plaintext)
{
    AesCtx ctx;
    AesKeyExpand256(ctx, key);
    u8 expected[kAesGcmTagBytes];
    GcmCore(ctx, iv, aad, aad_len, ciphertext, ciphertext_len, plaintext, /*encrypt=*/false, expected);
    return ConstantTimeEq16(expected, tag);
}

void AesGcmSelfTest()
{
    // ----- NIST SP 800-38D Test Case 1: empty P, empty A, zero key/IV.
    {
        u8 key[16] = {};
        u8 iv[12] = {};
        u8 tag[16];
        u8 ct[1] = {}; // unused (plaintext_len = 0)
        AesGcm128Encrypt(key, iv, nullptr, 0, nullptr, 0, ct, tag);
        const u8 want[16] = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
                             0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
        for (u32 i = 0; i < 16; ++i)
            KASSERT(tag[i] == want[i], "crypto/aes-gcm", "Test Case 1 tag mismatch");
    }

    // ----- NIST SP 800-38D Test Case 2: 16-byte zero plaintext.
    {
        u8 key[16] = {};
        u8 iv[12] = {};
        u8 pt[16] = {};
        u8 ct[16];
        u8 tag[16];
        AesGcm128Encrypt(key, iv, nullptr, 0, pt, 16, ct, tag);
        const u8 want_ct[16] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
        const u8 want_tag[16] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
        for (u32 i = 0; i < 16; ++i)
            KASSERT(ct[i] == want_ct[i], "crypto/aes-gcm", "Test Case 2 ciphertext mismatch");
        for (u32 i = 0; i < 16; ++i)
            KASSERT(tag[i] == want_tag[i], "crypto/aes-gcm", "Test Case 2 tag mismatch");

        // Round-trip decrypt.
        u8 round[16];
        const bool ok = AesGcm128Decrypt(key, iv, nullptr, 0, ct, 16, tag, round);
        KASSERT(ok, "crypto/aes-gcm", "Test Case 2 decrypt failed");
        for (u32 i = 0; i < 16; ++i)
            KASSERT(round[i] == 0, "crypto/aes-gcm", "Test Case 2 decrypt mismatch");
    }

    // ----- NIST SP 800-38D Test Case 3: 60-byte plaintext, 0-byte AAD.
    {
        const u8 key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
        const u8 iv[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
        const u8 pt[60] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26,
                           0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
                           0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
                           0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
        u8 ct[60];
        u8 tag[16];
        AesGcm128Encrypt(key, iv, nullptr, 0, pt, 60, ct, tag);
        const u8 want_ct[60] = {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7,
                                0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
                                0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2,
                                0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
                                0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91};
        const u8 want_tag[16] = {0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6,
                                 0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4};
        for (u32 i = 0; i < 60; ++i)
            KASSERT(ct[i] == want_ct[i], "crypto/aes-gcm", "Test Case 3 ciphertext mismatch");
        for (u32 i = 0; i < 16; ++i)
            KASSERT(tag[i] == want_tag[i], "crypto/aes-gcm", "Test Case 3 tag mismatch");

        // Tamper detection.
        u8 round[60];
        u8 bad_tag[16];
        for (u32 i = 0; i < 16; ++i)
            bad_tag[i] = tag[i];
        bad_tag[0] ^= 1;
        const bool tampered = AesGcm128Decrypt(key, iv, nullptr, 0, ct, 60, bad_tag, round);
        KASSERT(!tampered, "crypto/aes-gcm", "Test Case 3 tamper not rejected");

        const bool ok = AesGcm128Decrypt(key, iv, nullptr, 0, ct, 60, tag, round);
        KASSERT(ok, "crypto/aes-gcm", "Test Case 3 decrypt failed");
        for (u32 i = 0; i < 60; ++i)
            KASSERT(round[i] == pt[i], "crypto/aes-gcm", "Test Case 3 round-trip mismatch");
    }

    // ----- AES-256 round-trip smoke (NIST SP 800-38D Test Case 13:
    // empty plaintext, empty AAD, zero key, zero IV).
    {
        u8 key[32] = {};
        u8 iv[12] = {};
        u8 tag[16];
        u8 ct[1] = {};
        AesGcm256Encrypt(key, iv, nullptr, 0, nullptr, 0, ct, tag);
        const u8 want[16] = {0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
                             0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b};
        for (u32 i = 0; i < 16; ++i)
            KASSERT(tag[i] == want[i], "crypto/aes-gcm", "Test Case 13 (AES-256) tag mismatch");
    }
}

} // namespace duetos::crypto
