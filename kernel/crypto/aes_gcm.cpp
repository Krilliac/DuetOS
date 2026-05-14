#include "crypto/aes_gcm.h"

#include "arch/x86_64/serial.h"

namespace duetos::crypto
{

namespace
{

inline void Xor16(u8* dst, const u8* a, const u8* b)
{
    for (u32 i = 0; i < 16; ++i)
        dst[i] = a[i] ^ b[i];
}

// GF(2^128) multiplication used by GHASH. Field is defined by
// the polynomial x^128 + x^7 + x^2 + x + 1. Bit ordering
// follows NIST SP 800-38D (the "big-endian" convention) — bit 0
// of byte 0 is the highest-order coefficient.
//
// Algorithm: walk Y bit-by-bit from MSB to LSB. Maintain V as
// X (initially) and Z as 0; for each bit of Y, if set then
// Z ^= V; then advance V by one bit (right-shift across the
// 16-byte big-endian word, XOR with R = 0xE100... when the
// shifted-out bit was 1).
void GfMul(u8 Z[16], const u8 X[16], const u8 Y[16])
{
    u8 V[16];
    u8 W[16];
    for (u32 i = 0; i < 16; ++i)
    {
        Z[i] = 0;
        V[i] = X[i];
    }
    for (u32 byte = 0; byte < 16; ++byte)
    {
        for (u32 bit = 0; bit < 8; ++bit)
        {
            // Examine MSB-first.
            const u8 y_bit = (Y[byte] >> (7 - bit)) & 1;
            if (y_bit)
                Xor16(Z, Z, V);
            // V <<<-shift by 1 bit (NIST big-endian: bit 0 of
            // byte 0 is the most-significant coefficient, so
            // "shift right" in this convention means low-bit
            // out of byte 15 lands in high-bit of next byte +
            // possible reduction).
            const u8 v_lsb = V[15] & 1;
            for (u32 i = 16; i-- > 1;)
                V[i] = (V[i] >> 1) | ((V[i - 1] & 1) << 7);
            V[0] >>= 1;
            if (v_lsb)
            {
                W[0] = 0xE1;
                for (u32 i = 1; i < 16; ++i)
                    W[i] = 0;
                Xor16(V, V, W);
            }
        }
    }
}

void GhashBlock(u8 Y[16], const u8 H[16], const u8 X[16])
{
    Xor16(Y, Y, X);
    u8 tmp[16];
    GfMul(tmp, Y, H);
    for (u32 i = 0; i < 16; ++i)
        Y[i] = tmp[i];
}

// Increment the low 32 bits (big-endian) of a 16-byte counter.
void Inc32(u8 ctr[16])
{
    for (u32 i = 16; i-- > 12;)
    {
        ++ctr[i];
        if (ctr[i] != 0)
            return;
    }
}

// Encrypt-or-decrypt `n` bytes via AES-CTR starting from `J0`
// PLUS ONE (J1 = J0 + 1). Writes to `out`; reads `in`. The
// last block is XOR'd only over `n - 16*floor(n/16)` bytes.
void Ctr32(const AesCtx& ctx, const u8 J0[16], const u8* in, u32 n, u8* out)
{
    u8 ctr[16];
    for (u32 i = 0; i < 16; ++i)
        ctr[i] = J0[i];
    Inc32(ctr);
    u8 ks[16];
    u32 off = 0;
    while (off < n)
    {
        AesEncryptBlock(ctx, ctr, ks);
        const u32 take = (n - off >= 16) ? 16 : (n - off);
        for (u32 i = 0; i < take; ++i)
            out[off + i] = in[off + i] ^ ks[i];
        Inc32(ctr);
        off += take;
    }
}

// Big-endian 64-bit write into `dst[0..8)`.
void StoreU64Be(u8 dst[8], u64 v)
{
    for (u32 i = 0; i < 8; ++i)
        dst[i] = static_cast<u8>((v >> ((7 - i) * 8)) & 0xFF);
}

// Compute the GHASH over (AAD || CT) with the length block
// appended: [len(AAD) in bits as u64-BE | len(CT) in bits as u64-BE].
void Ghash(const u8 H[16], const u8* aad, u32 aad_len, const u8* ct, u32 ct_len, u8 out[16])
{
    u8 Y[16] = {0};
    auto consume = [&](const u8* data, u32 n)
    {
        u32 off = 0;
        while (off + 16 <= n)
        {
            GhashBlock(Y, H, data + off);
            off += 16;
        }
        if (off < n)
        {
            u8 padded[16] = {0};
            for (u32 i = 0; i < n - off; ++i)
                padded[i] = data[off + i];
            GhashBlock(Y, H, padded);
        }
    };
    consume(aad, aad_len);
    consume(ct, ct_len);
    u8 len_block[16] = {0};
    StoreU64Be(len_block + 0, u64(aad_len) * 8);
    StoreU64Be(len_block + 8, u64(ct_len) * 8);
    GhashBlock(Y, H, len_block);
    for (u32 i = 0; i < 16; ++i)
        out[i] = Y[i];
}

bool ConstTimeEqual(const u8* a, const u8* b, u32 n)
{
    u8 diff = 0;
    for (u32 i = 0; i < n; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

} // namespace

bool AesGcm128Encrypt(const u8 key[kAes128KeyBytes], const u8 iv[kGcmIvBytes], const u8* aad, u32 aad_len, const u8* pt,
                      u32 pt_len, u8* ct, u8 tag[kGcmTagBytes])
{
    if (key == nullptr || iv == nullptr || tag == nullptr)
        return false;
    if (pt_len > 0 && (pt == nullptr || ct == nullptr))
        return false;
    if (aad_len > 0 && aad == nullptr)
        return false;
    if (pt_len > 0x80000000u)
        return false;
    AesCtx ctx{};
    AesKeyExpand128(ctx, key);
    // H = AES_E(K, 0^128).
    u8 H[16] = {0};
    AesEncryptBlock(ctx, H, H);
    // J0 = IV(12 bytes) || 0x00000001.
    u8 J0[16];
    for (u32 i = 0; i < 12; ++i)
        J0[i] = iv[i];
    J0[12] = 0;
    J0[13] = 0;
    J0[14] = 0;
    J0[15] = 1;
    // C = CTR32(K, inc32(J0), P)
    Ctr32(ctx, J0, pt, pt_len, ct);
    // S = GHASH(H, AAD || C || len(AAD) || len(C))
    u8 S[16];
    Ghash(H, aad, aad_len, ct, pt_len, S);
    // T = MSB_128(E_K(J0) XOR S)
    u8 ej0[16];
    AesEncryptBlock(ctx, J0, ej0);
    for (u32 i = 0; i < 16; ++i)
        tag[i] = ej0[i] ^ S[i];
    return true;
}

bool AesGcm128Decrypt(const u8 key[kAes128KeyBytes], const u8 iv[kGcmIvBytes], const u8* aad, u32 aad_len, const u8* ct,
                      u32 ct_len, const u8 tag[kGcmTagBytes], u8* pt)
{
    if (key == nullptr || iv == nullptr || tag == nullptr)
        return false;
    if (ct_len > 0 && (ct == nullptr || pt == nullptr))
        return false;
    if (aad_len > 0 && aad == nullptr)
        return false;
    AesCtx ctx{};
    AesKeyExpand128(ctx, key);
    u8 H[16] = {0};
    AesEncryptBlock(ctx, H, H);
    u8 J0[16];
    for (u32 i = 0; i < 12; ++i)
        J0[i] = iv[i];
    J0[12] = 0;
    J0[13] = 0;
    J0[14] = 0;
    J0[15] = 1;
    // Compute tag BEFORE writing plaintext so we don't leak a
    // partial pt on failure.
    u8 S[16];
    Ghash(H, aad, aad_len, ct, ct_len, S);
    u8 expected_tag[16];
    u8 ej0[16];
    AesEncryptBlock(ctx, J0, ej0);
    for (u32 i = 0; i < 16; ++i)
        expected_tag[i] = ej0[i] ^ S[i];
    if (!ConstTimeEqual(expected_tag, tag, 16))
        return false;
    Ctr32(ctx, J0, ct, ct_len, pt);
    return true;
}

// ---------------------------------------------------------------------------
// Self-test (NIST SP 800-38D test vectors, AES-128-GCM)
// ---------------------------------------------------------------------------

void AesGcmSelfTest()
{
    using arch::SerialWrite;

    // Vector 1: empty PT + empty AAD with the all-zero key/IV.
    // Expected tag: 58e2fccefa7e3061367f1d57a4e7455a.
    {
        const u8 key[16] = {0};
        const u8 iv[12] = {0};
        u8 tag[16];
        if (!AesGcm128Encrypt(key, iv, nullptr, 0, nullptr, 0, nullptr, tag))
        {
            SerialWrite("[aes-gcm] FAIL v1-encrypt\n");
            return;
        }
        const u8 want[16] = {0x58, 0xE2, 0xFC, 0xCE, 0xFA, 0x7E, 0x30, 0x61,
                             0x36, 0x7F, 0x1D, 0x57, 0xA4, 0xE7, 0x45, 0x5A};
        for (u32 i = 0; i < 16; ++i)
        {
            if (tag[i] != want[i])
            {
                SerialWrite("[aes-gcm] FAIL v1-tag\n");
                return;
            }
        }
    }

    // Vector 2: 16-byte all-zero PT, empty AAD, all-zero key/IV.
    // Expected CT: 0388dace60b6a392f328c2b971b2fe78.
    // Expected tag: ab6e47d42cec13bdf53a67b21257bddf.
    {
        const u8 key[16] = {0};
        const u8 iv[12] = {0};
        const u8 pt[16] = {0};
        u8 ct[16];
        u8 tag[16];
        if (!AesGcm128Encrypt(key, iv, nullptr, 0, pt, 16, ct, tag))
        {
            SerialWrite("[aes-gcm] FAIL v2-encrypt\n");
            return;
        }
        const u8 want_ct[16] = {0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92,
                                0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78};
        const u8 want_tag[16] = {0xAB, 0x6E, 0x47, 0xD4, 0x2C, 0xEC, 0x13, 0xBD,
                                 0xF5, 0x3A, 0x67, 0xB2, 0x12, 0x57, 0xBD, 0xDF};
        for (u32 i = 0; i < 16; ++i)
        {
            if (ct[i] != want_ct[i])
            {
                SerialWrite("[aes-gcm] FAIL v2-ct\n");
                return;
            }
            if (tag[i] != want_tag[i])
            {
                SerialWrite("[aes-gcm] FAIL v2-tag\n");
                return;
            }
        }
        // Round-trip: decrypt with the known-good tag should
        // produce the original plaintext.
        u8 rt[16];
        if (!AesGcm128Decrypt(key, iv, nullptr, 0, ct, 16, tag, rt))
        {
            SerialWrite("[aes-gcm] FAIL v2-decrypt\n");
            return;
        }
        for (u32 i = 0; i < 16; ++i)
        {
            if (rt[i] != 0)
            {
                SerialWrite("[aes-gcm] FAIL v2-rt\n");
                return;
            }
        }
        // Negative test: tampered tag rejects.
        u8 bad_tag[16];
        for (u32 i = 0; i < 16; ++i)
            bad_tag[i] = tag[i];
        bad_tag[0] ^= 0x80;
        if (AesGcm128Decrypt(key, iv, nullptr, 0, ct, 16, bad_tag, rt))
        {
            SerialWrite("[aes-gcm] FAIL v2-tampered-tag-still-passed\n");
            return;
        }
    }

    SerialWrite("[aes-gcm] PASS (NIST KAT v1 + v2 + round-trip + tamper)\n");
}

} // namespace duetos::crypto
