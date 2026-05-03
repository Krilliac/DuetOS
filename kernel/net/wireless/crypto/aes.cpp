#include "net/wireless/crypto/aes.h"

#include "core/panic.h"

/*
 * Reference: FIPS 197 (Advanced Encryption Standard, NIST 2001).
 *
 * Plain table-driven implementation — one S-box + inverse S-box
 * + GF(2^8) xtime for the column mix, no T-tables. Slower than a
 * 4 KiB T-table form, but ~12x smaller in .rodata + simpler to
 * read alongside the spec. AES-NI hardware path is gated behind
 * CPUID and not in v0; the kernel-side AES caller surface is
 * small enough (Wi-Fi key unwrap on association, not per-frame)
 * that the software path is acceptable until a per-frame consumer
 * appears.
 */

namespace duetos::net::wireless::crypto
{

namespace
{

// FIPS 197 Figure 7 — forward S-box.
const u8 kSBox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9,
    0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F,
    0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07,
    0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3,
    0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
    0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3,
    0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F,
    0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC,
    0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A,
    0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70,
    0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42,
    0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

// FIPS 197 Figure 14 — inverse S-box.
const u8 kInvSBox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39,
    0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2,
    0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76,
    0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC,
    0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
    0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C,
    0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F,
    0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62,
    0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD,
    0x5A, 0xF4, 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60,
    0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6,
    0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

// Round constants (Rcon[i] = x^(i-1) in GF(2^8) for i ≥ 1).
// AES-128 uses indices 1..10; AES-256 uses 1..7 (one Rcon use per
// 8-word stride). Index 0 is unused.
const u8 kRcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

// Multiply a byte by 2 in GF(2^8) modulo the AES polynomial
// x^8 + x^4 + x^3 + x + 1 (0x11B).
u8 XTime(u8 b)
{
    return static_cast<u8>((b << 1) ^ (((b >> 7) & 1u) * 0x1Bu));
}

// b * 09 = b * 8 + b
u8 GMul9(u8 b)
{
    return static_cast<u8>(XTime(XTime(XTime(b))) ^ b);
}

// b * 0B = b * 8 + b * 2 + b
u8 GMulB(u8 b)
{
    return static_cast<u8>(XTime(XTime(XTime(b))) ^ XTime(b) ^ b);
}

// b * 0D = b * 8 + b * 4 + b
u8 GMulD(u8 b)
{
    return static_cast<u8>(XTime(XTime(XTime(b))) ^ XTime(XTime(b)) ^ b);
}

// b * 0E = b * 8 + b * 4 + b * 2
u8 GMulE(u8 b)
{
    return static_cast<u8>(XTime(XTime(XTime(b))) ^ XTime(XTime(b)) ^ XTime(b));
}

void AddRoundKey(u8 state[16], const u8 round_key[16])
{
    for (u32 i = 0; i < 16; ++i)
        state[i] ^= round_key[i];
}

void SubBytes(u8 state[16])
{
    for (u32 i = 0; i < 16; ++i)
        state[i] = kSBox[state[i]];
}

void InvSubBytes(u8 state[16])
{
    for (u32 i = 0; i < 16; ++i)
        state[i] = kInvSBox[state[i]];
}

// AES state layout: state[r + 4*c] (column-major). ShiftRows
// rotates row r left by r positions.
void ShiftRows(u8 s[16])
{
    u8 t;
    // Row 1: left by 1 (s[1], s[5], s[9], s[13]).
    t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    // Row 2: left by 2 (swap s[2]↔s[10], s[6]↔s[14]).
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    // Row 3: left by 3 ≡ right by 1.
    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

void InvShiftRows(u8 s[16])
{
    u8 t;
    // Row 1: right by 1.
    t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;
    // Row 2: right by 2.
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    // Row 3: right by 3 ≡ left by 1.
    t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

void MixColumns(u8 s[16])
{
    for (u32 c = 0; c < 4; ++c)
    {
        const u32 base = c * 4;
        const u8 a0 = s[base + 0];
        const u8 a1 = s[base + 1];
        const u8 a2 = s[base + 2];
        const u8 a3 = s[base + 3];
        s[base + 0] = static_cast<u8>(XTime(a0) ^ XTime(a1) ^ a1 ^ a2 ^ a3);
        s[base + 1] = static_cast<u8>(a0 ^ XTime(a1) ^ XTime(a2) ^ a2 ^ a3);
        s[base + 2] = static_cast<u8>(a0 ^ a1 ^ XTime(a2) ^ XTime(a3) ^ a3);
        s[base + 3] = static_cast<u8>(XTime(a0) ^ a0 ^ a1 ^ a2 ^ XTime(a3));
    }
}

void InvMixColumns(u8 s[16])
{
    for (u32 c = 0; c < 4; ++c)
    {
        const u32 base = c * 4;
        const u8 a0 = s[base + 0];
        const u8 a1 = s[base + 1];
        const u8 a2 = s[base + 2];
        const u8 a3 = s[base + 3];
        s[base + 0] = static_cast<u8>(GMulE(a0) ^ GMulB(a1) ^ GMulD(a2) ^ GMul9(a3));
        s[base + 1] = static_cast<u8>(GMul9(a0) ^ GMulE(a1) ^ GMulB(a2) ^ GMulD(a3));
        s[base + 2] = static_cast<u8>(GMulD(a0) ^ GMul9(a1) ^ GMulE(a2) ^ GMulB(a3));
        s[base + 3] = static_cast<u8>(GMulB(a0) ^ GMulD(a1) ^ GMul9(a2) ^ GMulE(a3));
    }
}

// FIPS 197 §5.2 — Key Expansion. Generic over Nk (4 for AES-128,
// 8 for AES-256). Writes 4*(Nr+1) words = 16*(Nr+1) bytes into
// `ctx.round_keys`.
void AesKeyExpand(AesCtx& ctx, const u8* key, u32 key_bytes, u32 num_rounds)
{
    const u32 nk = key_bytes / 4;                 // 4 or 8
    const u32 total_words = (num_rounds + 1) * 4; // 44 or 60

    u8* rk = ctx.round_keys;
    for (u32 i = 0; i < key_bytes; ++i)
        rk[i] = key[i];

    for (u32 i = nk; i < total_words; ++i)
    {
        u8 t0 = rk[(i - 1) * 4 + 0];
        u8 t1 = rk[(i - 1) * 4 + 1];
        u8 t2 = rk[(i - 1) * 4 + 2];
        u8 t3 = rk[(i - 1) * 4 + 3];

        if (i % nk == 0)
        {
            // RotWord + SubWord + Rcon.
            const u8 r0 = t0;
            t0 = static_cast<u8>(kSBox[t1] ^ kRcon[i / nk]);
            t1 = kSBox[t2];
            t2 = kSBox[t3];
            t3 = kSBox[r0];
        }
        else if (nk > 6 && (i % nk) == 4)
        {
            // SubWord only (AES-256 path, fires every 8 words at i%8==4).
            t0 = kSBox[t0];
            t1 = kSBox[t1];
            t2 = kSBox[t2];
            t3 = kSBox[t3];
        }

        rk[i * 4 + 0] = static_cast<u8>(rk[(i - nk) * 4 + 0] ^ t0);
        rk[i * 4 + 1] = static_cast<u8>(rk[(i - nk) * 4 + 1] ^ t1);
        rk[i * 4 + 2] = static_cast<u8>(rk[(i - nk) * 4 + 2] ^ t2);
        rk[i * 4 + 3] = static_cast<u8>(rk[(i - nk) * 4 + 3] ^ t3);
    }

    ctx.num_rounds = num_rounds;
}

} // namespace

void AesKeyExpand128(AesCtx& ctx, const u8 key[kAes128KeyBytes])
{
    AesKeyExpand(ctx, key, kAes128KeyBytes, kAes128Rounds);
}

void AesKeyExpand256(AesCtx& ctx, const u8 key[kAes256KeyBytes])
{
    AesKeyExpand(ctx, key, kAes256KeyBytes, kAes256Rounds);
}

void AesEncryptBlock(const AesCtx& ctx, const u8 in[kAesBlockBytes], u8 out[kAesBlockBytes])
{
    u8 state[16];
    for (u32 i = 0; i < 16; ++i)
        state[i] = in[i];

    AddRoundKey(state, &ctx.round_keys[0]);

    for (u32 round = 1; round < ctx.num_rounds; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, &ctx.round_keys[round * 16]);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &ctx.round_keys[ctx.num_rounds * 16]);

    for (u32 i = 0; i < 16; ++i)
        out[i] = state[i];
}

void AesDecryptBlock(const AesCtx& ctx, const u8 in[kAesBlockBytes], u8 out[kAesBlockBytes])
{
    u8 state[16];
    for (u32 i = 0; i < 16; ++i)
        state[i] = in[i];

    AddRoundKey(state, &ctx.round_keys[ctx.num_rounds * 16]);

    for (u32 round = ctx.num_rounds - 1; round >= 1; --round)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, &ctx.round_keys[round * 16]);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, &ctx.round_keys[0]);

    for (u32 i = 0; i < 16; ++i)
        out[i] = state[i];
}

void AesSelfTest()
{
    // FIPS 197 Appendix B — AES-128 worked example.
    //   Plaintext: 32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34
    //   Key:       2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C
    //   Cipher:    39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32
    {
        const u8 key[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
        const u8 pt[16] = {0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                           0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34};
        const u8 want[16] = {0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
                             0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32};
        AesCtx ctx;
        AesKeyExpand128(ctx, key);
        u8 ct[16];
        AesEncryptBlock(ctx, pt, ct);
        for (u32 i = 0; i < 16; ++i)
            KASSERT(ct[i] == want[i], "net/wireless/crypto/aes", "AES-128 FIPS 197 Appendix B encrypt mismatch");
        u8 rt[16];
        AesDecryptBlock(ctx, ct, rt);
        for (u32 i = 0; i < 16; ++i)
            KASSERT(rt[i] == pt[i], "net/wireless/crypto/aes", "AES-128 FIPS 197 Appendix B decrypt mismatch");
    }

    // FIPS 197 Appendix C.1 — AES-128 with key 00..0F, plaintext 00..FF.
    //   Cipher: 69 C4 E0 D8 6A 7B 04 30 D8 CD B7 80 70 B4 C5 5A
    {
        const u8 key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const u8 pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const u8 want[16] = {0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
                             0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A};
        AesCtx ctx;
        AesKeyExpand128(ctx, key);
        u8 ct[16];
        AesEncryptBlock(ctx, pt, ct);
        for (u32 i = 0; i < 16; ++i)
            KASSERT(ct[i] == want[i], "net/wireless/crypto/aes", "AES-128 FIPS 197 Appendix C.1 encrypt mismatch");
        u8 rt[16];
        AesDecryptBlock(ctx, ct, rt);
        for (u32 i = 0; i < 16; ++i)
            KASSERT(rt[i] == pt[i], "net/wireless/crypto/aes", "AES-128 FIPS 197 Appendix C.1 decrypt mismatch");
    }

    // FIPS 197 Appendix C.3 — AES-256 with key 00..1F, plaintext 00..FF.
    //   Cipher: 8E A2 B7 CA 51 67 45 BF EA FC 49 90 4B 49 60 89
    {
        const u8 key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                            0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
        const u8 pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const u8 want[16] = {0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
                             0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89};
        AesCtx ctx;
        AesKeyExpand256(ctx, key);
        u8 ct[16];
        AesEncryptBlock(ctx, pt, ct);
        for (u32 i = 0; i < 16; ++i)
            KASSERT(ct[i] == want[i], "net/wireless/crypto/aes", "AES-256 FIPS 197 Appendix C.3 encrypt mismatch");
        u8 rt[16];
        AesDecryptBlock(ctx, ct, rt);
        for (u32 i = 0; i < 16; ++i)
            KASSERT(rt[i] == pt[i], "net/wireless/crypto/aes", "AES-256 FIPS 197 Appendix C.3 decrypt mismatch");
    }
}

} // namespace duetos::net::wireless::crypto
