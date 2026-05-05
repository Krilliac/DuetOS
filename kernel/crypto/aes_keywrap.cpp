#include "crypto/aes_keywrap.h"

#include "core/panic.h"

/*
 * Reference: RFC 3394 — Advanced Encryption Standard (AES) Key
 * Wrap Algorithm (J. Schaad / R. Housley, Sept 2002). NIST
 * SP 800-38F adopts the same construction as "KW".
 *
 * Algorithm (wrap):
 *
 *   A = IV (8 bytes)
 *   For i = 1..n: R[i] = P[i]                  // n = plaintext / 8
 *   For j = 0..5:
 *     For i = 1..n:
 *       B    = AES(KEK, A | R[i])              // single block enc
 *       A    = MSB64(B) XOR (n*j + i)
 *       R[i] = LSB64(B)
 *   Output: C[0] = A, C[i] = R[i] for i = 1..n
 *
 * Unwrap reverses the loops and checks A == IV at the end.
 *
 * The output buffer doubles as scratch storage: we write R[]
 * directly into out[8..] (wrap) or out[0..] (unwrap), so the
 * algorithm runs in-place against the caller's buffer with no
 * extra heap or large stack allocation.
 */

namespace duetos::crypto
{

namespace
{

// Big-endian load/store of a 64-bit semi-block.
u64 LoadBe64(const u8* p)
{
    u64 v = 0;
    for (u32 i = 0; i < 8; ++i)
        v = (v << 8) | static_cast<u64>(p[i]);
    return v;
}

void StoreBe64(u64 v, u8* p)
{
    for (i32 i = 7; i >= 0; --i)
    {
        p[i] = static_cast<u8>(v & 0xFFu);
        v >>= 8;
    }
}

bool IsValidKekRounds(u32 num_rounds)
{
    return num_rounds == kAes128Rounds || num_rounds == kAes256Rounds;
}

} // namespace

bool AesKeyWrap(const AesCtx& kek, const u8* plaintext, u32 plaintext_bytes, u8* out)
{
    if (plaintext == nullptr || out == nullptr)
        return false;
    if (plaintext_bytes == 0 || (plaintext_bytes % kAesKwSemiBlockBytes) != 0)
        return false;
    const u32 n = plaintext_bytes / kAesKwSemiBlockBytes;
    if (n < 2 || n > kAesKwMaxSemiBlocks)
        return false;
    if (!IsValidKekRounds(kek.num_rounds))
        return false;

    // Stage R[] in the output. R[i] for i = 1..n maps to
    // out[8 + (i-1)*8 .. +8].
    for (u32 i = 0; i < plaintext_bytes; ++i)
        out[kAesKwSemiBlockBytes + i] = plaintext[i];

    u64 a = kAesKwDefaultIV;

    u8 block_in[kAesBlockBytes];
    u8 block_out[kAesBlockBytes];

    for (u32 j = 0; j < 6; ++j)
    {
        for (u32 i = 1; i <= n; ++i)
        {
            StoreBe64(a, &block_in[0]);
            for (u32 k = 0; k < kAesKwSemiBlockBytes; ++k)
                block_in[kAesKwSemiBlockBytes + k] = out[i * kAesKwSemiBlockBytes + k];

            AesEncryptBlock(kek, block_in, block_out);

            const u64 b_high = LoadBe64(&block_out[0]);
            const u64 t = static_cast<u64>(n) * j + i;
            a = b_high ^ t;
            for (u32 k = 0; k < kAesKwSemiBlockBytes; ++k)
                out[i * kAesKwSemiBlockBytes + k] = block_out[kAesKwSemiBlockBytes + k];
        }
    }

    StoreBe64(a, &out[0]);
    return true;
}

bool AesKeyUnwrap(const AesCtx& kek, const u8* ciphertext, u32 ciphertext_bytes, u8* out)
{
    if (ciphertext == nullptr || out == nullptr)
        return false;
    if (ciphertext_bytes < (2 * kAesKwSemiBlockBytes + kAesKwSemiBlockBytes))
        return false;
    if ((ciphertext_bytes % kAesKwSemiBlockBytes) != 0)
        return false;
    const u32 n = (ciphertext_bytes / kAesKwSemiBlockBytes) - 1;
    if (n < 2 || n > kAesKwMaxSemiBlocks)
        return false;
    if (!IsValidKekRounds(kek.num_rounds))
        return false;

    u64 a = LoadBe64(&ciphertext[0]);
    for (u32 i = 0; i < n * kAesKwSemiBlockBytes; ++i)
        out[i] = ciphertext[kAesKwSemiBlockBytes + i];

    u8 block_in[kAesBlockBytes];
    u8 block_out[kAesBlockBytes];

    // j = 5..0, i = n..1. Use signed counters since underflow ends
    // the loops.
    for (i32 j = 5; j >= 0; --j)
    {
        for (i32 i = static_cast<i32>(n); i >= 1; --i)
        {
            const u64 t = static_cast<u64>(n) * static_cast<u64>(j) + static_cast<u64>(i);
            StoreBe64(a ^ t, &block_in[0]);
            const u32 r_off = static_cast<u32>(i - 1) * kAesKwSemiBlockBytes;
            for (u32 k = 0; k < kAesKwSemiBlockBytes; ++k)
                block_in[kAesKwSemiBlockBytes + k] = out[r_off + k];

            AesDecryptBlock(kek, block_in, block_out);

            a = LoadBe64(&block_out[0]);
            for (u32 k = 0; k < kAesKwSemiBlockBytes; ++k)
                out[r_off + k] = block_out[kAesKwSemiBlockBytes + k];
        }
    }

    return a == kAesKwDefaultIV;
}

void AesKeyWrapSelfTest()
{
    // RFC 3394 §4.1 — Wrap 128 bits of Key Data with a 128-bit KEK.
    {
        const u8 kek[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const u8 pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const u8 want[24] = {0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8,
                             0xFB, 0x5A, 0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5};
        AesCtx ctx;
        AesKeyExpand128(ctx, kek);
        u8 ct[24];
        const bool wrap_ok = AesKeyWrap(ctx, pt, 16, ct);
        KASSERT(wrap_ok, "crypto/aes_keywrap", "RFC 3394 §4.1 wrap rejected valid input");
        for (u32 i = 0; i < 24; ++i)
            KASSERT(ct[i] == want[i], "crypto/aes_keywrap", "RFC 3394 §4.1 wrap mismatch");
        u8 rt[16];
        const bool unwrap_ok = AesKeyUnwrap(ctx, ct, 24, rt);
        KASSERT(unwrap_ok, "crypto/aes_keywrap", "RFC 3394 §4.1 unwrap integrity check failed");
        for (u32 i = 0; i < 16; ++i)
            KASSERT(rt[i] == pt[i], "crypto/aes_keywrap", "RFC 3394 §4.1 round-trip mismatch");
    }

    // RFC 3394 §4.3 — Wrap 128 bits of Key Data with a 256-bit KEK.
    {
        const u8 kek[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                            0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
        const u8 pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const u8 want[24] = {0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2, 0x63, 0xE9, 0x77, 0x79,
                             0x05, 0x81, 0x8A, 0x2A, 0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7};
        AesCtx ctx;
        AesKeyExpand256(ctx, kek);
        u8 ct[24];
        const bool wrap_ok = AesKeyWrap(ctx, pt, 16, ct);
        KASSERT(wrap_ok, "crypto/aes_keywrap", "RFC 3394 §4.3 wrap rejected valid input");
        for (u32 i = 0; i < 24; ++i)
            KASSERT(ct[i] == want[i], "crypto/aes_keywrap", "RFC 3394 §4.3 wrap mismatch");
        u8 rt[16];
        const bool unwrap_ok = AesKeyUnwrap(ctx, ct, 24, rt);
        KASSERT(unwrap_ok, "crypto/aes_keywrap", "RFC 3394 §4.3 unwrap integrity check failed");
        for (u32 i = 0; i < 16; ++i)
            KASSERT(rt[i] == pt[i], "crypto/aes_keywrap", "RFC 3394 §4.3 round-trip mismatch");
    }

    // RFC 3394 §4.6 — Wrap 256 bits with a 256-bit KEK (n=4 path).
    // Exercises multiple inner-loop iterations per j step.
    {
        const u8 kek[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                            0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
        const u8 pt[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
                           0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                           0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const u8 want[40] = {0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87,
                             0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7,
                             0x1A, 0x99, 0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21};
        AesCtx ctx;
        AesKeyExpand256(ctx, kek);
        u8 ct[40];
        const bool wrap_ok = AesKeyWrap(ctx, pt, 32, ct);
        KASSERT(wrap_ok, "crypto/aes_keywrap", "RFC 3394 §4.6 wrap rejected valid input");
        for (u32 i = 0; i < 40; ++i)
            KASSERT(ct[i] == want[i], "crypto/aes_keywrap", "RFC 3394 §4.6 wrap mismatch");
        u8 rt[32];
        const bool unwrap_ok = AesKeyUnwrap(ctx, ct, 40, rt);
        KASSERT(unwrap_ok, "crypto/aes_keywrap", "RFC 3394 §4.6 unwrap integrity check failed");
        for (u32 i = 0; i < 32; ++i)
            KASSERT(rt[i] == pt[i], "crypto/aes_keywrap", "RFC 3394 §4.6 round-trip mismatch");
    }

    // Tamper detection: flipping a bit in the wrapped IV must
    // cause unwrap to fail.
    {
        const u8 kek[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const u8 pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        AesCtx ctx;
        AesKeyExpand128(ctx, kek);
        u8 ct[24];
        AesKeyWrap(ctx, pt, 16, ct);
        ct[0] ^= 0x01;
        u8 rt[16];
        const bool unwrap_ok = AesKeyUnwrap(ctx, ct, 24, rt);
        KASSERT(!unwrap_ok, "crypto/aes_keywrap",
                "RFC 3394 unwrap accepted tampered ciphertext (integrity check broken)");
    }

    // Bad-input rejection: zero-length, non-multiple-of-8, n=1
    // (one semi-block — RFC 3394 requires n ≥ 2).
    {
        const u8 kek[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        AesCtx ctx;
        AesKeyExpand128(ctx, kek);
        u8 buf[24];
        const u8 dummy[16] = {0};
        KASSERT(!AesKeyWrap(ctx, dummy, 0, buf), "crypto/aes_keywrap", "wrap accepted len=0");
        KASSERT(!AesKeyWrap(ctx, dummy, 7, buf), "crypto/aes_keywrap", "wrap accepted len=7 (not %8)");
        KASSERT(!AesKeyWrap(ctx, dummy, 8, buf), "crypto/aes_keywrap", "wrap accepted single-semi-block input (n=1)");
        KASSERT(!AesKeyUnwrap(ctx, buf, 16, buf), "crypto/aes_keywrap", "unwrap accepted len=16 (need ≥ 24)");
    }
}

} // namespace duetos::crypto
