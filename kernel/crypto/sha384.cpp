#include "crypto/sha384.h"

#include "core/panic.h"
#include "util/compiler.h"

/*
 * SHA-384 = SHA-512 (FIPS 180-4 §5.3.4 IV) truncated to 48 bytes.
 *
 * The 64-bit-word compression below is the SHA-512 block function; only
 * the initial hash value (IV) and the output truncation are SHA-384
 * specific. We never need full SHA-512 here, so the file carries just
 * the SHA-384 surface.
 *
 * No sanitizer wrap suppression needed for the additive state mixing —
 * SHA's modular arithmetic on u64 wraps by design, but we annotate the
 * block function to match sha256.cpp's pattern.
 */

namespace duetos::crypto
{

namespace
{

// SHA-512 round constants (first 64 bits of the fractional parts of the
// cube roots of the first 80 primes). FIPS 180-4 §4.2.3.
constexpr u64 K[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull,
    0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull, 0x12835b0145706fbeull,
    0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull, 0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull, 0x983e5152ee66dfabull,
    0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull,
    0x53380d139d95b3dfull, 0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull, 0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
    0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull,
    0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull, 0xca273eceea26619cull,
    0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
    0x113f9804bef90daeull, 0x1b710b35131c471bull, 0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};

inline u64 Ror64(u64 x, u32 n)
{
    return (x >> n) | (x << (64u - n));
}

DUETOS_NO_SANITIZE_WRAP void Sha384ProcessBlock(Sha384Ctx& ctx, const u8* block)
{
    u64 w[80];
    for (u32 i = 0; i < 16; ++i)
    {
        const u8* p = block + i * 8;
        w[i] = (static_cast<u64>(p[0]) << 56) | (static_cast<u64>(p[1]) << 48) | (static_cast<u64>(p[2]) << 40) |
               (static_cast<u64>(p[3]) << 32) | (static_cast<u64>(p[4]) << 24) | (static_cast<u64>(p[5]) << 16) |
               (static_cast<u64>(p[6]) << 8) | static_cast<u64>(p[7]);
    }
    for (u32 i = 16; i < 80; ++i)
    {
        const u64 s0 = Ror64(w[i - 15], 1) ^ Ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        const u64 s1 = Ror64(w[i - 2], 19) ^ Ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    u64 a = ctx.state[0];
    u64 b = ctx.state[1];
    u64 c = ctx.state[2];
    u64 d = ctx.state[3];
    u64 e = ctx.state[4];
    u64 f = ctx.state[5];
    u64 g = ctx.state[6];
    u64 h = ctx.state[7];

    for (u32 i = 0; i < 80; ++i)
    {
        const u64 S1 = Ror64(e, 14) ^ Ror64(e, 18) ^ Ror64(e, 41);
        const u64 ch = (e & f) ^ (~e & g);
        const u64 t1 = h + S1 + ch + K[i] + w[i];
        const u64 S0 = Ror64(a, 28) ^ Ror64(a, 34) ^ Ror64(a, 39);
        const u64 maj = (a & b) ^ (a & c) ^ (b & c);
        const u64 t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
    ctx.state[5] += f;
    ctx.state[6] += g;
    ctx.state[7] += h;
}

} // namespace

void Sha384Init(Sha384Ctx& ctx)
{
    // SHA-384 IV (FIPS 180-4 §5.3.4).
    ctx.state[0] = 0xcbbb9d5dc1059ed8ull;
    ctx.state[1] = 0x629a292a367cd507ull;
    ctx.state[2] = 0x9159015a3070dd17ull;
    ctx.state[3] = 0x152fecd8f70e5939ull;
    ctx.state[4] = 0x67332667ffc00b31ull;
    ctx.state[5] = 0x8eb44a8768581511ull;
    ctx.state[6] = 0xdb0c2e0d64f98fa7ull;
    ctx.state[7] = 0x47b5481dbefa4fa4ull;
    ctx.length_low = 0;
    ctx.length_high = 0;
    ctx.buffered_bytes = 0;
    for (u32 i = 0; i < kSha384BlockBytes; ++i)
        ctx.block[i] = 0;
}

void Sha384Update(Sha384Ctx& ctx, const u8* data, u32 length)
{
    if (data == nullptr || length == 0)
        return;
    const u64 add_bits = static_cast<u64>(length) * 8u;
    const u64 before = ctx.length_low;
    ctx.length_low += add_bits;
    if (ctx.length_low < before)
        ++ctx.length_high; // carry into the high 64 bits

    u32 i = 0;
    if (ctx.buffered_bytes != 0)
    {
        const u32 want = kSha384BlockBytes - ctx.buffered_bytes;
        const u32 take = (length < want) ? length : want;
        for (u32 k = 0; k < take; ++k)
            ctx.block[ctx.buffered_bytes + k] = data[k];
        ctx.buffered_bytes += take;
        i = take;
        if (ctx.buffered_bytes == kSha384BlockBytes)
        {
            Sha384ProcessBlock(ctx, ctx.block);
            ctx.buffered_bytes = 0;
        }
    }
    while (i + kSha384BlockBytes <= length)
    {
        Sha384ProcessBlock(ctx, data + i);
        i += kSha384BlockBytes;
    }
    while (i < length)
        ctx.block[ctx.buffered_bytes++] = data[i++];
}

void Sha384Final(Sha384Ctx& ctx, u8 out[kSha384DigestBytes])
{
    // SHA-512 family uses a 128-bit length field at the end of the
    // padded block.
    ctx.block[ctx.buffered_bytes++] = 0x80;
    if (ctx.buffered_bytes > kSha384BlockBytes - 16)
    {
        while (ctx.buffered_bytes < kSha384BlockBytes)
            ctx.block[ctx.buffered_bytes++] = 0;
        Sha384ProcessBlock(ctx, ctx.block);
        ctx.buffered_bytes = 0;
    }
    while (ctx.buffered_bytes < kSha384BlockBytes - 16)
        ctx.block[ctx.buffered_bytes++] = 0;
    // 128-bit big-endian bit length: high 64 then low 64.
    for (i32 i = 7; i >= 0; --i)
        ctx.block[ctx.buffered_bytes++] = static_cast<u8>((ctx.length_high >> (i * 8)) & 0xFFu);
    for (i32 i = 7; i >= 0; --i)
        ctx.block[ctx.buffered_bytes++] = static_cast<u8>((ctx.length_low >> (i * 8)) & 0xFFu);
    Sha384ProcessBlock(ctx, ctx.block);

    // Output the first 6 of 8 state words (48 bytes) — the SHA-384
    // truncation.
    for (u32 i = 0; i < 6; ++i)
        for (u32 b = 0; b < 8; ++b)
            out[i * 8 + b] = static_cast<u8>((ctx.state[i] >> ((7u - b) * 8)) & 0xFFu);
}

void Sha384Hash(const u8* data, u32 length, u8 out[kSha384DigestBytes])
{
    Sha384Ctx ctx;
    Sha384Init(ctx);
    Sha384Update(ctx, data, length);
    Sha384Final(ctx, out);
}

void Sha384SelfTest()
{
    // FIPS 180-4 example: SHA-384("abc").
    {
        const u8 msg[3] = {'a', 'b', 'c'};
        u8 d[kSha384DigestBytes];
        Sha384Hash(msg, 3, d);
        const u8 want[kSha384DigestBytes] = {0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
                                             0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
                                             0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
                                             0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};
        for (u32 i = 0; i < kSha384DigestBytes; ++i)
            KASSERT(d[i] == want[i], "crypto/sha384", "sha384 KAT \"abc\" mismatch");
    }
    // Empty string.
    {
        u8 d[kSha384DigestBytes];
        Sha384Hash(nullptr, 0, d);
        const u8 want[kSha384DigestBytes] = {0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
                                             0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
                                             0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
                                             0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b};
        for (u32 i = 0; i < kSha384DigestBytes; ++i)
            KASSERT(d[i] == want[i], "crypto/sha384", "sha384 KAT empty mismatch");
    }
}

} // namespace duetos::crypto
