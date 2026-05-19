#include "crypto/sha256.h"

#include "core/panic.h"
#include "util/compiler.h"

namespace duetos::crypto
{

namespace
{

const u32 k_round[64] = {
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
    0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu, 0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
    0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
    0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
    0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
    0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u, 0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u};

DUETOS_NO_SANITIZE_WRAP u32 RotR(u32 v, u32 n)
{
    return (v >> n) | (v << (32u - n));
}

DUETOS_NO_SANITIZE_WRAP void Sha256ProcessBlock(Sha256Ctx& ctx, const u8* block)
{
    u32 w[64];
    for (u32 i = 0; i < 16; ++i)
    {
        w[i] = (static_cast<u32>(block[i * 4]) << 24) | (static_cast<u32>(block[i * 4 + 1]) << 16) |
               (static_cast<u32>(block[i * 4 + 2]) << 8) | static_cast<u32>(block[i * 4 + 3]);
    }
    for (u32 i = 16; i < 64; ++i)
    {
        const u32 s0 = RotR(w[i - 15], 7) ^ RotR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const u32 s1 = RotR(w[i - 2], 17) ^ RotR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    u32 a = ctx.state[0];
    u32 b = ctx.state[1];
    u32 c = ctx.state[2];
    u32 d = ctx.state[3];
    u32 e = ctx.state[4];
    u32 f = ctx.state[5];
    u32 g = ctx.state[6];
    u32 h = ctx.state[7];

    for (u32 i = 0; i < 64; ++i)
    {
        const u32 S1 = RotR(e, 6) ^ RotR(e, 11) ^ RotR(e, 25);
        const u32 ch = (e & f) ^ ((~e) & g);
        const u32 t1 = h + S1 + ch + k_round[i] + w[i];
        const u32 S0 = RotR(a, 2) ^ RotR(a, 13) ^ RotR(a, 22);
        const u32 mj = (a & b) ^ (a & c) ^ (b & c);
        const u32 t2 = S0 + mj;
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

void Sha256Init(Sha256Ctx& ctx)
{
    ctx.state[0] = 0x6A09E667u;
    ctx.state[1] = 0xBB67AE85u;
    ctx.state[2] = 0x3C6EF372u;
    ctx.state[3] = 0xA54FF53Au;
    ctx.state[4] = 0x510E527Fu;
    ctx.state[5] = 0x9B05688Cu;
    ctx.state[6] = 0x1F83D9ABu;
    ctx.state[7] = 0x5BE0CD19u;
    ctx.length_bits = 0;
    ctx.buffered_bytes = 0;
    for (u32 i = 0; i < kSha256BlockBytes; ++i)
        ctx.block[i] = 0;
}

void Sha256Update(Sha256Ctx& ctx, const u8* data, u32 length)
{
    if (data == nullptr || length == 0)
        return;
    ctx.length_bits += static_cast<u64>(length) * 8u;

    u32 i = 0;
    if (ctx.buffered_bytes != 0)
    {
        const u32 want = kSha256BlockBytes - ctx.buffered_bytes;
        const u32 take = (length < want) ? length : want;
        for (u32 k = 0; k < take; ++k)
            ctx.block[ctx.buffered_bytes + k] = data[k];
        ctx.buffered_bytes += take;
        i = take;
        if (ctx.buffered_bytes == kSha256BlockBytes)
        {
            Sha256ProcessBlock(ctx, ctx.block);
            ctx.buffered_bytes = 0;
        }
    }
    while (i + kSha256BlockBytes <= length)
    {
        Sha256ProcessBlock(ctx, data + i);
        i += kSha256BlockBytes;
    }
    while (i < length)
        ctx.block[ctx.buffered_bytes++] = data[i++];
}

void Sha256Final(Sha256Ctx& ctx, u8 out[kSha256DigestBytes])
{
    ctx.block[ctx.buffered_bytes++] = 0x80;
    if (ctx.buffered_bytes > kSha256BlockBytes - 8)
    {
        while (ctx.buffered_bytes < kSha256BlockBytes)
            ctx.block[ctx.buffered_bytes++] = 0;
        Sha256ProcessBlock(ctx, ctx.block);
        ctx.buffered_bytes = 0;
    }
    while (ctx.buffered_bytes < kSha256BlockBytes - 8)
        ctx.block[ctx.buffered_bytes++] = 0;
    for (i32 i = 7; i >= 0; --i)
        ctx.block[ctx.buffered_bytes++] = static_cast<u8>((ctx.length_bits >> (i * 8)) & 0xFFu);
    Sha256ProcessBlock(ctx, ctx.block);

    for (u32 i = 0; i < 8; ++i)
    {
        out[i * 4 + 0] = static_cast<u8>((ctx.state[i] >> 24) & 0xFFu);
        out[i * 4 + 1] = static_cast<u8>((ctx.state[i] >> 16) & 0xFFu);
        out[i * 4 + 2] = static_cast<u8>((ctx.state[i] >> 8) & 0xFFu);
        out[i * 4 + 3] = static_cast<u8>(ctx.state[i] & 0xFFu);
    }
}

void Sha256Hash(const u8* data, u32 length, u8 out[kSha256DigestBytes])
{
    Sha256Ctx ctx;
    Sha256Init(ctx);
    Sha256Update(ctx, data, length);
    Sha256Final(ctx, out);
}

void Sha256SelfTest()
{
    // FIPS 180-2 Appendix B.1: "abc".
    {
        const u8 msg[3] = {'a', 'b', 'c'};
        u8 d[32];
        Sha256Hash(msg, 3, d);
        const u8 want[32] = {0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40,
                             0xDE, 0x5D, 0xAE, 0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17,
                             0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD};
        for (u32 i = 0; i < 32; ++i)
            KASSERT(d[i] == want[i], "crypto/sha256", "sha256 KAT \"abc\" mismatch");
    }
    // Empty string.
    {
        u8 d[32];
        Sha256Hash(nullptr, 0, d);
        const u8 want[32] = {0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4,
                             0xC8, 0x99, 0x6F, 0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B,
                             0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55};
        for (u32 i = 0; i < 32; ++i)
            KASSERT(d[i] == want[i], "crypto/sha256", "sha256 KAT empty mismatch");
    }
}

} // namespace duetos::crypto
