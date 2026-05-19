#include "crypto/sha1.h"

#include "core/panic.h"
#include "util/compiler.h"

namespace duetos::crypto
{

namespace
{

DUETOS_NO_SANITIZE_WRAP u32 RotL(u32 v, u32 n)
{
    return (v << n) | (v >> (32u - n));
}

DUETOS_NO_SANITIZE_WRAP void Sha1ProcessBlock(Sha1Ctx& ctx, const u8* block)
{
    u32 w[80];
    for (u32 i = 0; i < 16; ++i)
    {
        w[i] = (static_cast<u32>(block[i * 4]) << 24) | (static_cast<u32>(block[i * 4 + 1]) << 16) |
               (static_cast<u32>(block[i * 4 + 2]) << 8) | static_cast<u32>(block[i * 4 + 3]);
    }
    for (u32 i = 16; i < 80; ++i)
        w[i] = RotL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    u32 a = ctx.state[0];
    u32 b = ctx.state[1];
    u32 c = ctx.state[2];
    u32 d = ctx.state[3];
    u32 e = ctx.state[4];

    for (u32 i = 0; i < 80; ++i)
    {
        u32 f;
        u32 k;
        if (i < 20)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        const u32 t = RotL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = RotL(b, 30);
        b = a;
        a = t;
    }
    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
}

} // namespace

void Sha1Init(Sha1Ctx& ctx)
{
    ctx.state[0] = 0x67452301u;
    ctx.state[1] = 0xEFCDAB89u;
    ctx.state[2] = 0x98BADCFEu;
    ctx.state[3] = 0x10325476u;
    ctx.state[4] = 0xC3D2E1F0u;
    ctx.length_bits = 0;
    ctx.buffered_bytes = 0;
    for (u32 i = 0; i < kSha1BlockBytes; ++i)
        ctx.block[i] = 0;
}

void Sha1Update(Sha1Ctx& ctx, const u8* data, u32 length)
{
    if (data == nullptr || length == 0)
        return;
    ctx.length_bits += static_cast<u64>(length) * 8u;

    u32 i = 0;
    if (ctx.buffered_bytes != 0)
    {
        // Fill the existing buffer.
        const u32 want = kSha1BlockBytes - ctx.buffered_bytes;
        const u32 take = (length < want) ? length : want;
        for (u32 k = 0; k < take; ++k)
            ctx.block[ctx.buffered_bytes + k] = data[k];
        ctx.buffered_bytes += take;
        i = take;
        if (ctx.buffered_bytes == kSha1BlockBytes)
        {
            Sha1ProcessBlock(ctx, ctx.block);
            ctx.buffered_bytes = 0;
        }
    }
    while (i + kSha1BlockBytes <= length)
    {
        Sha1ProcessBlock(ctx, data + i);
        i += kSha1BlockBytes;
    }
    while (i < length)
    {
        ctx.block[ctx.buffered_bytes++] = data[i++];
    }
}

void Sha1Final(Sha1Ctx& ctx, u8 out[kSha1DigestBytes])
{
    // Append 0x80, zeros, then 64-bit big-endian length.
    ctx.block[ctx.buffered_bytes++] = 0x80;
    if (ctx.buffered_bytes > kSha1BlockBytes - 8)
    {
        while (ctx.buffered_bytes < kSha1BlockBytes)
            ctx.block[ctx.buffered_bytes++] = 0;
        Sha1ProcessBlock(ctx, ctx.block);
        ctx.buffered_bytes = 0;
    }
    while (ctx.buffered_bytes < kSha1BlockBytes - 8)
        ctx.block[ctx.buffered_bytes++] = 0;
    for (i32 i = 7; i >= 0; --i)
    {
        ctx.block[ctx.buffered_bytes++] = static_cast<u8>((ctx.length_bits >> (i * 8)) & 0xFFu);
    }
    Sha1ProcessBlock(ctx, ctx.block);

    for (u32 i = 0; i < 5; ++i)
    {
        out[i * 4 + 0] = static_cast<u8>((ctx.state[i] >> 24) & 0xFFu);
        out[i * 4 + 1] = static_cast<u8>((ctx.state[i] >> 16) & 0xFFu);
        out[i * 4 + 2] = static_cast<u8>((ctx.state[i] >> 8) & 0xFFu);
        out[i * 4 + 3] = static_cast<u8>(ctx.state[i] & 0xFFu);
    }
}

void Sha1Hash(const u8* data, u32 length, u8 out[kSha1DigestBytes])
{
    Sha1Ctx ctx;
    Sha1Init(ctx);
    Sha1Update(ctx, data, length);
    Sha1Final(ctx, out);
}

void Sha1SelfTest()
{
    // FIPS 180-1 Appendix A.1: "abc"
    {
        const u8 msg[3] = {'a', 'b', 'c'};
        u8 d[20];
        Sha1Hash(msg, 3, d);
        const u8 want[20] = {0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
                             0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D};
        for (u32 i = 0; i < 20; ++i)
            KASSERT(d[i] == want[i], "crypto/sha1", "sha1 KAT \"abc\" mismatch");
    }
    // FIPS 180-1 Appendix A.2:
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    {
        const u8* msg = reinterpret_cast<const u8*>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        u8 d[20];
        Sha1Hash(msg, 56, d);
        const u8 want[20] = {0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
                             0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1};
        for (u32 i = 0; i < 20; ++i)
            KASSERT(d[i] == want[i], "crypto/sha1", "sha1 KAT 56-byte mismatch");
    }
    // Empty string vector.
    {
        u8 d[20];
        Sha1Hash(nullptr, 0, d);
        const u8 want[20] = {0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
                             0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09};
        for (u32 i = 0; i < 20; ++i)
            KASSERT(d[i] == want[i], "crypto/sha1", "sha1 KAT empty mismatch");
    }
}

} // namespace duetos::crypto
