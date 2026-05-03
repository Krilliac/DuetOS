#include "net/wireless/crypto/md5.h"

#include "core/panic.h"

/*
 * Reference: RFC 1321 — The MD5 Message-Digest Algorithm
 * (R. Rivest, April 1992). Same construction as SHA-1: little-
 * endian 32-bit words, 64-byte blocks, 64-step round function
 * across four 16-step rounds with distinct mixing functions
 * (F, G, H, I).
 *
 * MD5 is broken; this TU exists for legacy interop only. See
 * `md5.h` for the policy.
 */

namespace duetos::net::wireless::crypto
{

namespace
{

// Per-step rotate amounts. Four groups of four constants, repeated
// across the 16 steps of each round.
const u32 k_shift[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,  // F
                         5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,  // G
                         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,  // H
                         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21}; // I

// Per-step constants T[i] = floor(2^32 * |sin(i + 1)|) (RFC 1321 §3.4).
const u32 k_table[64] = {
    0xD76AA478u, 0xE8C7B756u, 0x242070DBu, 0xC1BDCEEEu, 0xF57C0FAFu, 0x4787C62Au, 0xA8304613u, 0xFD469501u,
    0x698098D8u, 0x8B44F7AFu, 0xFFFF5BB1u, 0x895CD7BEu, 0x6B901122u, 0xFD987193u, 0xA679438Eu, 0x49B40821u,
    0xF61E2562u, 0xC040B340u, 0x265E5A51u, 0xE9B6C7AAu, 0xD62F105Du, 0x02441453u, 0xD8A1E681u, 0xE7D3FBC8u,
    0x21E1CDE6u, 0xC33707D6u, 0xF4D50D87u, 0x455A14EDu, 0xA9E3E905u, 0xFCEFA3F8u, 0x676F02D9u, 0x8D2A4C8Au,
    0xFFFA3942u, 0x8771F681u, 0x6D9D6122u, 0xFDE5380Cu, 0xA4BEEA44u, 0x4BDECFA9u, 0xF6BB4B60u, 0xBEBFBC70u,
    0x289B7EC6u, 0xEAA127FAu, 0xD4EF3085u, 0x04881D05u, 0xD9D4D039u, 0xE6DB99E5u, 0x1FA27CF8u, 0xC4AC5665u,
    0xF4292244u, 0x432AFF97u, 0xAB9423A7u, 0xFC93A039u, 0x655B59C3u, 0x8F0CCC92u, 0xFFEFF47Du, 0x85845DD1u,
    0x6FA87E4Fu, 0xFE2CE6E0u, 0xA3014314u, 0x4E0811A1u, 0xF7537E82u, 0xBD3AF235u, 0x2AD7D2BBu, 0xEB86D391u};

u32 RotL(u32 v, u32 n)
{
    return (v << n) | (v >> (32u - n));
}

u32 LoadLe32(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

void StoreLe32(u32 v, u8* p)
{
    p[0] = static_cast<u8>(v & 0xFFu);
    p[1] = static_cast<u8>((v >> 8) & 0xFFu);
    p[2] = static_cast<u8>((v >> 16) & 0xFFu);
    p[3] = static_cast<u8>((v >> 24) & 0xFFu);
}

void Md5ProcessBlock(Md5Ctx& ctx, const u8* block)
{
    u32 m[16];
    for (u32 i = 0; i < 16; ++i)
        m[i] = LoadLe32(block + i * 4);

    u32 a = ctx.state[0];
    u32 b = ctx.state[1];
    u32 c = ctx.state[2];
    u32 d = ctx.state[3];

    for (u32 i = 0; i < 64; ++i)
    {
        u32 f;
        u32 g;
        if (i < 16)
        {
            f = (b & c) | ((~b) & d);
            g = i;
        }
        else if (i < 32)
        {
            f = (d & b) | ((~d) & c);
            g = (5u * i + 1u) % 16u;
        }
        else if (i < 48)
        {
            f = b ^ c ^ d;
            g = (3u * i + 5u) % 16u;
        }
        else
        {
            f = c ^ (b | (~d));
            g = (7u * i) % 16u;
        }
        const u32 temp = d;
        d = c;
        c = b;
        b = b + RotL(a + f + k_table[i] + m[g], k_shift[i]);
        a = temp;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
}

} // namespace

void Md5Init(Md5Ctx& ctx)
{
    ctx.state[0] = 0x67452301u;
    ctx.state[1] = 0xEFCDAB89u;
    ctx.state[2] = 0x98BADCFEu;
    ctx.state[3] = 0x10325476u;
    ctx.length_bits = 0;
    ctx.buffered_bytes = 0;
    for (u32 i = 0; i < kMd5BlockBytes; ++i)
        ctx.block[i] = 0;
}

void Md5Update(Md5Ctx& ctx, const u8* data, u32 length)
{
    if (data == nullptr || length == 0)
        return;
    ctx.length_bits += static_cast<u64>(length) * 8u;

    u32 i = 0;
    if (ctx.buffered_bytes != 0)
    {
        const u32 want = kMd5BlockBytes - ctx.buffered_bytes;
        const u32 take = (length < want) ? length : want;
        for (u32 k = 0; k < take; ++k)
            ctx.block[ctx.buffered_bytes + k] = data[k];
        ctx.buffered_bytes += take;
        i = take;
        if (ctx.buffered_bytes == kMd5BlockBytes)
        {
            Md5ProcessBlock(ctx, ctx.block);
            ctx.buffered_bytes = 0;
        }
    }
    while (i + kMd5BlockBytes <= length)
    {
        Md5ProcessBlock(ctx, data + i);
        i += kMd5BlockBytes;
    }
    while (i < length)
        ctx.block[ctx.buffered_bytes++] = data[i++];
}

void Md5Final(Md5Ctx& ctx, u8 out[kMd5DigestBytes])
{
    ctx.block[ctx.buffered_bytes++] = 0x80;
    if (ctx.buffered_bytes > kMd5BlockBytes - 8)
    {
        while (ctx.buffered_bytes < kMd5BlockBytes)
            ctx.block[ctx.buffered_bytes++] = 0;
        Md5ProcessBlock(ctx, ctx.block);
        ctx.buffered_bytes = 0;
    }
    while (ctx.buffered_bytes < kMd5BlockBytes - 8)
        ctx.block[ctx.buffered_bytes++] = 0;
    // MD5 length is little-endian, low 32 bits first.
    const u64 len = ctx.length_bits;
    StoreLe32(static_cast<u32>(len & 0xFFFFFFFFu), &ctx.block[ctx.buffered_bytes]);
    StoreLe32(static_cast<u32>((len >> 32) & 0xFFFFFFFFu), &ctx.block[ctx.buffered_bytes + 4]);
    Md5ProcessBlock(ctx, ctx.block);

    StoreLe32(ctx.state[0], &out[0]);
    StoreLe32(ctx.state[1], &out[4]);
    StoreLe32(ctx.state[2], &out[8]);
    StoreLe32(ctx.state[3], &out[12]);
}

void Md5Hash(const u8* data, u32 length, u8 out[kMd5DigestBytes])
{
    Md5Ctx ctx;
    Md5Init(ctx);
    Md5Update(ctx, data, length);
    Md5Final(ctx, out);
}

void Md5SelfTest()
{
    // RFC 1321 Appendix A.5 — MD5 test suite.
    struct Vector
    {
        const char* msg;
        u32 len;
        u8 want[16];
    };

    const Vector vectors[7] = {
        {"", 0, {0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04, 0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E}},
        {"a", 1, {0x0C, 0xC1, 0x75, 0xB9, 0xC0, 0xF1, 0xB6, 0xA8, 0x31, 0xC3, 0x99, 0xE2, 0x69, 0x77, 0x26, 0x61}},
        {"abc", 3, {0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0, 0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72}},
        {"message digest",
         14,
         {0xF9, 0x6B, 0x69, 0x7D, 0x7C, 0xB7, 0x93, 0x8D, 0x52, 0x5A, 0x2F, 0x31, 0xAA, 0xF1, 0x61, 0xD0}},
        {"abcdefghijklmnopqrstuvwxyz",
         26,
         {0xC3, 0xFC, 0xD3, 0xD7, 0x61, 0x92, 0xE4, 0x00, 0x7D, 0xFB, 0x49, 0x6C, 0xCA, 0x67, 0xE1, 0x3B}},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         62,
         {0xD1, 0x74, 0xAB, 0x98, 0xD2, 0x77, 0xD9, 0xF5, 0xA5, 0x61, 0x1C, 0x2C, 0x9F, 0x41, 0x9D, 0x9F}},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         80,
         {0x57, 0xED, 0xF4, 0xA2, 0x2B, 0xE3, 0xC9, 0x55, 0xAC, 0x49, 0xDA, 0x2E, 0x21, 0x07, 0xB6, 0x7A}}};

    for (u32 v = 0; v < 7; ++v)
    {
        u8 got[16];
        Md5Hash(reinterpret_cast<const u8*>(vectors[v].msg), vectors[v].len, got);
        for (u32 i = 0; i < 16; ++i)
            KASSERT(got[i] == vectors[v].want[i], "net/wireless/crypto/md5", "RFC 1321 Appendix A.5 vector mismatch");
    }
}

} // namespace duetos::net::wireless::crypto
