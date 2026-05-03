#include "crypto/sha512.h"

#include "core/panic.h"

namespace duetos::crypto
{

namespace
{

// FIPS 180-4 §4.2.3 — first 64 bits of the fractional parts of
// the cube roots of the first eighty primes 2..409.
constexpr u64 kK[80] = {
    0x428A2F98D728AE22ull, 0x7137449123EF65CDull, 0xB5C0FBCFEC4D3B2Full, 0xE9B5DBA58189DBBCull, 0x3956C25BF348B538ull,
    0x59F111F1B605D019ull, 0x923F82A4AF194F9Bull, 0xAB1C5ED5DA6D8118ull, 0xD807AA98A3030242ull, 0x12835B0145706FBEull,
    0x243185BE4EE4B28Cull, 0x550C7DC3D5FFB4E2ull, 0x72BE5D74F27B896Full, 0x80DEB1FE3B1696B1ull, 0x9BDC06A725C71235ull,
    0xC19BF174CF692694ull, 0xE49B69C19EF14AD2ull, 0xEFBE4786384F25E3ull, 0x0FC19DC68B8CD5B5ull, 0x240CA1CC77AC9C65ull,
    0x2DE92C6F592B0275ull, 0x4A7484AA6EA6E483ull, 0x5CB0A9DCBD41FBD4ull, 0x76F988DA831153B5ull, 0x983E5152EE66DFABull,
    0xA831C66D2DB43210ull, 0xB00327C898FB213Full, 0xBF597FC7BEEF0EE4ull, 0xC6E00BF33DA88FC2ull, 0xD5A79147930AA725ull,
    0x06CA6351E003826Full, 0x142929670A0E6E70ull, 0x27B70A8546D22FFCull, 0x2E1B21385C26C926ull, 0x4D2C6DFC5AC42AEDull,
    0x53380D139D95B3DFull, 0x650A73548BAF63DEull, 0x766A0ABB3C77B2A8ull, 0x81C2C92E47EDAEE6ull, 0x92722C851482353Bull,
    0xA2BFE8A14CF10364ull, 0xA81A664BBC423001ull, 0xC24B8B70D0F89791ull, 0xC76C51A30654BE30ull, 0xD192E819D6EF5218ull,
    0xD69906245565A910ull, 0xF40E35855771202Aull, 0x106AA07032BBD1B8ull, 0x19A4C116B8D2D0C8ull, 0x1E376C085141AB53ull,
    0x2748774CDF8EEB99ull, 0x34B0BCB5E19B48A8ull, 0x391C0CB3C5C95A63ull, 0x4ED8AA4AE3418ACBull, 0x5B9CCA4F7763E373ull,
    0x682E6FF3D6B2B8A3ull, 0x748F82EE5DEFB2FCull, 0x78A5636F43172F60ull, 0x84C87814A1F0AB72ull, 0x8CC702081A6439ECull,
    0x90BEFFFA23631E28ull, 0xA4506CEBDE82BDE9ull, 0xBEF9A3F7B2C67915ull, 0xC67178F2E372532Bull, 0xCA273ECEEA26619Cull,
    0xD186B8C721C0C207ull, 0xEADA7DD6CDE0EB1Eull, 0xF57D4F7FEE6ED178ull, 0x06F067AA72176FBAull, 0x0A637DC5A2C898A6ull,
    0x113F9804BEF90DAEull, 0x1B710B35131C471Bull, 0x28DB77F523047D84ull, 0x32CAAB7B40C72493ull, 0x3C9EBE0A15C9BEBCull,
    0x431D67C49C100D4Cull, 0x4CC5D4BECB3E42B6ull, 0x597F299CFC657E2Aull, 0x5FCB6FAB3AD6FAECull, 0x6C44198C4A475817ull,
};

inline u64 RotR64(u64 x, u32 n)
{
    return (x >> n) | (x << (64 - n));
}

inline u64 BigSigma0(u64 x)
{
    return RotR64(x, 28) ^ RotR64(x, 34) ^ RotR64(x, 39);
}
inline u64 BigSigma1(u64 x)
{
    return RotR64(x, 14) ^ RotR64(x, 18) ^ RotR64(x, 41);
}
inline u64 LilSigma0(u64 x)
{
    return RotR64(x, 1) ^ RotR64(x, 8) ^ (x >> 7);
}
inline u64 LilSigma1(u64 x)
{
    return RotR64(x, 19) ^ RotR64(x, 61) ^ (x >> 6);
}
inline u64 Ch(u64 x, u64 y, u64 z)
{
    return (x & y) ^ (~x & z);
}
inline u64 Maj(u64 x, u64 y, u64 z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

u64 LoadU64Be(const u8* p)
{
    return (u64(p[0]) << 56) | (u64(p[1]) << 48) | (u64(p[2]) << 40) | (u64(p[3]) << 32) | (u64(p[4]) << 24) |
           (u64(p[5]) << 16) | (u64(p[6]) << 8) | u64(p[7]);
}

void StoreU64Be(u8* p, u64 v)
{
    p[0] = u8(v >> 56);
    p[1] = u8(v >> 48);
    p[2] = u8(v >> 40);
    p[3] = u8(v >> 32);
    p[4] = u8(v >> 24);
    p[5] = u8(v >> 16);
    p[6] = u8(v >> 8);
    p[7] = u8(v);
}

void Compress(u64 state[8], const u8 block[kSha512BlockBytes])
{
    u64 w[80];
    for (u32 i = 0; i < 16; ++i)
        w[i] = LoadU64Be(block + i * 8);
    for (u32 i = 16; i < 80; ++i)
        w[i] = LilSigma1(w[i - 2]) + w[i - 7] + LilSigma0(w[i - 15]) + w[i - 16];

    u64 a = state[0], b = state[1], c = state[2], d = state[3];
    u64 e = state[4], f = state[5], g = state[6], h = state[7];
    for (u32 i = 0; i < 80; ++i)
    {
        const u64 t1 = h + BigSigma1(e) + Ch(e, f, g) + kK[i] + w[i];
        const u64 t2 = BigSigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void AddBitLength(Sha512Ctx& ctx, u64 added_bits)
{
    const u64 prev = ctx.length_bits_lo;
    ctx.length_bits_lo += added_bits;
    if (ctx.length_bits_lo < prev)
        ++ctx.length_bits_hi;
}

void DoUpdate(Sha512Ctx& ctx, const u8* data, u32 length)
{
    AddBitLength(ctx, u64(length) * 8);
    if (ctx.buffered_bytes > 0)
    {
        const u32 want = kSha512BlockBytes - ctx.buffered_bytes;
        const u32 take = (length < want) ? length : want;
        for (u32 i = 0; i < take; ++i)
            ctx.block[ctx.buffered_bytes + i] = data[i];
        ctx.buffered_bytes += take;
        data += take;
        length -= take;
        if (ctx.buffered_bytes == kSha512BlockBytes)
        {
            Compress(ctx.state, ctx.block);
            ctx.buffered_bytes = 0;
        }
    }
    while (length >= kSha512BlockBytes)
    {
        Compress(ctx.state, data);
        data += kSha512BlockBytes;
        length -= kSha512BlockBytes;
    }
    for (u32 i = 0; i < length; ++i)
        ctx.block[i] = data[i];
    ctx.buffered_bytes += length;
}

void DoFinal(Sha512Ctx& ctx, u8* out, u32 out_bytes)
{
    // Pad: append 0x80, then zeros until 16 bytes (= 128-bit length)
    // remain in the block, then 128-bit big-endian length.
    const u32 saved_buf = ctx.buffered_bytes;
    ctx.block[saved_buf] = 0x80;
    if (saved_buf >= kSha512BlockBytes - 16)
    {
        for (u32 i = saved_buf + 1; i < kSha512BlockBytes; ++i)
            ctx.block[i] = 0;
        Compress(ctx.state, ctx.block);
        for (u32 i = 0; i < kSha512BlockBytes - 16; ++i)
            ctx.block[i] = 0;
    }
    else
    {
        for (u32 i = saved_buf + 1; i < kSha512BlockBytes - 16; ++i)
            ctx.block[i] = 0;
    }
    StoreU64Be(ctx.block + kSha512BlockBytes - 16, ctx.length_bits_hi);
    StoreU64Be(ctx.block + kSha512BlockBytes - 8, ctx.length_bits_lo);
    Compress(ctx.state, ctx.block);

    const u32 lanes = out_bytes / 8;
    for (u32 i = 0; i < lanes; ++i)
        StoreU64Be(out + i * 8, ctx.state[i]);
}

} // namespace

void Sha512Init(Sha512Ctx& ctx)
{
    // FIPS 180-4 §5.3.5 — first 64 bits of the fractional parts of
    // the square roots of the first eight primes.
    ctx.state[0] = 0x6A09E667F3BCC908ull;
    ctx.state[1] = 0xBB67AE8584CAA73Bull;
    ctx.state[2] = 0x3C6EF372FE94F82Bull;
    ctx.state[3] = 0xA54FF53A5F1D36F1ull;
    ctx.state[4] = 0x510E527FADE682D1ull;
    ctx.state[5] = 0x9B05688C2B3E6C1Full;
    ctx.state[6] = 0x1F83D9ABFB41BD6Bull;
    ctx.state[7] = 0x5BE0CD19137E2179ull;
    ctx.length_bits_lo = 0;
    ctx.length_bits_hi = 0;
    ctx.buffered_bytes = 0;
}

void Sha384Init(Sha512Ctx& ctx)
{
    // FIPS 180-4 §5.3.4 — first 64 bits of the fractional parts of
    // the square roots of primes 23..53 (per the spec's table).
    ctx.state[0] = 0xCBBB9D5DC1059ED8ull;
    ctx.state[1] = 0x629A292A367CD507ull;
    ctx.state[2] = 0x9159015A3070DD17ull;
    ctx.state[3] = 0x152FECD8F70E5939ull;
    ctx.state[4] = 0x67332667FFC00B31ull;
    ctx.state[5] = 0x8EB44A8768581511ull;
    ctx.state[6] = 0xDB0C2E0D64F98FA7ull;
    ctx.state[7] = 0x47B5481DBEFA4FA4ull;
    ctx.length_bits_lo = 0;
    ctx.length_bits_hi = 0;
    ctx.buffered_bytes = 0;
}

void Sha512Update(Sha512Ctx& ctx, const u8* data, u32 length)
{
    DoUpdate(ctx, data, length);
}

void Sha512Final(Sha512Ctx& ctx, u8 out[kSha512DigestBytes])
{
    DoFinal(ctx, out, kSha512DigestBytes);
}

void Sha384Final(Sha512Ctx& ctx, u8 out[kSha384DigestBytes])
{
    DoFinal(ctx, out, kSha384DigestBytes);
}

void Sha512Hash(const u8* data, u32 length, u8 out[kSha512DigestBytes])
{
    Sha512Ctx ctx;
    Sha512Init(ctx);
    Sha512Update(ctx, data, length);
    Sha512Final(ctx, out);
}

void Sha384Hash(const u8* data, u32 length, u8 out[kSha384DigestBytes])
{
    Sha512Ctx ctx;
    Sha384Init(ctx);
    Sha512Update(ctx, data, length);
    Sha384Final(ctx, out);
}

void Sha512SelfTest()
{
    // ----- FIPS 180-4 SHA-512("abc") = ddaf35a193617aba cc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
    {
        const u8 msg[3] = {'a', 'b', 'c'};
        u8 out[64];
        Sha512Hash(msg, 3, out);
        const u8 want[64] = {0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae,
                             0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e,
                             0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1,
                             0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23,
                             0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
        for (u32 i = 0; i < 64; ++i)
            KASSERT(out[i] == want[i], "crypto/sha512", "SHA-512 \"abc\" mismatch");
    }
    // ----- SHA-512("") = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
    {
        u8 out[64];
        Sha512Hash(nullptr, 0, out);
        const u8 want[64] = {0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6,
                             0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4,
                             0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2,
                             0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd,
                             0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};
        for (u32 i = 0; i < 64; ++i)
            KASSERT(out[i] == want[i], "crypto/sha512", "SHA-512 \"\" mismatch");
    }
    // ----- FIPS 180-4 SHA-384("abc") = cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7
    {
        const u8 msg[3] = {'a', 'b', 'c'};
        u8 out[48];
        Sha384Hash(msg, 3, out);
        const u8 want[48] = {0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
                             0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
                             0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
                             0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};
        for (u32 i = 0; i < 48; ++i)
            KASSERT(out[i] == want[i], "crypto/sha384", "SHA-384 \"abc\" mismatch");
    }
    // ----- Multi-block: 1000 × 'a' (a known FIPS test). Truncated test —
    // verify just the first 8 bytes of SHA-512(1000×'a') match the
    // canonical reference 0x67ba5535a46e3f86.
    {
        u8 out[64];
        Sha512Ctx ctx;
        Sha512Init(ctx);
        u8 a = 'a';
        for (u32 i = 0; i < 1000; ++i)
            Sha512Update(ctx, &a, 1);
        Sha512Final(ctx, out);
        const u8 want_prefix[8] = {0x67, 0xba, 0x55, 0x35, 0xa4, 0x6e, 0x3f, 0x86};
        for (u32 i = 0; i < 8; ++i)
            KASSERT(out[i] == want_prefix[i], "crypto/sha512", "1000×'a' prefix mismatch");
    }
}

} // namespace duetos::crypto
