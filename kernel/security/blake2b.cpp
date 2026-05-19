/*
 * DuetOS — Blake2b (RFC 7693), reference-style implementation.
 *
 * See blake2b.h for the public contract. The code below follows
 * the RFC pseudocode line-by-line; comments quote the relevant
 * section numbers so a reviewer can cross-check.
 */

#include "security/blake2b.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "util/compiler.h"
#include "util/types.h"

namespace duetos::security
{

namespace
{

// RFC 7693 §2.6 — initialisation vector (SHA-512 IV).
constexpr u64 kBlake2bIV[8] = {0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL,
                               0xA54FF53A5F1D36F1ULL, 0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
                               0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL};

// RFC 7693 §2.7 — message word permutation schedule (sigma).
constexpr u8 kSigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

DUETOS_NO_SANITIZE_WRAP inline u64 RotR64(u64 x, u32 n)
{
    // Mask both shift amounts to [0,63]. For every n the callers
    // actually use (16/24/32/63) this is bit-identical to the
    // naive `x << (64 - n)`; the mask additionally makes n==0
    // well-defined (identity) instead of `x << 64` UB, so
    // -fsanitize=undefined's shift-exponent check can never trip
    // here regardless of how RotR64 gets inlined/folded.
    return (x >> (n & 63)) | (x << ((64u - n) & 63));
}

// Load a little-endian u64 from 8 bytes.
DUETOS_NO_SANITIZE_WRAP inline u64 LoadLE64(const u8* p)
{
    u64 r = 0;
    for (u32 i = 0; i < 8; ++i)
        r |= static_cast<u64>(p[i]) << (8u * i);
    return r;
}

DUETOS_NO_SANITIZE_WRAP inline void StoreLE64(u8* p, u64 v)
{
    for (u32 i = 0; i < 8; ++i)
        p[i] = static_cast<u8>(v >> (8u * i));
}

// RFC 7693 §3.1 — G mixing function.
DUETOS_NO_SANITIZE_WRAP inline void G(u64* v, u32 a, u32 b, u32 c, u32 d, u64 x, u64 y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = RotR64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = RotR64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = RotR64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = RotR64(v[b] ^ v[c], 63);
}

// RFC 7693 §3.2 — compression function F.
DUETOS_NO_SANITIZE_WRAP void Compress(Blake2bState& s, const u8 block[kBlake2bBlockBytes], bool last)
{
    u64 m[16];
    for (u32 i = 0; i < 16; ++i)
        m[i] = LoadLE64(block + i * 8);

    u64 v[16];
    for (u32 i = 0; i < 8; ++i)
    {
        v[i] = s.h[i];
        v[i + 8] = kBlake2bIV[i];
    }
    v[12] ^= s.t[0];
    v[13] ^= s.t[1];
    if (last)
        v[14] = ~v[14];

    for (u32 r = 0; r < 12; ++r)
    {
        const u8* sg = kSigma[r];
        G(v, 0, 4, 8, 12, m[sg[0]], m[sg[1]]);
        G(v, 1, 5, 9, 13, m[sg[2]], m[sg[3]]);
        G(v, 2, 6, 10, 14, m[sg[4]], m[sg[5]]);
        G(v, 3, 7, 11, 15, m[sg[6]], m[sg[7]]);
        G(v, 0, 5, 10, 15, m[sg[8]], m[sg[9]]);
        G(v, 1, 6, 11, 12, m[sg[10]], m[sg[11]]);
        G(v, 2, 7, 8, 13, m[sg[12]], m[sg[13]]);
        G(v, 3, 4, 9, 14, m[sg[14]], m[sg[15]]);
    }
    for (u32 i = 0; i < 8; ++i)
        s.h[i] ^= v[i] ^ v[i + 8];
}

DUETOS_NO_SANITIZE_WRAP void IncrementCounter(Blake2bState& s, u64 inc)
{
    s.t[0] += inc;
    if (s.t[0] < inc)
        s.t[1] += 1;
}

} // namespace

void Blake2bInit(Blake2bState& s, u32 out_bytes)
{
    if (out_bytes == 0 || out_bytes > kBlake2bMaxOutBytes)
        duetos::core::Panic("blake2b", "Init: out_bytes out of range");
    for (u32 i = 0; i < 8; ++i)
        s.h[i] = kBlake2bIV[i];
    // RFC 7693 §2.5: parameter block xor — out_bytes, key_bytes=0,
    // fanout=1, depth=1. Resulting low-order byte of h[0] xor:
    //   out_bytes | (0 << 8) | (1 << 16) | (1 << 24)
    s.h[0] ^= 0x01010000u | out_bytes;
    s.t[0] = 0;
    s.t[1] = 0;
    s.buflen = 0;
    s.outlen = out_bytes;
    for (u32 i = 0; i < kBlake2bBlockBytes; ++i)
        s.buf[i] = 0;
}

void Blake2bUpdate(Blake2bState& s, const u8* in, u32 n)
{
    while (n > 0)
    {
        const u32 space = kBlake2bBlockBytes - s.buflen;
        if (n <= space)
        {
            // RFC 7693 §3.3: do not compress if input might be the
            // final block — buffer it instead. Final compression
            // happens in Blake2bFinal.
            for (u32 i = 0; i < n; ++i)
                s.buf[s.buflen + i] = in[i];
            s.buflen += n;
            return;
        }
        // Fill buf and compress (not last).
        for (u32 i = 0; i < space; ++i)
            s.buf[s.buflen + i] = in[i];
        IncrementCounter(s, kBlake2bBlockBytes);
        Compress(s, s.buf, false);
        s.buflen = 0;
        in += space;
        n -= space;
    }
}

void Blake2bFinal(Blake2bState& s, u8* out)
{
    // Last block — pad with zeros, set last-block flag.
    for (u32 i = s.buflen; i < kBlake2bBlockBytes; ++i)
        s.buf[i] = 0;
    IncrementCounter(s, s.buflen);
    Compress(s, s.buf, true);

    // Write `outlen` bytes of state to out.
    u8 raw[kBlake2bMaxOutBytes];
    for (u32 i = 0; i < 8; ++i)
        StoreLE64(raw + i * 8, s.h[i]);
    for (u32 i = 0; i < s.outlen; ++i)
        out[i] = raw[i];
}

void Blake2bHash(const u8* in, u32 in_len, u8* out, u32 out_bytes)
{
    Blake2bState s;
    Blake2bInit(s, out_bytes);
    Blake2bUpdate(s, in, in_len);
    Blake2bFinal(s, out);
}

namespace
{

bool BytesEq(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

} // namespace

void Blake2bSelfTest()
{
    arch::SerialWrite("[blake2b] self-test: RFC 7693 vectors\n");

    // RFC 7693 Appendix A — "abc" -> known 64-byte digest.
    static const u8 kAbcDigest[64] = {
        0xBA, 0x80, 0xA5, 0x3F, 0x98, 0x1C, 0x4D, 0x0D, 0x6A, 0x27, 0x97, 0xB6, 0x9F, 0x12, 0xF6, 0xE9,
        0x4C, 0x21, 0x2F, 0x14, 0x68, 0x5A, 0xC4, 0xB7, 0x4B, 0x12, 0xBB, 0x6F, 0xDB, 0xFF, 0xA2, 0xD1,
        0x7D, 0x87, 0xC5, 0x39, 0x2A, 0xAB, 0x79, 0x2D, 0xC2, 0x52, 0xD5, 0xDE, 0x45, 0x33, 0xCC, 0x95,
        0x18, 0xD3, 0x8A, 0xA8, 0xDB, 0xF1, 0x92, 0x5A, 0xB9, 0x23, 0x86, 0xED, 0xD4, 0x00, 0x99, 0x23,
    };
    u8 got[64];
    const u8 abc[3] = {'a', 'b', 'c'};
    Blake2bHash(abc, 3, got, 64);
    if (!BytesEq(got, kAbcDigest, 64))
        duetos::core::Panic("blake2b", "self-test: 'abc' digest mismatch");

    // Empty-message digest — also well-known.
    static const u8 kEmptyDigest[64] = {
        0x78, 0x6A, 0x02, 0xF7, 0x42, 0x01, 0x59, 0x03, 0xC6, 0xC6, 0xFD, 0x85, 0x25, 0x52, 0xD2, 0x72,
        0x91, 0x2F, 0x47, 0x40, 0xE1, 0x58, 0x47, 0x61, 0x8A, 0x86, 0xE2, 0x17, 0xF7, 0x1F, 0x54, 0x19,
        0xD2, 0x5E, 0x10, 0x31, 0xAF, 0xEE, 0x58, 0x53, 0x13, 0x89, 0x64, 0x44, 0x93, 0x4E, 0xB0, 0x4B,
        0x90, 0x3A, 0x68, 0x5B, 0x14, 0x48, 0xB7, 0x55, 0xD5, 0x6F, 0x70, 0x1A, 0xFE, 0x9B, 0xE2, 0xCE,
    };
    Blake2bHash(nullptr, 0, got, 64);
    if (!BytesEq(got, kEmptyDigest, 64))
        duetos::core::Panic("blake2b", "self-test: empty digest mismatch");

    arch::SerialWrite("[blake2b] self-test: PASS\n");
}

} // namespace duetos::security
