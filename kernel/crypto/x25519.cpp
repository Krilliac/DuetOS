#include "crypto/x25519.h"

// X25519 scalar multiplication. The field-arithmetic + Montgomery-ladder
// core is the public-domain TweetNaCl `crypto_scalarmult` (D. Bernstein
// et al.), transcribed to the project's integer types. It is a compact,
// constant-time reference whose correctness is pinned by the RFC 7748
// §5.2 / §6.1 vectors in tests/host/test_x25519.cpp. Field elements are
// `gf` = 16 limbs of radix 2^16 (i64 to hold intermediate products).

namespace duetos::crypto
{
namespace
{

typedef i64 gf[16];

constexpr gf k121665 = {0xDB41, 1};

void Car25519(gf o)
{
    for (int i = 0; i < 16; ++i)
    {
        o[i] += (1LL << 16);
        i64 c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

// Constant-time conditional swap of p and q when b == 1.
void Sel25519(gf p, gf q, int b)
{
    i64 c = ~(static_cast<i64>(b) - 1);
    for (int i = 0; i < 16; ++i)
    {
        i64 t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

void Pack25519(u8* o, const gf n)
{
    gf m, t;
    for (int i = 0; i < 16; ++i)
        t[i] = n[i];
    Car25519(t);
    Car25519(t);
    Car25519(t);
    for (int j = 0; j < 2; ++j)
    {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i)
        {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        Sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i)
    {
        o[2 * i] = static_cast<u8>(t[i] & 0xff);
        o[2 * i + 1] = static_cast<u8>(t[i] >> 8);
    }
}

void Unpack25519(gf o, const u8* n)
{
    for (int i = 0; i < 16; ++i)
        o[i] = n[2 * i] + (static_cast<i64>(n[2 * i + 1]) << 8);
    o[15] &= 0x7fff;
}

void Add(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; ++i)
        o[i] = a[i] + b[i];
}
void Sub(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; ++i)
        o[i] = a[i] - b[i];
}
void Mul(gf o, const gf a, const gf b)
{
    i64 t[31];
    for (int i = 0; i < 31; ++i)
        t[i] = 0;
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j)
            t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; ++i)
        t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i)
        o[i] = t[i];
    Car25519(o);
    Car25519(o);
}
void Sqr(gf o, const gf a)
{
    Mul(o, a, a);
}

// o = i^(p-2) mod p — the field inverse via Fermat (RFC 7748 fixed chain).
void Inv25519(gf o, const gf i)
{
    gf c;
    for (int a = 0; a < 16; ++a)
        c[a] = i[a];
    for (int a = 253; a >= 0; --a)
    {
        Sqr(c, c);
        if (a != 2 && a != 4)
            Mul(c, c, i);
    }
    for (int a = 0; a < 16; ++a)
        o[a] = c[a];
}

void ScalarMult(u8* q, const u8* n, const u8* p)
{
    u8 z[32];
    i64 x[80];
    gf a, b, c, d, e, f;
    for (int i = 0; i < 31; ++i)
        z[i] = n[i];
    z[31] = (n[31] & 127) | 64; // clamp high bits
    z[0] &= 248;                // clamp low bits
    Unpack25519(x, p);
    for (int i = 0; i < 16; ++i)
    {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i)
    {
        i64 r = (z[i >> 3] >> (i & 7)) & 1;
        Sel25519(a, b, static_cast<int>(r));
        Sel25519(c, d, static_cast<int>(r));
        Add(e, a, c);
        Sub(a, a, c);
        Add(c, b, d);
        Sub(b, b, d);
        Sqr(d, e);
        Sqr(f, a);
        Mul(a, c, a);
        Mul(c, b, e);
        Add(e, a, c);
        Sub(a, a, c);
        Sqr(b, a);
        Sub(c, d, f);
        Mul(a, c, k121665);
        Add(a, a, d);
        Mul(c, c, a);
        Mul(a, d, f);
        Mul(d, b, x);
        Sqr(b, e);
        Sel25519(a, b, static_cast<int>(r));
        Sel25519(c, d, static_cast<int>(r));
    }
    for (int i = 0; i < 16; ++i)
    {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    Inv25519(x + 32, x + 32);
    Mul(x + 16, x + 16, x + 32);
    Pack25519(q, x + 16);
}

} // namespace

void X25519(u8 out[32], const u8 scalar[32], const u8 u[32])
{
    ScalarMult(out, scalar, u);
}

void X25519Base(u8 out[32], const u8 scalar[32])
{
    u8 base[32] = {9}; // basepoint u = 9, remaining bytes zero
    ScalarMult(out, scalar, base);
}

} // namespace duetos::crypto
