#include "net/ec.h"

#include "arch/x86_64/serial.h"
#include "crypto/bigint.h"
#include "debug/probes.h"

/*
 * ECDSA verification over NIST P-256 / P-384. See ec.h for scope and
 * the security posture (verify-only, public data, fail-closed).
 *
 * Implementation notes:
 *   - Field arithmetic is BigInt mod p. The bigint is 4096 bits wide, so
 *     a 384-bit product (768 bits) never overflows BigIntMul.
 *   - Modular inverse uses Fermat: a^(p-2) mod p (p prime). Slower than
 *     extended-Euclid but we only do a handful per verify, all on public
 *     data, so it is fine.
 *   - Points live in Jacobian projective coords (X, Y, Z) with the affine
 *     mapping x = X/Z^2, y = Y/Z^3. Add/double avoid per-step inversion;
 *     a single inversion converts back to affine at the end of the scalar
 *     multiply. This is the standard SEC1 add/double.
 *   - ECDSA-Verify follows FIPS 186-4 §4.1.4 / SEC1 §4.1.4 exactly:
 *     range-check r,s; e = leftmost bits of hash; w = s^-1 mod n;
 *     u1 = e*w mod n; u2 = r*w mod n; R = u1*G + u2*Q; accept iff
 *     R.x mod n == r.
 */

namespace duetos::net::ec
{

using duetos::crypto::BigInt;

namespace
{

// --- Curve constants (FIPS 186-4 D.1.2; cross-checked vs OpenSSL). ----------

constexpr u8 kEcP256P[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr u8 kEcP256A[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
constexpr u8 kEcP256B[32] = {0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd,
                             0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53,
                             0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b};
constexpr u8 kEcP256N[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
                             0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
constexpr u8 kEcP256Gx[32] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
                              0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
                              0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
constexpr u8 kEcP256Gy[32] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
                              0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
                              0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};

constexpr u8 kEcP384P[48] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};
constexpr u8 kEcP384A[48] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfc};
constexpr u8 kEcP384B[48] = {0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b,
                             0xe3, 0xf8, 0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12,
                             0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d,
                             0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef};
constexpr u8 kEcP384N[48] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
                             0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73};
constexpr u8 kEcP384Gx[48] = {0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e,
                              0xf3, 0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
                              0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d,
                              0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7};
constexpr u8 kEcP384Gy[48] = {0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf,
                              0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
                              0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce,
                              0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f};

// --- Field arithmetic mod p (all operands assumed already < p, except as
//     noted; results reduced into [0, p)). -----------------------------------

// out = (a + b) mod p.  a,b < p so a+b < 2p; one conditional subtract.
void FpAdd(BigInt* out, const BigInt& a, const BigInt& b, const BigInt& p)
{
    BigInt t{};
    duetos::crypto::BigIntAdd(&t, a, b);
    if (duetos::crypto::BigIntCompare(t, p) >= 0)
    {
        BigInt r{};
        duetos::crypto::BigIntSub(&r, t, p);
        duetos::crypto::BigIntCopy(out, r);
    }
    else
    {
        duetos::crypto::BigIntCopy(out, t);
    }
}

// out = (a - b) mod p.  Adds p first when a < b to keep the unsigned
// bigint non-negative (its Sub asserts on underflow).
void FpSub(BigInt* out, const BigInt& a, const BigInt& b, const BigInt& p)
{
    BigInt r{};
    if (duetos::crypto::BigIntCompare(a, b) >= 0)
    {
        duetos::crypto::BigIntSub(&r, a, b);
    }
    else
    {
        BigInt t{};
        duetos::crypto::BigIntAdd(&t, a, p);
        duetos::crypto::BigIntSub(&r, t, b);
    }
    duetos::crypto::BigIntCopy(out, r);
}

// out = (a * b) mod p.  The full product fits in the 4096-bit bigint.
void FpMul(BigInt* out, const BigInt& a, const BigInt& b, const BigInt& p)
{
    BigInt prod{};
    duetos::crypto::BigIntMul(&prod, a, b);
    duetos::crypto::BigIntMod(out, prod, p);
}

// out = a^-1 mod p via Fermat's little theorem: a^(p-2) mod p (p prime).
void FpInv(BigInt* out, const BigInt& a, const BigInt& p)
{
    BigInt two{};
    duetos::crypto::BigIntZero(&two);
    two.limbs[0] = 2;
    two.used = 1;
    BigInt pm2{};
    duetos::crypto::BigIntSub(&pm2, p, two);
    duetos::crypto::BigIntModExp(out, a, pm2, p);
}

// --- Jacobian point ops (x = X/Z^2, y = Y/Z^3). Z==0 marks infinity. --------

struct Jacobian
{
    BigInt x;
    BigInt y;
    BigInt z; // z == 0  <=>  point at infinity
};

bool JacIsInfinity(const Jacobian& q)
{
    return duetos::crypto::BigIntIsZero(q.z);
}

void JacSetInfinity(Jacobian* q)
{
    duetos::crypto::BigIntZero(&q->x);
    q->x.limbs[0] = 1;
    q->x.used = 1;
    duetos::crypto::BigIntZero(&q->y);
    q->y.limbs[0] = 1;
    q->y.used = 1;
    duetos::crypto::BigIntZero(&q->z);
}

void JacFromAffine(Jacobian* out, const Point& p)
{
    duetos::crypto::BigIntCopy(&out->x, p.x);
    duetos::crypto::BigIntCopy(&out->y, p.y);
    duetos::crypto::BigIntZero(&out->z);
    out->z.limbs[0] = 1;
    out->z.used = 1;
}

// Point doubling: out = 2*in (SEC1 / standard a-general formulas).
void JacDouble(Jacobian* out, const Jacobian& in, const BigInt& a, const BigInt& p)
{
    if (JacIsInfinity(in) || duetos::crypto::BigIntIsZero(in.y))
    {
        JacSetInfinity(out);
        return;
    }

    BigInt xx{}, yy{}, yyyy{}, zz{}, s{}, m{}, t{}, tmp{}, tmp2{};

    FpMul(&yy, in.y, in.y, p); // YY = Y^2
    FpMul(&yyyy, yy, yy, p);   // YYYY = YY^2
    FpMul(&zz, in.z, in.z, p); // ZZ = Z^2
    FpMul(&xx, in.x, in.x, p); // XX = X^2

    // S = 4 * X * YY
    FpMul(&s, in.x, yy, p);
    FpAdd(&s, s, s, p);
    FpAdd(&s, s, s, p);

    // M = 3*XX + a*ZZ^2
    BigInt zz2{};
    FpMul(&zz2, zz, zz, p); // ZZ^2 = Z^4
    FpMul(&tmp, a, zz2, p); // a*Z^4
    FpAdd(&m, xx, xx, p);
    FpAdd(&m, m, xx, p);  // 3*XX
    FpAdd(&m, m, tmp, p); // + a*Z^4

    // X3 = M^2 - 2*S
    FpMul(&t, m, m, p);
    FpAdd(&tmp, s, s, p); // 2S
    FpSub(&out->x, t, tmp, p);

    // Y3 = M*(S - X3) - 8*YYYY
    FpSub(&tmp, s, out->x, p);
    FpMul(&tmp2, m, tmp, p);
    BigInt eight_yyyy{};
    FpAdd(&eight_yyyy, yyyy, yyyy, p);             // 2
    FpAdd(&eight_yyyy, eight_yyyy, eight_yyyy, p); // 4
    FpAdd(&eight_yyyy, eight_yyyy, eight_yyyy, p); // 8
    FpSub(&out->y, tmp2, eight_yyyy, p);

    // Z3 = 2 * Y * Z
    FpMul(&tmp, in.y, in.z, p);
    FpAdd(&out->z, tmp, tmp, p);
}

// Point addition: out = p1 + p2 (general Jacobian, "add-2007-bl" shape).
// Handles the infinity and doubling special cases.
void JacAdd(Jacobian* out, const Jacobian& p1, const Jacobian& p2, const BigInt& a, const BigInt& p)
{
    if (JacIsInfinity(p1))
    {
        duetos::crypto::BigIntCopy(&out->x, p2.x);
        duetos::crypto::BigIntCopy(&out->y, p2.y);
        duetos::crypto::BigIntCopy(&out->z, p2.z);
        return;
    }
    if (JacIsInfinity(p2))
    {
        duetos::crypto::BigIntCopy(&out->x, p1.x);
        duetos::crypto::BigIntCopy(&out->y, p1.y);
        duetos::crypto::BigIntCopy(&out->z, p1.z);
        return;
    }

    BigInt z1z1{}, z2z2{}, u1{}, u2{}, s1{}, s2{}, tmp{};
    FpMul(&z1z1, p1.z, p1.z, p); // Z1Z1 = Z1^2
    FpMul(&z2z2, p2.z, p2.z, p); // Z2Z2 = Z2^2
    FpMul(&u1, p1.x, z2z2, p);   // U1 = X1*Z2Z2
    FpMul(&u2, p2.x, z1z1, p);   // U2 = X2*Z1Z1
    FpMul(&tmp, p2.z, z2z2, p);  // Z2^3
    FpMul(&s1, p1.y, tmp, p);    // S1 = Y1*Z2^3
    FpMul(&tmp, p1.z, z1z1, p);  // Z1^3
    FpMul(&s2, p2.y, tmp, p);    // S2 = Y2*Z1^3

    BigInt h{}, r{};
    FpSub(&h, u2, u1, p); // H = U2 - U1
    FpSub(&r, s2, s1, p); // r = S2 - S1

    if (duetos::crypto::BigIntIsZero(h))
    {
        if (duetos::crypto::BigIntIsZero(r))
        {
            JacDouble(out, p1, a, p); // same point -> double
            return;
        }
        JacSetInfinity(out); // p1 == -p2 -> infinity
        return;
    }

    BigInt hh{}, hhh{}, u1hh{}, t1{}, t2{};
    FpMul(&hh, h, h, p);     // HH = H^2
    FpMul(&hhh, hh, h, p);   // HHH = H^3
    FpMul(&u1hh, u1, hh, p); // U1*HH

    // X3 = r^2 - HHH - 2*U1*HH
    FpMul(&t1, r, r, p);
    FpSub(&t1, t1, hhh, p);
    FpAdd(&t2, u1hh, u1hh, p);
    FpSub(&out->x, t1, t2, p);

    // Y3 = r*(U1*HH - X3) - S1*HHH
    FpSub(&t1, u1hh, out->x, p);
    FpMul(&t1, r, t1, p);
    FpMul(&t2, s1, hhh, p);
    FpSub(&out->y, t1, t2, p);

    // Z3 = Z1*Z2*H
    FpMul(&t1, p1.z, p2.z, p);
    FpMul(&out->z, t1, h, p);
}

// Convert a Jacobian point back to affine: x = X/Z^2, y = Y/Z^3. Returns
// false for the point at infinity (no affine representation).
bool JacToAffine(Point* out, const Jacobian& q, const BigInt& p)
{
    if (JacIsInfinity(q))
    {
        out->infinity = true;
        return false;
    }
    BigInt zinv{}, zinv2{}, zinv3{};
    FpInv(&zinv, q.z, p);
    FpMul(&zinv2, zinv, zinv, p);
    FpMul(&zinv3, zinv2, zinv, p);
    FpMul(&out->x, q.x, zinv2, p);
    FpMul(&out->y, q.y, zinv3, p);
    out->infinity = false;
    return true;
}

// Scalar multiply: out = k * P (affine -> affine), double-and-add over the
// bits of k, MSB first. Variable-time (public data only). Returns false if
// the result is the point at infinity.
bool ScalarMul(Point* out, const BigInt& k, const Point& base, const BigInt& a, const BigInt& p)
{
    Jacobian acc{};
    JacSetInfinity(&acc);
    Jacobian basej{};
    JacFromAffine(&basej, base);

    // Walk bits from the most significant set bit down. Bounding the start
    // at k.used*32 (instead of the full 4096-bit width) is the difference
    // between ~256/384 doublings and ~4096 — the latter trips the boot
    // soft-lockup watchdog under TCG. k.used == 0 means k == 0 -> infinity.
    if (k.used == 0)
        return JacToAffine(out, acc, p);
    for (i32 limb = static_cast<i32>(k.used) - 1; limb >= 0; --limb)
    {
        for (i32 bit = 31; bit >= 0; --bit)
        {
            Jacobian dbl{};
            JacDouble(&dbl, acc, a, p);
            acc = dbl;
            if ((k.limbs[limb] >> bit) & 1u)
            {
                Jacobian sum{};
                JacAdd(&sum, acc, basej, a, p);
                acc = sum;
            }
        }
    }
    return JacToAffine(out, acc, p);
}

// Linear combination out = u1*G + u2*Q (the ECDSA verify core). Computed
// as two scalar multiplies plus one add — Shamir's trick would be faster
// but this path is not hot.
bool LinComb(Point* out, const BigInt& u1, const Point& g, const BigInt& u2, const Point& q, const BigInt& a,
             const BigInt& p)
{
    Point p1{}, p2{};
    const bool ok1 = ScalarMul(&p1, u1, g, a, p);
    const bool ok2 = ScalarMul(&p2, u2, q, a, p);

    Jacobian j1{}, j2{};
    if (ok1)
        JacFromAffine(&j1, p1);
    else
        JacSetInfinity(&j1);
    if (ok2)
        JacFromAffine(&j2, p2);
    else
        JacSetInfinity(&j2);

    Jacobian sum{};
    JacAdd(&sum, j1, j2, a, p);
    return JacToAffine(out, sum, p);
}

// Load a curve's domain parameters into the resolved Curve struct.
bool LoadCurve(Curve* out, const u8* p_be, const u8* a_be, const u8* b_be, const u8* n_be, const u8* gx_be,
               const u8* gy_be, u32 nbytes)
{
    if (!duetos::crypto::BigIntFromBytesBE(&out->p, p_be, nbytes))
        return false;
    if (!duetos::crypto::BigIntFromBytesBE(&out->a, a_be, nbytes))
        return false;
    if (!duetos::crypto::BigIntFromBytesBE(&out->b, b_be, nbytes))
        return false;
    if (!duetos::crypto::BigIntFromBytesBE(&out->n, n_be, nbytes))
        return false;
    if (!duetos::crypto::BigIntFromBytesBE(&out->g.x, gx_be, nbytes))
        return false;
    if (!duetos::crypto::BigIntFromBytesBE(&out->g.y, gy_be, nbytes))
        return false;
    out->g.infinity = false;
    out->field_bytes = nbytes;
    return true;
}

} // namespace

bool GetCurve(CurveId id, Curve* out)
{
    switch (id)
    {
    case CurveId::P256:
        return LoadCurve(out, kEcP256P, kEcP256A, kEcP256B, kEcP256N, kEcP256Gx, kEcP256Gy, 32);
    case CurveId::P384:
        return LoadCurve(out, kEcP384P, kEcP384A, kEcP384B, kEcP384N, kEcP384Gx, kEcP384Gy, 48);
    }
    return false;
}

bool ParsePublicKey(const Curve& curve, const u8* point, u32 len, Point* out)
{
    // SEC1 uncompressed: 0x04 || X(field_bytes) || Y(field_bytes).
    // GAP: compressed forms (0x02/0x03) are not accepted — fail closed.
    if (point == nullptr || len != 1u + 2u * curve.field_bytes)
        return false;
    if (point[0] != 0x04)
        return false;

    const u8* xb = point + 1;
    const u8* yb = point + 1 + curve.field_bytes;
    if (!duetos::crypto::BigIntFromBytesBE(&out->x, xb, curve.field_bytes))
        return false;
    if (!duetos::crypto::BigIntFromBytesBE(&out->y, yb, curve.field_bytes))
        return false;
    out->infinity = false;

    // Coordinates must be in [0, p).
    if (duetos::crypto::BigIntCompare(out->x, curve.p) >= 0)
        return false;
    if (duetos::crypto::BigIntCompare(out->y, curve.p) >= 0)
        return false;

    // On-curve check: y^2 == x^3 + a*x + b (mod p).
    BigInt lhs{}, x2{}, x3{}, ax{}, rhs{};
    FpMul(&lhs, out->y, out->y, curve.p);
    FpMul(&x2, out->x, out->x, curve.p);
    FpMul(&x3, x2, out->x, curve.p);
    FpMul(&ax, curve.a, out->x, curve.p);
    FpAdd(&rhs, x3, ax, curve.p);
    FpAdd(&rhs, rhs, curve.b, curve.p);
    if (duetos::crypto::BigIntCompare(lhs, rhs) != 0)
        return false;

    return true;
}

bool EcdsaVerify(const Curve& curve, const Point& pubkey, const u8* hash, u32 hlen, const u8* r_be, u32 r_len,
                 const u8* s_be, u32 s_len)
{
    if (hash == nullptr || hlen == 0 || r_be == nullptr || s_be == nullptr)
        return false;

    // Load r, s and range-check: must be in [1, n-1].
    BigInt r{}, s{};
    if (!duetos::crypto::BigIntFromBytesBE(&r, r_be, r_len))
        return false;
    if (!duetos::crypto::BigIntFromBytesBE(&s, s_be, s_len))
        return false;
    if (duetos::crypto::BigIntIsZero(r) || duetos::crypto::BigIntCompare(r, curve.n) >= 0)
        return false;
    if (duetos::crypto::BigIntIsZero(s) || duetos::crypto::BigIntCompare(s, curve.n) >= 0)
        return false;

    // e = leftmost min(hlen, field_bytes) bytes of the hash, as an
    // integer, then reduced mod n. SEC1 §4.1.4 step 3: when the hash is
    // longer than n's bit length, the leftmost bits are used. For P-256
    // (SHA-256) and P-384 (SHA-384) the hash length matches the field
    // width, so we take the whole digest; clamp defensively.
    const u32 take = (hlen < curve.field_bytes) ? hlen : curve.field_bytes;
    BigInt e{};
    if (!duetos::crypto::BigIntFromBytesBE(&e, hash, take))
        return false;
    BigInt ered{};
    duetos::crypto::BigIntMod(&ered, e, curve.n);

    // w = s^-1 mod n  (n is prime for both curves -> Fermat inverse).
    BigInt w{};
    FpInv(&w, s, curve.n);

    // u1 = e*w mod n,  u2 = r*w mod n.
    BigInt u1{}, u2{};
    FpMul(&u1, ered, w, curve.n);
    FpMul(&u2, r, w, curve.n);

    // R = u1*G + u2*Q.
    Point rpt{};
    if (!LinComb(&rpt, u1, curve.g, u2, pubkey, curve.a, curve.p))
        return false; // R == infinity -> invalid

    // Accept iff (R.x mod n) == r.
    BigInt rx_mod{};
    duetos::crypto::BigIntMod(&rx_mod, rpt.x, curve.n);
    return duetos::crypto::BigIntCompare(rx_mod, r) == 0;
}

// ---------------------------------------------------------------------------
// Boot self-test.
//
// KAT provenance (host OpenSSL 3.x, message = "DuetOS ECDSA KAT message"):
//   openssl ecparam -name prime256v1 -genkey -noout -out k.key
//   openssl dgst -sha256 -sign k.key -out k.sig msg          # P-256
//   openssl ec -in k.key -pubout -conv_form uncompressed ... # 0x04||X||Y
//   (P-384: -name secp384r1, -sha384). r,s are the two INTEGERs of the
//   ECDSA-Sig-Value SEQUENCE; Hash is the raw message digest.
// ---------------------------------------------------------------------------

namespace
{

// P-256 / SHA-256 KAT.
constexpr u8 kEcK256Pub[] = {0x04, 0x98, 0x10, 0x79, 0xe5, 0xae, 0x83, 0x18, 0xfa, 0x0f, 0xf6, 0xea, 0x4d,
                             0xb3, 0xd5, 0xea, 0x7a, 0xc1, 0xf4, 0x81, 0xa8, 0x39, 0x34, 0x0a, 0x91, 0x54,
                             0x7d, 0xe1, 0x85, 0x69, 0x6b, 0x5c, 0x58, 0xb0, 0x1e, 0x07, 0xad, 0xb4, 0x2a,
                             0x45, 0x54, 0x13, 0xfd, 0x66, 0xb7, 0x2b, 0xd7, 0xc6, 0x00, 0x89, 0xe1, 0xad,
                             0xa5, 0xa2, 0x04, 0x3a, 0x61, 0xde, 0xf5, 0x91, 0xf9, 0xef, 0x0e, 0x13, 0xb7};
constexpr u8 kEcK256Hash[] = {0xe8, 0xed, 0x26, 0x26, 0xda, 0xcb, 0x42, 0x89, 0xfc, 0xbb, 0x43,
                              0x3c, 0x6a, 0xf9, 0xc0, 0xa5, 0x24, 0x2c, 0x01, 0x19, 0x2a, 0x9e,
                              0x2f, 0xdd, 0x42, 0x7b, 0x1a, 0x3c, 0xef, 0xdc, 0x60, 0x8c};
constexpr u8 kEcK256R[] = {0x6d, 0xa2, 0x79, 0xad, 0x0f, 0x49, 0x0c, 0x1c, 0xdc, 0x97, 0x27,
                           0x86, 0xda, 0x34, 0x6b, 0xa1, 0x3b, 0x05, 0x50, 0x5d, 0x19, 0x98,
                           0x99, 0x6b, 0xcd, 0x81, 0xc8, 0x5e, 0x0b, 0x17, 0xd0, 0x16};
constexpr u8 kEcK256S[] = {0xb9, 0xc9, 0xe2, 0xd8, 0xfc, 0xd1, 0xa4, 0xd8, 0x67, 0x6b, 0x5f,
                           0xce, 0x00, 0x16, 0xc4, 0x8b, 0xc4, 0xa4, 0xd5, 0xb3, 0xae, 0x7f,
                           0x32, 0x33, 0x2c, 0x53, 0xfc, 0xa7, 0x17, 0xc3, 0xe7, 0xc3};

// P-384 / SHA-384 KAT.
constexpr u8 kEcK384Pub[] = {0x04, 0xda, 0x36, 0xe2, 0xa5, 0xbf, 0x31, 0xfb, 0x71, 0x4c, 0xdb, 0x59, 0x9d, 0x5a,
                             0xc4, 0xec, 0xd3, 0x9d, 0x19, 0xa6, 0x27, 0x2d, 0x50, 0x70, 0x2a, 0x6d, 0xfa, 0x52,
                             0xe3, 0xf8, 0x85, 0xac, 0x8d, 0xcc, 0xf0, 0x16, 0xdd, 0x87, 0xdf, 0x6c, 0xc8, 0x51,
                             0x7e, 0x4c, 0x47, 0xb6, 0xdd, 0xe1, 0xf3, 0x60, 0xf7, 0x17, 0x8e, 0x02, 0x15, 0xc5,
                             0x5e, 0x64, 0x7a, 0x55, 0x54, 0x8e, 0xd0, 0xe4, 0xd6, 0x11, 0x0f, 0xe8, 0x9f, 0x97,
                             0x8c, 0x0a, 0xc4, 0x1e, 0x69, 0xa0, 0x08, 0x81, 0x1f, 0x07, 0xbc, 0x77, 0x27, 0x80,
                             0x2c, 0xd8, 0x98, 0x6f, 0xa8, 0x3a, 0xf6, 0x58, 0x62, 0x6e, 0x7a, 0x39, 0x6d};
constexpr u8 kEcK384Hash[] = {0xc9, 0x31, 0xb3, 0x87, 0x96, 0xb7, 0xeb, 0x35, 0x21, 0x1f, 0x65, 0x15,
                              0x81, 0x5c, 0x74, 0x3a, 0xc5, 0x5e, 0x1d, 0x15, 0xea, 0xca, 0x72, 0xa6,
                              0x3a, 0xc8, 0x2a, 0x41, 0x9e, 0x3d, 0x2d, 0xf0, 0x14, 0xf2, 0xcb, 0xbb,
                              0x64, 0x7f, 0xba, 0xa9, 0x4d, 0xc0, 0x19, 0x3e, 0x4c, 0x8a, 0x48, 0x08};
constexpr u8 kEcK384R[] = {0xac, 0xd8, 0xb0, 0xf6, 0xbf, 0xda, 0x0a, 0xcf, 0x31, 0xbd, 0x67, 0x13,
                           0x07, 0xbf, 0xa4, 0x92, 0x1d, 0x7b, 0x17, 0x36, 0xbe, 0xf9, 0x77, 0xa7,
                           0x4d, 0x07, 0x0d, 0xce, 0x0e, 0x75, 0x58, 0xcb, 0xfd, 0xef, 0x36, 0x9b,
                           0x45, 0x42, 0xec, 0x2a, 0x44, 0xd7, 0xbd, 0xff, 0xc8, 0xe9, 0x67, 0x76};
constexpr u8 kEcK384S[] = {0x2b, 0xad, 0xcb, 0x19, 0xc4, 0x0c, 0x96, 0xfc, 0x11, 0xb5, 0x20, 0x51,
                           0xae, 0xdf, 0x85, 0x01, 0xa1, 0x29, 0x31, 0x0c, 0x3d, 0x88, 0x7f, 0x79,
                           0x4f, 0xf8, 0x9c, 0x9f, 0x9b, 0x9c, 0xb4, 0xd5, 0x91, 0x37, 0x79, 0xf7,
                           0x25, 0x08, 0xf0, 0x98, 0x04, 0xa6, 0x22, 0x3a, 0x27, 0xbc, 0x45, 0x2b};

void EcSelfTestFail(const char* label, u32 code)
{
    arch::SerialWrite("[ec-selftest] FAIL (");
    arch::SerialWrite(label);
    arch::SerialWrite(")\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, code);
}

} // namespace

void EcSelfTest()
{
    // --- P-256 positive: the KAT signature must verify.
    Curve c256{};
    if (!GetCurve(CurveId::P256, &c256))
    {
        EcSelfTestFail("p256-getcurve", 0xEC'01u);
        return;
    }
    Point q256{};
    if (!ParsePublicKey(c256, kEcK256Pub, sizeof(kEcK256Pub), &q256))
    {
        EcSelfTestFail("p256-parsekey", 0xEC'02u);
        return;
    }
    if (!EcdsaVerify(c256, q256, kEcK256Hash, sizeof(kEcK256Hash), kEcK256R, sizeof(kEcK256R), kEcK256S,
                     sizeof(kEcK256S)))
    {
        EcSelfTestFail("p256-verify", 0xEC'03u);
        return;
    }

    // --- P-256 negative: a tampered r must fail.
    {
        u8 bad_r[sizeof(kEcK256R)];
        for (u32 i = 0; i < sizeof(kEcK256R); ++i)
            bad_r[i] = kEcK256R[i];
        bad_r[sizeof(bad_r) - 1] ^= 0x01;
        if (EcdsaVerify(c256, q256, kEcK256Hash, sizeof(kEcK256Hash), bad_r, sizeof(bad_r), kEcK256S, sizeof(kEcK256S)))
        {
            EcSelfTestFail("p256-neg-tampered-r", 0xEC'04u);
            return;
        }
    }

    // --- P-256 negative: s == n (out of [1, n-1]) must fail. Use n's bytes.
    {
        if (EcdsaVerify(c256, q256, kEcK256Hash, sizeof(kEcK256Hash), kEcK256R, sizeof(kEcK256R), kEcP256N,
                        sizeof(kEcP256N)))
        {
            EcSelfTestFail("p256-neg-s-range", 0xEC'05u);
            return;
        }
    }

    // --- P-256 negative: an off-curve point must be rejected by ParsePublicKey.
    {
        u8 off[sizeof(kEcK256Pub)];
        for (u32 i = 0; i < sizeof(kEcK256Pub); ++i)
            off[i] = kEcK256Pub[i];
        off[sizeof(off) - 1] ^= 0x01; // perturb Y -> no longer on curve
        Point junk{};
        if (ParsePublicKey(c256, off, sizeof(off), &junk))
        {
            EcSelfTestFail("p256-neg-offcurve", 0xEC'06u);
            return;
        }
    }

    // --- P-384 positive: the KAT signature must verify.
    Curve c384{};
    if (!GetCurve(CurveId::P384, &c384))
    {
        EcSelfTestFail("p384-getcurve", 0xEC'10u);
        return;
    }
    Point q384{};
    if (!ParsePublicKey(c384, kEcK384Pub, sizeof(kEcK384Pub), &q384))
    {
        EcSelfTestFail("p384-parsekey", 0xEC'11u);
        return;
    }
    if (!EcdsaVerify(c384, q384, kEcK384Hash, sizeof(kEcK384Hash), kEcK384R, sizeof(kEcK384R), kEcK384S,
                     sizeof(kEcK384S)))
    {
        EcSelfTestFail("p384-verify", 0xEC'12u);
        return;
    }

    // --- P-384 negative: a tampered hash byte must fail.
    {
        u8 bad_h[sizeof(kEcK384Hash)];
        for (u32 i = 0; i < sizeof(kEcK384Hash); ++i)
            bad_h[i] = kEcK384Hash[i];
        bad_h[0] ^= 0x80;
        if (EcdsaVerify(c384, q384, bad_h, sizeof(bad_h), kEcK384R, sizeof(kEcK384R), kEcK384S, sizeof(kEcK384S)))
        {
            EcSelfTestFail("p384-neg-tampered-hash", 0xEC'13u);
            return;
        }
    }

    arch::SerialWrite("[ec-selftest] PASS (P-256+P-384 ECDSA verify; "
                      "4 positive checks / 4 negative: tampered-r, s-range, off-curve, tampered-hash)\n");
}

} // namespace duetos::net::ec
