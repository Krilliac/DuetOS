#include "util/soft_float.h"

/*
 * DuetOS — Soft-float runtime, implementation.
 *
 * Round-to-nearest-ties-to-even (banker's rounding). Denormal
 * inputs treated as zero. Denormal results flushed to zero. NaN
 * results canonicalised to quiet-NaN. See header for the scope
 * statement.
 *
 * The four core ops (Add, Mul, Div, Sqrt) are written for clarity
 * over micro-optimisation — the SPIR-V interpreter calls each at
 * most once per shader instruction, not in hot per-pixel loops
 * (when shaders eventually do drive per-pixel work, the
 * rasterizer will run them through a small JIT or a fast path; a
 * portable soft-float fallback is still the correctness oracle).
 */

namespace duetos::core
{

namespace
{

// IEEE 754 binary32 field decompositions.
struct Sf32Parts
{
    u32 sign;     // 0 or 1
    i32 exp_raw;  // raw biased exponent 0..255
    u32 mantissa; // raw 23-bit mantissa (no implicit bit)
};

Sf32Parts Decompose(Sf32 x)
{
    Sf32Parts p;
    p.sign = (x.bits >> 31) & 1u;
    p.exp_raw = static_cast<i32>((x.bits >> 23) & 0xFFu);
    p.mantissa = x.bits & 0x007FFFFFu;
    return p;
}

// Pack sign / unbiased exponent / 24-bit mantissa (with implicit
// leading 1, i.e. range [0x800000, 0xFFFFFF]) into an Sf32.
// Handles overflow to inf and underflow to zero. Assumes the
// mantissa has already been rounded to 24 bits.
Sf32 PackNormal(u32 sign, i32 unbiased_exp, u32 mantissa24)
{
    // Renormalise: shift until the leading bit sits at position 23.
    while (mantissa24 >= (1u << 24))
    {
        mantissa24 >>= 1;
        ++unbiased_exp;
    }
    while (mantissa24 != 0 && (mantissa24 & (1u << 23)) == 0u && unbiased_exp > -126)
    {
        mantissa24 <<= 1;
        --unbiased_exp;
    }
    if (mantissa24 == 0)
        return Sf32{sign << 31};
    const i32 biased = unbiased_exp + 127;
    if (biased >= 255)
        return Sf32{(sign << 31) | 0x7F800000u}; // overflow -> inf
    if (biased <= 0)
        return Sf32{sign << 31}; // underflow / denormal -> 0 (FTZ)
    const u32 mant_bits = mantissa24 & 0x007FFFFFu;
    return Sf32{(sign << 31) | (static_cast<u32>(biased) << 23) | mant_bits};
}

// Round a 27-bit-wide intermediate mantissa (1 implicit + 23
// stored + 3 guard/round/sticky) to 24 bits using round-to-
// nearest-ties-to-even. Returns the rounded 24-bit mantissa,
// which may carry into bit 24 — the caller renormalises.
u32 RoundTiesToEven(u32 wide_mant27)
{
    const u32 g = (wide_mant27 >> 2) & 1u; // guard
    const u32 r = (wide_mant27 >> 1) & 1u; // round
    const u32 s = wide_mant27 & 1u;        // sticky
    const u32 truncated = wide_mant27 >> 3;
    const u32 round_bits = (g << 2) | (r << 1) | s;
    if (round_bits < 0x4u)
        return truncated;
    if (round_bits > 0x4u)
        return truncated + 1u;
    // Halfway: ties to even (round toward even LSB).
    return (truncated & 1u) ? truncated + 1u : truncated;
}

} // namespace

// ------------------------------------------------------------------
// Addition / subtraction
// ------------------------------------------------------------------

Sf32 Sf32Add(Sf32 a, Sf32 b)
{
    // NaN propagation.
    if (Sf32IsNaN(a) || Sf32IsNaN(b))
        return Sf32QNaN();

    // Infinities.
    if (Sf32IsInf(a) && Sf32IsInf(b))
    {
        if (Sf32IsNegative(a) == Sf32IsNegative(b))
            return a;
        return Sf32QNaN(); // inf + (-inf) = NaN
    }
    if (Sf32IsInf(a))
        return a;
    if (Sf32IsInf(b))
        return b;

    Sf32Parts pa = Decompose(a);
    Sf32Parts pb = Decompose(b);

    // Zero handling — IEEE: +0 + +0 = +0, +0 + -0 = +0, -0 + -0 = -0.
    if (pa.exp_raw == 0 && pa.mantissa == 0)
        return (pb.exp_raw == 0 && pb.mantissa == 0 && pa.sign == 1 && pb.sign == 1) ? Sf32{0x80000000u} : b;
    if (pb.exp_raw == 0 && pb.mantissa == 0)
        return a;

    // Promote denormals to zero on input (FTZ semantics).
    if (pa.exp_raw == 0)
        return b;
    if (pb.exp_raw == 0)
        return a;

    // Materialise the implicit leading 1 and align mantissas.
    // We work with 27 bits (1 leading + 23 fraction + 3 GRS) so the
    // RoundTiesToEven helper can do its thing.
    u32 ma = (pa.mantissa | 0x00800000u) << 3;
    u32 mb = (pb.mantissa | 0x00800000u) << 3;
    i32 ea = pa.exp_raw - 127;
    i32 eb = pb.exp_raw - 127;

    if (ea > eb)
    {
        const i32 shift = ea - eb;
        if (shift >= 32)
            return a; // b is negligible
        // Build sticky by OR-ing the shifted-out bits.
        const u32 sticky_mask = (1u << shift) - 1u;
        const u32 shifted_out = mb & sticky_mask;
        mb = (mb >> shift) | (shifted_out ? 1u : 0u);
        eb = ea;
    }
    else if (eb > ea)
    {
        const i32 shift = eb - ea;
        if (shift >= 32)
            return b;
        const u32 sticky_mask = (1u << shift) - 1u;
        const u32 shifted_out = ma & sticky_mask;
        ma = (ma >> shift) | (shifted_out ? 1u : 0u);
        ea = eb;
    }

    // Same exponent now — decide on a true add vs subtract.
    u32 sign_result = pa.sign;
    u64 mant_sum;
    if (pa.sign == pb.sign)
    {
        mant_sum = static_cast<u64>(ma) + mb;
    }
    else
    {
        if (ma >= mb)
        {
            mant_sum = static_cast<u64>(ma) - mb;
            sign_result = pa.sign;
        }
        else
        {
            mant_sum = static_cast<u64>(mb) - ma;
            sign_result = pb.sign;
        }
        if (mant_sum == 0)
            return Sf32Zero(); // exact cancellation -> +0
    }

    // Re-normalise: the sum can be 28 bits wide (carry into bit 27)
    // or as narrow as 1 bit (massive cancellation). Loop until the
    // leading bit of the 27-bit form sits at position 26.
    i32 e = ea;
    while (mant_sum >= (1ull << 27))
    {
        // Sticky carries through a right shift.
        const u32 sticky = static_cast<u32>(mant_sum) & 1u;
        mant_sum = (mant_sum >> 1) | sticky;
        ++e;
    }
    while (mant_sum != 0 && (mant_sum & (1ull << 26)) == 0ull && e > -126)
    {
        mant_sum <<= 1;
        --e;
    }
    if (mant_sum == 0)
        return Sf32Zero();

    const u32 rounded = RoundTiesToEven(static_cast<u32>(mant_sum));
    return PackNormal(sign_result, e, rounded);
}

Sf32 Sf32Sub(Sf32 a, Sf32 b)
{
    return Sf32Add(a, Sf32Neg(b));
}

// ------------------------------------------------------------------
// Multiplication
// ------------------------------------------------------------------

Sf32 Sf32Mul(Sf32 a, Sf32 b)
{
    if (Sf32IsNaN(a) || Sf32IsNaN(b))
        return Sf32QNaN();

    const u32 sign = Decompose(a).sign ^ Decompose(b).sign;

    if (Sf32IsInf(a) || Sf32IsInf(b))
    {
        if (Sf32IsZero(a) || Sf32IsZero(b))
            return Sf32QNaN(); // 0 * inf = NaN
        return Sf32{(sign << 31) | 0x7F800000u};
    }
    if (Sf32IsZero(a) || Sf32IsZero(b))
        return Sf32{sign << 31};

    Sf32Parts pa = Decompose(a);
    Sf32Parts pb = Decompose(b);

    // Denormal-as-zero on input.
    if (pa.exp_raw == 0 || pb.exp_raw == 0)
        return Sf32{sign << 31};

    const u32 ma = pa.mantissa | 0x00800000u;      // 24-bit
    const u32 mb = pb.mantissa | 0x00800000u;      // 24-bit
    const u64 product = static_cast<u64>(ma) * mb; // 48-bit max
    // PackNormal takes the UNBIASED exponent. ea_unbiased + eb_unbiased
    // = (ea_raw - 127) + (eb_raw - 127) = ea_raw + eb_raw - 254.
    const i32 exp_sum = pa.exp_raw + pb.exp_raw - 254;

    // The 48-bit product has its leading bit at position 47 OR 46.
    // Shift right so the leading 1 sits at bit 26 (i.e. 27-bit form
    // with 3 G/R/S bits).
    u64 shifted = product;
    i32 e = exp_sum;
    if (shifted & (1ull << 47))
    {
        // Result is in [1.0, 2.0) << exp; shift right by 21 to bring
        // bit 47 down to bit 26.
        const u32 sticky_mask = (1u << 21) - 1u;
        const u32 sticky = (static_cast<u32>(shifted) & sticky_mask) ? 1u : 0u;
        shifted = (shifted >> 21) | sticky;
        e += 1;
    }
    else
    {
        // Result is in [0.5, 1.0) << exp; shift right by 20.
        const u32 sticky_mask = (1u << 20) - 1u;
        const u32 sticky = (static_cast<u32>(shifted) & sticky_mask) ? 1u : 0u;
        shifted = (shifted >> 20) | sticky;
    }

    const u32 rounded = RoundTiesToEven(static_cast<u32>(shifted));
    return PackNormal(sign, e, rounded);
}

// ------------------------------------------------------------------
// Division
// ------------------------------------------------------------------

Sf32 Sf32Div(Sf32 a, Sf32 b)
{
    if (Sf32IsNaN(a) || Sf32IsNaN(b))
        return Sf32QNaN();

    const u32 sign = Decompose(a).sign ^ Decompose(b).sign;

    if (Sf32IsInf(a) && Sf32IsInf(b))
        return Sf32QNaN(); // inf / inf = NaN
    if (Sf32IsZero(a) && Sf32IsZero(b))
        return Sf32QNaN(); // 0 / 0 = NaN
    if (Sf32IsInf(a))
        return Sf32{(sign << 31) | 0x7F800000u};
    if (Sf32IsZero(b))
        return Sf32{(sign << 31) | 0x7F800000u}; // x/0 = +/-inf
    if (Sf32IsInf(b) || Sf32IsZero(a))
        return Sf32{sign << 31};

    Sf32Parts pa = Decompose(a);
    Sf32Parts pb = Decompose(b);

    if (pa.exp_raw == 0 || pb.exp_raw == 0)
        return Sf32{sign << 31};

    // Long-division. Both mantissas are Q1.23 (24-bit values with
    // the implicit 1 at bit 23). We want the quotient in Q1.26 form
    // (27 bits: 1 leading + 23 fraction + 3 GRS) so the
    // RoundTiesToEven helper sees a leading 1 at bit 26.
    //
    // Fixed-point identity: (ma << 26) / mb yields a value of
    // `(ma/mb) * 2^26`. With ma, mb in [2^23, 2^24), the ratio is
    // in [0.5, 2), so the quotient is in [2^25, 2^27). Leading bit
    // is at 25 (ratio < 1) or 26 (ratio >= 1); PackNormal handles
    // both via its left-shift renormalisation loop, so we don't
    // need a pre-shift here.
    const u32 ma = pa.mantissa | 0x00800000u;
    const u32 mb = pb.mantissa | 0x00800000u;
    const u64 num = static_cast<u64>(ma) << 26;
    u64 q = num / mb;
    const u64 rem = num % mb;
    const i32 e = pa.exp_raw - pb.exp_raw;

    // Sticky from non-zero remainder so RoundTiesToEven sees the
    // truncated low bits.
    if (rem != 0)
        q |= 1u;

    const u32 rounded = RoundTiesToEven(static_cast<u32>(q));
    return PackNormal(sign, e, rounded);
}

// ------------------------------------------------------------------
// Square root (Newton-Raphson on the integer mantissa)
// ------------------------------------------------------------------

Sf32 Sf32Sqrt(Sf32 x)
{
    if (Sf32IsNaN(x))
        return Sf32QNaN();
    if (Sf32IsNegative(x) && !Sf32IsZero(x))
        return Sf32QNaN(); // sqrt(-x) for x > 0 = NaN; sqrt(-0) = -0 (handled below)
    if (Sf32IsZero(x))
        return x; // sqrt(+/-0) = +/-0
    if (Sf32IsInf(x))
        return x; // sqrt(+inf) = +inf

    Sf32Parts p = Decompose(x);
    if (p.exp_raw == 0)
        return Sf32Zero(); // denormal -> 0 (FTZ)

    // Integer-square-root on the mantissa.
    //
    // x = m * 2^e where m is Q1.23 (so m_real = m / 2^23, in [1,2))
    // sqrt(x) = sqrt(m_real) * 2^(e/2). Treat even and odd exponents
    // separately so the integer sqrt always lands a 24-bit result:
    //   even e: M = m << 23  (= m_real * 2^46, in [2^46, 2^47));
    //           int_sqrt(M) in [2^23, 2^23.5); result_exp = e/2.
    //   odd  e: M = m << 24  (= m_real * 2^47, in [2^47, 2^48));
    //           int_sqrt(M) in [2^23.5, 2^24); result_exp = (e-1)/2.
    // Both cases give a 24-bit mantissa with the implicit 1 at bit 23.
    const i32 unbiased = p.exp_raw - 127;
    const u64 m24 = static_cast<u64>(p.mantissa | 0x00800000u);
    const bool e_odd = (unbiased & 1) != 0;
    u64 M = e_odd ? (m24 << 24) : (m24 << 23);
    const i32 result_exp = e_odd ? ((unbiased - 1) / 2) : (unbiased / 2);

    // Bit-by-bit integer sqrt (digit recurrence). For an input
    // in [2^46, 2^48) the result is 24 bits in [2^23, 2^24).
    u64 result = 0;
    u64 bit = 1ull << 46; // highest even bit covering [2^46, 2^48)
    while (bit > M)
        bit >>= 2;
    while (bit != 0)
    {
        if (M >= result + bit)
        {
            M -= result + bit;
            result = (result >> 1) + bit;
        }
        else
        {
            result >>= 1;
        }
        bit >>= 2;
    }
    // result is the floor of the true sqrt. Round-to-nearest by
    // comparing the remainder against 2*result+1.
    if (2 * M > 2 * result + 1)
        ++result;

    return PackNormal(0u, result_exp, static_cast<u32>(result));
}

// ------------------------------------------------------------------
// Comparison
// ------------------------------------------------------------------

bool Sf32LessThan(Sf32 a, Sf32 b)
{
    if (Sf32IsNaN(a) || Sf32IsNaN(b))
        return false; // unordered
    if (Sf32IsZero(a) && Sf32IsZero(b))
        return false; // +0 == -0
    const bool a_neg = Sf32IsNegative(a);
    const bool b_neg = Sf32IsNegative(b);
    if (a_neg != b_neg)
        return a_neg;
    // Same sign — compare magnitudes via the encoded bit pattern.
    if (a_neg)
        return (a.bits & 0x7FFFFFFFu) > (b.bits & 0x7FFFFFFFu);
    return (a.bits & 0x7FFFFFFFu) < (b.bits & 0x7FFFFFFFu);
}

bool Sf32GreaterThan(Sf32 a, Sf32 b)
{
    return Sf32LessThan(b, a);
}

bool Sf32Equal(Sf32 a, Sf32 b)
{
    if (Sf32IsNaN(a) || Sf32IsNaN(b))
        return false;
    if (Sf32IsZero(a) && Sf32IsZero(b))
        return true; // +0 == -0
    return a.bits == b.bits;
}

// ------------------------------------------------------------------
// GLSL-style helpers (min/max/mix/step)
// ------------------------------------------------------------------

Sf32 Sf32Min(Sf32 a, Sf32 b)
{
    if (Sf32IsNaN(a))
        return b;
    if (Sf32IsNaN(b))
        return a;
    return Sf32LessThan(a, b) ? a : b;
}

Sf32 Sf32Max(Sf32 a, Sf32 b)
{
    if (Sf32IsNaN(a))
        return b;
    if (Sf32IsNaN(b))
        return a;
    return Sf32GreaterThan(a, b) ? a : b;
}

Sf32 Sf32Mix(Sf32 a, Sf32 b, Sf32 t)
{
    // a * (1 - t) + b * t
    const Sf32 one_minus_t = Sf32Sub(Sf32One(), t);
    return Sf32Add(Sf32Mul(a, one_minus_t), Sf32Mul(b, t));
}

Sf32 Sf32Step(Sf32 edge, Sf32 x)
{
    // GLSL spec: 0.0 if x < edge, 1.0 otherwise.
    if (Sf32IsNaN(x) || Sf32IsNaN(edge))
        return Sf32Zero();
    return Sf32LessThan(x, edge) ? Sf32Zero() : Sf32One();
}

// ------------------------------------------------------------------
// Sin / Cos / Exp / Log / Pow — polynomial approximations.
// ------------------------------------------------------------------
//
// All four piggy-back on Sf32Add / Sf32Mul / Sf32Div, so they're
// portable across the soft-float runtime. They're not Cephes-grade
// but are accurate enough for shader use — the typical shader
// consumer is procedural lighting / pattern generation where 5e-4
// max error is invisible. A future caller that needs higher
// precision adds extension entry points; v1 keeps the surface
// small.

namespace
{

constexpr Sf32 SfPi()
{
    return Sf32{0x40490FDBu}; // 3.1415927
}
constexpr Sf32 SfTwoPi()
{
    return Sf32{0x40C90FDBu}; // 6.2831853
}
constexpr Sf32 SfHalfPi()
{
    return Sf32{0x3FC90FDBu}; // 1.5707964
}
constexpr Sf32 SfInvTwoPi()
{
    return Sf32{0x3E22F983u}; // 0.15915494
}
constexpr Sf32 SfLn2()
{
    return Sf32{0x3F317218u}; // 0.6931472
}
constexpr Sf32 SfInvLn2()
{
    return Sf32{0x3FB8AA3Bu}; // 1.4426950 (1/ln 2)
}

} // namespace

Sf32 Sf32Sin(Sf32 x)
{
    if (Sf32IsNaN(x) || Sf32IsInf(x))
        return Sf32QNaN();

    // Range-reduce x to [-pi, pi]: k = floor(x / 2pi + 0.5);
    // x' = x - k * 2pi. Pure Sf32 arithmetic.
    const Sf32 half = Sf32{0x3F000000u};
    const Sf32 k_f = Sf32Add(Sf32Mul(x, SfInvTwoPi()), half);
    const i32 k = Sf32ToI32(k_f);
    Sf32 r = Sf32Sub(x, Sf32Mul(Sf32FromI32(k), SfTwoPi()));

    // Map [-pi, pi] -> [-pi/2, pi/2] using identities so the
    // polynomial covers a smaller range. sin(pi - r) = sin(r),
    // sin(-pi - r) = -sin(-r) = sin(r) with sign flipped.
    bool sign_flip = false;
    if (Sf32GreaterThan(r, SfHalfPi()))
    {
        r = Sf32Sub(SfPi(), r);
    }
    else if (Sf32LessThan(r, Sf32Neg(SfHalfPi())))
    {
        r = Sf32Sub(Sf32Neg(SfPi()), r);
        sign_flip = true;
    }

    // 7th-order minimax: sin(r) ~= r - r^3/6 + r^5/120 - r^7/5040
    // Coefficients computed from Taylor; for [-pi/2, pi/2] this
    // sits at ~3e-5 max error which is plenty for shader work.
    const Sf32 r2 = Sf32Mul(r, r);
    const Sf32 r3 = Sf32Mul(r2, r);
    const Sf32 r5 = Sf32Mul(r3, r2);
    const Sf32 r7 = Sf32Mul(r5, r2);
    const Sf32 c3 = Sf32{0x3E2AAAABu}; // 1/6
    const Sf32 c5 = Sf32{0x3C088889u}; // 1/120
    const Sf32 c7 = Sf32{0x39500D01u}; // 1/5040
    Sf32 s = Sf32Sub(r, Sf32Mul(r3, c3));
    s = Sf32Add(s, Sf32Mul(r5, c5));
    s = Sf32Sub(s, Sf32Mul(r7, c7));
    return sign_flip ? Sf32Neg(s) : s;
}

Sf32 Sf32Cos(Sf32 x)
{
    // cos(x) = sin(x + pi/2)
    return Sf32Sin(Sf32Add(x, SfHalfPi()));
}

Sf32 Sf32Exp(Sf32 x)
{
    if (Sf32IsNaN(x))
        return Sf32QNaN();
    // Saturation: clamp to the binary32 dynamic range.
    const Sf32 kMaxExpArg = Sf32{0x42B17218u}; // 88.722839 — log(FLT_MAX)
    const Sf32 kMinExpArg = Sf32{0xC2AEAC50u}; // -87.336544 — log(FLT_MIN)
    if (Sf32GreaterThan(x, kMaxExpArg))
        return Sf32Inf();
    if (Sf32LessThan(x, kMinExpArg))
        return Sf32Zero();

    // x = n * ln(2) + r, where r in [-ln2/2, ln2/2].
    // exp(x) = 2^n * exp(r). Compute n by rounding x * 1/ln2 to
    // the nearest integer; r = x - n*ln2.
    const Sf32 half = Sf32{0x3F000000u};
    const Sf32 n_f = Sf32Add(Sf32Mul(x, SfInvLn2()), Sf32IsNegative(x) ? Sf32Neg(half) : half);
    const i32 n = Sf32ToI32(n_f);
    const Sf32 r = Sf32Sub(x, Sf32Mul(Sf32FromI32(n), SfLn2()));

    // exp(r) ~= 1 + r + r^2/2 + r^3/6 + r^4/24 + r^5/120
    const Sf32 r2 = Sf32Mul(r, r);
    const Sf32 r3 = Sf32Mul(r2, r);
    const Sf32 r4 = Sf32Mul(r3, r);
    const Sf32 r5 = Sf32Mul(r4, r);
    const Sf32 c2 = Sf32{0x3F000000u}; // 1/2
    const Sf32 c3 = Sf32{0x3E2AAAABu}; // 1/6
    const Sf32 c4 = Sf32{0x3D2AAAABu}; // 1/24
    const Sf32 c5 = Sf32{0x3C088889u}; // 1/120
    Sf32 e_r = Sf32One();
    e_r = Sf32Add(e_r, r);
    e_r = Sf32Add(e_r, Sf32Mul(r2, c2));
    e_r = Sf32Add(e_r, Sf32Mul(r3, c3));
    e_r = Sf32Add(e_r, Sf32Mul(r4, c4));
    e_r = Sf32Add(e_r, Sf32Mul(r5, c5));

    // 2^n by direct bit manipulation: exponent field += n.
    // Clamp the exponent to [1, 254] (denormals flushed; saturate
    // before encoding).
    if (n > 127)
        return Sf32Inf();
    if (n < -126)
        return Sf32Zero();
    const u32 two_to_n_bits = static_cast<u32>(static_cast<i32>(127) + n) << 23;
    return Sf32Mul(e_r, Sf32{two_to_n_bits});
}

Sf32 Sf32Log(Sf32 x)
{
    if (Sf32IsNaN(x))
        return Sf32QNaN();
    if (Sf32IsNegative(x) && !Sf32IsZero(x))
        return Sf32QNaN();
    if (Sf32IsZero(x))
        return Sf32{0xFF800000u}; // -inf
    if (Sf32IsInf(x))
        return Sf32Inf();

    // x = m * 2^e, m in [1, 2). log(x) = log(m) + e * ln(2).
    const i32 e_raw = static_cast<i32>((x.bits >> 23) & 0xFFu);
    if (e_raw == 0)
        return Sf32{0xFF800000u}; // denormal -> -inf (FTZ)
    const i32 e_unbiased = e_raw - 127;
    Sf32 m{(x.bits & 0x007FFFFFu) | 0x3F800000u}; // m in [1, 2)

    // log(m) via a degree-5 minimax over [1, 2) using y = (m-1)/(m+1)
    // so the series converges fast. log(m) = 2 * (y + y^3/3 + y^5/5 + ...).
    const Sf32 num = Sf32Sub(m, Sf32One());
    const Sf32 den = Sf32Add(m, Sf32One());
    const Sf32 y = Sf32Div(num, den);
    const Sf32 y2 = Sf32Mul(y, y);
    const Sf32 y3 = Sf32Mul(y2, y);
    const Sf32 y5 = Sf32Mul(y3, y2);
    const Sf32 c3 = Sf32{0x3EAAAAABu}; // 1/3
    const Sf32 c5 = Sf32{0x3E4CCCCDu}; // 1/5
    Sf32 ser = Sf32Add(y, Sf32Mul(y3, c3));
    ser = Sf32Add(ser, Sf32Mul(y5, c5));
    const Sf32 log_m = Sf32Mul(Sf32{0x40000000u}, ser); // * 2

    return Sf32Add(log_m, Sf32Mul(Sf32FromI32(e_unbiased), SfLn2()));
}

Sf32 Sf32Pow(Sf32 x, Sf32 y)
{
    if (Sf32IsNaN(x) || Sf32IsNaN(y))
        return Sf32QNaN();
    if (Sf32IsZero(x))
        return Sf32IsZero(y) ? Sf32One() : Sf32Zero();
    if (Sf32IsZero(y))
        return Sf32One();
    if (Sf32IsNegative(x))
        return Sf32QNaN(); // v1 only handles positive bases
    return Sf32Exp(Sf32Mul(y, Sf32Log(x)));
}

// ------------------------------------------------------------------
// Conversion
// ------------------------------------------------------------------

i32 Sf32ToI32(Sf32 x)
{
    if (Sf32IsNaN(x) || Sf32IsZero(x))
        return 0;
    Sf32Parts p = Decompose(x);
    if (p.exp_raw == 0)
        return 0; // denormal -> 0
    const i32 unbiased = p.exp_raw - 127;
    if (unbiased < 0)
        return 0; // |x| < 1 -> truncate to zero
    if (unbiased > 30)
    {
        // |x| >= 2^31 — saturate.
        if (Sf32IsInf(x))
            return p.sign ? static_cast<i32>(0x80000000u) : 0x7FFFFFFF;
        if (unbiased == 31 && p.sign && p.mantissa == 0)
            return static_cast<i32>(0x80000000u); // exactly -2^31
        return p.sign ? static_cast<i32>(0x80000000u) : 0x7FFFFFFF;
    }
    const u32 mant = p.mantissa | 0x00800000u;
    u32 mag;
    if (unbiased >= 23)
        mag = mant << (unbiased - 23);
    else
        mag = mant >> (23 - unbiased);
    return p.sign ? -static_cast<i32>(mag) : static_cast<i32>(mag);
}

u32 Sf32ToU32(Sf32 x)
{
    if (Sf32IsNaN(x) || Sf32IsZero(x))
        return 0;
    if (Sf32IsNegative(x))
        return 0;
    Sf32Parts p = Decompose(x);
    if (p.exp_raw == 0)
        return 0;
    const i32 unbiased = p.exp_raw - 127;
    if (unbiased < 0)
        return 0;
    if (unbiased > 31)
        return Sf32IsInf(x) ? 0xFFFFFFFFu : 0xFFFFFFFFu;
    const u32 mant = p.mantissa | 0x00800000u;
    if (unbiased == 31)
    {
        // 2^31..2^32 — mantissa is 24-bit, shift left by 8.
        return mant << 8;
    }
    if (unbiased >= 23)
        return mant << (unbiased - 23);
    return mant >> (23 - unbiased);
}

Sf32 Sf32FromI32(i32 x)
{
    if (x == 0)
        return Sf32Zero();
    const u32 sign = (x < 0) ? 1u : 0u;
    u32 mag = (x < 0) ? static_cast<u32>(-static_cast<i64>(x)) : static_cast<u32>(x);
    // Find highest set bit.
    i32 exp = 0;
    for (i32 i = 31; i >= 0; --i)
    {
        if (mag & (1u << i))
        {
            exp = i;
            break;
        }
    }
    // Build a 27-bit form for rounding: leading bit at position 26.
    u64 wide = static_cast<u64>(mag);
    if (exp > 26)
    {
        const i32 shift = exp - 26;
        const u32 sticky_mask = (1u << shift) - 1u;
        const u32 sticky = (mag & sticky_mask) ? 1u : 0u;
        wide = (wide >> shift) | sticky;
    }
    else
    {
        wide <<= (26 - exp);
    }
    const u32 rounded = RoundTiesToEven(static_cast<u32>(wide));
    return PackNormal(sign, exp, rounded);
}

Sf32 Sf32FromU32(u32 x)
{
    if (x == 0)
        return Sf32Zero();
    i32 exp = 0;
    for (i32 i = 31; i >= 0; --i)
    {
        if (x & (1u << i))
        {
            exp = i;
            break;
        }
    }
    u64 wide = static_cast<u64>(x);
    if (exp > 26)
    {
        const i32 shift = exp - 26;
        const u32 sticky_mask = (1u << shift) - 1u;
        const u32 sticky = (x & sticky_mask) ? 1u : 0u;
        wide = (wide >> shift) | sticky;
    }
    else
    {
        wide <<= (26 - exp);
    }
    const u32 rounded = RoundTiesToEven(static_cast<u32>(wide));
    return PackNormal(0u, exp, rounded);
}

} // namespace duetos::core
