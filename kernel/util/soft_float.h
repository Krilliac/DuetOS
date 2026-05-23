#pragma once

#include "util/types.h"

/*
 * DuetOS — Soft-float runtime (IEEE 754 binary32).
 *
 * The kernel is compiled with `-mno-sse -mno-sse2` and does not
 * link any compiler-rt soft-float helpers, so `float` cannot be
 * used in kernel code at all (no scalar SSE, no x87 — the
 * scheduler doesn't save the FPU state for the kernel ring). Any
 * subsystem that genuinely needs binary32 arithmetic — most
 * notably the SPIR-V interpreter that drives the Vulkan ICD's
 * programmable rasterizer — has to do the math in pure integer
 * code.
 *
 * This TU implements that. The interface is `Sf32` — an opaque
 * struct wrapping a `u32` IEEE 754 bit pattern — plus the small
 * set of arithmetic / comparison / conversion entry points the
 * shader interpreter needs:
 *
 *   - construction: from sign+exp+mantissa, from u32 bits,
 *     from i32 / u32 / canonical 0.0 / 1.0 / -1.0 helpers
 *   - arithmetic: Add, Sub, Mul, Div, Neg, Abs
 *   - extras for shaders: Sqrt, FMin, FMax, FClamp, FMix, Step
 *   - comparison: LessThan, GreaterThan, Equal, LessOrEqual,
 *     GreaterOrEqual, NotEqual (IEEE ordered semantics — NaN
 *     compares unordered with everything)
 *   - conversion: ToI32 (truncation, IEEE saturation on overflow),
 *     ToU32, FromI32, FromU32
 *
 * Implementation strategy: full-precision integer arithmetic on
 * sign / exponent / mantissa fields, with denormals flushed to
 * zero on output (the shader workloads don't care about denormal
 * preservation and FTZ keeps the code compact). NaN payload is
 * not preserved — every NaN result encodes as a canonical
 * quiet-NaN bit pattern. Rounding: round to nearest, ties to
 * even (the IEEE default).
 *
 * This is deliberately scoped to what shaders need. It is NOT a
 * conformance-grade soft-float library — no denormal arithmetic,
 * no signed zero discrimination in comparisons (per IEEE +0 ==
 * -0), no FP exception flags (no inexact / overflow / underflow
 * sticky bits). If a future caller needs those, they bolt on
 * here.
 *
 * Context: kernel. Header-only types + a flat C++23 namespace.
 */

namespace duetos::core
{

/// IEEE 754 binary32 bit-pattern wrapper.
///
/// Storage is the raw 32-bit encoding: sign in bit 31, exponent
/// in bits 30..23 (biased by 127, with 0 = subnormal/zero and
/// 255 = infinity/NaN), mantissa in bits 22..0 (with an implicit
/// leading 1 for normals).
struct Sf32
{
    u32 bits;
};

// --------------------------------------------------------------
// Construction helpers
// --------------------------------------------------------------

/// Encode a single-precision float from its IEEE 754 bit pattern.
/// Useful when the caller already has the encoding (e.g. embedded
/// constants from a SPIR-V OpConstant payload, host-side test
/// vectors). Bit pattern is taken as-is — no normalisation.
constexpr Sf32 Sf32FromBits(u32 bits)
{
    return Sf32{bits};
}

/// Convert back to the raw 32-bit encoding.
constexpr u32 Sf32ToBits(Sf32 x)
{
    return x.bits;
}

/// Canonical positive zero (0x00000000).
constexpr Sf32 Sf32Zero()
{
    return Sf32{0u};
}

/// Canonical 1.0 (0x3F800000).
constexpr Sf32 Sf32One()
{
    return Sf32{0x3F800000u};
}

/// Canonical -1.0 (0xBF800000).
constexpr Sf32 Sf32NegOne()
{
    return Sf32{0xBF800000u};
}

/// Canonical +infinity (0x7F800000).
constexpr Sf32 Sf32Inf()
{
    return Sf32{0x7F800000u};
}

/// Canonical quiet NaN (0x7FC00000 — sign 0, exp all-1s,
/// mantissa MSB set per IEEE 754 quiet-NaN convention).
constexpr Sf32 Sf32QNaN()
{
    return Sf32{0x7FC00000u};
}

// --------------------------------------------------------------
// Predicates (introspection without arithmetic)
// --------------------------------------------------------------

constexpr bool Sf32IsZero(Sf32 x)
{
    return (x.bits & 0x7FFFFFFFu) == 0u;
}

constexpr bool Sf32IsNaN(Sf32 x)
{
    return (x.bits & 0x7F800000u) == 0x7F800000u && (x.bits & 0x007FFFFFu) != 0u;
}

constexpr bool Sf32IsInf(Sf32 x)
{
    return (x.bits & 0x7FFFFFFFu) == 0x7F800000u;
}

constexpr bool Sf32IsNegative(Sf32 x)
{
    return (x.bits & 0x80000000u) != 0u;
}

// --------------------------------------------------------------
// Arithmetic
// --------------------------------------------------------------

Sf32 Sf32Add(Sf32 a, Sf32 b);
Sf32 Sf32Sub(Sf32 a, Sf32 b);
Sf32 Sf32Mul(Sf32 a, Sf32 b);
Sf32 Sf32Div(Sf32 a, Sf32 b);

/// Negate: flip the sign bit. Works for +0 / -0, NaN preserved.
constexpr Sf32 Sf32Neg(Sf32 x)
{
    return Sf32{x.bits ^ 0x80000000u};
}

/// Absolute value: clear the sign bit.
constexpr Sf32 Sf32Abs(Sf32 x)
{
    return Sf32{x.bits & 0x7FFFFFFFu};
}

/// Square root (Newton-Raphson, ~24-bit accurate). Returns NaN
/// for negative inputs, +0 for +/-0, +inf for +inf.
Sf32 Sf32Sqrt(Sf32 x);

// --------------------------------------------------------------
// GLSL.std.450 helpers used by shaders
// --------------------------------------------------------------

Sf32 Sf32Min(Sf32 a, Sf32 b);
Sf32 Sf32Max(Sf32 a, Sf32 b);

/// `Sf32Clamp(x, lo, hi) = Sf32Min(Sf32Max(x, lo), hi)`. NaN
/// propagation follows the same chain as the underlying
/// min/max.
inline Sf32 Sf32Clamp(Sf32 x, Sf32 lo, Sf32 hi)
{
    return Sf32Min(Sf32Max(x, lo), hi);
}

/// Linear blend: `a*(1-t) + b*t`. Standard GLSL `mix`.
Sf32 Sf32Mix(Sf32 a, Sf32 b, Sf32 t);

/// GLSL step: 0.0 if x < edge, 1.0 otherwise. NaN inputs yield
/// 0.0 (consistent with GLSL implementation-defined behaviour
/// when the comparison is unordered).
Sf32 Sf32Step(Sf32 edge, Sf32 x);

// --------------------------------------------------------------
// Comparison (IEEE ordered — NaN compares unordered)
// --------------------------------------------------------------

bool Sf32LessThan(Sf32 a, Sf32 b);
bool Sf32GreaterThan(Sf32 a, Sf32 b);
bool Sf32Equal(Sf32 a, Sf32 b);
inline bool Sf32LessOrEqual(Sf32 a, Sf32 b)
{
    return Sf32LessThan(a, b) || Sf32Equal(a, b);
}
inline bool Sf32GreaterOrEqual(Sf32 a, Sf32 b)
{
    return Sf32GreaterThan(a, b) || Sf32Equal(a, b);
}
inline bool Sf32NotEqual(Sf32 a, Sf32 b)
{
    // IEEE NotEqual is the *unordered* form: true if a != b OR
    // either is NaN. Shaders use OpFOrdNotEqual (ordered) and
    // OpFUnordNotEqual (unordered) separately; the interpreter
    // calls one of these from the helper.
    return !Sf32Equal(a, b);
}

// --------------------------------------------------------------
// Conversions
// --------------------------------------------------------------

/// Truncate toward zero. Saturates: NaN -> 0, |x| > INT32_MAX
/// pins to INT32_MAX or INT32_MIN per IEEE saturation.
i32 Sf32ToI32(Sf32 x);

/// Same shape as ToI32 but for unsigned. NaN -> 0, negative -> 0,
/// overflow -> UINT32_MAX.
u32 Sf32ToU32(Sf32 x);

/// Convert from a signed 32-bit integer. Always exact for values
/// representable as binary32; values whose magnitude exceeds 2^24
/// round to nearest.
Sf32 Sf32FromI32(i32 x);

/// Convert from an unsigned 32-bit integer. Same rounding rules
/// as the signed version.
Sf32 Sf32FromU32(u32 x);

// --------------------------------------------------------------
// Boot self-test (panic on regression).
// --------------------------------------------------------------

/// Walks a curated set of arithmetic / comparison / conversion
/// vectors. Panics if any case diverges from the expected
/// result. Wired into `boot_bringup.cpp` behind
/// `DUETOS_BOOT_SELFTEST` so it runs once at boot and produces
/// the structural sentinel `[util/soft_float] self-test PASS`.
void Sf32SelfTest();

} // namespace duetos::core
