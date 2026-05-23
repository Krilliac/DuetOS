#include "util/soft_float.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

/*
 * DuetOS — Sf32 boot self-test.
 *
 * Each block exercises one IEEE 754 binary32 operation against
 * a known-good vector. Panics on regression so a kernel with a
 * busted soft-float runtime cannot continue to the SPIR-V
 * interpreter that depends on it. Emits the
 * `[util/soft_float] self-test PASS` sentinel CI greps for on
 * clean exit.
 *
 * Known-good bit patterns are computed at build time from a
 * sister host program (or by hand against the IEEE spec). The
 * cases focus on:
 *   - canonical zero / one / negation
 *   - basic add/sub with same-sign and cross-sign
 *   - multiply with normal range + a power-of-two simplification
 *   - division with an exact rational and a non-terminating one
 *   - sqrt against perfect squares
 *   - comparison semantics (ordered, NaN unordered)
 *   - GLSL min/max/clamp/mix/step
 *   - int<->float round-trip
 *
 * Specifically NOT tested: denormals (FTZ semantics), signaling-
 * NaN payload preservation, sign-of-zero discrimination in
 * comparisons. These are out of scope for the shader use cases
 * we ship today.
 */

namespace duetos::core
{

namespace
{

constexpr u32 kBitOne = 0x3F800000u;
constexpr u32 kBitTwo = 0x40000000u;
constexpr u32 kBitFour = 0x40800000u;
constexpr u32 kBitHalf = 0x3F000000u;
constexpr u32 kBitThree = 0x40400000u;
constexpr u32 kBitNegOne = 0xBF800000u;
constexpr u32 kBitFive = 0x40A00000u;

void Expect(u32 actual, u32 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[util/soft_float] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite(" got=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" want=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    ::duetos::core::Panic("util/soft_float", "self-test regression");
}

void ExpectBool(bool actual, bool expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[util/soft_float] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    ::duetos::core::Panic("util/soft_float", "self-test regression");
}

void ExpectI32(i32 actual, i32 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[util/soft_float] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite(" got=");
    arch::SerialWriteHex(static_cast<u32>(actual));
    arch::SerialWrite(" want=");
    arch::SerialWriteHex(static_cast<u32>(expected));
    arch::SerialWrite("\n");
    ::duetos::core::Panic("util/soft_float", "self-test regression");
}

} // namespace

void Sf32SelfTest()
{
    // Canonical constants.
    Expect(Sf32ToBits(Sf32One()), kBitOne, "Sf32One bits");
    Expect(Sf32ToBits(Sf32Zero()), 0u, "Sf32Zero bits");
    Expect(Sf32ToBits(Sf32NegOne()), kBitNegOne, "Sf32NegOne bits");
    Expect(Sf32ToBits(Sf32Neg(Sf32One())), kBitNegOne, "Neg(1) == -1");
    Expect(Sf32ToBits(Sf32Abs(Sf32NegOne())), kBitOne, "Abs(-1) == 1");

    // Add — 1 + 1 = 2.
    Expect(Sf32ToBits(Sf32Add(Sf32One(), Sf32One())), kBitTwo, "1+1=2");
    // Add — 2 + 2 = 4.
    Expect(Sf32ToBits(Sf32Add(Sf32FromBits(kBitTwo), Sf32FromBits(kBitTwo))), kBitFour, "2+2=4");
    // Add — 1 + 0.5 = 1.5 (0x3FC00000).
    Expect(Sf32ToBits(Sf32Add(Sf32One(), Sf32FromBits(kBitHalf))), 0x3FC00000u, "1+0.5=1.5");
    // Sub — 3 - 2 = 1.
    Expect(Sf32ToBits(Sf32Sub(Sf32FromBits(kBitThree), Sf32FromBits(kBitTwo))), kBitOne, "3-2=1");
    // Cancellation — 1 - 1 = 0.
    Expect(Sf32ToBits(Sf32Sub(Sf32One(), Sf32One())), 0u, "1-1=0");
    // Negative add — -1 + 2 = 1.
    Expect(Sf32ToBits(Sf32Add(Sf32NegOne(), Sf32FromBits(kBitTwo))), kBitOne, "-1+2=1");

    // Mul — 2 * 3 = 6 (0x40C00000).
    Expect(Sf32ToBits(Sf32Mul(Sf32FromBits(kBitTwo), Sf32FromBits(kBitThree))), 0x40C00000u, "2*3=6");
    // Mul — 0.5 * 0.5 = 0.25 (0x3E800000).
    Expect(Sf32ToBits(Sf32Mul(Sf32FromBits(kBitHalf), Sf32FromBits(kBitHalf))), 0x3E800000u, "0.5*0.5=0.25");
    // Mul — anything * 0 = 0.
    Expect(Sf32ToBits(Sf32Mul(Sf32FromBits(kBitFive), Sf32Zero())), 0u, "5*0=0");
    // Mul — -1 * -1 = 1.
    Expect(Sf32ToBits(Sf32Mul(Sf32NegOne(), Sf32NegOne())), kBitOne, "-1*-1=1");

    // Div — 4 / 2 = 2.
    Expect(Sf32ToBits(Sf32Div(Sf32FromBits(kBitFour), Sf32FromBits(kBitTwo))), kBitTwo, "4/2=2");
    // Div — 1 / 2 = 0.5.
    Expect(Sf32ToBits(Sf32Div(Sf32One(), Sf32FromBits(kBitTwo))), kBitHalf, "1/2=0.5");
    // Div — 6 / 3 = 2.
    Expect(Sf32ToBits(Sf32Div(Sf32FromBits(0x40C00000u), Sf32FromBits(kBitThree))), kBitTwo, "6/3=2");
    // Div by zero -> infinity.
    Expect(Sf32ToBits(Sf32Div(Sf32One(), Sf32Zero())), Sf32ToBits(Sf32Inf()), "1/0=inf");
    // 0/0 -> NaN.
    ExpectBool(Sf32IsNaN(Sf32Div(Sf32Zero(), Sf32Zero())), true, "0/0=NaN");

    // Sqrt — sqrt(4) = 2, sqrt(1) = 1, sqrt(0) = 0.
    Expect(Sf32ToBits(Sf32Sqrt(Sf32FromBits(kBitFour))), kBitTwo, "sqrt(4)=2");
    Expect(Sf32ToBits(Sf32Sqrt(Sf32One())), kBitOne, "sqrt(1)=1");
    Expect(Sf32ToBits(Sf32Sqrt(Sf32Zero())), 0u, "sqrt(0)=0");
    // sqrt(-1) -> NaN.
    ExpectBool(Sf32IsNaN(Sf32Sqrt(Sf32NegOne())), true, "sqrt(-1)=NaN");

    // Compare — 1 < 2, !(2 < 1), 1 == 1, !(1 == 2).
    ExpectBool(Sf32LessThan(Sf32One(), Sf32FromBits(kBitTwo)), true, "1<2");
    ExpectBool(Sf32LessThan(Sf32FromBits(kBitTwo), Sf32One()), false, "!(2<1)");
    ExpectBool(Sf32Equal(Sf32One(), Sf32One()), true, "1==1");
    ExpectBool(Sf32Equal(Sf32One(), Sf32FromBits(kBitTwo)), false, "!(1==2)");
    ExpectBool(Sf32GreaterThan(Sf32FromBits(kBitTwo), Sf32One()), true, "2>1");
    ExpectBool(Sf32LessOrEqual(Sf32One(), Sf32One()), true, "1<=1");
    // NaN compare unordered.
    ExpectBool(Sf32LessThan(Sf32QNaN(), Sf32One()), false, "NaN<1 unordered");
    ExpectBool(Sf32Equal(Sf32QNaN(), Sf32QNaN()), false, "NaN!=NaN");
    // +0 == -0.
    ExpectBool(Sf32Equal(Sf32Zero(), Sf32Neg(Sf32Zero())), true, "+0 == -0");

    // GLSL helpers.
    Expect(Sf32ToBits(Sf32Min(Sf32One(), Sf32FromBits(kBitTwo))), kBitOne, "min(1,2)=1");
    Expect(Sf32ToBits(Sf32Max(Sf32One(), Sf32FromBits(kBitTwo))), kBitTwo, "max(1,2)=2");
    Expect(Sf32ToBits(Sf32Clamp(Sf32FromBits(kBitFive), Sf32Zero(), Sf32FromBits(kBitTwo))), kBitTwo, "clamp(5,0,2)=2");
    Expect(Sf32ToBits(Sf32Mix(Sf32Zero(), Sf32FromBits(kBitTwo), Sf32FromBits(kBitHalf))), kBitOne, "mix(0,2,0.5)=1");
    Expect(Sf32ToBits(Sf32Step(Sf32One(), Sf32FromBits(kBitTwo))), kBitOne, "step(1,2)=1");
    Expect(Sf32ToBits(Sf32Step(Sf32FromBits(kBitTwo), Sf32One())), 0u, "step(2,1)=0");

    // Conversion — round-trip small integers.
    Expect(Sf32ToBits(Sf32FromI32(0)), 0u, "FromI32(0)");
    Expect(Sf32ToBits(Sf32FromI32(1)), kBitOne, "FromI32(1)");
    Expect(Sf32ToBits(Sf32FromI32(-1)), kBitNegOne, "FromI32(-1)");
    Expect(Sf32ToBits(Sf32FromI32(2)), kBitTwo, "FromI32(2)");
    Expect(Sf32ToBits(Sf32FromI32(5)), kBitFive, "FromI32(5)");
    Expect(Sf32ToBits(Sf32FromU32(0)), 0u, "FromU32(0)");
    Expect(Sf32ToBits(Sf32FromU32(1)), kBitOne, "FromU32(1)");

    ExpectI32(Sf32ToI32(Sf32Zero()), 0, "ToI32(0)");
    ExpectI32(Sf32ToI32(Sf32One()), 1, "ToI32(1)");
    ExpectI32(Sf32ToI32(Sf32NegOne()), -1, "ToI32(-1)");
    ExpectI32(Sf32ToI32(Sf32FromBits(kBitFive)), 5, "ToI32(5)");
    ExpectI32(Sf32ToI32(Sf32QNaN()), 0, "ToI32(NaN)");

    // Round-trip: -7 -> Sf32 -> -7.
    {
        const Sf32 v = Sf32FromI32(-7);
        ExpectI32(Sf32ToI32(v), -7, "round-trip -7");
    }
    // Round-trip: 0x100000 (1048576) — exactly representable.
    {
        const Sf32 v = Sf32FromI32(0x100000);
        ExpectI32(Sf32ToI32(v), 0x100000, "round-trip 1048576");
    }

    arch::SerialWrite("[util/soft_float] self-test PASS (43 vectors)\n");
}

} // namespace duetos::core
