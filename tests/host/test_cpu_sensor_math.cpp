// test_cpu_sensor_math.cpp — hosted unit test for the CPU thermal and
// frequency decode math.
//
// Covers kernel/arch/x86_64/cpu_sensor_math.h:
//   ZenTempMilliC       — AMD Zen THM_TCON_CUR_TMP -> millidegrees
//   ZenFamilySupported  — which AMD families this decode applies to
//   MilliCToWholeC      — millidegrees -> u8 Celsius, clamped
//   ZenPstateMhz        — AMD P-state FID/DID -> MHz
//   EffectiveMhz        — APERF/MPERF ratio x base -> MHz
//
// Why this test exists rather than a boot assertion: neither decode is
// observable off the target. QEMU models no SMN aperture, so the AMD
// temperature register cannot be read under emulation at all, and the
// Zen P-state MSRs are not emulated either. A QEMU boot therefore
// proves only that the read plumbing does not fault — it can never
// prove the decode is right. The arithmetic is where a wrong shift
// silently turns 61 C into 488 C, and that half needs no hardware.
//
// The kernel callers are kernel/arch/x86_64/thermal.cpp and
// kernel/arch/x86_64/cpufreq.cpp; both also run a subset of these
// cases as on-target boot self-tests.

#include "host_test_helper.h"

#include "arch/x86_64/cpu_sensor_math.h"

using namespace duetos_host_test;
namespace csm = duetos::arch::cpu_sensor_math;

using duetos::u32;
using duetos::u64;

namespace
{

// Build a THM_TCON_CUR_TMP value from an 11-bit raw count.
constexpr u32 CurTmp(u32 raw, bool range_sel)
{
    u32 v = raw << csm::kZenCurTempShift;
    if (range_sel)
        v |= csm::kZenCurTempRangeSelBit;
    return v;
}

// Build a PStateDef from FID / DID.
constexpr u64 PstateDef(u32 fid, u32 did, bool enabled)
{
    u64 v = (static_cast<u64>(did & 0x3Fu) << 8) | static_cast<u64>(fid & 0xFFu);
    if (enabled)
        v |= (1ULL << 63);
    return v;
}

} // namespace

int main()
{
    // --- Zen temperature: the 0.125 C/LSB scale ----------------------
    // 0 counts is exactly 0 C, not "no reading" — the caller
    // distinguishes those with its own validity flag, never with the
    // value.
    EXPECT_EQ(static_cast<int>(csm::ZenTempMilliC(CurTmp(0, false))), 0);
    // 8 counts = 1.000 C. This is the one that catches an off-by-one
    // in the shift: at shift 20 or 22 the same register reads 0.5 C or
    // 2 C and still looks plausible.
    EXPECT_EQ(static_cast<int>(csm::ZenTempMilliC(CurTmp(8, false))), 1000);
    // A realistic idle reading: 0x1D8 (472) counts = 59.000 C.
    EXPECT_EQ(static_cast<int>(csm::ZenTempMilliC(CurTmp(472, false))), 59000);
    // Full scale of the 11-bit field without the range offset:
    // 2047 * 0.125 = 255.875 C.
    EXPECT_EQ(static_cast<int>(csm::ZenTempMilliC(CurTmp(2047, false))), 255875);

    // --- Zen temperature: the range-select offset --------------------
    // Bit 19 shifts the whole scale down by 49 C. Same raw count,
    // 49000 mC lower.
    EXPECT_EQ(static_cast<int>(csm::ZenTempMilliC(CurTmp(472, true))), 59000 - 49000);
    // Near the bottom of the shifted range the result is negative,
    // which the decode must express rather than wrap.
    EXPECT_TRUE(csm::ZenTempMilliC(CurTmp(8, true)) < 0);
    EXPECT_EQ(static_cast<int>(csm::ZenTempMilliC(CurTmp(8, true))), 1000 - 49000);
    // Bits outside 31:21 and bit 19 must not leak into the answer —
    // the low bits of this register carry unrelated control fields.
    EXPECT_EQ(static_cast<int>(csm::ZenTempMilliC(CurTmp(472, false) | 0x0007FFFFu)), 59000);

    // --- millidegrees -> whole degrees -------------------------------
    EXPECT_EQ(static_cast<int>(csm::MilliCToWholeC(59000)), 59);
    // Truncation, not rounding. Pinned so nobody "fixes" it into
    // rounding and shifts every reading by a degree.
    EXPECT_EQ(static_cast<int>(csm::MilliCToWholeC(59999)), 59);
    // A negative Tctl clamps to 0 rather than wrapping through u8 —
    // the failure this guards is a 200-something-degree reading on a
    // cold idle machine.
    EXPECT_EQ(static_cast<int>(csm::MilliCToWholeC(-1)), 0);
    EXPECT_EQ(static_cast<int>(csm::MilliCToWholeC(-48000)), 0);
    EXPECT_EQ(static_cast<int>(csm::MilliCToWholeC(0)), 0);
    // And the top clamps at the u8 ceiling instead of truncating to a
    // small plausible number.
    EXPECT_EQ(static_cast<int>(csm::MilliCToWholeC(255875)), 255);
    EXPECT_EQ(static_cast<int>(csm::MilliCToWholeC(300000)), 255);

    // --- family gate --------------------------------------------------
    // Zen through Zen5 share this register layout.
    EXPECT_TRUE(csm::ZenFamilySupported(0x17));
    EXPECT_TRUE(csm::ZenFamilySupported(0x19));
    EXPECT_TRUE(csm::ZenFamilySupported(0x1A));
    // Everything else must report unsupported. Pre-Zen AMD parts have
    // a thermal register too, at a different place with a different
    // layout — decoding one with this code would produce a confident
    // wrong number, which is worse than no number.
    EXPECT_FALSE(csm::ZenFamilySupported(0x15));
    EXPECT_FALSE(csm::ZenFamilySupported(0x16));
    EXPECT_FALSE(csm::ZenFamilySupported(0x18));
    EXPECT_FALSE(csm::ZenFamilySupported(0x1B));
    // An Intel family number must never open the AMD path.
    EXPECT_FALSE(csm::ZenFamilySupported(0x06));
    EXPECT_FALSE(csm::ZenFamilySupported(0x0F));
    EXPECT_FALSE(csm::ZenFamilySupported(0));

    // --- Zen P-state -> MHz -------------------------------------------
    // CoreCOF = FID / DID * 200. FID 0x98 (152), DID 8 -> 3800 MHz,
    // the P0 of a Ryzen 7840HS.
    EXPECT_EQ(static_cast<int>(csm::ZenPstateMhz(PstateDef(152, 8, true))), 3800);
    // DID 12 is the /1.5 divisor: 152 * 200 / 12 = 2533 MHz.
    EXPECT_EQ(static_cast<int>(csm::ZenPstateMhz(PstateDef(152, 12, true))), 2533);
    // A low-power state: FID 0x44 (68), DID 24 -> 566 MHz.
    EXPECT_EQ(static_cast<int>(csm::ZenPstateMhz(PstateDef(68, 24, true))), 566);
    // Disabled state is unknown (0), never a frequency. This is the
    // check that stops an unpopulated P-state slot from being read as
    // a real operating point.
    EXPECT_EQ(static_cast<int>(csm::ZenPstateMhz(PstateDef(152, 8, false))), 0);
    // Divisors below 8 are not encodable; treat as unknown rather than
    // dividing by a value that produces an absurd multi-GHz answer.
    EXPECT_EQ(static_cast<int>(csm::ZenPstateMhz(PstateDef(152, 0, true))), 0);
    EXPECT_EQ(static_cast<int>(csm::ZenPstateMhz(PstateDef(152, 7, true))), 0);
    // FID 0 is likewise not a 0 MHz CPU, it is an empty slot.
    EXPECT_EQ(static_cast<int>(csm::ZenPstateMhz(PstateDef(0, 8, true))), 0);
    // An all-ones read (the classic "nothing answered" pattern) must
    // not decode to a frequency: DID would be 0x3F, FID 0xFF ->
    // 255 * 200 / 63 = 809, which IS a plausible-looking number, so
    // this case documents the one place the guard cannot help and the
    // caller's ReadMsrSafe result is what rules it out.
    EXPECT_TRUE(csm::ZenPstateMhz(~0ULL) != 0);

    // --- effective frequency -------------------------------------------
    // APERF advancing at the same rate as MPERF means running at base.
    EXPECT_EQ(static_cast<int>(csm::EffectiveMhz(2800, 0, 0, 1000, 1000)), 2800);
    // Half the APERF advance is half the frequency.
    EXPECT_EQ(static_cast<int>(csm::EffectiveMhz(2800, 0, 0, 1000, 500)), 1400);
    // Turbo: APERF outrunning MPERF by 1.5x.
    EXPECT_EQ(static_cast<int>(csm::EffectiveMhz(2800, 0, 0, 1000, 1500)), 4200);
    // Non-zero starting points (the real call shape — two live
    // snapshots, not a zeroed baseline).
    EXPECT_EQ(static_cast<int>(csm::EffectiveMhz(3800, 500, 900, 1500, 2400)), 5700);
    // Counters that did not advance yield 0, which the caller renders
    // as "no reading". This is the QEMU-under-TCG case: unknown MSRs
    // answer 0 forever, so both deltas are 0.
    EXPECT_EQ(static_cast<int>(csm::EffectiveMhz(2800, 0, 0, 0, 0)), 0);
    EXPECT_EQ(static_cast<int>(csm::EffectiveMhz(2800, 100, 100, 100, 100)), 0);
    // A wrapped / decreasing counter yields 0 rather than a huge
    // number from unsigned underflow.
    EXPECT_EQ(static_cast<int>(csm::EffectiveMhz(2800, 100, 100, 50, 200)), 0);
    EXPECT_EQ(static_cast<int>(csm::EffectiveMhz(2800, 100, 200, 200, 100)), 0);
    // A large but realistic delta pair must not overflow the
    // multiply: 4 GHz base with counters in the tens of billions.
    EXPECT_EQ(static_cast<int>(csm::EffectiveMhz(4000, 0, 0, 40000000000ULL, 40000000000ULL)), 4000);

    return finish_main("cpu_sensor_math");
}
