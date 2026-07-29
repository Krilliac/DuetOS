#pragma once

#include "util/types.h"

/*
 * DuetOS — CPU sensor decode math.
 *
 * FREESTANDING on purpose: pure functions over raw register /
 * counter values, no kernel headers, no globals, no MMIO. The
 * kernel callers are `arch/x86_64/thermal.cpp` and
 * `arch/x86_64/cpufreq.cpp`; `tests/host/test_cpu_sensor_math.cpp`
 * exercises the same functions directly against synthetic inputs.
 *
 * Why the arithmetic lives here rather than inline at the read
 * sites: the reads themselves are unverifiable off the target —
 * QEMU models neither AMD's SMN aperture nor the Zen P-state MSRs,
 * so a boot proves only that the plumbing does not fault. The
 * DECODE is where an off-by-a-shift silently turns 61 C into 488 C,
 * and that half can be pinned on the host with no hardware at all.
 *
 * Everything here returns "no answer" as a distinguishable value
 * (0 MHz, `false` from a supported-predicate) rather than a plausible
 * default. Substituting a plausible default is the specific failure
 * this whole surface exists to avoid.
 */

namespace duetos::arch::cpu_sensor_math
{

// ---------------------------------------------------------------------
// AMD Zen die temperature (SMN THM_TCON_CUR_TMP)
// ---------------------------------------------------------------------
//
// Zen reports core temperature through the System Management Network,
// NOT through an MSR. The register is at SMN address 0x00059800 and is
// reached via the index/data pair in PCI config space on device 0:0.0.
// Layout:
//
//   bits 31:21  CurTmp   — unsigned count, 0.125 C per LSB
//   bit  19     CurTmpTjSel / range select — when set the scale is
//                          offset by -49 C (range -49..206 instead of
//                          0..255)
//
// The decoded figure is Tctl, the control temperature the firmware and
// fan tables use.

inline constexpr u32 kZenCurTempShift = 21;
inline constexpr u32 kZenCurTempRangeSelBit = 1u << 19;

/// Decode THM_TCON_CUR_TMP into millidegrees Celsius (Tctl).
///
/// GAP: first- and second-generation Threadripper and the X-suffix
/// Ryzen 1000/2000 parts bias Tctl above Tdie by a fixed +10..+27 C so
/// their fan curves ramp early; this returns the raw reported Tctl on
/// every part. Revisit if one of those SKUs is ever under test — the
/// bias table is keyed off the brand string, which we would have to
/// carry solely for those SKUs.
constexpr i32 ZenTempMilliC(u32 regval)
{
    i32 milli = static_cast<i32>((regval >> kZenCurTempShift) * 125u);
    if ((regval & kZenCurTempRangeSelBit) != 0)
        milli -= 49000;
    return milli;
}

/// True for the AMD families this file knows how to decode: 17h
/// (Zen/Zen+/Zen2), 19h (Zen3/Zen4), 1Ah (Zen5). One predicate covers
/// both the SMN temperature register above and the P-state encoding
/// below, because both changed at Zen and have been stable since.
///
/// An unrecognised family must report unsupported, never a number.
/// Pre-Zen AMD parts (10h..16h) do have a thermal register and P-state
/// MSRs, but at a different PCI function and with a different FID/DID
/// encoding, so decoding them here would produce a confident wrong
/// answer.
constexpr bool ZenFamilySupported(u32 family)
{
    return family == 0x17 || family == 0x19 || family == 0x1A;
}

/// Millidegrees to whole degrees, clamping the sub-zero range to 0.
/// Callers store Celsius in a u8; a negative Tctl (idle Zen parts in a
/// cold room can report just under 0 after the range-select offset)
/// must not wrap into 200-something.
constexpr u8 MilliCToWholeC(i32 milli)
{
    if (milli <= 0)
        return 0;
    const i32 whole = milli / 1000;
    if (whole > 255)
        return 255;
    return static_cast<u8>(whole);
}

// ---------------------------------------------------------------------
// AMD Zen P-state frequency (MSR_PSTATE_DEF)
// ---------------------------------------------------------------------
//
// Family 17h+ encodes each P-state's frequency in MSR C001_0064 + n:
//
//   bit  63     PstateEn
//   bits 13:8   CpuDfsId (divisor, in eighths)
//   bits  7:0   CpuFid   (multiplier)
//
// CoreCOF = (CpuFid / CpuDfsId) * 200 MHz. P0 is the base (guaranteed)
// frequency; the highest enabled index is the max-efficiency state.

/// Decode one PStateDef into MHz. Returns 0 for a disabled state or a
/// divisor the spec does not allow (< 8), which is the "unknown"
/// signal — never a plausible default.
constexpr u32 ZenPstateMhz(u64 pstate_def)
{
    if ((pstate_def & (1ULL << 63)) == 0)
        return 0;
    const u32 fid = static_cast<u32>(pstate_def & 0xFFu);
    const u32 did = static_cast<u32>((pstate_def >> 8) & 0x3Fu);
    if (fid == 0 || did < 8)
        return 0;
    return static_cast<u32>((static_cast<u64>(fid) * 200ULL) / did);
}

// ---------------------------------------------------------------------
// Effective frequency (APERF / MPERF)
// ---------------------------------------------------------------------

/// Effective frequency: base * dAPERF / dMPERF. Guards a zero or
/// decreasing MPERF delta (counter wrap, or the counters not advancing
/// because the platform does not implement them) by returning 0.
constexpr u32 EffectiveMhz(u32 base_mhz, u64 mperf0, u64 aperf0, u64 mperf1, u64 aperf1)
{
    if (mperf1 <= mperf0 || aperf1 < aperf0)
        return 0;
    const u64 dm = mperf1 - mperf0;
    const u64 da = aperf1 - aperf0;
    if (dm == 0)
        return 0;
    return static_cast<u32>((static_cast<u64>(base_mhz) * da) / dm);
}

} // namespace duetos::arch::cpu_sensor_math
