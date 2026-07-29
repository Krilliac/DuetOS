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

// ---------------------------------------------------------------------
// Intel ratio-field decode
// ---------------------------------------------------------------------
//
// Three different Intel MSRs carry a ratio in bits 15:8, and one
// carries the turbo ceiling in bits 7:0. They are spelled out as four
// named functions rather than one shared bit-extractor because the
// MEANING differs even where the shift does not, and a control path
// that mixes up "the ratio running now" with "the highest ratio this
// part will ever accept" writes a wrong number to real silicon.

/// IA32_PERF_STATUS (0x198) bits 15:8 — the ratio in effect right now.
constexpr u32 IntelPerfStatusRatio(u64 perf_status)
{
    return static_cast<u32>((perf_status >> 8) & 0xFFu);
}

/// IA32_PLATFORM_INFO (0xCE) bits 15:8 — max non-turbo ("base",
/// guaranteed) ratio. This is the highest ratio the part sustains
/// without turbo.
constexpr u32 IntelPlatformInfoBaseRatio(u64 platform_info)
{
    return static_cast<u32>((platform_info >> 8) & 0xFFu);
}

/// IA32_PLATFORM_INFO (0xCE) bits 47:40 — max-efficiency (lowest)
/// ratio. This is the floor of the part's own advertised window.
constexpr u32 IntelPlatformInfoMinRatio(u64 platform_info)
{
    return static_cast<u32>((platform_info >> 40) & 0xFFu);
}

/// MSR_TURBO_RATIO_LIMIT (0x1AD) bits 7:0 — the max turbo ratio with
/// one active core, i.e. the highest ratio this part advertises at
/// all. Bits 15:8, 23:16 ... are the 2-, 3-, ...-core limits and are
/// necessarily <= this one, so the 1-core field is the ceiling.
constexpr u32 IntelTurboRatioLimit1C(u64 turbo_ratio_limit)
{
    return static_cast<u32>(turbo_ratio_limit & 0xFFu);
}

// ---------------------------------------------------------------------
// Ratio admission (the clamp that keeps a request inside the part's
// own advertised window)
// ---------------------------------------------------------------------

/// Admit `want` only if the part itself advertised a window that
/// contains it. Returns `want` when admissible, 0 when not.
///
/// This REFUSES rather than silently clamping. Clamping would let a
/// caller ask for 60x on a 28x part and quietly get 28x — a number
/// nobody chose, applied to hardware, with no error to notice. The
/// refusal is what makes "never write a ratio you did not read back
/// from the part" enforceable: the only ratios that get through are
/// ones inside a window read out of the silicon this boot.
///
/// A zero bound means "the platform did not tell us", which is not a
/// licence to guess — those refuse too. So does an inverted window
/// (min > max), which means one of the two reads is garbage.
constexpr u32 RatioAdmit(u32 want, u32 min_ratio, u32 max_ratio)
{
    if (want == 0 || min_ratio == 0 || max_ratio == 0)
        return 0;
    if (min_ratio > max_ratio)
        return 0;
    if (want < min_ratio || want > max_ratio)
        return 0;
    return want;
}

// ---------------------------------------------------------------------
// Intel legacy P-state control — IA32_PERF_CTL (0x199)
// ---------------------------------------------------------------------

/// Splice `ratio` into IA32_PERF_CTL bits 15:8, preserving every other
/// bit of `current` — notably bit 32 (IDA/turbo disengage), which the
/// firmware may have set and which is NOT ours to clear.
///
/// Read-modify-write rather than a fresh value on purpose: composing a
/// value from scratch silently reverts whatever else the platform put
/// in that register.
constexpr u64 IntelPerfCtlWithRatio(u64 current, u32 ratio)
{
    return (current & ~0xFF00ULL) | (static_cast<u64>(ratio & 0xFFu) << 8);
}

/// IA32_PERF_CTL (0x199) bits 15:8 — the ratio currently REQUESTED.
///
/// Same shift as IntelPerfStatusRatio, different register and different
/// meaning: this is what was asked for, that is what is running. The
/// write path reads this one back to verify its own write, and must not
/// confuse "the request landed" with "the silicon delivered it".
constexpr u32 IntelPerfCtlRatio(u64 perf_ctl)
{
    return static_cast<u32>((perf_ctl >> 8) & 0xFFu);
}

// ---------------------------------------------------------------------
// Intel HWP — IA32_HWP_CAPABILITIES (0x771) / IA32_HWP_REQUEST (0x774)
// ---------------------------------------------------------------------
//
// Under HWP the four performance fields are in abstract "performance"
// units, not ratios — but on every shipping part the mapping is 1:1
// with the bus ratio, and more importantly HWP_CAPABILITIES is the
// part's own statement of its window, so admitting against it needs no
// unit conversion at all.
//
//   IA32_HWP_CAPABILITIES  7:0 highest, 15:8 guaranteed,
//                          23:16 most-efficient, 31:24 lowest
//   IA32_HWP_REQUEST       7:0 minimum, 15:8 maximum, 23:16 desired,
//                          31:24 EPP, 41:32 activity window,
//                          42 package control

constexpr u32 HwpCapHighest(u64 caps)
{
    return static_cast<u32>(caps & 0xFFu);
}

constexpr u32 HwpCapGuaranteed(u64 caps)
{
    return static_cast<u32>((caps >> 8) & 0xFFu);
}

constexpr u32 HwpCapMostEfficient(u64 caps)
{
    return static_cast<u32>((caps >> 16) & 0xFFu);
}

constexpr u32 HwpCapLowest(u64 caps)
{
    return static_cast<u32>((caps >> 24) & 0xFFu);
}

/// Splice minimum / maximum / desired performance into IA32_HWP_REQUEST,
/// preserving the Energy-Performance Preference (31:24), the activity
/// window (41:32) and the package-control bit (42) that firmware or a
/// previous request already established.
///
/// EPP is deliberately NOT a parameter. Setting min == max == desired
/// pins the operating point outright, which is the whole of what this
/// surface promises; an EPP hint is a separate policy knob that would
/// need its own justification (see Roadmap: EPP + idle governors).
constexpr u64 HwpRequestWithPerf(u64 current, u32 min_perf, u32 max_perf, u32 desired)
{
    constexpr u64 kPerfFieldsMask = 0x00FFFFFFULL; // bits 23:0
    u64 fields = static_cast<u64>(min_perf & 0xFFu);
    fields |= static_cast<u64>(max_perf & 0xFFu) << 8;
    fields |= static_cast<u64>(desired & 0xFFu) << 16;
    return (current & ~kPerfFieldsMask) | fields;
}

/// Read back the desired-performance field so a write can be VERIFIED
/// rather than assumed. Bits 23:16.
constexpr u32 HwpRequestDesired(u64 request)
{
    return static_cast<u32>((request >> 16) & 0xFFu);
}

// ---------------------------------------------------------------------
// AMD P-state selection — MSR_PSTATE_CTL (0xC0010062)
// ---------------------------------------------------------------------
//
// AMD does not take a ratio. It takes an INDEX into the platform's own
// pre-defined P-state table (MSR_PSTATE_DEF, decoded by ZenPstateMhz
// above), and each of those entries already couples a validated
// (CpuFid, CpuDfsId, CpuVid) triple. Selecting an index therefore
// never synthesises a voltage — the voltage that goes with the ratio
// is the one AMD's firmware programmed.
//
// Writing MSR_PSTATE_DEF itself WOULD mean choosing a CpuVid. That is
// the Plundervolt surface and is never done here; only PSTATE_CTL is
// written. Hence no helper composes a PStateDef value.

inline constexpr u32 kAmdPstateCtlIndexMask = 0x7u;

/// Extract the requested index from a PSTATE_CTL value, so a write can
/// be read back and verified against what was asked for.
constexpr u32 AmdPstateCtlIndex(u64 pstate_ctl)
{
    return static_cast<u32>(pstate_ctl & kAmdPstateCtlIndexMask);
}

} // namespace duetos::arch::cpu_sensor_math
