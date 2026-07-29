#pragma once

#include "util/types.h"

/*
 * DuetOS — CPU frequency MSR numbers and the CPUID helper, shared by
 * the two cpufreq translation units.
 *
 * PRIVATE to kernel/arch/x86_64. Included by `cpufreq.cpp` (telemetry
 * read) and `cpufreq_ctl.cpp` (P-state control). It exists so those two
 * TUs cannot drift apart on a register number — a control path that
 * writes 0x198 because it disagreed with the read path about which MSR
 * is IA32_PERF_CTL is precisely the failure this file removes.
 *
 * Constants only, plus one stateless CPUID wrapper. No globals, no
 * caches: each TU owns its own availability cache, because the two
 * halves probe different register sets and a shared cache would make
 * one half's probe results silently authoritative for the other.
 *
 * The public surface is `cpufreq.h`. Nothing outside those two TUs
 * should include this.
 */

namespace duetos::arch::cpufreq_msr
{

// --- Intel: read side ---
inline constexpr u32 kPlatformInfo = 0xCE;    // base + max-efficiency ratios
inline constexpr u32 kIa32PerfStatus = 0x198; // current operating ratio

// --- Intel: control side ---
inline constexpr u32 kIa32PerfCtl = 0x199;         // legacy P-state request
inline constexpr u32 kTurboRatioLimit = 0x1AD;     // 1-core turbo ceiling
inline constexpr u32 kIa32PmEnable = 0x770;        // bit 0 = HWP enabled
inline constexpr u32 kIa32HwpCapabilities = 0x771; // part's own HWP window
inline constexpr u32 kIa32HwpRequest = 0x774;      // min/max/desired perf

// --- Both vendors: rate counters ---
inline constexpr u32 kIa32Mperf = 0xE7;
inline constexpr u32 kIa32Aperf = 0xE8;

// --- AMD family 17h+ P-state interface ---
//
// Note what is absent: there is no constant for a WRITE to
// MSR_PSTATE_DEF. That register carries CpuVid, so composing a value
// for it means choosing a voltage. It is read (to decode the frequency
// of each enabled state) and never written; see the "NO VOLTAGE, EVER"
// paragraph in cpufreq.h.
inline constexpr u32 kAmdPstateCtl = 0xC0010062;    // requested index, bits 2:0
inline constexpr u32 kAmdPstateStatus = 0xC0010063; // live index, bits 2:0
inline constexpr u32 kAmdPstateDef0 = 0xC0010064;   // +n for P-state n
inline constexpr u32 kAmdPstateCount = 8;

// Reference clock. 100 MHz BCLK on every Nehalem-and-later Intel part.
// The AMD path decodes MHz directly out of the P-state FID/DID and
// never touches this.
inline constexpr u32 kBclkMhz = 100;

struct CpuidRegs
{
    u32 eax, ebx, ecx, edx;
};

inline CpuidRegs Cpuid(u32 leaf)
{
    CpuidRegs r;
    asm volatile("cpuid" : "=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx) : "a"(leaf), "c"(0));
    return r;
}

} // namespace duetos::arch::cpufreq_msr
