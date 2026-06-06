#pragma once

#include "util/types.h"

/*
 * DuetOS — CPU frequency / P-state telemetry, v0.
 *
 * READ-ONLY. Reads the architectural frequency-reporting MSRs and
 * decodes them into MHz. It NEVER writes a P-state / voltage MSR
 * (IA32_PERF_CTL, the OC mailbox, HWP request) — driving frequency or
 * voltage from software is a physical-damage surface (see
 * wiki/security/Hardware-Safety.md), so frequency here is telemetry
 * only; any future P-state *control* must sit behind a kernel
 * capability + an explicit tune mode.
 *
 * Intel:
 *   MSR_PLATFORM_INFO  (0xCE)  — base ratio (bits 15:8), max-efficiency
 *                                (lowest) ratio (bits 47:40).
 *   IA32_PERF_STATUS   (0x198) — current operating ratio (bits 15:8).
 *   IA32_MPERF (0xE7) / IA32_APERF (0xE8) — fixed-rate / actual-rate
 *                                counters; their delta ratio × base
 *                                gives the effective frequency under load.
 * AMD (family 17h+):
 *   MPERF / APERF exist at the same MSR numbers, so the effective-
 *   frequency path works; the static base/min ratios live in different
 *   MSRs (P-state defs) and are reported as "unknown" in v0.
 *
 * The bus/reference clock is taken as 100 MHz (the BCLK on every
 * Nehalem-and-later Intel part and Zen AMD part). Pre-Nehalem FSB
 * parts are out of scope.
 *
 * Gating mirrors thermal.cpp / rapl.cpp exactly: reads issue only when
 * CpuHas(kCpuFeatMsr) AND the vendor is recognised AND we are not under
 * a hypervisor (IsEmulator()) — KVM/TCG do not reliably expose these
 * MSRs, and an unimplemented-MSR rdmsr would #GP. On those paths
 * CpuFreqRead() returns valid=false.
 *
 * Context: kernel. Non-privileged MSRs; rdmsr in ring 0 is fine.
 */

namespace duetos::arch
{

struct CpuFreqReading
{
    bool valid;        // a plausible reading was obtained
    bool is_intel;     // which vendor decode was used
    u32 bclk_mhz;      // reference clock (100)
    u32 current_mhz;   // current operating point (IA32_PERF_STATUS)
    bool ratios_valid; // static base/min ratios present (Intel)
    u32 base_mhz;      // base (guaranteed) frequency
    u32 min_mhz;       // max-efficiency (lowest) frequency
};

/// Sample the frequency MSRs once. Returns a zeroed record
/// (valid=false) when the CPU lacks MSRs, the vendor is unrecognised,
/// or we are under a hypervisor.
CpuFreqReading CpuFreqRead();

/// Effective frequency over `window_ms`: reads MPERF/APERF, busy-waits
/// the window on the monotonic clock, reads again, and returns
/// base_mhz * dAPERF / dMPERF in MHz. Returns 0 when unavailable, the
/// window is 0, or the counters did not advance. Spins for the whole
/// window — keep `window_ms` small (≈200 ms), interactive use only.
u32 CpuFreqSampleEffectiveMhz(u32 window_ms);

/// Sample once + log a one-line summary at boot. No-ops (logs a Debug
/// line) when frequency MSRs are unavailable.
void CpuFreqProbe();

/// Pure-math boot self-test of the ratio→MHz + effective-frequency
/// arithmetic. Panics on mismatch (gates CI); emits one
/// "[cpufreq-selftest] PASS" line. Touches no hardware, so it runs
/// identically on QEMU and bare metal.
void CpuFreqSelfTest();

} // namespace duetos::arch
