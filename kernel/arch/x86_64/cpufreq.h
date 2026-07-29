#pragma once

#include "util/types.h"

/*
 * DuetOS — CPU frequency / P-state telemetry, v1.
 *
 * READ-ONLY. Reads the frequency-reporting MSRs and decodes them into
 * MHz. It NEVER writes a P-state / voltage MSR (IA32_PERF_CTL, the OC
 * mailbox, HWP request) — driving frequency or voltage from software is
 * a physical-damage surface (see wiki/security/Hardware-Safety.md), so
 * frequency here is telemetry only; any future P-state *control* must
 * sit behind a kernel capability + an explicit tune mode.
 *
 * Intel:
 *   MSR_PLATFORM_INFO  (0xCE)  — base ratio (bits 15:8), max-efficiency
 *                                (lowest) ratio (bits 47:40).
 *   IA32_PERF_STATUS   (0x198) — current operating ratio (bits 15:8).
 * AMD (family 17h+):
 *   MSR_PSTATE_DEF     (0xC0010064 + n) — per-P-state FID/DID. P0 is
 *                                the base frequency; the highest
 *                                enabled index is the minimum.
 *   MSR_PSTATE_STATUS  (0xC0010063) — index of the live P-state, which
 *                                is how `current_mhz` is obtained on
 *                                AMD (IA32_PERF_STATUS is Intel-only).
 * Both:
 *   IA32_MPERF (0xE7) / IA32_APERF (0xE8) — fixed-rate / actual-rate
 *                                counters; their delta ratio x base
 *                                gives the effective frequency under
 *                                load. AMD advertises them through
 *                                CPUID 0x80000007 EDX bit 10
 *                                (EffFreqRO); Intel through leaf 6
 *                                ECX bit 0 (`hardware coordination
 *                                feedback`).
 *
 * The bus/reference clock is taken as 100 MHz (the BCLK on every
 * Nehalem-and-later Intel part). Pre-Nehalem FSB parts are out of
 * scope. The AMD path does not use BCLK at all — the P-state encoding
 * already yields MHz.
 *
 * GATING CHANGED IN v1. Every read now goes through
 * `arch::ReadMsrSafe`, so an MSR the part does not implement is a
 * recovered #GP rather than a wedged boot. That retires the blanket
 * "bail under any hypervisor" gate the previous version needed: we
 * ASK for each MSR and report exactly what came back. A hypervisor
 * that exposes the counters now yields real numbers; one that does not
 * yields `valid == false`, which is the honest answer rather than a
 * predicted one.
 *
 * Context: kernel. rdmsr in ring 0 is fine; safe from any context.
 */

namespace duetos::arch
{

struct CpuFreqReading
{
    bool valid;          // at least one real figure was obtained
    bool is_intel;       // which vendor decode was used
    u32 bclk_mhz;        // reference clock (100; 0 on the AMD path)
    bool current_valid;  // `current_mhz` carries a live operating point
    u32 current_mhz;     // current operating point
    bool ratios_valid;   // static base/min figures present
    u32 base_mhz;        // base (guaranteed) frequency
    u32 min_mhz;         // max-efficiency (lowest) frequency
    bool counters_valid; // APERF/MPERF are readable on this machine
};

/// Sample the frequency MSRs once. Returns a zeroed record
/// (valid=false) when nothing on this machine answers — which is a
/// different fact from 0 MHz and must be rendered as such.
CpuFreqReading CpuFreqRead();

/// Effective frequency over `window_ms`: reads MPERF/APERF, busy-waits
/// the window on the monotonic clock, reads again, and returns
/// base_mhz * dAPERF / dMPERF in MHz. Returns 0 when unavailable, the
/// window is 0, or the counters did not advance. Spins for the whole
/// window — keep `window_ms` small (~200 ms), interactive use only.
u32 CpuFreqSampleEffectiveMhz(u32 window_ms);

/// Sample once + log a one-line summary at boot. Logs an explicit
/// "unsupported" line rather than zeros when nothing answers.
void CpuFreqProbe();

/// Pure-math boot self-test of the ratio->MHz, AMD P-state and
/// effective-frequency arithmetic, plus the unsupported-vs-zero
/// invariant on the live reading. Panics on mismatch (gates CI);
/// emits one "[cpufreq-selftest] PASS" line.
void CpuFreqSelfTest();

} // namespace duetos::arch
