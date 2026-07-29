#pragma once

#include "util/types.h"

/*
 * DuetOS — CPU frequency / P-state telemetry + control, v2.
 *
 * Reads the frequency-reporting MSRs and decodes them into MHz, and —
 * only when explicitly unlocked — selects a P-state.
 *
 * WHAT CHANGED IN v2 (2026-07-29). v1 was read-only and refused to
 * write IA32_PERF_CTL / HWP at all, per Hardware-Safety row 89. The
 * project owner has approved P-state SELECTION; that row is amended in
 * the same commit that added this. What stayed forbidden did not
 * loosen at all:
 *
 *   - NO VOLTAGE, EVER. Nothing here writes a Vcore / VID field, the
 *     OC mailbox (MSR 0x150), or MSR_PSTATE_DEF (whose CpuVid field
 *     couples a voltage to the ratio). The AMD path selects an INDEX
 *     into the platform's own pre-validated P-state table precisely so
 *     that no (ratio, voltage) pair is ever synthesised here.
 *   - NO POWER OR THERMAL LIMITS. RAPL PKG_POWER_LIMIT, PROCHOT
 *     disable and thermal-throttle defeat remain untouched.
 *   - NO GUEST REACH. No syscall exposes this. No Win32 or Linux thunk
 *     can reach it. A malicious PE/ELF therefore cannot drive the
 *     clock at all — which matters both thermally and because a
 *     workload that can modulate frequency has a cross-isolation
 *     signalling channel and a Hertzbleed-class amplifier.
 *
 * The three gates a write must pass, in order:
 *
 *   1. TUNE MODE. Off unless the operator booted with `cpufreq=tune`.
 *      A default boot cannot write a P-state MSR at all.
 *   2. CAPABILITY. The only caller is the kernel shell's `cpufreq`
 *      command, which takes kCapPowerTune through the ordinary
 *      RequireCap / broker path first.
 *   3. PLATFORM-ADVERTISED WINDOW. The request is admitted only if it
 *      falls inside a window this boot read out of the part's own
 *      registers (Intel: IA32_PLATFORM_INFO / MSR_TURBO_RATIO_LIMIT,
 *      or IA32_HWP_CAPABILITIES under HWP; AMD: the enabled entries of
 *      MSR_PSTATE_DEF). Out-of-window requests are REFUSED, not
 *      clamped — see cpu_sensor_math::RatioAdmit for why.
 *
 * Every write goes through `arch::WriteMsrSafe`, so a #GP on a part
 * that declines the MSR is a recovered fault and a WriteFailed status,
 * not a dead box. Every write is then read back and verified.
 *
 * Intel:
 *   MSR_PLATFORM_INFO  (0xCE)  — base ratio (bits 15:8), max-efficiency
 *                                (lowest) ratio (bits 47:40).
 *   IA32_PERF_STATUS   (0x198) — current operating ratio (bits 15:8).
 *   MSR_TURBO_RATIO_LIMIT (0x1AD) — 1-core turbo ceiling (bits 7:0).
 *   IA32_PERF_CTL      (0x199) — legacy P-state request (bits 15:8).
 *   IA32_PM_ENABLE     (0x770) — HWP enable (bit 0), write-once.
 *   IA32_HWP_CAPABILITIES (0x771) — highest / guaranteed / most-
 *                                efficient / lowest performance.
 *   IA32_HWP_REQUEST   (0x774) — min / max / desired performance.
 * AMD (family 17h+):
 *   MSR_PSTATE_DEF     (0xC0010064 + n) — per-P-state FID/DID. P0 is
 *                                the base frequency; the highest
 *                                enabled index is the minimum.
 *   MSR_PSTATE_STATUS  (0xC0010063) — index of the live P-state, which
 *                                is how `current_mhz` is obtained on
 *                                AMD (IA32_PERF_STATUS is Intel-only).
 *   MSR_PSTATE_CTL     (0xC0010062) — requested P-state INDEX (bits
 *                                2:0). The only register this file
 *                                writes on AMD.
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

// ---------------------------------------------------------------------
// P-state control  (implemented in cpufreq_ctl.cpp)
// ---------------------------------------------------------------------
//
// Everything below is the WRITE half. It lives in its own translation
// unit so that "which code can drive the hardware" is answerable by
// file name; `cpufreq.cpp` keeps only the read half and calls
// CpuFreqControlRead / CpuFreqMechanismName for its boot line.

/// Which register the control path would drive on this machine.
enum class CpuFreqMechanism : u8
{
    None = 0,  // nothing writable answered
    PerfCtl,   // Intel legacy IA32_PERF_CTL
    Hwp,       // Intel IA32_HWP_REQUEST (preferred where advertised)
    AmdPstate, // AMD MSR_PSTATE_CTL index select
};

/// The control window this part advertised, read from its own
/// registers this boot. `unit_is_ratio` says which direction the
/// numbers run:
///
///   true  (Intel) — HIGHER is faster. Under `PerfCtl` the value is a
///                   bus ratio, so `value * CpuFreqRead().bclk_mhz` is
///                   the frequency. Under `Hwp` it is an abstract
///                   PERFORMANCE unit; it is 1:1 with the bus ratio on
///                   every shipping part, but that is not architectural
///                   — do not present an HWP value as MHz. Comparing it
///                   against IA32_HWP_CAPABILITIES needs no conversion,
///                   which is why the admission path never does one.
///   false (AMD)   — a P-state INDEX, where a LOWER index is a HIGHER
///                   frequency. Decode the MHz through the P-state
///                   table, never by scaling the index.
///
/// Never fabricated — `valid == false` when the platform declined,
/// which is a different fact from a window of zero.
struct CpuFreqControlCaps
{
    bool valid;
    bool unit_is_ratio;         // true = Intel ratio, false = AMD index
    CpuFreqMechanism mechanism; //
    u32 lowest;                 // lowest-performance admissible value
    u32 highest;                // highest-performance admissible value
    u32 current;                // value in effect right now (0 = unknown)

    // Two REFERENCE POINTS inside the window, for an operator choosing
    // a value. Neither constrains admission — the window does — and
    // both are 0 where the mechanism does not report something the
    // window does not already say.
    //
    //   guaranteed     — the sustainable point the part guarantees
    //                    (HWP: IA32_HWP_CAPABILITIES guaranteed;
    //                    PerfCtl: the max non-turbo ratio, i.e. the
    //                    highest ratio held without turbo). Values
    //                    above it are turbo/opportunistic.
    //   most_efficient — the best perf-per-watt point (HWP only).
    //                    Distinct from `lowest`, which is the absolute
    //                    floor; on the legacy path the two coincide, so
    //                    it stays 0 there rather than repeating one.
    u32 guaranteed;
    u32 most_efficient;
};

/// Outcome of a P-state request. Every non-Ok value names the gate
/// that refused, because "it did not work" is useless to an operator
/// deciding whether to pass `cpufreq=tune` or to stop asking.
enum class CpuFreqSetStatus : u8
{
    Ok = 0,
    TuneModeOff, // operator did not boot with `cpufreq=tune`
    Unsupported, // no writable control interface on this part
    OutOfRange,  // outside the window the platform advertised
    WriteFailed, // the wrmsr faulted (#GP) and was recovered
    NotVerified, // write landed without faulting, read-back disagreed
};

/// Human-readable form of a status, for shell output and logs.
const char* CpuFreqSetStatusName(CpuFreqSetStatus status);

/// Short token for a mechanism ("hwp" / "perf_ctl" / "amd_pstate" /
/// "none"), used by the boot line and the transition log.
const char* CpuFreqMechanismName(CpuFreqMechanism mechanism);

/// Boot-time unlock. Called once from boot bringup when the cmdline
/// carries `cpufreq=tune`. Until then — and on any boot without the
/// token — `CpuFreqSetTarget` refuses with TuneModeOff and no P-state
/// MSR is ever written.
void CpuFreqTuneEnable();

/// True iff `cpufreq=tune` unlocked the control path this boot.
bool CpuFreqTuneEnabled();

/// Probe the writable control interface. Safe on any boot, tune mode
/// or not — it only reads, so an operator can see what WOULD be
/// available before deciding to unlock it.
CpuFreqControlCaps CpuFreqControlRead();

/// Request an operating point. `target` is a bus ratio on Intel and a
/// P-state index on AMD (see CpuFreqControlCaps::unit_is_ratio).
///
/// CALLER OBLIGATION: this function enforces tune mode, the platform
/// window and the safe-write path, but it does NOT check capabilities —
/// `arch` has no view of the process model. Every caller must take
/// kCapPowerTune first. Today the single caller is the kernel shell's
/// `cpufreq` command, which does exactly that via RequireCap. Do not
/// add a caller that skips it, and do not expose this through a
/// syscall: no guest binary may drive the clock.
///
/// Logs the transition (old value, new value, mechanism) on success at
/// WARN, because changing the hardware's operating point is something
/// a boot log should show without an operator having to raise the log
/// level to find it.
CpuFreqSetStatus CpuFreqSetTarget(u32 target);

/// Boot self-test of the control half: the refuse-don't-clamp admission
/// window, both MSR read-modify-write splices, the "unsupported caps
/// carry no window" invariant, and — the one that matters most — that
/// with tune mode off `CpuFreqSetTarget` refuses before touching
/// anything. Panics on mismatch (gates CI); emits one
/// "[cpufreq-ctl-selftest] PASS" line.
///
/// Runs before the cmdline is parsed, so the default-locked branch is
/// the one CI exercises and the self-test can never itself write a
/// P-state MSR.
void CpuFreqControlSelfTest();

} // namespace duetos::arch
