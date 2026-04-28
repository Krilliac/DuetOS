#pragma once

#include "util/types.h"

/*
 * DuetOS — portable scheduler-tick API, v0 (plan A2-followup).
 *
 * WHAT
 *   A thin façade around `arch::TimerTicks` and the kernel's tick
 *   rate constant. Consumers that today read `arch::TimerTicks()`
 *   directly (sched, syscalls, watchdog, soft-lockup, etc.)
 *   eventually migrate to `time::TickCount()` so the arch
 *   backend can be swapped under them — first ARM64 generic
 *   timer, later TSC-deadline once that lands.
 *
 * WHY
 *   `arch::TimerTicks` is x86_64-specific (LAPIC + HPET wired
 *   together in `arch/x86_64/timer.cpp`). The kernel's notion of
 *   "scheduler tick" is portable: a free-running counter at a
 *   well-known frequency, monotonic, IRQ-context-safe. This
 *   header is the portable name; the platform name stays
 *   reachable for the rare caller that has to talk LAPIC.
 *
 * WHAT v0 IS NOT
 *   - It does NOT migrate any existing call sites — adding the
 *     wrapper is purely additive. Migration is tracked as a
 *     follow-up.
 *   - It does NOT yet own the periodic-timer programming
 *     (`TimerInit`, the LAPIC-divider math) — that stays in
 *     `arch/x86_64/timer.cpp` until ARM64's generic-timer port
 *     gives the second backend that justifies the abstraction.
 *
 * SCOPE
 *   Five accessors. All cheap: `TickCount` is one indirect call,
 *   the rest are constants or two-multiply integer math. Safe to
 *   call from any context (IRQ, task, NMI, before SMP comes up).
 */

namespace duetos::time
{

/// Current scheduler-tick count. Monotonic non-decreasing across
/// the lifetime of the kernel; resets only on full reboot. v0
/// is x86-LAPIC-backed via `arch::TimerTicks()`.
u64 TickCount();

/// Kernel scheduler tick frequency in Hz. v0 ships at 100 Hz —
/// matches `CmdSleep`'s assumption + the soft-lockup detector's
/// 100-tick threshold. A future debug preset may bump this for
/// finer profiling resolution; portable callers should NOT
/// hardcode the constant.
constexpr u64 kTickHz = 100;

/// Kernel scheduler tick frequency in Hz.
inline constexpr u64 TickHz()
{
    return kTickHz;
}

/// Duration of one scheduler tick in nanoseconds. v0: 10 ms.
inline constexpr u64 TickPeriodNs()
{
    return 1'000'000'000ULL / kTickHz;
}

/// Convert a tick count to nanoseconds. Cheap (single multiply).
inline constexpr u64 TicksToNs(u64 ticks)
{
    return ticks * TickPeriodNs();
}

/// Convert nanoseconds to a tick count, rounding DOWN. The
/// caller picks the rounding policy: `(ns + period - 1) / period`
/// for round-up, this for round-down. Cheap (one divide).
inline constexpr u64 NsToTicks(u64 ns)
{
    return ns / TickPeriodNs();
}

/// Boot-time self-test. Verifies the tick→ns→tick round-trip is
/// lossless across whole-tick boundaries, asserts a non-zero
/// `TickCount()` is observable after a busy-wait. Panics on
/// mismatch.
void TickSelfTest();

/// Portable scheduler-tick init wrapper (plan A2-followup).
/// Forwards to the arch backend's timer programming today
/// (`arch::TimerInit` on x86_64 — LAPIC-divider math + IRQ
/// routing). Lets `kernel_main` call `time::TimerInit()`
/// instead of the arch-specific entry point so an ARM64
/// generic-timer port can drop a second backend in cleanly
/// without changing the boot code that calls it.
void TimerInit();

} // namespace duetos::time
