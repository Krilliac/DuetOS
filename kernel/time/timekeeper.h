#pragma once

#include "util/types.h"

/*
 * DuetOS — high-level time API, v0 (plan A2).
 *
 * Wraps the currently-selected `Clocksource` so consumers get a
 * one-line monotonic read instead of repeating the
 * `arch::HpetReadCounter() * HpetPeriodFemtoseconds() / 1e6`
 * incantation inline.
 *
 * v0 surface:
 *
 *   `time::TimekeeperInit()`
 *       Registers HPET as a clocksource (rating 250, monotonic).
 *       Calls `ClocksourceRefreshCurrent`. Must be called after
 *       `arch::HpetInit`.
 *
 *   `time::MonotonicNs()`
 *       Nanoseconds since boot from the active clocksource.
 *       Returns 0 if no monotonic clocksource is registered (the
 *       caller should treat this as "time is not yet available").
 *
 * Out of scope for v0:
 *   - CLOCK_REALTIME / CLOCK_BOOTTIME (wall-clock conversion stays
 *     in time_syscall.cpp until a follow-up migrates it).
 *   - Hot-swap from one clocksource to another at runtime
 *     (`RefreshCurrent` is callable but the typical use is
 *     "register all providers at boot, pick once").
 *   - Per-CPU time-stamp counters (TSC) — calibration story is
 *     its own slice.
 */

namespace duetos::time
{

/// Register HPET as a clocksource provider and select the best
/// available source. Safe to call before HPET is up — it logs a
/// warning and returns; a later call after HPET init can succeed.
void TimekeeperInit();

/// Nanoseconds since boot from the currently-active monotonic
/// clocksource. Returns 0 if `TimekeeperInit` has not yet
/// successfully selected a source. Cheap (one indirect call to
/// the source's `read_ns`).
u64 MonotonicNs();

/// Resolution (in ns) of the currently-active clocksource, for
/// callers that want to gauge cost of a delay loop. Returns 0 if
/// no source is active.
u64 ResolutionNs();

/// Boot-time elapsed in nanoseconds. v0: alias for `MonotonicNs`
/// (CLOCK_BOOTTIME == CLOCK_MONOTONIC in our model — there's no
/// suspend/resume yet, so the two diverge only when there's a
/// "kernel was suspended" gap to skip over). Kept as a separate
/// accessor so callers that mean "boot time" don't have to be
/// rewritten when a real CLOCK_BOOTTIME lands.
u64 BoottimeNs();

/// Wall-clock time in Windows FILETIME units — 100-nanosecond
/// ticks since 1601-01-01 00:00:00 UTC. Samples the CMOS RTC and
/// performs the Gregorian-day arithmetic; no clocksource needed
/// (the RTC is its own time source independent of HPET/TSC).
/// Cheap (~hundreds of cycles for the CMOS reads + the arithmetic).
/// Returns 0 only on impossible RTC values; in practice always
/// returns a usable value.
u64 RealtimeFiletime();

/// Boot-time self-test. Verifies that after `TimekeeperInit`:
///   - `MonotonicNs()` returns a non-zero, strictly-increasing
///     value across two reads (with a tiny busy-wait in between).
///   - `ResolutionNs()` returns the source's reported resolution.
/// Panics on mismatch. No-op if `TimekeeperInit` could not pick
/// a clocksource (e.g. no HPET on the platform).
void TimekeeperSelfTest();

} // namespace duetos::time
