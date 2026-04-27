#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — clocksource abstraction, v0 (plan A2).
 *
 * WHAT
 *   A `Clocksource` is anything that can answer "monotonically
 *   non-decreasing nanoseconds since some boot-fixed origin".
 *   Multiple providers may register at boot (HPET, TSC, LAPIC,
 *   RTC); the timekeeper picks the one with the highest rating
 *   among those marked monotonic.
 *
 * WHY
 *   Today every consumer that needs a nanosecond timestamp goes
 *   straight to `arch::HpetReadCounter() * HpetPeriodFemtoseconds()
 *   / 1e6`. That's three layer-violations in one expression:
 *     - x86_64-specific (no ARM64 path).
 *     - HPET-specific (no fallback when the platform has no HPET).
 *     - inline (every caller re-implements the multiply/divide).
 *   The Clocksource interface gives one callable per platform, one
 *   callable per consumer, and one place to argue about resolution
 *   / cost / monotonicity.
 *
 * WHAT v0 IS NOT
 *   - It does NOT migrate the existing `DoNowNs` syscall handler
 *     or any other current call site to use this interface.
 *     Migration is tracked as a follow-up. The infra is purely
 *     additive — `time::MonotonicNs()` works (returns HPET-derived
 *     ns once HPET is registered), but existing inline reads stay
 *     where they are.
 *   - No TSC clocksource yet. Invariant-TSC detection + frequency
 *     calibration has its own cost and lands when there's a
 *     consumer that benefits from sub-HPET resolution.
 *   - No CLOCK_REALTIME / CLOCK_BOOTTIME yet — the timekeeper
 *     wraps just the monotonic side for v0. Wall-clock conversion
 *     stays in `time_syscall.cpp`.
 *
 * RATING
 *   Higher is better. Used by `ClocksourceSelectBest` to pick
 *   the best registered monotonic clocksource. Suggested values
 *   (loosely tracking Linux's `rating` convention):
 *     - 50  : RTC (1 s resolution; coarse).
 *     - 100 : LAPIC counter (per-CPU, may not be monotonic across
 *             CPUs — leave `monotonic = false` if that's the case).
 *     - 250 : HPET (~10 ns; chip-wide; always monotonic).
 *     - 300 : Invariant-TSC (sub-ns; cheapest to read).
 *   The numeric range matters less than the relative ordering.
 *
 * THREADING
 *   Registration is not thread-safe; runs once per provider
 *   during init phase. After SMP comes up the registry is
 *   read-only. `read_ns` callbacks must be safe to call from any
 *   CPU and any context (IRQ, task, NMI). HPET's MMIO read is.
 */

namespace duetos::time
{

/// Function-pointer "vtable" for a clocksource provider. No virtual,
/// no RTTI — kernel C++ convention.
using ClocksourceReadNs = u64 (*)();
using ClocksourceResolutionNs = u64 (*)();

struct Clocksource
{
    const char* name;                      ///< Stable string literal, used in logs and `inspect time`.
    ClocksourceReadNs read_ns;             ///< Required. Monotonic ns since boot-fixed origin.
    ClocksourceResolutionNs resolution_ns; ///< Approx resolution in ns (HPET ~10, TSC ~1).
    bool monotonic;                        ///< False excludes from `SelectBest` (still listed for diagnostics).
    u32 rating;                            ///< Higher = better; see header comment.
};

/// Registry capacity. Sized for the realistic provider count
/// (HPET, TSC, LAPIC, RTC, plus a future ARM64 generic-timer slot).
inline constexpr u32 kMaxClocksources = 8;

/// Register a provider. Returns Ok on success. Err{InvalidArgument}
/// for null pointer / null `name` / null `read_ns`. Err{OutOfMemory}
/// if the registry is full.
::duetos::core::Result<void> ClocksourceRegister(const Clocksource* cs);

/// Number of registered providers (diagnostics).
u32 ClocksourceCount();

/// Read-only accessor; nullptr if `index >= ClocksourceCount()`.
const Clocksource* ClocksourceGet(u32 index);

/// Look up by name. Linear scan; returns nullptr if not found.
const Clocksource* ClocksourceFind(const char* name);

/// Pick the highest-rated monotonic provider currently registered.
/// Returns nullptr if no monotonic provider has been registered.
/// Cheap (O(N) where N <= kMaxClocksources).
const Clocksource* ClocksourceSelectBest();

/// Currently-active clocksource — the result of the most recent
/// `ClocksourceSelectBest` call cached by the timekeeper. Returns
/// nullptr until `TimekeeperInit` has run.
const Clocksource* ClocksourceCurrent();

/// Cache the result of `SelectBest` so subsequent reads don't pay
/// the linear scan. Called by `TimekeeperInit`. Re-callable if a
/// later-registered provider should take over.
void ClocksourceRefreshCurrent();

/// Boot-time self-test. Registers two synthetic clocksources, one
/// monotonic with rating 100 and one non-monotonic with rating
/// 200, asserts SelectBest returns the monotonic one. Asserts
/// FindByName works, OutOfMemory is returned past capacity, null
/// arguments are rejected. Panics on mismatch.
void ClocksourceSelfTest();

} // namespace duetos::time
