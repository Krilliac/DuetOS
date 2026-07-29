#pragma once

#include "util/types.h"

/*
 * DuetOS — telemetry percentage math.
 *
 * FREESTANDING on purpose: pure functions over counter deltas, no
 * kernel headers, no globals. `tests/host/test_telemetry_cpu.cpp`
 * exercises them directly; `kernel/diag/telemetry.cpp` is the kernel
 * caller.
 *
 * Why this is a separate header rather than inline arithmetic at each
 * call site: before it existed, the CPU-busy percentage was re-derived
 * in at least three places (diag/resmon.cpp, apps/sysmon.cpp and the
 * taskbar pill), each with slightly different clamping and
 * first-sample handling. Percentages that disagree between two panes
 * of the same UI are a bug report waiting to happen, so the arithmetic
 * gets ONE home and a test.
 *
 * Counter model: the scheduler keeps monotonically-increasing
 * `total_ticks` and `idle_ticks` per CPU (kernel/cpu/percpu.h). Busy
 * time is `total - idle`. A utilisation percentage is only meaningful
 * over an interval, so every function here works on the DELTA between
 * two snapshots — never on lifetime values, which would report an
 * average since boot and go stale-flat within minutes of uptime.
 */

namespace duetos::diag::telemetry_math
{

/// Busy percentage (0..100) from one CPU's tick deltas.
///
/// `total_delta == 0` means no timer tick landed on that CPU during the
/// window — the caller must treat the result as "no data", not as 0%
/// busy. An idle CPU still ticks, so a genuinely idle core reports
/// total_delta > 0 with idle_delta == total_delta; a total_delta of 0
/// only happens for a CPU that is offline, tickless, or sampled twice
/// inside one tick period.
///
/// Clamps rather than trusting the inputs: `idle_delta > total_delta`
/// is arithmetically impossible (idle is a subset of total) but can be
/// observed transiently on SMP, because the two counters are read
/// without a lock and a tick can land between the two loads. Clamping
/// keeps a torn read from producing a wild percentage.
inline u8 BusyPercent(u64 total_delta, u64 idle_delta)
{
    if (total_delta == 0)
        return 0;
    const u64 idle = (idle_delta > total_delta) ? total_delta : idle_delta;
    const u64 busy = total_delta - idle;
    const u64 pct = (busy * 100ULL) / total_delta;
    return static_cast<u8>(pct > 100 ? 100 : pct);
}

/// Monotonic delta between two counter samples.
///
/// Returns 0 when `now < prev`. That ordering is not supposed to
/// happen — these counters only increase — but it does occur in two
/// real situations: an unlocked cross-CPU read that tears, and a CPU
/// that came online between samples so its "previous" value was never
/// captured. Saturating at 0 turns both into "no data for this window"
/// instead of a ~2^64 delta that would render as 100% forever.
inline u64 CounterDelta(u64 now, u64 prev)
{
    return (now > prev) ? (now - prev) : 0;
}

/// Aggregate busy percentage across CPUs, from summed deltas.
///
/// This is deliberately the SUM of per-CPU deltas rather than the mean
/// of per-CPU percentages. The two differ whenever CPUs tick at
/// different rates — an AP that came online mid-window, or a CPU that
/// missed ticks under load — and the summed form is the correct one:
/// it weights each CPU by how much time it actually accounted for.
/// Averaging percentages would let a CPU with two ticks of history
/// swing the system-wide number as hard as one with a thousand.
///
/// Keeping the aggregate derived from the same per-CPU deltas the
/// per-core figures come from is what makes the two agree by
/// construction; there is no second, independently-maintained global
/// counter to drift out of sync.
inline u8 AggregateBusyPercent(u64 summed_total_delta, u64 summed_idle_delta)
{
    return BusyPercent(summed_total_delta, summed_idle_delta);
}

/// Percentage of `used` out of `total`, clamped to 0..100.
/// Returns 0 when `total == 0` (nothing measurable yet).
inline u8 UsedPercent(u64 used, u64 total)
{
    if (total == 0)
        return 0;
    const u64 u = (used > total) ? total : used;
    const u64 pct = (u * 100ULL) / total;
    return static_cast<u8>(pct > 100 ? 100 : pct);
}

} // namespace duetos::diag::telemetry_math
