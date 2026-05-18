#pragma once

#include "util/types.h"

/*
 * DuetOS — resource monitor: one-call CPU / memory / box snapshot.
 *
 * The kernel already exposes the raw counters this rolls up —
 * `sched::SchedStatsRead`, `mm::TotalFrames` / `FreeFramesCount` /
 * `PeakUsedFrames`, `mm::KernelHeapStatsRead`, `sched::LoadavgSnapshot`,
 * `arch::SmpCpusOnline`, `time::TickCount`. The problem this solves is
 * that every consumer (the `top` / `free` / `stats` / `loadavg` shell
 * commands, the heartbeat, a future telemetry sink) re-derives the same
 * utilisation percentages from four subsystems, and they don't all agree
 * on the arithmetic. `ResmonSample` is the single source of truth: it
 * reads each counter once and computes the derived percentages in one
 * place, so a CPU-busy% printed by `resmon` matches the one a future
 * pressure-warn would gate on.
 *
 * `ResmonSample` is cheap and lock-free — every underlying read is a
 * plain counter snapshot. Safe from any context (IRQ, task, before SMP
 * is up: load averages then read as 0.0, online_cpus as 1).
 */

namespace duetos::diag
{

struct ResmonSnapshot
{
    // --- CPU / time ---
    u64 uptime_ticks;   // monotonic scheduler ticks since boot
    u64 uptime_seconds; // uptime_ticks / TickHz
    u64 total_ticks;    // scheduler-accounted ticks since boot
    u64 idle_ticks;     // ticks spent in the idle task
    u64 cpu_busy_pct;   // (total - idle) * 100 / total, since boot
    u32 online_cpus;    // BSP + APs that came online
    u32 load_1m_q11;    // 1-min load, Q11 fixed point (2048 == 1.00)
    u32 load_5m_q11;    // 5-min load, Q11 fixed point
    u32 load_15m_q11;   // 15-min load, Q11 fixed point

    // --- Memory ---
    u64 phys_total_kib;   // total physical RAM the frame allocator owns
    u64 phys_used_kib;    // (total - free) frames, in KiB
    u64 phys_free_kib;    // free frames, in KiB
    u64 phys_peak_kib;    // high-water used frames, in KiB
    u64 phys_used_pct;    // phys_used * 100 / phys_total
    u64 heap_pool_bytes;  // total kernel-heap pool size
    u64 heap_used_bytes;  // sum of live allocations (incl. headers)
    u64 heap_free_bytes;  // sum of free chunks
    u64 heap_used_pct;    // heap_used * 100 / heap_pool
    u64 heap_largest_run; // largest contiguous free chunk (fragmentation)

    // --- Box (system rollup) ---
    u64 tasks_live;       // runnable + running
    u64 tasks_sleeping;   // timed-sleep
    u64 tasks_blocked;    // on a wait queue
    u64 context_switches; // lifetime
    u64 tasks_created;    // lifetime
    u64 tasks_exited;     // lifetime
};

/// Sample every resource counter once and compute the derived
/// utilisation percentages. Lock-free, no allocation, any context.
ResmonSnapshot ResmonSample();

} // namespace duetos::diag
