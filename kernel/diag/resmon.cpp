/*
 * DuetOS — resource monitor implementation.
 *
 * See resmon.h for the rationale. This TU only reads existing
 * snapshot APIs and does integer roll-up arithmetic; it owns no
 * state and takes no locks.
 */

#include "diag/resmon.h"

#include "arch/x86_64/smp.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "sched/loadavg.h"
#include "sched/sched.h"
#include "time/tick.h"

namespace duetos::diag
{

namespace
{

// Page size is 4 KiB; one frame == 4 KiB. Keep this local so the
// roll-up doesn't pull a paging header into a pure-counter TU.
constexpr u64 kFrameKiB = 4;

} // namespace

ResmonSnapshot ResmonSample()
{
    ResmonSnapshot s{};

    // --- CPU / time ---
    s.uptime_ticks = duetos::time::TickCount();
    s.uptime_seconds = s.uptime_ticks / duetos::time::TickHz();
    s.online_cpus = static_cast<u32>(duetos::arch::SmpCpusOnline());

    const auto sched = duetos::sched::SchedStatsRead();
    s.total_ticks = sched.total_ticks;
    s.idle_ticks = sched.idle_ticks;
    s.cpu_busy_pct = (sched.total_ticks > 0) ? ((sched.total_ticks - sched.idle_ticks) * 100u / sched.total_ticks) : 0;

    duetos::sched::LoadavgSnapshot(&s.load_1m_q11, &s.load_5m_q11, &s.load_15m_q11);

    // --- Memory: physical frames ---
    const u64 total_frames = duetos::mm::TotalFrames();
    const u64 free_frames = duetos::mm::FreeFramesCount();
    const u64 used_frames = (total_frames >= free_frames) ? (total_frames - free_frames) : 0;
    s.phys_total_kib = total_frames * kFrameKiB;
    s.phys_used_kib = used_frames * kFrameKiB;
    s.phys_free_kib = free_frames * kFrameKiB;
    s.phys_peak_kib = duetos::mm::PeakUsedFrames() * kFrameKiB;
    s.phys_used_pct = (total_frames > 0) ? (used_frames * 100u / total_frames) : 0;

    // --- Memory: kernel heap ---
    const auto heap = duetos::mm::KernelHeapStatsRead();
    s.heap_pool_bytes = heap.pool_bytes;
    s.heap_used_bytes = heap.used_bytes;
    s.heap_free_bytes = heap.free_bytes;
    s.heap_largest_run = heap.largest_free_run;
    s.heap_used_pct = (heap.pool_bytes > 0) ? (heap.used_bytes * 100u / heap.pool_bytes) : 0;

    // --- Box rollup ---
    s.tasks_live = sched.tasks_live;
    s.tasks_sleeping = sched.tasks_sleeping;
    s.tasks_blocked = sched.tasks_blocked;
    s.context_switches = sched.context_switches;
    s.tasks_created = sched.tasks_created;
    s.tasks_exited = sched.tasks_exited;

    return s;
}

} // namespace duetos::diag
