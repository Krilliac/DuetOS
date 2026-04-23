#include "heartbeat.h"

#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smp.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../sched/sched.h"
#include "../subsystems/translation/translate.h"
#include "klog.h"
#include "panic.h"
#include "runtime_checker.h"

namespace customos::core
{

namespace
{

// Heartbeat interval in timer ticks. 100 Hz * 5 s = 500 ticks. Long
// enough that boot noise doesn't overwhelm the first few heartbeats;
// short enough that a hang in (say) the reaper is obvious within a
// couple of beats.
constexpr u64 kHeartbeatTicks = 500;

[[noreturn]] void HeartbeatMain(void* /*arg*/)
{
    // Absolute-deadline cadence. Incrementing the deadline each
    // iteration eliminates drift from the dump body's own latency —
    // otherwise a heartbeat that takes 12 ms to serialize every 5 s
    // pushes the period out by 0.2% per beat. SchedSleepUntil's
    // wrap-safe compare handles the "already past" case by
    // yielding, so a long stall just compresses subsequent
    // heartbeats rather than breaking the loop.
    u64 deadline = sched::SchedNowTicks() + kHeartbeatTicks;
    for (;;)
    {
        sched::SchedSleepUntil(deadline);
        deadline += kHeartbeatTicks;

        const auto sched_stats = sched::SchedStatsRead();
        const auto heap_stats = mm::KernelHeapStatsRead();

        // One compound line per stat category. Keeping each line short
        // enough that grep extracts one field cleanly, and keeping the
        // category on the left so log reading is predictable.
        LogWithValue(LogLevel::Info, "kheartbeat", "cpus_online", arch::SmpCpusOnline());
        LogWithValue(LogLevel::Info, "kheartbeat", "ctx_switches", sched_stats.context_switches);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_live", sched_stats.tasks_live);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_sleeping", sched_stats.tasks_sleeping);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_blocked", sched_stats.tasks_blocked);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_reaped", sched_stats.tasks_reaped);
        LogWithValue(LogLevel::Info, "kheartbeat", "heap_used_bytes", heap_stats.used_bytes);
        LogWithValue(LogLevel::Info, "kheartbeat", "heap_free_bytes", heap_stats.free_bytes);
        LogWithValue(LogLevel::Info, "kheartbeat", "heap_free_chunks", heap_stats.free_chunk_count);
        LogWithValue(LogLevel::Info, "kheartbeat", "frames_free", mm::FreeFramesCount());
        // Translator overhead snapshot. Raw TSC counts — the reader
        // divides by host TSC Hz to get ns. See translate.h for
        // the rationale (no reliable TSC→ns calibration yet).
        ::customos::subsystems::translation::TranslatorOverheadDump();
        // System CPU-busy fraction, since boot. total_ticks is the
        // raw 100 Hz timer count; idle_ticks is the subset spent in
        // the idle task (priority == Idle). 100 - idle/total = busy%.
        // Guard against 0 ticks when the heartbeat beats before the
        // first real timer tick arrives.
        const u64 total = sched_stats.total_ticks;
        const u64 busy_pct = (total > 0) ? ((total - sched_stats.idle_ticks) * 100u / total) : 0;
        LogWithValue(LogLevel::Info, "kheartbeat", "cpu_busy_pct", busy_pct);

        // Runtime invariant scan. Each failing test emits its
        // own Warn-level klog line via `Report`; we also surface
        // the per-scan count + cumulative total here so the
        // heartbeat line is self-contained for machine parsing.
        RuntimeCheckerTick();
        const auto& h = RuntimeCheckerStatusRead();
        LogWithValue(LogLevel::Info, "kheartbeat", "health_last_scan_issues", h.last_scan_issues);
        LogWithValue(LogLevel::Info, "kheartbeat", "health_issues_total", h.issues_found_total);
    }
}

} // namespace

void StartHeartbeatThread()
{
    static constinit bool s_started = false;
    KASSERT(!s_started, "core/heartbeat", "double StartHeartbeatThread");
    s_started = true;

    sched::SchedCreate(&HeartbeatMain, nullptr, "kheartbeat");
}

} // namespace customos::core
