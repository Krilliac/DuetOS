#include "heartbeat.h"

#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smp.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../sched/sched.h"
#include "../subsystems/translation/translate.h"
#include "fault_domain.h"
#include "klog.h"
#include "panic.h"
#include "runtime_checker.h"

namespace duetos::core
{

namespace
{

// Heartbeat interval in timer ticks. 100 Hz * 5 s = 500 ticks. Long
// enough that boot noise doesn't overwhelm the first few heartbeats;
// short enough that a hang in (say) the reaper is obvious within a
// couple of beats.
constexpr u64 kHeartbeatTicks = 500;
constexpr u64 kTimerHz = 100;

u64 DeltaClampMonotonic(const char* counter_name, u64 now, u64 prev)
{
    if (now >= prev)
        return now - prev;

    // Counter regression should never happen. Emit a structured
    // warning so post-mortem logs show which counter went bad and
    // by how much, then clamp to keep heartbeat math deterministic.
    LogWith2Values(LogLevel::Warn, "kheartbeat", "counter regressed", "now", now, "prev", prev);
    LogWithString(LogLevel::Warn, "kheartbeat", "counter regressed name", "counter", counter_name);
    return 0;
}

[[noreturn]] void HeartbeatMain(void* /*arg*/)
{
    // Previous-beat snapshots so we can emit deltas/rates in addition
    // to lifetime counters. This makes the heartbeat self-debuggable:
    // operators can spot "stuck" subsystems (no progress deltas) and
    // sudden spikes (e.g. scheduler churn) without doing manual
    // subtraction between two distant log lines.
    u64 prev_tick_sample = sched::SchedNowTicks();
    auto prev_sched_stats = sched::SchedStatsRead();
    auto prev_heap_stats = mm::KernelHeapStatsRead();

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
        const u64 beat_ticks = DeltaClampMonotonic("total_ticks", sched_stats.total_ticks, prev_tick_sample);
        const u64 ctx_switches_delta =
            DeltaClampMonotonic("context_switches", sched_stats.context_switches, prev_sched_stats.context_switches);
        const u64 tasks_created_delta =
            DeltaClampMonotonic("tasks_created", sched_stats.tasks_created, prev_sched_stats.tasks_created);
        const u64 tasks_exited_delta =
            DeltaClampMonotonic("tasks_exited", sched_stats.tasks_exited, prev_sched_stats.tasks_exited);
        const u64 heap_allocs_delta =
            DeltaClampMonotonic("heap_alloc_count", heap_stats.alloc_count, prev_heap_stats.alloc_count);
        const u64 heap_frees_delta =
            DeltaClampMonotonic("heap_free_count", heap_stats.free_count, prev_heap_stats.free_count);
        const u64 ctx_switches_per_sec = (beat_ticks > 0) ? (ctx_switches_delta * kTimerHz) / beat_ticks : 0;

        // One compound line per stat category. Keeping each line short
        // enough that grep extracts one field cleanly, and keeping the
        // category on the left so log reading is predictable.
        LogWithValue(LogLevel::Info, "kheartbeat", "cpus_online", arch::SmpCpusOnline());
        LogWithValue(LogLevel::Info, "kheartbeat", "ctx_switches", sched_stats.context_switches);
        LogWithValue(LogLevel::Info, "kheartbeat", "ctx_switches_delta", ctx_switches_delta);
        LogWithValue(LogLevel::Info, "kheartbeat", "ctx_switches_per_sec", ctx_switches_per_sec);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_live", sched_stats.tasks_live);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_sleeping", sched_stats.tasks_sleeping);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_blocked", sched_stats.tasks_blocked);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_reaped", sched_stats.tasks_reaped);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_created_delta", tasks_created_delta);
        LogWithValue(LogLevel::Info, "kheartbeat", "tasks_exited_delta", tasks_exited_delta);
        LogWithValue(LogLevel::Info, "kheartbeat", "heap_used_bytes", heap_stats.used_bytes);
        LogWithValue(LogLevel::Info, "kheartbeat", "heap_free_bytes", heap_stats.free_bytes);
        LogWithValue(LogLevel::Info, "kheartbeat", "heap_largest_free_run", heap_stats.largest_free_run);
        LogWithValue(LogLevel::Info, "kheartbeat", "heap_free_chunks", heap_stats.free_chunk_count);
        LogWithValue(LogLevel::Info, "kheartbeat", "heap_allocs_delta", heap_allocs_delta);
        LogWithValue(LogLevel::Info, "kheartbeat", "heap_frees_delta", heap_frees_delta);
        LogWithValue(LogLevel::Info, "kheartbeat", "frames_free", mm::FreeFramesCount());
        LogWithValue(LogLevel::Info, "kheartbeat", "heartbeat_beat_ticks", beat_ticks);
        // Translator overhead snapshot. Raw TSC counts — the reader
        // divides by host TSC Hz to get ns. See translate.h for
        // the rationale (no reliable TSC→ns calibration yet).
        ::duetos::subsystems::translation::TranslatorOverheadDump();
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

        // Drain any fault-domain restart requests posted from the
        // trap handler since the previous beat. Cheap when no
        // flags are set — one linear scan over the bounded
        // registry.
        FaultDomainTick();
        LogWithValue(LogLevel::Info, "kheartbeat", "fault_domains_count", FaultDomainCount());

        prev_tick_sample = sched_stats.total_ticks;
        prev_sched_stats = sched_stats;
        prev_heap_stats = heap_stats;
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

} // namespace duetos::core
