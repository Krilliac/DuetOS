#include "heartbeat.h"

#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smp.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../sched/sched.h"
#include "klog.h"
#include "panic.h"

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
    for (;;)
    {
        sched::SchedSleepTicks(kHeartbeatTicks);

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
