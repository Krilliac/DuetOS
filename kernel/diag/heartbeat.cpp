#include "diag/heartbeat.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "drivers/iommu/vtd.h"
#include "drivers/storage/ahci.h"
#include "drivers/storage/nvme.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "subsystems/translation/translate.h"
#include "fs/boot_slot.h"
#include "fs/installer.h"
#include "fs/ramfs.h"
#include "security/fault_domain.h"
#include "log/klog.h"
#include "core/panic.h"
#include "diag/fault_react.h"
#include "diag/fma/diagnose.h"
#include "diag/fma/ereport.h"
#include "diag/hung_task.h"
#include "diag/kstat.h"
#include "diag/runtime_checker.h"

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

// FAT32-backed persistence shim for the boot-slot state file. Called
// once per boot, right after MarkHealthyNow() flips us to healthy, so
// the next boot sees `last_healthy` + a refilled `tries_remaining`
// even after a clean shutdown. Routes through the shared
// `installer::PersistSlotState` bridge, which replaces the existing
// state file (the old local Fat32CreateAtPath writer failed whenever
// the file already existed — i.e. on every installed disk) and
// regenerates grub.cfg so `set default` follows the promotion.
// Failures are logged + swallowed: a freshly-formatted disk without
// an ESP shouldn't brick the heartbeat, and the next clean boot will
// re-attempt persistence.
bool PersistBootSlotState(const ::duetos::fs::boot_slot::State& st)
{
    const auto* vol = ::duetos::fs::installer::FindBootSlotVolume();
    if (vol == nullptr)
    {
        LogWithValue(LogLevel::Warn, "kheartbeat", "boot-slot persist: no FAT32 vol", 0);
        return false;
    }
    if (!::duetos::fs::installer::PersistSlotState(vol, st))
    {
        LogWithValue(LogLevel::Warn, "kheartbeat", "boot-slot persist: write failed", 1);
        return false;
    }
    LogWithString(LogLevel::Info, "kheartbeat", "boot-slot persisted", "path",
                  ::duetos::fs::boot_slot::kSlotStateFilePath);
    return true;
}

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

// ------- kstat readers for the heartbeat-observed counters. -------
//
// Each reader is a static function that pulls the live value from
// the existing source-of-truth accessor (`sched::SchedStatsRead`,
// `mm::KernelHeapStatsRead`, etc.). All accessors are documented as
// cheap snapshots — they're already called every heartbeat for the
// klog emissions below. The kstat registry exposes the same numbers
// to machine consumers (kshell, /proc/kstat, future FMA reader)
// without parsing the klog text stream.
//
// The klog emissions stay — kstat is a parallel structured surface,
// not a replacement. Human operators reading the serial log keep the
// one-line-per-counter view; tooling gets the typed value.

u64 ReadSchedContextSwitches(void*)
{
    return ::duetos::sched::SchedStatsRead().context_switches;
}
u64 ReadSchedTasksLive(void*)
{
    return ::duetos::sched::SchedStatsRead().tasks_live;
}
u64 ReadSchedTasksSleeping(void*)
{
    return ::duetos::sched::SchedStatsRead().tasks_sleeping;
}
u64 ReadSchedTasksBlocked(void*)
{
    return ::duetos::sched::SchedStatsRead().tasks_blocked;
}
u64 ReadSchedTasksCreated(void*)
{
    return ::duetos::sched::SchedStatsRead().tasks_created;
}
u64 ReadSchedTasksExited(void*)
{
    return ::duetos::sched::SchedStatsRead().tasks_exited;
}

u64 ReadHeapUsedBytes(void*)
{
    return ::duetos::mm::KernelHeapStatsRead().used_bytes;
}
u64 ReadHeapFreeBytes(void*)
{
    return ::duetos::mm::KernelHeapStatsRead().free_bytes;
}
u64 ReadHeapLargestFreeRun(void*)
{
    return ::duetos::mm::KernelHeapStatsRead().largest_free_run;
}
u64 ReadHeapAllocCount(void*)
{
    return ::duetos::mm::KernelHeapStatsRead().alloc_count;
}
u64 ReadHeapFreeCount(void*)
{
    return ::duetos::mm::KernelHeapStatsRead().free_count;
}

// KMalloc slab-route layer (<= 512 B allocations). Both gauges are a
// BREAKDOWN of heap_used_bytes — slabs are KMalloc-backed — so
// mm:heap_used_bytes keeps its meaning; these tell "live in routed
// objects" from "parked free in route caches" without parsing logs.
u64 ReadHeapRoutedLiveBytes(void*)
{
    return ::duetos::mm::KernelHeapStatsRead().routed_live_bytes;
}
u64 ReadHeapRoutedCachedBytes(void*)
{
    return ::duetos::mm::KernelHeapStatsRead().routed_cached_free_bytes;
}

u64 ReadFramesFree(void*)
{
    return ::duetos::mm::FreeFramesCount();
}

u64 ReadCpusOnline(void*)
{
    return ::duetos::arch::SmpCpusOnline();
}
u64 ReadCpuBusyPct(void*)
{
    const auto s = ::duetos::sched::SchedStatsRead();
    const u64 total = s.total_ticks;
    if (total == 0)
    {
        return 0;
    }
    return ((total - s.idle_ticks) * 100u) / total;
}

u64 ReadHealthIssuesTotal(void*)
{
    return ::duetos::core::RuntimeCheckerStatusRead().issues_found_total;
}

u64 ReadFmaSuspectCount(void*)
{
    return static_cast<u64>(::duetos::diag::fma::SuspectCount());
}

u64 ReadFmaEventsTotal(void*)
{
    return ::duetos::diag::fma::EreportStatsRead().events_total;
}

u64 ReadFmaEventsDropped(void*)
{
    return ::duetos::diag::fma::EreportStatsRead().events_dropped;
}

u64 ReadFmaDiagnosesTotal(void*)
{
    return ::duetos::diag::fma::EreportStatsRead().diagnoses_total;
}

// One-shot registration of every heartbeat-observed counter into
// the kstat registry. Called from the first heartbeat beat — the
// scheduler / heap / frame-allocator surfaces all exist by then
// (the heartbeat itself can't have started without them). Latched
// so subsequent beats skip the work; if a registration fails
// (`g_register_failures` ticks), we log it once and proceed — the
// kstat registry is best-effort, never gating.
void RegisterHeartbeatKstats()
{
    using K = ::duetos::diag::KstatKind;
    namespace D = ::duetos::diag;

    // Snapshot the failure baseline BEFORE our batch so we only
    // attribute new failures to our calls. The boot-time
    // `KstatSelfTest` deliberately exercises the dup-key reject,
    // leaving `register_failures = 1`; without the baseline a
    // clean run would emit a misleading WARN here.
    const u32 pre_failures = D::KstatRegistryStatsRead().register_failures;

    D::KstatRegister("sched", "context_switches", K::Counter, &ReadSchedContextSwitches, nullptr);
    D::KstatRegister("sched", "tasks_live", K::Gauge, &ReadSchedTasksLive, nullptr);
    D::KstatRegister("sched", "tasks_sleeping", K::Gauge, &ReadSchedTasksSleeping, nullptr);
    D::KstatRegister("sched", "tasks_blocked", K::Gauge, &ReadSchedTasksBlocked, nullptr);
    D::KstatRegister("sched", "tasks_created", K::Counter, &ReadSchedTasksCreated, nullptr);
    D::KstatRegister("sched", "tasks_exited", K::Counter, &ReadSchedTasksExited, nullptr);

    D::KstatRegister("mm", "heap_used_bytes", K::Gauge, &ReadHeapUsedBytes, nullptr);
    D::KstatRegister("mm", "heap_free_bytes", K::Gauge, &ReadHeapFreeBytes, nullptr);
    D::KstatRegister("mm", "heap_largest_free_run", K::Gauge, &ReadHeapLargestFreeRun, nullptr);
    D::KstatRegister("mm", "heap_alloc_count", K::Counter, &ReadHeapAllocCount, nullptr);
    D::KstatRegister("mm", "heap_free_count", K::Counter, &ReadHeapFreeCount, nullptr);
    D::KstatRegister("mm", "kmalloc_routed_live_bytes", K::Gauge, &ReadHeapRoutedLiveBytes, nullptr);
    D::KstatRegister("mm", "kmalloc_routed_cached_bytes", K::Gauge, &ReadHeapRoutedCachedBytes, nullptr);
    D::KstatRegister("mm", "frames_free", K::Gauge, &ReadFramesFree, nullptr);

    D::KstatRegister("cpu", "online", K::Gauge, &ReadCpusOnline, nullptr);
    D::KstatRegister("cpu", "busy_pct", K::Gauge, &ReadCpuBusyPct, nullptr);

    D::KstatRegister("health", "issues_total", K::Counter, &ReadHealthIssuesTotal, nullptr);

    // FMA: per-spec the "health:suspects" gauge is the live count of
    // diagnosis-engine suspects. Sibling counters expose ereport
    // throughput for tooling that wants to plot the engine's load.
    D::KstatRegister("health", "suspects", K::Gauge, &ReadFmaSuspectCount, nullptr);
    D::KstatRegister("fma", "events_total", K::Counter, &ReadFmaEventsTotal, nullptr);
    D::KstatRegister("fma", "events_dropped", K::Counter, &ReadFmaEventsDropped, nullptr);
    D::KstatRegister("fma", "diagnoses_total", K::Counter, &ReadFmaDiagnosesTotal, nullptr);

    const auto stats = D::KstatRegistryStatsRead();
    LogWithValue(LogLevel::Info, "kheartbeat", "kstat entries live", stats.entries_live);
    if (stats.register_failures > pre_failures)
    {
        // Strictly OUR failures — the self-test's intentional
        // dup-key reject is excluded by the pre-batch baseline.
        LogWithValue(LogLevel::Warn, "kheartbeat", "kstat register failures", stats.register_failures - pre_failures);
    }
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
    // A/B-slot watchdog: once we've made it past the FIRST heartbeat
    // delay, the boot path is provably reaching steady state. Mark
    // the current slot healthy so the next boot has a fresh
    // tries_remaining + last_healthy pin, and a botched kernel update
    // can't run away with the active flag. Idempotent: subsequent
    // beats are no-ops via the static guard.
    static constinit bool s_marked_healthy = false;
    // Register all heartbeat-observed counters into the kstat
    // registry on the very first beat. One-shot via a static guard;
    // subsequent beats just walk the registry via `/proc/kstat`.
    // Deferring to the first beat (rather than registering at boot
    // self-test time) keeps the kstat registry empty during the
    // self-test, so the test can assert exact entry counts.
    static constinit bool s_kstat_registered = false;
    for (;;)
    {
        sched::SchedSleepUntil(deadline);
        deadline += kHeartbeatTicks;
        if (!s_kstat_registered)
        {
            RegisterHeartbeatKstats();
            s_kstat_registered = true;
        }
        if (!s_marked_healthy)
        {
            const auto st = ::duetos::fs::boot_slot::MarkHealthyNow();
            LogWithString(LogLevel::Info, "kheartbeat", "boot-slot healthy", "active",
                          ::duetos::fs::boot_slot::Name(st.active));
            // Persist the post-MarkHealthy state to /boot/duetos-slot.cfg
            // so the next bootloader pass sees a refilled tries_remaining
            // and the up-to-date last_healthy. Without this, a clean
            // shutdown of an A/B-deployed kernel loses the healthy mark
            // and the next boot decrements tries_remaining as if the
            // previous attempt had failed.
            PersistBootSlotState(st);
            s_marked_healthy = true;
        }

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

        // Hung-task detector. Walks the all-tasks list looking
        // for tasks stuck in Blocked state for longer than the
        // 30 s threshold; complements the per-CPU soft-lockup
        // detector by catching the deadlock / lost-wakeup /
        // dropped-signal class. Cheap when nothing is hung — one
        // bounded list walk + zero allocations.
        ::duetos::diag::HungTaskTick();

        // Drain any deferred fault-react reports recorded from
        // the trap handler since the previous beat. Each pending
        // slot is dispatched through diag::FaultReactDispatch so
        // the per-domain policy + kernel-owned floor get a say
        // before the lossless restart bool fires. Must run BEFORE
        // FaultDomainTick so a `RestartDomain` reaction's
        // re-MarkRestart is picked up by the same beat.
        ::duetos::diag::FaultReactDrainPending();

        // Drain any fault-domain restart requests posted from the
        // trap handler since the previous beat. Cheap when no
        // flags are set — one linear scan over the bounded
        // registry.
        FaultDomainTick();
        LogWithValue(LogLevel::Info, "kheartbeat", "fault_domains_count", FaultDomainCount());

        // Poll the IOMMU for DMA faults a rogue/buggy device raised since
        // the last beat. Silent when clean; no-op when VT-d isn't enabled.
        // Bridges the gap until a fault MSI/IRQ handler lands.
        ::duetos::drivers::iommu::VtdFaultPoll();

        // Sweep the storage controllers for surprise-removal: a SATA
        // drive or NVMe controller unplugged while idle never raises an
        // I/O error (nothing is issuing commands), so without this poll
        // the kernel would keep believing a yanked-but-idle disk is
        // alive until the next read. Each call latches a vanished
        // device offline so subsequent I/O fails fast. Silent when
        // every device is healthy; no-op when none are present. Same
        // "poll from the heartbeat until a hot-unplug IRQ lands" pattern
        // as the VT-d fault poll above.
        ::duetos::drivers::storage::AhciHealthPoll();
        ::duetos::drivers::storage::NvmeHealthPoll();

        // FMA diagnosis pass. Runs AFTER FaultReactDrainPending +
        // FaultDomainTick so the engine sees the full picture of
        // this beat's events. v0: 3 rules (ECC / driver / kernel-
        // integrity correlation). Cheap when the ereport ring is
        // empty (one walk over 256 slots + filter); sub-ms even at
        // a full ring. The returned new-suspect count is logged
        // only when non-zero so a clean boot stays quiet.
        const u32 new_suspects = ::duetos::diag::fma::DiagnoseTick();
        if (new_suspects > 0)
        {
            LogWithValue(LogLevel::Warn, "kheartbeat", "fma_new_suspects", new_suspects);
        }

        // Refresh /proc/dumps with the current recent-dumps ring
        // so userland tools see the latest crash records without
        // a shell session. Cheap when the ring is empty (one
        // bounded scan + zero copy).
        ::duetos::fs::RamfsDumpsSnapshot();

        // Refresh /proc/fixjournal from the live fix-journal ring.
        // Same shape: bounded format, no allocations, refreshed on
        // every heartbeat so the ramfs view is at most one tick
        // stale. Reviewers (Claude or human) read this directly
        // without needing a shell prompt; the userland flusher
        // (slice 5) also pulls from here.
        ::duetos::fs::RamfsFixJournalSnapshot();

        // Refresh /proc/kstat from the live kstat registry. Same
        // bounded-format pattern: one walk over <=128 entries, each
        // entry's reader is documented as cheap, no allocations.
        // Userland tooling reads /proc/kstat for typed metrics in
        // parallel with the human-readable klog emissions below.
        ::duetos::fs::RamfsKstatSnapshot();

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
