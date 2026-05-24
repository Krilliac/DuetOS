#include "diag/selfthink.h"

#include "arch/x86_64/smp.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "debug/probes.h"
#include "diag/fix_journal.h"
#include "diag/introspect.h"
#include "diag/runtime_checker.h"
#include "diag/selfthink_baselines.h"
#include "env/autonomic.h"
#include "env/autonomic_feedback.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "security/fault_domain.h"
#include "time/tick.h"
#include "util/string.h"

namespace duetos::diag::selfthink
{

namespace
{

// kselfthink wake cadence — every kSelfthinkTicks scheduler ticks
// we refresh the latest portrait. 100 Hz * 1 s default. A future
// slice exposes this via env if a per-flavour cadence is wanted.
constexpr u64 kSelfthinkTicks = 100;

// Causal ring storage. Head is a single u64 we bump on every
// append; index by `head % kCausalRingCap`. Total fires is a
// monotonically-increasing counter independent of wrap so an
// operator can see how much got rolled off the end.
CausalEntry g_causal_ring[kCausalRingCap] = {};
u64 g_causal_head = 0;
u64 g_causal_total = 0;

// Latest portrait — refreshed by the kselfthink thread. Defaults
// to zeros until the first tick lands, so a shell query that
// races boot sees a zero portrait rather than a torn read.
SelfPortrait g_latest_portrait = {};

bool g_started = false;

// Copy at most `cap-1` chars of `src` into `dst` and NUL-terminate.
// Caller guarantees `cap >= 1`. Used for the CausalEntry tag, where
// we need a bounded copy that doesn't pull in <string.h>.
void CopyTag(char* dst, u64 cap, const char* src)
{
    if (src == nullptr || cap == 0)
    {
        if (cap > 0)
            dst[0] = '\0';
        return;
    }
    u64 i = 0;
    while (i + 1 < cap && src[i] != '\0')
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

} // namespace

void CausalRecord(CausalKind kind, u16 source_id, u64 value, u64 caller_rip, const char* tag)
{
    // Single-writer-per-CPU race is fine: the worst that happens
    // under SMP contention is two CPUs claim the same slot and
    // one overwrites the other. The total counter is the source
    // of truth for "how many events"; the ring is a best-effort
    // tail. Identical contract to the probe ring.
    const u64 idx = g_causal_head;
    ++g_causal_head;
    ++g_causal_total;

    CausalEntry& e = g_causal_ring[idx % kCausalRingCap];
    e.tick = ::duetos::time::TickCount();
    e.cpu_id = ::duetos::cpu::CurrentCpuIdOrBsp();
    e.kind = static_cast<u16>(kind);
    e.source_id = source_id;
    e.value = value;
    e.caller_rip = caller_rip;
    CopyTag(e.tag, sizeof(e.tag), tag);
}

u32 CausalRingWalk(bool (*cb)(const CausalEntry& e, void* ctx), void* ctx)
{
    if (cb == nullptr)
        return 0;

    const u64 head = g_causal_head;
    const u64 entries = (head < kCausalRingCap) ? head : kCausalRingCap;
    u32 visited = 0;

    for (u64 i = 0; i < entries; ++i)
    {
        // Walk newest → oldest. `head - 1 - i` is the latest slot
        // first, decrementing back through the ring.
        const u64 slot = (head - 1 - i) % kCausalRingCap;
        const CausalEntry& e = g_causal_ring[slot];
        ++visited;
        if (!cb(e, ctx))
            break;
    }
    return visited;
}

u64 CausalRingTotal()
{
    return g_causal_total;
}

const SelfPortrait& SelfthinkLatestPortrait()
{
    return g_latest_portrait;
}

SelfPortrait SelfPortraitSnapshot()
{
    SelfPortrait p = {};
    p.tick_taken = ::duetos::time::TickCount();

    // CPU + memory + box arithmetic via the canonical single-source-
    // of-truth resmon snapshot. Reused so derived percentages match
    // what `resmon`, `top`, and `free` print on the same boot.
    p.resmon = ResmonSample();

    // Scheduler — additional surface beyond what resmon copies.
    const auto sched_stats = ::duetos::sched::SchedStatsRead();
    p.sched_total_ticks = sched_stats.total_ticks;
    p.sched_idle_ticks = sched_stats.idle_ticks;
    p.sched_tasks_reaped = sched_stats.tasks_reaped;

    // Memory — frame allocator absolute counts + heap shape that
    // resmon doesn't carry (heap allocator counters, free chunks).
    p.mm_frames_total = ::duetos::mm::TotalFrames();
    p.mm_frames_free = ::duetos::mm::FreeFramesCount();
    p.mm_frames_peak_used = ::duetos::mm::PeakUsedFrames();
    const auto heap_stats = ::duetos::mm::KernelHeapStatsRead();
    p.mm_heap_alloc_count = heap_stats.alloc_count;
    p.mm_heap_free_count = heap_stats.free_count;
    p.mm_heap_free_chunks = heap_stats.free_chunk_count;

    // Health — runtime-checker scan totals.
    const auto& health = ::duetos::core::RuntimeCheckerStatusRead();
    p.health_scans_run = health.scans_run;
    p.health_issues_total = health.issues_found_total;
    p.health_last_scan_issues = health.last_scan_issues;
    p.health_last_issue = static_cast<u32>(health.last_issue);
    p.health_baseline_ok = static_cast<u32>(health.baseline_captured);

    // Fix-journal volume.
    const auto fix_stats = ::duetos::diag::FixJournalGetStats();
    p.fix_records_total = fix_stats.records_recorded;
    p.fix_records_unique = fix_stats.records_unique;
    p.fix_records_dropped = fix_stats.records_dropped;

    // Cross-boot introspect digest (the existing diag/introspect
    // module). Surfacing it here means an operator looking at the
    // SelfPortrait sees the prior-boot delta without a second
    // command — selfthink and introspect cooperate rather than
    // requiring two grep targets.
    const auto introspect_stats = ::duetos::diag::introspect::GetStats();
    p.introspect_new = introspect_stats.new_count;
    p.introspect_persistent = introspect_stats.persistent;
    p.introspect_resolved = introspect_stats.resolved;

    // Probe ring — armed-fire total.
    p.probe_total_fires = ::duetos::debug::ProbeRingTotalFires();

    // Autonomic engine report.
    const auto& auto_report = ::duetos::env::AutonomicStatus();
    p.auto_ticks = auto_report.ticks;
    p.auto_actions_fired = auto_report.actions_fired;
    p.auto_last_action = static_cast<u32>(auto_report.last);
    p.auto_last_rule = static_cast<u32>(auto_report.last_rule);

    // Fault domains — current registry population.
    p.fault_domains_count = ::duetos::core::FaultDomainCount();

    return p;
}

namespace
{

[[noreturn]] void SelfthinkMain(void* /*arg*/)
{
    // Drift-free cadence: increment the deadline each iteration so
    // the dump body's own latency doesn't push the period out.
    // Identical pattern to kheartbeat. SchedSleepUntil's wrap-safe
    // compare handles the "already past" case by yielding.
    u64 deadline = ::duetos::sched::SchedNowTicks() + kSelfthinkTicks;
    for (;;)
    {
        ::duetos::sched::SchedSleepUntil(deadline);
        deadline += kSelfthinkTicks;

        // Refresh the latest portrait so shell queries hit a
        // pre-built snapshot rather than reassembling on every
        // call. Cheap — every underlying reader is lock-free.
        g_latest_portrait = SelfPortraitSnapshot();

        // Drive the closed-loop autonomic-feedback evaluator:
        // any feedback entry whose deadline has passed gets
        // classified and recorded into the causal chain. Cheap
        // when the ring is empty (one bounded scan).
        ::duetos::env::feedback::Tick();

        // Feed the rolling baselines and surface anomalies.
        // Sample once per metric; check the new sample against
        // the prior history; if it deviates beyond the
        // configured k, append a CausalKind::Anomaly entry so
        // the chain dump shows the deviation alongside probe
        // fires + autonomic actions.
        using baselines::MetricId;
        const u64 free_frames = g_latest_portrait.mm_frames_free;
        const u64 heap_pct = g_latest_portrait.resmon.heap_used_pct;
        const u64 runnable = g_latest_portrait.resmon.tasks_live;

        const struct
        {
            MetricId id;
            u64 value;
        } samples[] = {
            {MetricId::FreeFrames, free_frames},
            {MetricId::HeapUsedPct, heap_pct},
            {MetricId::RunnableTasks, runnable},
        };
        for (const auto& s : samples)
        {
            // Check BEFORE Sample so the anomaly compares the
            // new reading against the PRIOR window (current
            // sample isn't included in its own baseline yet).
            if (baselines::IsAnomaly(s.id, s.value))
            {
                baselines::RecordAnomaly(s.id);
                CausalRecord(CausalKind::Anomaly, static_cast<u16>(s.id), s.value, 0, "baseline");
            }
            baselines::Sample(s.id, s.value);
        }
    }
}

} // namespace

void StartSelfthinkThread()
{
    KASSERT(!g_started, "diag/selfthink", "double StartSelfthinkThread");
    g_started = true;

    ::duetos::sched::SchedCreate(&SelfthinkMain, nullptr, "kselfthink");
}

void SelfthinkSelfTest()
{
    using duetos::core::Log;
    using duetos::core::LogLevel;
    using duetos::core::LogWithValue;

    // 1. Snapshot must complete without faulting and the
    // arithmetic must be coherent with itself.
    const SelfPortrait p = SelfPortraitSnapshot();

    if (p.tick_taken < p.resmon.uptime_ticks)
    {
        LogWithValue(LogLevel::Error, "diag/selfthink", "selftest: tick regression", p.tick_taken);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(&SelfthinkSelfTest), 1);
        return;
    }

    if (p.mm_frames_total > 0 && p.mm_frames_free > p.mm_frames_total)
    {
        LogWithValue(LogLevel::Error, "diag/selfthink", "selftest: frames_free > total", p.mm_frames_free);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(&SelfthinkSelfTest), 2);
        return;
    }

    // 2. Causal ring round-trip — append a sentinel, walk to find it.
    const u64 prev_total = CausalRingTotal();
    CausalRecord(CausalKind::Annotation, 0, 0xDEADBEEFu, 0, "selftest");
    if (CausalRingTotal() != prev_total + 1)
    {
        LogWithValue(LogLevel::Error, "diag/selfthink", "selftest: causal total stuck", CausalRingTotal());
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(&SelfthinkSelfTest), 3);
        return;
    }
    struct FindCtx
    {
        bool seen;
    } ctx{false};
    auto find_cb = +[](const CausalEntry& e, void* c) -> bool
    {
        auto* x = static_cast<FindCtx*>(c);
        if (e.kind == static_cast<u16>(CausalKind::Annotation) && e.value == 0xDEADBEEFu)
        {
            x->seen = true;
            return false;
        }
        return true;
    };
    CausalRingWalk(find_cb, &ctx);
    if (!ctx.seen)
    {
        Log(LogLevel::Error, "diag/selfthink", "selftest: causal sentinel missing");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(&SelfthinkSelfTest), 4);
        return;
    }

    // 3. CausalEntry tag must be NUL-terminated even with a
    // truncating input.
    char overflow[64] = {};
    for (u64 i = 0; i < sizeof(overflow) - 1; ++i)
        overflow[i] = 'A';
    overflow[sizeof(overflow) - 1] = '\0';
    CausalRecord(CausalKind::Annotation, 0, 0, 0, overflow);
    struct TagCtx
    {
        bool ok;
    } tag_ctx{false};
    auto tag_cb = +[](const CausalEntry& e, void* c) -> bool
    {
        auto* x = static_cast<TagCtx*>(c);
        if (e.kind == static_cast<u16>(CausalKind::Annotation) && e.value == 0)
        {
            // Last slot of tag must be the NUL terminator.
            x->ok = (e.tag[sizeof(e.tag) - 1] == '\0');
            return false;
        }
        return true;
    };
    CausalRingWalk(tag_cb, &tag_ctx);
    if (!tag_ctx.ok)
    {
        Log(LogLevel::Error, "diag/selfthink", "selftest: tag not NUL-terminated");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<u64>(&SelfthinkSelfTest), 5);
        return;
    }

    // All sub-checks passed. Emit a structured pass line so a CI
    // grep has something positive to match against without
    // promoting every PASS to KLOG_INFO at runtime.
    LogWithValue(LogLevel::Info, "diag/selfthink", "selftest pass causal_total", CausalRingTotal());
}

} // namespace duetos::diag::selfthink
