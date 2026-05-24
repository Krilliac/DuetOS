/*
 * DuetOS — kernel shell: selfthink command.
 *
 * Live-query surface for the cross-subsystem `SelfPortrait` and
 * causal-chain ring built by `kernel/diag/selfthink.{h,cpp}`. The
 * verb name preserves the user's phrasing ("OS self thinking and
 * introspection"); the verb `introspect` is already taken by the
 * cross-boot fix-journal diff in `kernel/diag/introspect.{h,cpp}`.
 *
 *   selfthink            — current cross-subsystem self-portrait
 *   selfthink causality [N]
 *                        — last N causal entries (default 32),
 *                          newest first
 *
 * Future slices add `selfthink baselines`, `selfthink feedback`,
 * `selfthink why`, and `selfthink prev`.
 */

#include "shell/shell.h"

#include "diag/selfthink.h"
#include "diag/selfthink_baselines.h"
#include "drivers/video/console.h"
#include "env/autonomic.h"
#include "env/autonomic_feedback.h"
#include "shell/shell_internal.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::diag::selfthink::CausalEntry;
using duetos::diag::selfthink::CausalKind;
using duetos::diag::selfthink::SelfPortrait;
using duetos::drivers::video::ConsoleWrite;

constexpr u32 kDefaultCausalLimit = 32;

const char* CausalKindName(u16 kind)
{
    switch (static_cast<CausalKind>(kind))
    {
    case CausalKind::ProbeFire:
        return "probe";
    case CausalKind::AutoAction:
        return "autoact";
    case CausalKind::Anomaly:
        return "anomaly";
    case CausalKind::FaultReact:
        return "fault";
    case CausalKind::Heal:
        return "heal";
    case CausalKind::Annotation:
        return "annot";
    default:
        return "?";
    }
}

void SelfthinkUsage()
{
    ConsoleWrite("usage:\n");
    ConsoleWrite("  selfthink                       — current SelfPortrait\n");
    ConsoleWrite("  selfthink causality [N]         — last N causal entries (default 32)\n");
    ConsoleWrite("  selfthink baselines             — per-metric rolling mean/stddev/anomalies\n");
    ConsoleWrite("  selfthink feedback              — autonomic action outcomes\n");
}

void PrintPortrait()
{
    // Snapshot live rather than reading the kthread's cached
    // copy so the operator sees current values even when the
    // shell command runs between kselfthink ticks.
    const SelfPortrait p = duetos::diag::selfthink::SelfPortraitSnapshot();

    ConsoleWrite("selfthink portrait @ tick ");
    WriteU64Dec(p.tick_taken);
    ConsoleWrite("\n");

    ConsoleWrite("  cpu  uptime_s=");
    WriteU64Dec(p.resmon.uptime_seconds);
    ConsoleWrite("  online_cpus=");
    WriteU64Dec(p.resmon.online_cpus);
    ConsoleWrite("  busy_pct=");
    WriteU64Dec(p.resmon.cpu_busy_pct);
    ConsoleWrite("  load1m_q11=");
    WriteU64Dec(p.resmon.load_1m_q11);
    ConsoleWrite("\n");

    ConsoleWrite("  sched  live=");
    WriteU64Dec(p.resmon.tasks_live);
    ConsoleWrite("  sleeping=");
    WriteU64Dec(p.resmon.tasks_sleeping);
    ConsoleWrite("  blocked=");
    WriteU64Dec(p.resmon.tasks_blocked);
    ConsoleWrite("  ctx_switches=");
    WriteU64Dec(p.resmon.context_switches);
    ConsoleWrite("  reaped=");
    WriteU64Dec(p.sched_tasks_reaped);
    ConsoleWrite("\n");

    ConsoleWrite("  mem  frames_total=");
    WriteU64Dec(p.mm_frames_total);
    ConsoleWrite("  free=");
    WriteU64Dec(p.mm_frames_free);
    ConsoleWrite("  peak_used=");
    WriteU64Dec(p.mm_frames_peak_used);
    ConsoleWrite("  used_pct=");
    WriteU64Dec(p.resmon.phys_used_pct);
    ConsoleWrite("\n");

    ConsoleWrite("  heap  used_bytes=");
    WriteU64Dec(p.resmon.heap_used_bytes);
    ConsoleWrite("  free_bytes=");
    WriteU64Dec(p.resmon.heap_free_bytes);
    ConsoleWrite("  used_pct=");
    WriteU64Dec(p.resmon.heap_used_pct);
    ConsoleWrite("  largest_run=");
    WriteU64Dec(p.resmon.heap_largest_run);
    ConsoleWrite("  free_chunks=");
    WriteU64Dec(p.mm_heap_free_chunks);
    ConsoleWrite("\n");

    ConsoleWrite("  health  scans=");
    WriteU64Dec(p.health_scans_run);
    ConsoleWrite("  issues_total=");
    WriteU64Dec(p.health_issues_total);
    ConsoleWrite("  last_scan_issues=");
    WriteU64Dec(p.health_last_scan_issues);
    ConsoleWrite("  baseline_ok=");
    WriteU64Dec(p.health_baseline_ok);
    ConsoleWrite("\n");

    ConsoleWrite("  fix  total=");
    WriteU64Dec(p.fix_records_total);
    ConsoleWrite("  unique=");
    WriteU64Dec(p.fix_records_unique);
    ConsoleWrite("  dropped=");
    WriteU64Dec(p.fix_records_dropped);
    ConsoleWrite("\n");

    ConsoleWrite("  introspect  new=");
    WriteU64Dec(p.introspect_new);
    ConsoleWrite("  persistent=");
    WriteU64Dec(p.introspect_persistent);
    ConsoleWrite("  resolved=");
    WriteU64Dec(p.introspect_resolved);
    ConsoleWrite("\n");

    ConsoleWrite("  probes  total_fires=");
    WriteU64Dec(p.probe_total_fires);
    ConsoleWrite("\n");

    ConsoleWrite("  autonomic  ticks=");
    WriteU64Dec(p.auto_ticks);
    ConsoleWrite("  actions_fired=");
    WriteU64Dec(p.auto_actions_fired);
    ConsoleWrite("  last_rule=");
    WriteU64Dec(p.auto_last_rule);
    ConsoleWrite("  last_action=");
    WriteU64Dec(p.auto_last_action);
    ConsoleWrite("\n");

    ConsoleWrite("  fault_domains  count=");
    WriteU64Dec(p.fault_domains_count);
    ConsoleWrite("\n");

    ConsoleWrite("  causal_total=");
    WriteU64Dec(duetos::diag::selfthink::CausalRingTotal());
    ConsoleWrite("\n");
}

struct CausalCtx
{
    u32 remaining;
    u32 printed;
};

bool CausalRowCb(const CausalEntry& e, void* ctx)
{
    auto* x = static_cast<CausalCtx*>(ctx);
    if (x->remaining == 0)
        return false;

    ConsoleWrite("  tick=");
    WriteU64Dec(e.tick);
    ConsoleWrite("  cpu=");
    WriteU64Dec(e.cpu_id);
    ConsoleWrite("  ");
    ConsoleWrite(CausalKindName(e.kind));
    ConsoleWrite("  src=");
    WriteU64Dec(e.source_id);
    ConsoleWrite("  val=");
    WriteU64Dec(e.value);
    if (e.caller_rip != 0)
    {
        ConsoleWrite("  rip=0x");
        WriteU64Hex(e.caller_rip);
    }
    if (e.tag[0] != '\0')
    {
        ConsoleWrite("  tag=");
        ConsoleWrite(e.tag);
    }
    ConsoleWrite("\n");

    --x->remaining;
    ++x->printed;
    return true;
}

u32 ParseLimit(u32 argc, char** argv)
{
    if (argc < 3)
        return kDefaultCausalLimit;

    // Tiny ASCII u32 parser — accepts decimal digits only,
    // saturates at the ring capacity. No allocation, no
    // heap, no stdlib.
    u32 v = 0;
    for (const char* p = argv[2]; *p != '\0'; ++p)
    {
        if (*p < '0' || *p > '9')
            return kDefaultCausalLimit;
        v = v * 10 + static_cast<u32>(*p - '0');
        if (v > duetos::diag::selfthink::kCausalRingCap)
            return static_cast<u32>(duetos::diag::selfthink::kCausalRingCap);
    }
    return (v == 0) ? kDefaultCausalLimit : v;
}

void PrintBaselines()
{
    using duetos::diag::selfthink::baselines::MetricId;
    using duetos::diag::selfthink::baselines::MetricName;
    using duetos::diag::selfthink::baselines::Read;

    ConsoleWrite("selfthink baselines (rolling 256-sample window)\n");
    ConsoleWrite("  metric              count   last        mean        stddev    anomalies\n");
    for (u32 i = 0; i < static_cast<u32>(MetricId::Count); ++i)
    {
        const MetricId id = static_cast<MetricId>(i);
        const auto s = Read(id);
        ConsoleWrite("  ");
        WritePadLeft(MetricName(id), 18);
        ConsoleWrite("  ");
        WriteU64Dec(s.count);
        ConsoleWrite("\t");
        WriteU64Dec(s.last);
        ConsoleWrite("\t");
        WriteU64Dec(s.mean);
        ConsoleWrite("\t");
        WriteU64Dec(s.stddev);
        ConsoleWrite("\t");
        WriteU64Dec(s.anomalies_observed);
        ConsoleWrite("\n");
    }
}

void PrintFeedback()
{
    using duetos::env::AutoAction;
    using duetos::env::AutoActionName;
    using duetos::env::AutoRule;
    using duetos::env::AutoRuleName;
    using duetos::env::feedback::FeedbackEntry;
    using duetos::env::feedback::Outcome;
    using duetos::env::feedback::OutcomeName;

    const auto stats = duetos::env::feedback::StatsRead();
    ConsoleWrite("autonomic feedback stats: enqueued=");
    WriteU64Dec(stats.enqueued_total);
    ConsoleWrite(" evaluated=");
    WriteU64Dec(stats.evaluated_total);
    ConsoleWrite(" overflows=");
    WriteU64Dec(stats.ring_overflows);
    ConsoleWrite("\n  outcomes  improved=");
    WriteU64Dec(stats.per_outcome[static_cast<u32>(Outcome::Improved)]);
    ConsoleWrite(" nochange=");
    WriteU64Dec(stats.per_outcome[static_cast<u32>(Outcome::NoChange)]);
    ConsoleWrite(" worsened=");
    WriteU64Dec(stats.per_outcome[static_cast<u32>(Outcome::Worsened)]);
    ConsoleWrite(" diagnostic=");
    WriteU64Dec(stats.per_outcome[static_cast<u32>(Outcome::Diagnostic)]);
    ConsoleWrite("\n");

    ConsoleWrite("recent entries (newest first):\n");
    auto cb = +[](const FeedbackEntry& e, void* /*ctx*/) -> bool
    {
        if (e.live == 0 && e.tick_fired == 0)
            return false; // unpopulated slot — stop walk
        ConsoleWrite("  tick=");
        WriteU64Dec(e.tick_fired);
        ConsoleWrite("  rule=");
        ConsoleWrite(AutoRuleName(static_cast<AutoRule>(e.rule)));
        ConsoleWrite("  action=");
        ConsoleWrite(AutoActionName(static_cast<AutoAction>(e.action)));
        ConsoleWrite("  outcome=");
        ConsoleWrite(OutcomeName(static_cast<Outcome>(e.outcome)));
        ConsoleWrite("  pre.heap%=");
        WriteU64Dec(e.pre.heap_used_pct);
        ConsoleWrite("\n");
        return true;
    };
    const u32 visited = duetos::env::feedback::RingWalk(cb, nullptr);
    if (visited == 0)
        ConsoleWrite("(no feedback entries yet)\n");
}

void PrintCausality(u32 argc, char** argv)
{
    const u32 limit = ParseLimit(argc, argv);

    ConsoleWrite("selfthink causal-chain (newest first) total=");
    WriteU64Dec(duetos::diag::selfthink::CausalRingTotal());
    ConsoleWrite(" limit=");
    WriteU64Dec(limit);
    ConsoleWrite("\n");

    CausalCtx ctx{limit, 0};
    duetos::diag::selfthink::CausalRingWalk(&CausalRowCb, &ctx);

    if (ctx.printed == 0)
        ConsoleWrite("(no causal entries recorded yet)\n");
}

} // namespace

void CmdSelfthink(u32 argc, char** argv)
{
    if (argc < 2)
    {
        PrintPortrait();
        return;
    }
    const char* sub = argv[1];
    if (StrEq(sub, "causality"))
        PrintCausality(argc, argv);
    else if (StrEq(sub, "baselines"))
        PrintBaselines();
    else if (StrEq(sub, "feedback"))
        PrintFeedback();
    else
        SelfthinkUsage();
}

} // namespace duetos::core::shell::internal
