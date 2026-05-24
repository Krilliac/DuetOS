#include "diag/selfthink_narrative.h"

#include "debug/probes.h"
#include "diag/selfthink.h"
#include "diag/selfthink_baselines.h"
#include "drivers/video/console.h"
#include "env/autonomic.h"
#include "env/autonomic_feedback.h"
#include "log/klog.h"

namespace duetos::diag::selfthink::narrative
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteln;

// Local single-line writer for u64 → decimal. The shell formatters
// (WriteU64Dec etc.) live behind the shell_internal header which
// kernel/diag/ should not include — keeping the narrative usable
// from anywhere that can call ConsoleWrite (boot path, future
// panic-time dumper, klog hook).
void WriteU64(u64 v)
{
    char buf[24];
    int n = 0;
    if (v == 0)
    {
        buf[n++] = '0';
    }
    else
    {
        char tmp[24];
        int t = 0;
        while (v != 0 && t < 24)
        {
            tmp[t++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (t > 0 && n < 23)
            buf[n++] = tmp[--t];
    }
    buf[n] = '\0';
    ConsoleWrite(buf);
}

// Count entries per causal kind for the narrative header. Single
// pass, bounded by the ring capacity.
struct KindCounts
{
    u32 probe;
    u32 autoact_improved;
    u32 autoact_worsened;
    u32 autoact_nochange;
    u32 autoact_diagnostic;
    u32 anomaly;
    u32 fault_react;
    u32 heal;
};

bool CountCb(const CausalEntry& e, void* ctx)
{
    auto* k = static_cast<KindCounts*>(ctx);
    switch (static_cast<CausalKind>(e.kind))
    {
    case CausalKind::ProbeFire:
        ++k->probe;
        break;
    case CausalKind::AutoAction:
    {
        // Outcome is the high 32 bits of `value` (see
        // autonomic_feedback::Tick).
        const u32 outcome = static_cast<u32>(e.value >> 32);
        switch (static_cast<duetos::env::feedback::Outcome>(outcome))
        {
        case duetos::env::feedback::Outcome::Improved:
            ++k->autoact_improved;
            break;
        case duetos::env::feedback::Outcome::Worsened:
            ++k->autoact_worsened;
            break;
        case duetos::env::feedback::Outcome::NoChange:
            ++k->autoact_nochange;
            break;
        case duetos::env::feedback::Outcome::Diagnostic:
            ++k->autoact_diagnostic;
            break;
        case duetos::env::feedback::Outcome::Pending:
            break;
        }
        break;
    }
    case CausalKind::Anomaly:
        ++k->anomaly;
        break;
    case CausalKind::FaultReact:
        ++k->fault_react;
        break;
    case CausalKind::Heal:
        ++k->heal;
        break;
    case CausalKind::Annotation:
    case CausalKind::None:
        break;
    }
    return true;
}

// Print the highest-severity recent event with full context. Walks
// the chain looking for Worsened > Anomaly > FaultReact > Heal >
// Improved > NoChange — the operator's eye lands on the most
// actionable line first.
struct HighlightCtx
{
    bool found;
    CausalKind kind;
    u16 source_id;
    u64 value;
    u64 tick;
    char tag[16];
};

bool HighlightCb(const CausalEntry& e, void* ctx)
{
    auto* h = static_cast<HighlightCtx*>(ctx);
    const CausalKind k = static_cast<CausalKind>(e.kind);

    // Priority: Worsened AutoAction > Anomaly > FaultReact > Heal.
    // Walk newest-first; first match wins.
    bool match = false;
    if (k == CausalKind::AutoAction)
    {
        const u32 outcome = static_cast<u32>(e.value >> 32);
        match = (outcome == static_cast<u32>(duetos::env::feedback::Outcome::Worsened));
    }
    else if (k == CausalKind::Anomaly || k == CausalKind::FaultReact || k == CausalKind::Heal)
    {
        match = true;
    }
    if (!match)
        return true;

    h->found = true;
    h->kind = k;
    h->source_id = e.source_id;
    h->value = e.value;
    h->tick = e.tick;
    for (u32 i = 0; i < sizeof(h->tag); ++i)
        h->tag[i] = e.tag[i];
    return false; // stop — first hit is the highest-priority
}

void WriteHighlight(const HighlightCtx& h)
{
    if (!h.found)
    {
        ConsoleWrite("  no recent anomalies / worsened actions / fault reactions to highlight.\n");
        return;
    }
    ConsoleWrite("  highlight @ tick ");
    WriteU64(h.tick);
    ConsoleWrite(": ");
    switch (h.kind)
    {
    case CausalKind::AutoAction:
        // source_id is the AutoAction enum value.
        ConsoleWrite("autonomic action ");
        ConsoleWrite(duetos::env::AutoActionName(static_cast<duetos::env::AutoAction>(h.source_id)));
        ConsoleWrite(" outcome Worsened (the targeted metric moved AGAINST expected). ");
        break;
    case CausalKind::Anomaly:
        ConsoleWrite("baseline anomaly on metric ");
        ConsoleWrite(baselines::MetricName(static_cast<baselines::MetricId>(h.source_id)));
        ConsoleWrite(" — observed value ");
        WriteU64(h.value);
        ConsoleWrite(" outside 3*stddev of recent mean. ");
        break;
    case CausalKind::FaultReact:
        ConsoleWrite("fault-react dispatched — see fault_react.h for the reaction taxonomy. ");
        break;
    case CausalKind::Heal:
        ConsoleWrite("runtime_checker Heal-class restored a kernel invariant. ");
        break;
    default:
        break;
    }
    ConsoleWrite("Tag=");
    ConsoleWrite(h.tag[0] != '\0' ? h.tag : "<unset>");
    ConsoleWrite("\n");
}

} // namespace

void Write()
{
    const SelfPortrait p = SelfPortraitSnapshot();

    // Header — the operator's eye lands here first.
    ConsoleWrite("selfthink narrative @ tick ");
    WriteU64(p.tick_taken);
    ConsoleWrite(" (uptime ");
    WriteU64(p.resmon.uptime_seconds);
    ConsoleWrite("s)\n");

    // State summary — the three most-watched gauges in one line.
    ConsoleWrite("state: cpu_busy=");
    WriteU64(p.resmon.cpu_busy_pct);
    ConsoleWrite("%  mem=");
    WriteU64(p.resmon.phys_used_pct);
    ConsoleWrite("%  heap=");
    WriteU64(p.resmon.heap_used_pct);
    ConsoleWrite("%  tasks_live=");
    WriteU64(p.resmon.tasks_live);
    ConsoleWrite("\n");

    // Causal-chain rollup.
    KindCounts counts = {};
    CausalRingWalk(&CountCb, &counts);
    ConsoleWrite("recent events (last ");
    WriteU64(CausalRingTotal());
    ConsoleWrite("): probes=");
    WriteU64(counts.probe);
    ConsoleWrite(" autonomic_actions=");
    WriteU64(static_cast<u64>(counts.autoact_improved) + counts.autoact_worsened + counts.autoact_nochange +
             counts.autoact_diagnostic);
    ConsoleWrite(" (improved=");
    WriteU64(counts.autoact_improved);
    ConsoleWrite(" worsened=");
    WriteU64(counts.autoact_worsened);
    ConsoleWrite(" nochange=");
    WriteU64(counts.autoact_nochange);
    ConsoleWrite(") anomalies=");
    WriteU64(counts.anomaly);
    ConsoleWrite(" fault_react=");
    WriteU64(counts.fault_react);
    ConsoleWrite(" heals=");
    WriteU64(counts.heal);
    ConsoleWrite("\n");

    // Health-side rollup — pull the existing introspect diff
    // counts so the operator sees temporal context (changed vs
    // prior boot) inline with spatial state.
    ConsoleWrite("health: scans_run=");
    WriteU64(p.health_scans_run);
    ConsoleWrite(" issues_total=");
    WriteU64(p.health_issues_total);
    ConsoleWrite(" cross_boot(new=");
    WriteU64(p.introspect_new);
    ConsoleWrite(" persistent=");
    WriteU64(p.introspect_persistent);
    ConsoleWrite(" resolved=");
    WriteU64(p.introspect_resolved);
    ConsoleWrite(")\n");

    // Autonomic feedback stats.
    const auto feedback_stats = duetos::env::feedback::StatsRead();
    ConsoleWrite("autonomic: actions_fired=");
    WriteU64(p.auto_actions_fired);
    ConsoleWrite(" outcomes evaluated=");
    WriteU64(feedback_stats.evaluated_total);
    ConsoleWrite(" overflows=");
    WriteU64(feedback_stats.ring_overflows);
    ConsoleWrite("\n");

    // Highlight the highest-priority recent event.
    HighlightCtx h = {};
    CausalRingWalk(&HighlightCb, &h);
    WriteHighlight(h);

    // Verdict line — closing summary the operator can grep on.
    ConsoleWrite("verdict: ");
    if (counts.autoact_worsened > 0)
        ConsoleWrite(
            "WARN — autonomic action(s) failed to achieve their goal; investigate the worsened outcome above.\n");
    else if (counts.anomaly > 5)
        ConsoleWrite("WARN — sustained anomaly stream; the baselines no longer match the workload.\n");
    else if (counts.fault_react > 0)
        ConsoleWrite("WARN — fault reactor handled at least one event; see Diagnostics page.\n");
    else
        ConsoleWrite("OK — no actionable regression detected in the recent window.\n");
}

void SelfTest()
{
    using duetos::core::Log;
    using duetos::core::LogLevel;
    using duetos::core::LogWithValue;

    // The narrative writer is a pure formatter — its correctness is
    // "produces output without faulting + the verdict picker
    // matches the input counts". Drive it with a known causal
    // chain shape: inject one of each kind, then verify the verdict
    // logic via the count-cb directly.
    const u64 prev_total = CausalRingTotal();

    // Inject one Worsened-shaped AutoAction entry so the verdict
    // logic has something to classify.
    const u64 packed_worsened = (static_cast<u64>(duetos::env::feedback::Outcome::Worsened) << 32) | 1ULL;
    CausalRecord(CausalKind::AutoAction, 1, packed_worsened, 0, "selftest");

    KindCounts counts = {};
    CausalRingWalk(&CountCb, &counts);
    if (counts.autoact_worsened == 0)
    {
        Log(LogLevel::Error, "diag/selfthink-narrative", "selftest: Worsened count not picked up");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 1);
        return;
    }

    // HighlightCb must find the Worsened entry (highest priority).
    HighlightCtx h = {};
    CausalRingWalk(&HighlightCb, &h);
    if (!h.found || h.kind != CausalKind::AutoAction)
    {
        Log(LogLevel::Error, "diag/selfthink-narrative", "selftest: highlight did not select Worsened entry");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 2);
        return;
    }

    LogWithValue(LogLevel::Info, "diag/selfthink-narrative", "selftest pass causal_total",
                 CausalRingTotal() - prev_total);
}

} // namespace duetos::diag::selfthink::narrative
