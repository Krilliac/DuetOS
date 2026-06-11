#include "env/autonomic_feedback.h"

#include "debug/probes.h"
#include "diag/resmon.h"
#include "diag/runtime_checker.h"
#include "diag/selfthink.h"
#include "env/neural_policy.h"
#include "env/policy_shield.h"
#include "log/klog.h"
#include "time/tick.h"

namespace duetos::env::feedback
{

namespace
{

// Per CLAUDE.md "Don't add error handling beyond system boundaries":
// the ring is best-effort. Overflow overwrites the oldest still-
// live entry; the overflow counter surfaces the case so an
// operator notices when the engine is producing actions faster
// than the kselfthink tick can drain them.
FeedbackEntry g_ring[kFeedbackRingCap] = {};
u64 g_head = 0;
FeedbackStats g_stats = {};

// Noise floor for Improved vs NoChange classification. Below
// this percentage change the outcome is NoChange — avoids
// flagging baseline jitter as either a win or a regression.
constexpr u64 kNoisePctTimes100 = 200; // 2.00 %

bool DeadlinePassed(const FeedbackEntry& e, u64 now)
{
    if (e.live == 0)
        return false;
    return now >= e.check_at_tick;
}

// Compute |post - pre| * 10000 / pre, returning the "permille of
// permille" magnitude (i.e. percent × 100) as an integer so we
// don't need floating point. Returns 0 if pre is 0 (no meaningful
// comparison).
u64 RelativeMoveBP(u64 pre, u64 post)
{
    if (pre == 0)
        return 0;
    const u64 abs_delta = (post >= pre) ? (post - pre) : (pre - post);
    return (abs_delta * 10000ULL) / pre;
}

Outcome ClassifyDecreaseExpected(u64 pre, u64 post)
{
    if (pre == 0 && post == 0)
        return Outcome::NoChange;
    const u64 move = RelativeMoveBP(pre, post);
    if (move < kNoisePctTimes100)
        return Outcome::NoChange;
    return (post < pre) ? Outcome::Improved : Outcome::Worsened;
}

Outcome EvaluateAction(AutoAction a, const PreMetrics& pre, const PreMetrics& post)
{
    switch (a)
    {
    case AutoAction::MemReclaim:
        // Heap drain + frame-pool drain. Both heap_used_pct AND
        // phys_used_pct should decrease — but heap is the
        // primary effect (the drain returns chunks to the
        // freelist immediately, while phys frames only come back
        // when the pool returns them to the global allocator).
        return ClassifyDecreaseExpected(pre.heap_used_pct, post.heap_used_pct);
    case AutoAction::FootprintTrim:
        // Frame-pool drain only. Watch phys_used_pct.
        return ClassifyDecreaseExpected(pre.phys_used_pct, post.phys_used_pct);
    case AutoAction::ForceHealthScan:
        // The scan may SURFACE more issues (Improved means more
        // visible — the runtime_checker found more); operator
        // wants either direction to be visible.
        if (post.health_issues_total == pre.health_issues_total)
            return Outcome::NoChange;
        return Outcome::Improved;
    case AutoAction::SecurityEscalate:
    case AutoAction::SchedPerformance:
    case AutoAction::SchedBalanced:
    case AutoAction::SchedPowerSave:
    case AutoAction::SchedRebalanceNow:
        // No quantifiable single-metric effect window. The
        // action ran (logged + probe-fired); outcome is
        // diagnostic-only (a rebalance's effect shows in loadavg
        // over a longer horizon than the 100 ms feedback window).
        return Outcome::Diagnostic;
    case AutoAction::None:
    case AutoAction::Count:
        return Outcome::Diagnostic;
    }
    return Outcome::Diagnostic;
}

} // namespace

const char* OutcomeName(Outcome o)
{
    switch (o)
    {
    case Outcome::Pending:
        return "pending";
    case Outcome::Improved:
        return "improved";
    case Outcome::NoChange:
        return "no-change";
    case Outcome::Worsened:
        return "worsened";
    case Outcome::Diagnostic:
        return "diagnostic";
    }
    return "?";
}

PreMetrics CapturePreMetrics()
{
    const auto resmon = ::duetos::diag::ResmonSample();
    PreMetrics m;
    m.phys_used_pct = resmon.phys_used_pct;
    m.heap_used_pct = resmon.heap_used_pct;
    m.health_issues_total = ::duetos::core::RuntimeCheckerStatusRead().issues_found_total;
    return m;
}

void Enqueue(AutoRule rule, AutoAction action, const PreMetrics& pre, u64 fire_tick)
{
    const u64 idx = g_head++;
    FeedbackEntry& e = g_ring[idx % kFeedbackRingCap];

    // Overflow accounting: if we're stomping on an entry that
    // hasn't been evaluated yet, count the drop so the operator
    // sees feedback pressure independently of action rate.
    if (e.live != 0 && e.outcome == static_cast<u8>(Outcome::Pending))
        g_stats.ring_overflows++;

    e.live = 1;
    e.outcome = static_cast<u8>(Outcome::Pending);
    e.rule = static_cast<u8>(rule);
    e.action = static_cast<u8>(action);
    e.reserved = 0;
    e.tick_fired = fire_tick;
    e.check_at_tick = fire_tick + kFeedbackDelayTicks;
    e.pre = pre;

    g_stats.enqueued_total++;
}

void Tick()
{
    const u64 now = ::duetos::time::TickCount();
    PreMetrics post_cached = {};
    bool post_captured = false;

    for (u64 i = 0; i < kFeedbackRingCap; ++i)
    {
        FeedbackEntry& e = g_ring[i];
        if (!DeadlinePassed(e, now))
            continue;
        if (e.outcome != static_cast<u8>(Outcome::Pending))
            continue;

        // One post-capture per Tick is enough — every action's
        // deadline is the same kFeedbackDelayTicks past its
        // fire, and consecutive entries within a Tick share the
        // same post-window. Lazy capture keeps the no-pending
        // case zero-cost.
        if (!post_captured)
        {
            post_cached = CapturePreMetrics();
            post_captured = true;
        }

        const Outcome o = EvaluateAction(static_cast<AutoAction>(e.action), e.pre, post_cached);
        e.outcome = static_cast<u8>(o);
        e.live = 0;

        g_stats.evaluated_total++;
        g_stats.per_outcome[static_cast<u32>(o)]++;

        // Record an AutoAction causal entry encoding the
        // outcome and the rule that drove it.
        const u64 packed_value = (static_cast<u64>(o) << 32) | static_cast<u64>(e.rule);
        ::duetos::diag::selfthink::CausalRecord(::duetos::diag::selfthink::CausalKind::AutoAction,
                                                static_cast<u16>(e.action), packed_value, 0, "autonomic");

        // Live-mode online learning: feed the outcome back to the neural
        // policy as a reward, keyed to the decision's fire tick so the
        // synapses that fired THIS action update (credit assignment).
        // Diagnostic / Pending outcomes are not rewards. Only Live mode
        // learns — Shadow collects data without touching the weights.
        if (PolicyModeGet() == PolicyMode::Live)
        {
            int reward = 0;
            bool is_reward = true;
            switch (o)
            {
            case Outcome::Improved:
                reward = 1;
                break;
            case Outcome::Worsened:
                reward = -1;
                break;
            case Outcome::NoChange:
                reward = 0;
                break;
            default:
                is_reward = false;
                break;
            }
            if (is_reward)
            {
                NeuralPolicyReward(e.tick_fired, static_cast<AutoAction>(e.action), reward);
            }
        }

        // Worsened is the actionable signal — fire the probe so
        // an attached GDB can break at the exact frame where a
        // missed outcome first appeared. Disarmed by default;
        // operator arms it via `probe arm env.outcome_missed`.
        if (o == Outcome::Worsened)
        {
            ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kAutonomicOutcomeMissed, reinterpret_cast<u64>(&Tick),
                                       packed_value);
        }
    }
}

FeedbackStats StatsRead()
{
    return g_stats;
}

u32 RingWalk(bool (*cb)(const FeedbackEntry& e, void* ctx), void* ctx)
{
    if (cb == nullptr)
        return 0;

    const u64 head = g_head;
    const u64 entries = (head < kFeedbackRingCap) ? head : kFeedbackRingCap;
    u32 visited = 0;
    for (u64 i = 0; i < entries; ++i)
    {
        const u64 slot = (head - 1 - i) % kFeedbackRingCap;
        ++visited;
        if (!cb(g_ring[slot], ctx))
            break;
    }
    return visited;
}

void SelfTest()
{
    using duetos::core::Log;
    using duetos::core::LogLevel;
    using duetos::core::LogWithValue;

    // Test #1: capture → enqueue → fast-forward → tick → classify
    // Improved.
    PreMetrics pre{};
    pre.heap_used_pct = 80;
    pre.phys_used_pct = 70;
    pre.health_issues_total = 0;

    // Synthesize a "post" that would classify Improved for
    // MemReclaim: heap dropped from 80 to 60 (-25 %, well over
    // 2 % noise).
    const u64 prev_enq = g_stats.enqueued_total;
    Enqueue(AutoRule::MemPressure, AutoAction::MemReclaim, pre, ::duetos::time::TickCount());
    if (g_stats.enqueued_total != prev_enq + 1)
    {
        Log(LogLevel::Error, "env/autonomic-feedback", "selftest: enqueue total stuck");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 1);
        return;
    }

    // Verify EvaluateAction directly — the live Tick path would
    // need a real metric move which we can't engineer from a
    // selftest without touching the heap.
    PreMetrics post_improve = pre;
    post_improve.heap_used_pct = 60;
    if (EvaluateAction(AutoAction::MemReclaim, pre, post_improve) != Outcome::Improved)
    {
        Log(LogLevel::Error, "env/autonomic-feedback", "selftest: MemReclaim Improved misclassified");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 2);
        return;
    }

    PreMetrics post_worse = pre;
    post_worse.heap_used_pct = 95;
    if (EvaluateAction(AutoAction::MemReclaim, pre, post_worse) != Outcome::Worsened)
    {
        Log(LogLevel::Error, "env/autonomic-feedback", "selftest: MemReclaim Worsened misclassified");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 3);
        return;
    }

    PreMetrics post_noop = pre;
    post_noop.heap_used_pct = 81; // 1.25 % — under the 2 % noise floor
    if (EvaluateAction(AutoAction::MemReclaim, pre, post_noop) != Outcome::NoChange)
    {
        Log(LogLevel::Error, "env/autonomic-feedback", "selftest: MemReclaim NoChange misclassified");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 4);
        return;
    }

    // Diagnostic-class action: any post → Diagnostic.
    if (EvaluateAction(AutoAction::SchedPerformance, pre, post_improve) != Outcome::Diagnostic)
    {
        Log(LogLevel::Error, "env/autonomic-feedback", "selftest: SchedPerformance not Diagnostic");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 5);
        return;
    }

    LogWithValue(LogLevel::Info, "env/autonomic-feedback", "selftest pass entries", g_stats.enqueued_total);
}

} // namespace duetos::env::feedback
