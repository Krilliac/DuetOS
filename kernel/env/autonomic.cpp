#include "env/autonomic.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "diag/fix_journal.h"
#include "diag/runtime_checker.h"
#include "diag/stress_driver.h"
#include "env/autonomic_feedback.h"
#include "env/config_proposal.h"
#include "env/environment.h"
#include "env/neural_policy.h"
#include "env/policy_shield.h"
#include "syscall/inferred_gap.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "sched/loadavg.h"
#include "sched/sched.h"
#include "security/guard.h"
#include "security/policy.h"
#include "test/smoke_profile.h"
#include "time/tick.h"
#include "util/random.h"

namespace duetos::env
{

namespace
{

constinit AutonomicState g_state = {};
constinit AutonomicReport g_report = {};

// Last tick a cross-CPU rebalance actually fired — the state the
// `action_clamp` shield rate-limits against (0 = never).
constinit u64 g_last_rebalance_tick = 0;

constexpr u32 kQ11One = 2048; // loadavg fixed-point 1.0

// Minimum ticks between active rebalances under the action_clamp shield.
// An active balance walks every CPU's runqueue under the scheduler lock;
// a noisy saturation signal must not be allowed to spam it. ~500 ms @100Hz.
constexpr u64 kRebalanceMinIntervalTicks = 50;

void Push(AutoActionSet& s, AutoRule r, AutoAction a)
{
    if (s.count < kAutoActionSetCap)
    {
        s.rules[s.count] = r;
        s.actions[s.count] = a;
        ++s.count;
    }
}

// Map the env power policy (EnvPowerPolicy as u8) to the scheduler
// bias action. Kept here so the policy→bias contract is one place.
AutoAction BiasActionFor(u8 power_policy)
{
    switch (static_cast<EnvPowerPolicy>(power_policy))
    {
    case EnvPowerPolicy::Performance:
        return AutoAction::SchedPerformance;
    case EnvPowerPolicy::Balanced:
        return AutoAction::SchedBalanced;
    case EnvPowerPolicy::PowerSave:
        return AutoAction::SchedPowerSave;
    }
    return AutoAction::SchedBalanced;
}

void Eq(u64 actual, u64 expected, const char* what)
{
    if (actual == expected)
    {
        return;
    }
    arch::SerialWrite("[autonomic] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("env/autonomic", "autonomic self-test mismatch", actual);
}

} // namespace

const char* AutoActionName(AutoAction a)
{
    switch (a)
    {
    case AutoAction::None:
        return "none";
    case AutoAction::MemReclaim:
        return "mem-reclaim";
    case AutoAction::FootprintTrim:
        return "footprint-trim";
    case AutoAction::SecurityEscalate:
        return "security-escalate";
    case AutoAction::ForceHealthScan:
        return "force-health-scan";
    case AutoAction::SchedPerformance:
        return "sched-performance";
    case AutoAction::SchedBalanced:
        return "sched-balanced";
    case AutoAction::SchedPowerSave:
        return "sched-powersave";
    case AutoAction::SchedRebalanceNow:
        return "sched-rebalance-now";
    case AutoAction::Count:
        return "?";
    }
    return "?";
}

const char* AutoRuleName(AutoRule r)
{
    switch (r)
    {
    case AutoRule::None:
        return "none";
    case AutoRule::MemPressure:
        return "mem-pressure";
    case AutoRule::ThermalPower:
        return "thermal-power";
    case AutoRule::SecurityIntegrity:
        return "security-integrity";
    case AutoRule::CpuSaturation:
        return "cpu-saturation";
    case AutoRule::PowerTransition:
        return "power-transition";
    }
    return "?";
}

AutoActionSet AutonomicEvaluate(AutonomicState& st, const AutoInputs& in)
{
    AutoActionSet s = {};

    // Rule 1 — memory pressure (rising edge of free < floor).
    bool mem_pressure = false;
    if (in.total_frames != 0)
    {
        mem_pressure = (in.free_frames * 100u) / in.total_frames < kMemPressurePctFree;
    }
    if (mem_pressure && !st.mem_pressure)
    {
        Push(s, AutoRule::MemPressure, AutoAction::MemReclaim);
    }
    st.mem_pressure = mem_pressure;

    // Rule 2 — thermal throttle (rising edge).
    if (in.thermal_throttle && !st.thermal_active)
    {
        Push(s, AutoRule::ThermalPower, AutoAction::FootprintTrim);
        Push(s, AutoRule::ThermalPower, AutoAction::ForceHealthScan);
    }
    st.thermal_active = in.thermal_throttle;

    // Rule 3 — kernel-integrity findings increased since last tick.
    // issues_found_total only rises when a real check fails.
    if (st.valid && in.health_issues_total > st.health_total)
    {
        Push(s, AutoRule::SecurityIntegrity, AutoAction::SecurityEscalate);
    }
    st.health_total = in.health_issues_total;

    // Rule 4 — CPU saturation: 1-min loadavg above the online-CPU
    // count (rising edge). Catches runaway tasks / IRQ storms. On the
    // rising edge we both surface health (forced scan) AND poke the
    // scheduler for an out-of-band cross-CPU rebalance so a lopsided
    // runqueue spreads without waiting a full balance period.
    const bool cpu_sat = (in.cpu_online != 0) && (in.loadavg_1min_q11 > in.cpu_online * kQ11One);
    if (cpu_sat && !st.cpu_saturated)
    {
        Push(s, AutoRule::CpuSaturation, AutoAction::ForceHealthScan);
        Push(s, AutoRule::CpuSaturation, AutoAction::SchedRebalanceNow);
    }
    st.cpu_saturated = cpu_sat;

    // Rule 5 — power-policy transition drives the scheduler bias.
    // Fires on any change (and on first valid eval, to align the
    // scheduler with the boot-derived policy).
    if (!st.valid || in.power_policy != st.last_power_policy)
    {
        Push(s, AutoRule::PowerTransition, BiasActionFor(in.power_policy));
    }
    st.last_power_policy = in.power_policy;

    st.valid = true;
    return s;
}

void AutonomicApply(const AutoActionSet& set, u64 now)
{
    // Capture pre-action metrics once for the whole set. Every
    // action in `set` fires at the same logical instant, so they
    // all share the same pre-snapshot. The feedback ring is
    // walked by kselfthink's tick after the kFeedbackDelayTicks
    // window has elapsed and the post-snapshot becomes
    // meaningful.
    const ::duetos::env::feedback::PreMetrics pre = ::duetos::env::feedback::CapturePreMetrics();

    for (u32 i = 0; i < set.count; ++i)
    {
        const AutoAction a = set.actions[i];
        const AutoRule r = set.rules[i];

        switch (a)
        {
        case AutoAction::MemReclaim:
            mm::KernelHeapDrainBins();
            mm::FrameAllocatorDrainPools();
            break;
        case AutoAction::FootprintTrim:
            mm::FrameAllocatorDrainPools();
            break;
        case AutoAction::SecurityEscalate:
            // Kernel-integrity tampering detected by the runtime
            // checker — clamp the box: enforce image guard, apply
            // the Production policy profile. Both are idempotent
            // and log their own transition. actor_pid 0 = kernel.
            //
            // Smoke-profile gate: a headless smoke run can't answer
            // the interactive `Allow [y] / Deny [n]` prompt that a
            // Warn-verdict image fires under Enforce. With
            // escalation on, smoke profiles like pe-hello reach the
            // guard prompt, default-deny after 10s, and qemu's
            // outer timeout kills the VM before the smoke sentinel
            // emits — surfaces as `qemu smoke (pe-hello)` red on
            // every PR (regression from PR #314's autonomic engine
            // landing, traced via smoke-pe-hello.log tail showing
            // SECURITY GUARD PROMPT mid-wait when qemu killed it).
            // Once-warn so the silenced action stays auditable.
            //
            // Same applies to `stress=cpu|mem|mix|spin` headless
            // runs: under x86_64-debug, UBSAN/KASAN/red-zone audit
            // routinely produces a kernel-integrity finding that
            // raises Rule 3 within ~30s of boot. Escalating to
            // Enforce then traps ring3-hello-pe (PE_NO_IMPORTS
            // warning) on the guard prompt for the full 10s
            // default-deny, after which the stress driver task is
            // still on its 30-tick settle sleep — the outer wall
            // budget eats the entire stress window. Repro'd on
            // 4-vCPU debug boot of `tools/qemu/run-stress.sh cpu 15 4`
            // exiting with `qemu terminating on signal 15` and no
            // `[stress] done` sentinel. Mirror the smoke-profile
            // gate exactly: skip the escalation, emit one WARN so
            // the suppress stays auditable.
            if (::duetos::test::SmokeProfileGet() != ::duetos::test::SmokeProfile::None)
            {
                KLOG_ONCE_WARN("autonomic", "security-escalate suppressed under smoke profile (would block hello-pe)");
                break;
            }
            if (::duetos::core::diag::StressDriverArmed())
            {
                KLOG_ONCE_WARN("autonomic", "security-escalate suppressed under stress driver (would block hello-pe)");
                break;
            }
            security::SetGuardMode(security::Mode::Enforce);
            security::PolicySet(security::PolicyProfile::Production, 0);
            KLOG_WARN("autonomic", "kernel-integrity finding — escalated to Production/Enforce");
            break;
        case AutoAction::ForceHealthScan:
            (void)core::RuntimeCheckerScan();
            break;
        case AutoAction::SchedPerformance:
            sched::SchedSetPowerBias(sched::PowerBias::Performance);
            break;
        case AutoAction::SchedBalanced:
            sched::SchedSetPowerBias(sched::PowerBias::Balanced);
            break;
        case AutoAction::SchedPowerSave:
            sched::SchedSetPowerBias(sched::PowerBias::PowerSave);
            break;
        case AutoAction::SchedRebalanceNow:
        {
            // One-shot cross-CPU rebalance: poke the scheduler to run an
            // out-of-band active-balance pass on the next tick instead of
            // waiting up to a full balance period. Idempotent (a second
            // request before the tick consumes it still yields one pass).
            //
            // action_clamp shield: an active balance is expensive (it walks
            // every CPU's runqueue under the scheduler lock), so when the
            // clamp is on we hold the actuator to one pass per
            // kRebalanceMinIntervalTicks — the "actuator parameter stays
            // within safe bounds" guard. Toggle the clamp off and a
            // saturated box rebalances on every poll instead.
            if (ShieldConfigGet().action_clamp && g_last_rebalance_tick != 0 &&
                now - g_last_rebalance_tick < kRebalanceMinIntervalTicks)
            {
                KLOG_ONCE_WARN("autonomic", "rebalance rate-limited by action_clamp shield");
                break;
            }
            g_last_rebalance_tick = now;
            sched::SchedRequestActiveBalance();
            break;
        }
        case AutoAction::None:
        case AutoAction::Count:
            continue;
        }

        KLOG_INFO_S("autonomic", "rule fired", "action", AutoActionName(a));
        KLOG_DEBUG_S("autonomic", "rule", "by", AutoRuleName(r));
        const u64 packed = (static_cast<u64>(r) << 8) | static_cast<u64>(a);
        KBP_PROBE_V(debug::ProbeId::kAutonomicAction, packed);

        g_report.actions_fired++;
        g_report.per_action[static_cast<u32>(a)]++;
        g_report.last = a;
        g_report.last_rule = r;

        // Enqueue a feedback entry stamped with this poll's tick. The
        // kselfthink kthread's Tick() evaluates the outcome once the
        // deadline elapses, writes a CausalKind::AutoAction row, and (in
        // Live mode) feeds the reward back to the learner keyed by `now`.
        ::duetos::env::feedback::Enqueue(r, a, pre, now);
    }
}

namespace
{

AutoInputs SenseInputs()
{
    const SystemEnvironment e = EnvironmentGet();

    u32 l1 = 0, l5 = 0, l15 = 0;
    sched::LoadavgSnapshot(&l1, &l5, &l15);

    AutoInputs in = {};
    in.free_frames = mm::FreeFramesCount();
    in.total_frames = mm::TotalFrames();
    in.thermal_throttle = e.thermal_throttle;
    in.health_issues_total = core::RuntimeCheckerStatusRead().issues_found_total;
    in.loadavg_1min_q11 = l1;
    in.cpu_online = e.cpu_online;
    in.power_policy = static_cast<u8>(e.power_policy);
    return in;
}

void PolicyTrace(const AutoInputs& in, const AutoActionSet& rule_set, const AutoActionSet& net_set,
                 const AutoActionSet& final_set)
{
    // Verbose per-decision trace. DEBUG-gated so it stays quiet at
    // default log levels; an operator raises the level to watch the
    // policy decide tick-by-tick. In shadow mode the net's proposals are
    // logged but `final` actuates the rule floor — the divergence between
    // the "net proposes" lines and the actuated set IS the shadow data
    // the operator (and Slice 3's learner) reads.
    const u64 free_pct = in.total_frames != 0 ? (in.free_frames * 100u) / in.total_frames : 0u;
    KLOG_DEBUG_V("policy", "decide free_pct", free_pct);
    KLOG_DEBUG_V("policy", "decide rule_count", rule_set.count);
    KLOG_DEBUG_V("policy", "decide net_count", net_set.count);
    KLOG_DEBUG_V("policy", "decide final_count", final_set.count);
    for (u32 i = 0; i < net_set.count; ++i)
    {
        KLOG_DEBUG_S("policy", "net proposes", "action", AutoActionName(net_set.actions[i]));
    }
}

// Epsilon-greedy exploration rate (Q16). Held tight when the explore_cap
// shield is on; widened for un-shielded collection so a master-off boot
// samples more off-policy moves ("reel in the data").
constexpr u32 kExploreEpsilonShieldedQ16 = 655; // ~1.0%
constexpr u32 kExploreEpsilonRawQ16 = 6554;     // ~10.0%

// Build the learner's actuating proposal for a Live tick: forward the
// learned net (recording the decision context so the delayed reward can
// credit-assign it), sample bounded exploration, then drop any action
// whose circuit breaker is open. Shadow mode instead uses the pure,
// non-recording NeuralPolicyDecide (advisory only).
AutoActionSet BuildNetProposal(const AutoInputs& in, u64 now, const ShieldConfig& cfg)
{
    AutoActionSet net = NeuralPolicyDecideLive(in, now);

    const u32 eps = cfg.explore_cap ? kExploreEpsilonShieldedQ16 : kExploreEpsilonRawQ16;
    NeuralPolicyExplore(net, eps, static_cast<u32>(core::RandomU64() & 0xFFFFu));

    if (cfg.circuit_breaker)
    {
        AutoActionSet kept = {};
        for (u32 i = 0; i < net.count; ++i)
        {
            if (!NeuralPolicyActionBreakerTripped(net.actions[i], now))
            {
                Push(kept, net.rules[i], net.actions[i]);
            }
        }
        net = kept;
    }
    return net;
}

// Stable per-action pin so the fix journal dedups a recurring proposal
// (repeat_count = how durably the learner has avoided this action).
const char* ProposalPin(AutoAction a)
{
    switch (a)
    {
    case AutoAction::MemReclaim:
        return "env/neural-policy:avoid-mem-reclaim";
    case AutoAction::FootprintTrim:
        return "env/neural-policy:avoid-footprint-trim";
    case AutoAction::ForceHealthScan:
        return "env/neural-policy:avoid-force-scan";
    default:
        return "env/neural-policy:avoid-other";
    }
}

// Surface the learner's reviewable proposals to the fix journal as DATA
// (DD#016 — never a code mutation). Shielded reports only durable
// learned-away gates; the master-off firehose also reports gates trending
// toward suppression. Records dedup per action; an offline patch generator
// reads KERNEL.FIX and a human/Claude reviewer decides whether the rule
// should change. Called each Live poll (Shadow/Off leave the weights at
// the prior, so the scan is empty).
void EmitPolicyProposals(const ShieldConfig& cfg)
{
    PolicyProposal pr[kNetOut * kNetHidden];
    const bool aggressive = !cfg.shields_enabled; // master-off => firehose
    const u32 n = NeuralPolicyProposalScan(pr, static_cast<u32>(kNetOut * kNetHidden), aggressive);
    for (u32 i = 0; i < n; ++i)
    {
        const u64 ctx_a = (static_cast<u64>(pr[i].action) << 8) | static_cast<u64>(static_cast<u32>(pr[i].detector));
        const u64 ctx_b =
            (static_cast<u64>(static_cast<u32>(pr[i].prior)) << 32) | static_cast<u64>(static_cast<u32>(pr[i].learned));
        (void)::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::AutonomicProposal,
                                               ProposalPin(pr[i].action),
                                               "learner suppressed a rule action — review rule", ctx_a, ctx_b);
    }
}

} // namespace

AutoActionSet PolicyDecide(AutonomicState& st, const AutoInputs& in, u64 now)
{
    // Rule floor — always evaluated: the safety baseline AND the learner's
    // imitation teacher. Edge state is updated here.
    const AutoActionSet rule_set = AutonomicEvaluate(st, in);
    const PolicyMode mode = PolicyModeGet();
    const ShieldConfig& cfg = ShieldConfigGet();

    // Learned proposal. Off: none. Shadow: advisory (pure decide, traced,
    // never actuated). Live: the learner drives — forward + explore +
    // breaker filter, recording the decision context for the delayed reward.
    AutoActionSet net_set = {};
    if (mode == PolicyMode::Live)
    {
        net_set = BuildNetProposal(in, now, cfg);
    }
    else if (mode == PolicyMode::Shadow)
    {
        net_set = NeuralPolicyDecide(in);
    }

    // Reconcile: Off/Shadow -> the rule floor actuates; Live -> the net
    // drives with the floor's safety actions preserved (master-off -> raw).
    const AutoActionSet final_set = ShieldReconcile(cfg, mode, rule_set, net_set);
    PolicyTrace(in, rule_set, net_set, final_set);
    return final_set;
}

void AutonomicTick()
{
    g_report.ticks++;
    // One tick stamp for the whole poll: the decision context (for the
    // delayed reward) and the feedback entry must agree on the fire tick.
    const u64 now = ::duetos::time::TickCount();
    const AutoInputs in = SenseInputs();
    const AutoActionSet set = PolicyDecide(g_state, in, now);
    if (set.count != 0)
    {
        AutonomicApply(set, now);
    }

    // Surface any reviewable proposals the learner has accumulated. Only
    // Live mode learns, so Shadow/Off scan empty — gate to avoid the call.
    if (PolicyModeGet() == PolicyMode::Live)
    {
        EmitPolicyProposals(ShieldConfigGet());
        // Phase B dynamic fix-discovery: surface a bounded, evidence-backed
        // CONFIG proposal as DATA when runtime pressure crosses threshold —
        // here, inferred-gap discovery dropping distinct pins because the
        // per-boot cap is too low. DD#016: this writes a journal record, never
        // source. See docs/superpowers/specs/2026-06-11-dynamic-fix-discovery-design.md
        EmitConfigProposal(ConfigKnob::InferredGapPinCap, ::duetos::syscall::InferredGapDroppedCount());
    }
}

void AutonomicInit()
{
    // Prime the edge state to current conditions so the first live
    // tick does not false-fire on boot-time levels, then align the
    // scheduler bias to the boot-derived policy explicitly (one
    // idempotent call — no Apply log/probe storm at boot).
    const AutoInputs in = SenseInputs();
    AutoActionSet discard = AutonomicEvaluate(g_state, in);
    (void)discard;
    switch (static_cast<EnvPowerPolicy>(in.power_policy))
    {
    case EnvPowerPolicy::Performance:
        sched::SchedSetPowerBias(sched::PowerBias::Performance);
        break;
    case EnvPowerPolicy::Balanced:
        sched::SchedSetPowerBias(sched::PowerBias::Balanced);
        break;
    case EnvPowerPolicy::PowerSave:
        sched::SchedSetPowerBias(sched::PowerBias::PowerSave);
        break;
    }
    KLOG_INFO("autonomic", "engine primed");
}

const AutonomicReport& AutonomicStatus()
{
    return g_report;
}

void AutonomicSelfTest()
{
    // Pure-evaluator only — never calls AutonomicApply (a self-test
    // must not actually escalate security or trim memory).
    AutonomicState st = {};

    // Baseline: healthy box, Performance policy. First eval is
    // !valid so rule 5 aligns the scheduler; nothing else fires.
    AutoInputs base = {};
    base.free_frames = 900;
    base.total_frames = 1000;
    base.health_issues_total = 0;
    base.loadavg_1min_q11 = 0;
    base.cpu_online = 4;
    base.power_policy = static_cast<u8>(EnvPowerPolicy::Performance);
    AutoActionSet s = AutonomicEvaluate(st, base);
    Eq(s.count, 1, "baseline fires only rule5");
    Eq(static_cast<u64>(s.actions[0]), static_cast<u64>(AutoAction::SchedPerformance), "baseline=sched-perf");

    // Idempotence: same inputs again → no edge, no action.
    s = AutonomicEvaluate(st, base);
    Eq(s.count, 0, "idempotent steady state");

    // Rule 1: free drops below 10% → MemReclaim, once.
    AutoInputs lowmem = base;
    lowmem.free_frames = 50; // 5%
    s = AutonomicEvaluate(st, lowmem);
    Eq(s.count, 1, "lowmem fires one");
    Eq(static_cast<u64>(s.actions[0]), static_cast<u64>(AutoAction::MemReclaim), "lowmem=mem-reclaim");
    s = AutonomicEvaluate(st, lowmem);
    Eq(s.count, 0, "lowmem latched (no refire)");

    // Rule 2: thermal rising → FootprintTrim + ForceHealthScan.
    AutoInputs hot = lowmem;
    hot.thermal_throttle = true;
    s = AutonomicEvaluate(st, hot);
    Eq(s.count, 2, "thermal fires two");
    Eq(static_cast<u64>(s.actions[0]), static_cast<u64>(AutoAction::FootprintTrim), "thermal[0]=trim");
    Eq(static_cast<u64>(s.actions[1]), static_cast<u64>(AutoAction::ForceHealthScan), "thermal[1]=scan");

    // Rule 3: integrity counter rises → SecurityEscalate.
    AutoInputs tamper = hot;
    tamper.health_issues_total = 1;
    s = AutonomicEvaluate(st, tamper);
    Eq(s.count, 1, "tamper fires one");
    Eq(static_cast<u64>(s.actions[0]), static_cast<u64>(AutoAction::SecurityEscalate), "tamper=escalate");

    // Rule 4: loadavg above online-CPU count → ForceHealthScan + rebalance.
    AutoInputs busy = tamper;
    busy.loadavg_1min_q11 = busy.cpu_online * kQ11One + 1; // > nCPU
    s = AutonomicEvaluate(st, busy);
    Eq(s.count, 2, "cpu-sat fires two");
    Eq(static_cast<u64>(s.actions[0]), static_cast<u64>(AutoAction::ForceHealthScan), "cpu-sat[0]=scan");
    Eq(static_cast<u64>(s.actions[1]), static_cast<u64>(AutoAction::SchedRebalanceNow), "cpu-sat[1]=rebalance");

    // Rule 5: policy → PowerSave changes the scheduler bias.
    AutoInputs saver = busy;
    saver.power_policy = static_cast<u8>(EnvPowerPolicy::PowerSave);
    s = AutonomicEvaluate(st, saver);
    Eq(s.count, 1, "policy change fires one");
    Eq(static_cast<u64>(s.actions[0]), static_cast<u64>(AutoAction::SchedPowerSave), "policy=sched-powersave");

    // Name tables wired.
    Eq(u64(AutoActionName(AutoAction::MemReclaim)[0]), u64('m'), "name mem[0]");
    Eq(u64(AutoRuleName(AutoRule::PowerTransition)[0]), u64('p'), "name pwr[0]");

    arch::SerialWrite("[autonomic] selftest pass\n");
}

} // namespace duetos::env
