#include "env/neural_policy.h"

namespace duetos::env
{

void NetForward(const NetParams& p, const i32 feat[kNetIn], i32 logits[kNetOut])
{
    // Layer 1: hidden = ReLU( ((feat · W1) >> kQWeight) + b1 ).
    // Products are Q16·Q12 = Q28; the >>kQWeight brings them back to Q16,
    // matching the bias scale. i64 accumulator guards the Q28 width.
    i32 hidden[kNetHidden];
    for (int j = 0; j < kNetHidden; ++j)
    {
        i64 acc = 0;
        for (int i = 0; i < kNetIn; ++i)
        {
            acc += static_cast<i64>(feat[i]) * static_cast<i64>(p.w1[i][j]);
        }
        const i32 pre = static_cast<i32>(acc >> kQWeight) + p.b1[j];
        hidden[j] = pre > 0 ? pre : 0; // ReLU
    }

    // Layer 2: logits = ((hidden · W2) >> kQWeight) + b2. No activation —
    // the gate threshold lives in the caller.
    for (int k = 0; k < kNetOut; ++k)
    {
        i64 acc = 0;
        for (int j = 0; j < kNetHidden; ++j)
        {
            acc += static_cast<i64>(hidden[j]) * static_cast<i64>(p.w2[j][k]);
        }
        logits[k] = static_cast<i32>(acc >> kQWeight) + p.b2[k];
    }
}

void ExtractFeatures(const AutoInputs& in, i32 feat[kNetIn])
{
    constexpr i64 kQ16One = i64{1} << kQFeature; // 65536 == 1.0 (Q16)
    constexpr i64 kFeatCap = 16 * kQ16One;       // 16.0 — bound a runaway loadavg
    constexpr int kQLoadavg = 11;                // loadavg_1min_q11 is Q11

    // f0 — free fraction (Q16). Degenerate total -> "full free" (the
    // rule treats total==0 as "no mem pressure"; mirror that here).
    if (in.total_frames != 0)
    {
        feat[0] = static_cast<i32>((static_cast<i64>(in.free_frames) << kQFeature) / static_cast<i64>(in.total_frames));
    }
    else
    {
        feat[0] = static_cast<i32>(kQ16One);
    }

    // f1 — thermal throttle as 0 / 1.0 (Q16).
    feat[1] = in.thermal_throttle ? static_cast<i32>(kQ16One) : 0;

    // f2 — load per online CPU (Q16), capped. loadavg is Q11; the left
    // shift lifts Q11 -> Q16 before dividing by the CPU count.
    if (in.cpu_online != 0)
    {
        i64 per_cpu =
            (static_cast<i64>(in.loadavg_1min_q11) << (kQFeature - kQLoadavg)) / static_cast<i64>(in.cpu_online);
        if (per_cpu > kFeatCap)
        {
            per_cpu = kFeatCap;
        }
        feat[2] = static_cast<i32>(per_cpu);
    }
    else
    {
        feat[2] = 0;
    }
}

namespace
{

// Fire an action when its logit is strictly positive (Q16). The
// imitation outputs are 0 when the predicate is false and clearly
// positive when true, so a zero threshold reproduces the rule edge;
// online learning shifts a logit to suppress / reinforce a gate.
constexpr i32 kGateThreshold = 0;

// Circuit-breaker thresholds (kBreakerTrip / kBreakerCooldownTicks) are
// header constants so the host test pins the same values the kernel uses.

// Which AutoAction (and attribution rule) each output index drives.
struct NetActionMap
{
    AutoAction action;
    AutoRule rule;
};
constexpr NetActionMap kNetActionMap[kNetOut] = {
    {AutoAction::MemReclaim, AutoRule::MemPressure},
    {AutoAction::FootprintTrim, AutoRule::ThermalPower},
    {AutoAction::ForceHealthScan, AutoRule::CpuSaturation},
};

// Imitation-by-construction weights: the hidden layer is three fixed
// detectors; the output layer routes them to the discretionary actions,
// reproducing the rule level-predicates.
//   h0 = ReLU(0.10 - free_fraction)  -> MemReclaim
//   h1 = ReLU(thermal - 0.5)         -> FootprintTrim, ForceHealthScan
//   h2 = ReLU(load_per_cpu - 1.0)    -> ForceHealthScan
// Slice 3 makes the output layer (w2/b2) adapt online; the hidden
// detectors stay fixed. This literal is also the decay PRIOR the online
// update regularizes back toward (the safe floor the learner can't escape).
// GAP: thresholds are exact only to the Q16 LSB — b1[0]=6554 is 0.100006,
// not 0.10, so a free-fraction in [0.10, 0.100006) disagrees with the
// rule at the sub-LSB boundary. Immaterial off the boundary; revisit if a
// Slice-3 agreement metric needs bit-exact thresholds.
constexpr i16 kBig = 32767; // ~8.0 (Q12) — any positive detector -> decisive logit
constexpr NetParams kImitation = {
    // w1[in][hidden] (Q12)
    {
        {-4096, 0, 0}, // free-fraction -> h0 (mem), weight -1.0
        {0, 4096, 0},  // thermal       -> h1 (thermal), +1.0
        {0, 0, 4096},  // load-per-cpu  -> h2 (cpu), +1.0
    },
    // b1[hidden] (Q16): +0.10, -0.5, -1.0
    {6554, -32768, -65536},
    // w2[hidden][out] (Q12)
    {
        {kBig, 0, 0},    // h0 -> MemReclaim
        {0, kBig, kBig}, // h1 -> FootprintTrim AND ForceHealthScan
        {0, 0, kBig},    // h2 -> ForceHealthScan
    },
    // b2[out] (Q16)
    {0, 0, 0},
};

// The live, learned parameters. Boot-initialised to the imitation prior;
// only the output layer (w2/b2) is mutated online. Owned by the single
// env-monitor task — no lock (see the header's threading note).
constinit NetParams g_net = kImitation;

// Retained decision contexts: the hidden activations of each Live
// decision, keyed by the tick its delayed feedback reward will arrive
// under. A small ring suffices — rewards land ~kFeedbackDelayTicks (10)
// after the decision and decisions are ~200 ticks (one poll) apart.
struct LearnCtx
{
    u64 tick;
    bool used;
    i32 hidden[kNetHidden];
};
constinit LearnCtx g_ctx[kLearnCtxRing] = {};
constinit u32 g_ctx_head = 0;

// Per-output circuit-breaker state: a run of consecutive Worsened
// outcomes and the tick until which the breaker stays open.
constinit u64 g_consec_worsened[kNetOut] = {};
constinit u64 g_breaker_until[kNetOut] = {};

void Push(AutoActionSet& s, AutoRule r, AutoAction a)
{
    if (s.count < kAutoActionSetCap)
    {
        s.rules[s.count] = r;
        s.actions[s.count] = a;
        ++s.count;
    }
}

bool Contains(const AutoActionSet& s, AutoAction a)
{
    for (u32 i = 0; i < s.count; ++i)
    {
        if (s.actions[i] == a)
        {
            return true;
        }
    }
    return false;
}

void RemoveAction(AutoActionSet& s, AutoAction a)
{
    u32 w = 0;
    for (u32 i = 0; i < s.count; ++i)
    {
        if (s.actions[i] != a)
        {
            s.actions[w] = s.actions[i];
            s.rules[w] = s.rules[i];
            ++w;
        }
    }
    s.count = w;
}

// Output index this action maps to, or -1 if it is not a learned output
// (e.g. SecurityEscalate / the Sched* bias triplet stay rule-driven).
int OutputIndexFor(AutoAction a)
{
    for (int k = 0; k < kNetOut; ++k)
    {
        if (kNetActionMap[k].action == a)
        {
            return k;
        }
    }
    return -1;
}

// Forward pass through the learned net, capturing the hidden activations
// (the fixed imitation feature map — identical in g_net and kImitation)
// for credit assignment, and gating each output into a proposal set.
AutoActionSet ForwardGate(const AutoInputs& in, i32 hidden_out[kNetHidden])
{
    i32 feat[kNetIn];
    ExtractFeatures(in, feat);

    // Layer 1 (fixed detectors) — same math as NetForward, but we retain
    // the hidden vector for the learning update.
    for (int j = 0; j < kNetHidden; ++j)
    {
        i64 acc = 0;
        for (int i = 0; i < kNetIn; ++i)
        {
            acc += static_cast<i64>(feat[i]) * static_cast<i64>(g_net.w1[i][j]);
        }
        const i32 pre = static_cast<i32>(acc >> kQWeight) + g_net.b1[j];
        hidden_out[j] = pre > 0 ? pre : 0; // ReLU
    }

    // Layer 2 (learned) -> logits -> per-action gate.
    AutoActionSet s = {};
    for (int k = 0; k < kNetOut; ++k)
    {
        i64 acc = 0;
        for (int j = 0; j < kNetHidden; ++j)
        {
            acc += static_cast<i64>(hidden_out[j]) * static_cast<i64>(g_net.w2[j][k]);
        }
        const i32 logit = static_cast<i32>(acc >> kQWeight) + g_net.b2[k];
        if (logit > kGateThreshold)
        {
            Push(s, kNetActionMap[k].rule, kNetActionMap[k].action);
        }
    }
    return s;
}

i16 ClampW2(i32 v)
{
    if (v > kW2Clamp)
    {
        return kW2Clamp;
    }
    if (v < -kW2Clamp)
    {
        return static_cast<i16>(-kW2Clamp);
    }
    return static_cast<i16>(v);
}

i32 ClampB2(i32 v)
{
    if (v > kB2Clamp)
    {
        return kB2Clamp;
    }
    if (v < -kB2Clamp)
    {
        return -kB2Clamp;
    }
    return v;
}

} // namespace

AutoActionSet NeuralPolicyDecide(const AutoInputs& in)
{
    // Pure proposal (shadow mode + the boot self-test): forward the
    // learned net, gate, discard the hidden vector (no learning here).
    i32 hidden[kNetHidden];
    return ForwardGate(in, hidden);
}

AutoActionSet NeuralPolicyDecideLive(const AutoInputs& in, u64 tick)
{
    i32 hidden[kNetHidden];
    const AutoActionSet s = ForwardGate(in, hidden);

    // Retain this decision's hidden activations so the delayed reward can
    // credit-assign the update to exactly the synapses that produced it.
    LearnCtx& c = g_ctx[g_ctx_head % kLearnCtxRing];
    ++g_ctx_head;
    c.tick = tick;
    c.used = true;
    for (int j = 0; j < kNetHidden; ++j)
    {
        c.hidden[j] = hidden[j];
    }
    return s;
}

void NeuralPolicyReward(u64 decision_tick, AutoAction action, int reward)
{
    const int k = OutputIndexFor(action);
    if (k < 0)
    {
        return; // not a learned output — nothing to credit
    }

    // Circuit breaker tracks the raw outcome run, independent of whether
    // a hidden context still survives in the ring.
    if (reward < 0)
    {
        if (++g_consec_worsened[k] >= kBreakerTrip)
        {
            g_breaker_until[k] = decision_tick + kBreakerCooldownTicks;
        }
    }
    else
    {
        g_consec_worsened[k] = 0;
    }

    // Find the decision context for this tick. If it aged out of the ring
    // we can't credit-assign — the breaker still updated above.
    const LearnCtx* ctx = nullptr;
    for (u32 i = 0; i < kLearnCtxRing; ++i)
    {
        if (g_ctx[i].used && g_ctx[i].tick == decision_tick)
        {
            ctx = &g_ctx[i];
            break;
        }
    }
    if (ctx == nullptr)
    {
        return;
    }

    // Three-factor reward-modulated Hebbian on output column k:
    //   dW2_jk = (reward * h_j) >> kLearnShiftW
    // followed by a decay pull toward the imitation prior — the regularizer
    // that keeps the learned policy from drifting unboundedly off the floor.
    for (int j = 0; j < kNetHidden; ++j)
    {
        const i32 hebb = static_cast<i32>((static_cast<i64>(reward) * ctx->hidden[j]) >> kLearnShiftW);
        i32 w = ClampW2(g_net.w2[j][k] + hebb);
        w += (static_cast<i32>(kImitation.w2[j][k]) - w) >> kDecayShift;
        g_net.w2[j][k] = ClampW2(w);
    }
    i32 b = ClampB2(g_net.b2[k] + reward * kLearnStepB);
    b += (kImitation.b2[k] - b) >> kDecayShift;
    g_net.b2[k] = ClampB2(b);
}

void NeuralPolicyExplore(AutoActionSet& set, u32 epsilon_q16, u32 rand_q16)
{
    if (rand_q16 >= epsilon_q16)
    {
        return; // draw missed — stay on-policy
    }
    // Toggle exactly one learned action's membership. The high bits of the
    // same draw pick which, so the choice is reproducible in host tests.
    const int k = static_cast<int>((rand_q16 >> 4) % static_cast<u32>(kNetOut));
    const AutoAction a = kNetActionMap[k].action;
    if (Contains(set, a))
    {
        RemoveAction(set, a);
    }
    else
    {
        Push(set, kNetActionMap[k].rule, a);
    }
}

bool NeuralPolicyActionBreakerTripped(AutoAction action, u64 now)
{
    const int k = OutputIndexFor(action);
    if (k < 0)
    {
        return false;
    }
    return now < g_breaker_until[k];
}

void NeuralPolicyResetWeights()
{
    g_net = kImitation;
    for (u32 i = 0; i < kLearnCtxRing; ++i)
    {
        g_ctx[i].used = false;
    }
    g_ctx_head = 0;
    for (int k = 0; k < kNetOut; ++k)
    {
        g_consec_worsened[k] = 0;
        g_breaker_until[k] = 0;
    }
}

NetParams NeuralPolicyWeightsSnapshot()
{
    return g_net;
}

u32 NeuralPolicyProposalScan(PolicyProposal* out, u32 cap, bool aggressive)
{
    if (out == nullptr)
    {
        return 0;
    }
    // A proposal is a per-synapse signal: a (detector j -> output k) weight
    // the imitation prior made positive (action fires when detector j is
    // active) that online reward moved against. Shielded reports only the
    // durable flips (driven to/below zero — the action no longer fires
    // there). The firehose (aggressive) also reports any downward drift —
    // an experiment in progress the operator may want to watch live.
    u32 n = 0;
    for (int k = 0; k < kNetOut && n < cap; ++k)
    {
        for (int j = 0; j < kNetHidden && n < cap; ++j)
        {
            const i32 prior = kImitation.w2[j][k];
            const i32 learned = g_net.w2[j][k];
            const i32 limit = aggressive ? prior : 1; // strict: learned <= 0
            if (prior > 0 && learned < limit)
            {
                out[n].action = kNetActionMap[k].action;
                out[n].detector = j;
                out[n].learned = learned;
                out[n].prior = prior;
                ++n;
            }
        }
    }
    return n;
}

} // namespace duetos::env
