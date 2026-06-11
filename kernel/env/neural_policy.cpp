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
// positive when true, so a zero threshold reproduces the rule edge.
constexpr i32 kGateThreshold = 0;

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

void Push(AutoActionSet& s, AutoRule r, AutoAction a)
{
    if (s.count < 4u)
    {
        s.rules[s.count] = r;
        s.actions[s.count] = a;
        ++s.count;
    }
}

// Imitation-by-construction weights: the hidden layer is three fixed
// detectors; the output layer routes them to the discretionary actions,
// reproducing the rule level-predicates.
//   h0 = ReLU(0.10 - free_fraction)  -> MemReclaim
//   h1 = ReLU(thermal - 0.5)         -> FootprintTrim, ForceHealthScan
//   h2 = ReLU(load_per_cpu - 1.0)    -> ForceHealthScan
// Slice 3 makes the output layer (w2/b2) adapt online; the hidden
// detectors stay fixed.
// GAP: thresholds are exact only to the Q16 LSB — b1[0]=6554 is 0.100006,
// not 0.10, so a free-fraction in [0.10, 0.100006) disagrees with the
// rule at the sub-LSB boundary. Immaterial off the boundary; revisit if a
// Slice-3 agreement metric needs bit-exact thresholds.
const NetParams& NetImitationParams()
{
    constexpr i16 kBig = 32767; // ~8.0 (Q12) — any positive detector -> decisive logit
    static constexpr NetParams p = {
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
    return p;
}

} // namespace

AutoActionSet NeuralPolicyDecide(const AutoInputs& in)
{
    // Feature extraction -> fixed-point forward pass -> per-action gate.
    // The policy-mode gate and actuation live in PolicyDecide/ShieldApply;
    // this is a pure proposal (no kernel mutation, no actuator touch).
    i32 feat[kNetIn];
    ExtractFeatures(in, feat);

    i32 logits[kNetOut];
    NetForward(NetImitationParams(), feat, logits);

    AutoActionSet s = {};
    for (int k = 0; k < kNetOut; ++k)
    {
        if (logits[k] > kGateThreshold)
        {
            Push(s, kNetActionMap[k].rule, kNetActionMap[k].action);
        }
    }
    return s;
}

} // namespace duetos::env
