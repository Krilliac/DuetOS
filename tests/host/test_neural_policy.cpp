// tests/host/test_neural_policy.cpp
//
// Hosted unit tests for kernel/env/neural_policy.{h,cpp} — the
// fixed-point neural autonomic policy (Slice 2: forward pass + feature
// extraction + imitation-by-construction).
//
// Fixed-point contract (no FPU): features/activations are Q16
// (65536 = 1.0), weights are Q12 (4096 = 1.0); each layer accumulates
// products in i64 and requantizes by >>12, with a ReLU hidden layer.
//
// Slice 2 pins (this file grows as the slice does):
//   - NetForward: matmul + >>12 requantize + ReLU, hand-verifiable on a
//     known identity net.

#include "host_test_helper.h"

#include "env/neural_policy.h"

using duetos::i32;
using duetos::u32;
using duetos::u64;
using duetos::env::AutoAction;
using duetos::env::AutoActionSet;
using duetos::env::AutoInputs;
using duetos::env::ExtractFeatures;
using duetos::env::kBreakerCooldownTicks;
using duetos::env::kBreakerTrip;
using duetos::env::kNetHidden;
using duetos::env::kNetIn;
using duetos::env::kNetOut;
using duetos::env::kW2Clamp;
using duetos::env::NetForward;
using duetos::env::NetParams;
using duetos::env::NeuralPolicyActionBreakerTripped;
using duetos::env::NeuralPolicyDecide;
using duetos::env::NeuralPolicyDecideLive;
using duetos::env::NeuralPolicyExplore;
using duetos::env::NeuralPolicyProposalScan;
using duetos::env::NeuralPolicyResetWeights;
using duetos::env::NeuralPolicyReward;
using duetos::env::NeuralPolicyWeightsSnapshot;
using duetos::env::PolicyProposal;

int main()
{
    // ----- NetForward: identity net ------------------------------
    // w1 = w2 = identity·1.0 (Q12 4096 on the diagonal), biases 0.
    // Then hidden_j = ReLU(x_j) and logit_k = hidden_k, so the net is
    // an elementwise ReLU. Verifies the matmul, the >>12 requantize,
    // and that ReLU clamps the negative input to 0.
    {
        NetParams p = {};
        for (int d = 0; d < kNetIn && d < kNetHidden; ++d)
        {
            p.w1[d][d] = 4096; // 1.0 in Q12
        }
        for (int d = 0; d < kNetHidden && d < kNetOut; ++d)
        {
            p.w2[d][d] = 4096;
        }

        const i32 feat[kNetIn] = {32768, -16384, 131072}; // 0.5, -0.25, 2.0 (Q16)
        i32 logits[kNetOut] = {};
        NetForward(p, feat, logits);

        EXPECT_EQ(logits[0], 32768);  // ReLU(0.5)  = 0.5
        EXPECT_EQ(logits[1], 0);      // ReLU(-0.25) = 0  (clamped)
        EXPECT_EQ(logits[2], 131072); // ReLU(2.0)  = 2.0
    }

    // ----- ExtractFeatures: normalized Q16 features --------------
    {
        AutoInputs in = {};
        in.free_frames = 50u;
        in.total_frames = 1000u;
        in.thermal_throttle = false;
        in.cpu_online = 4u;
        in.loadavg_1min_q11 = 0u;

        i32 feat[kNetIn] = {};
        ExtractFeatures(in, feat);
        EXPECT_EQ(feat[0], (50 << 16) / 1000); // 0.05 free-fraction (Q16)
        EXPECT_EQ(feat[1], 0);                 // not thermal
        EXPECT_EQ(feat[2], 0);                 // no load

        in.thermal_throttle = true;
        ExtractFeatures(in, feat);
        EXPECT_EQ(feat[1], 65536); // thermal = 1.0 (Q16)

        // load-per-cpu: loadavg 8.0 (Q11) / 4 cpus = 2.0 -> Q16 131072.
        in.thermal_throttle = false;
        in.loadavg_1min_q11 = 16384u; // 8.0 in Q11
        ExtractFeatures(in, feat);
        EXPECT_EQ(feat[2], 131072);

        // Degenerate total_frames==0 -> "full free" so mem never false-fires.
        in.total_frames = 0u;
        ExtractFeatures(in, feat);
        EXPECT_EQ(feat[0], 65536);

        // load-per-cpu cap at 16.0 (Q16 1048576).
        AutoInputs hot = {};
        hot.total_frames = 1000u;
        hot.free_frames = 900u;
        hot.cpu_online = 4u;
        hot.loadavg_1min_q11 = 4u * 2048u * 100u; // per-cpu 100.0
        ExtractFeatures(hot, feat);
        EXPECT_EQ(feat[2], 16 * 65536);
    }

    // ----- Imitation: NeuralPolicyDecide == rule level-predicates ---
    // The net (hand-init by construction) must reproduce the discretionary
    // rules' level conditions: MemReclaim <= free<10%, FootprintTrim <=
    // thermal, ForceHealthScan <= thermal OR load-per-cpu>1. Each vector
    // isolates one detector.
    {
        auto has = [](const AutoActionSet& s, AutoAction a)
        {
            for (u32 i = 0; i < s.count; ++i)
            {
                if (s.actions[i] == a)
                {
                    return true;
                }
            }
            return false;
        };

        AutoInputs healthy = {};
        healthy.free_frames = 900u;
        healthy.total_frames = 1000u;
        healthy.cpu_online = 4u;
        // healthy: 90% free, no thermal, no load -> nothing fires.
        EXPECT_EQ(NeuralPolicyDecide(healthy).count, 0u);

        AutoInputs lowmem = healthy;
        lowmem.free_frames = 50u; // 5% free
        AutoActionSet s = NeuralPolicyDecide(lowmem);
        EXPECT_EQ(s.count, 1u);
        EXPECT_TRUE(has(s, AutoAction::MemReclaim));

        AutoInputs hot = healthy;
        hot.thermal_throttle = true;
        s = NeuralPolicyDecide(hot);
        EXPECT_TRUE(has(s, AutoAction::FootprintTrim));
        EXPECT_TRUE(has(s, AutoAction::ForceHealthScan));
        EXPECT_FALSE(has(s, AutoAction::MemReclaim));

        AutoInputs busy = healthy;
        busy.loadavg_1min_q11 = 4u * 2048u * 2u; // load-per-cpu = 2.0
        s = NeuralPolicyDecide(busy);
        EXPECT_TRUE(has(s, AutoAction::ForceHealthScan));
        EXPECT_FALSE(has(s, AutoAction::FootprintTrim));
        EXPECT_FALSE(has(s, AutoAction::MemReclaim));
    }

    // =================================================================
    // Slice 3 — online three-factor reward-modulated Hebbian learning.
    // Only the output layer (w2/b2) adapts; the hidden detectors (w1/b1)
    // stay the fixed imitation feature map. Reward r in {-1,0,+1} from the
    // delayed feedback outcome; credit-assigned to the synapses of the
    // action that fired, weighted by the decision's hidden activations.
    // Fixed-point is exact, so expected post-weights are computed by hand.
    // =================================================================

    auto has = [](const AutoActionSet& s, AutoAction a)
    {
        for (u32 i = 0; i < s.count; ++i)
        {
            if (s.actions[i] == a)
            {
                return true;
            }
        }
        return false;
    };

    // A canonical low-memory decision: free 5% -> hidden = [3278, 0, 0]
    // (h0 = ReLU(0.10006 - 0.05) in Q16), fires MemReclaim (output k=0).
    AutoInputs lowmem = {};
    lowmem.free_frames = 50u;
    lowmem.total_frames = 1000u;
    lowmem.cpu_online = 4u;

    // ----- Worsened reward pushes the fired synapse down ----------
    // dW2[0][0] = (r*h0) >> kLearnShiftW = (-3278) >> 8 = -13; then decay
    // toward the prior (32767) by (32767-32754)>>6 = 0. b2[0] = -256, then
    // +decay (0-(-256))>>6 = +4 -> -252. Non-firing rows (h1=h2=0) and the
    // other columns (different action) must NOT move (credit assignment).
    {
        NeuralPolicyResetWeights();
        AutoActionSet s = NeuralPolicyDecideLive(lowmem, 100u);
        EXPECT_TRUE(has(s, AutoAction::MemReclaim));

        NeuralPolicyReward(100u, AutoAction::MemReclaim, -1);
        NetParams p = NeuralPolicyWeightsSnapshot();
        EXPECT_EQ(p.w2[0][0], 32754); // moved down by the Hebbian step
        EXPECT_EQ(p.w2[1][0], 0);     // h1==0 -> row unchanged
        EXPECT_EQ(p.w2[2][0], 0);     // h2==0 -> row unchanged
        EXPECT_EQ(p.b2[0], -252);     // bias step + decay
        // Credit assignment: the FootprintTrim/ForceHealthScan columns
        // (k=1,2) were not the rewarded action -> untouched at prior.
        EXPECT_EQ(p.w2[1][1], 32767);
        EXPECT_EQ(p.w2[2][2], 32767);
        EXPECT_EQ(p.b2[1], 0);
        EXPECT_EQ(p.b2[2], 0);
    }

    // ----- Improved reward at the clamp stays clamped -------------
    // Prior w2[0][0]=32767 (i16 max). +Hebbian (+12) overflows the clamp;
    // it must saturate at +kW2Clamp, never wrap.
    {
        NeuralPolicyResetWeights();
        (void)NeuralPolicyDecideLive(lowmem, 100u);
        NeuralPolicyReward(100u, AutoAction::MemReclaim, +1);
        NetParams p = NeuralPolicyWeightsSnapshot();
        EXPECT_EQ(p.w2[0][0], 32767); // clamp held at the upper bound
    }

    // ----- A persistently-Worsening action is learned away -------
    // High load (per-cpu 8.0) fires ForceHealthScan (k=2) via h2=458752.
    // Repeated Worsened drives w2[2][2] negative; the clamp floors it at
    // -kW2Clamp (never below), and the learned net stops proposing the
    // action — the box taught itself to quit a move that keeps regressing.
    {
        NeuralPolicyResetWeights();
        AutoInputs busy = {};
        busy.free_frames = 900u;
        busy.total_frames = 1000u;
        busy.cpu_online = 4u;
        busy.loadavg_1min_q11 = 4u * 2048u * 8u; // load-per-cpu 8.0 (Q11)

        EXPECT_TRUE(has(NeuralPolicyDecideLive(busy, 0u), AutoAction::ForceHealthScan));
        for (u64 t = 1u; t <= 60u; ++t)
        {
            (void)NeuralPolicyDecideLive(busy, t);
            NeuralPolicyReward(t, AutoAction::ForceHealthScan, -1);
        }
        NetParams p = NeuralPolicyWeightsSnapshot();
        EXPECT_TRUE(p.w2[2][2] < 0);                            // flipped negative
        EXPECT_TRUE(p.w2[2][2] >= static_cast<i32>(-kW2Clamp)); // clamp floor respected
        EXPECT_FALSE(has(NeuralPolicyDecideLive(busy, 61u), AutoAction::ForceHealthScan));
    }

    // ----- Decay regularizes back toward the imitation prior ------
    // Drive w2[2][2] well below prior with a few high-load Worsened steps
    // (big h2 -> a large gap), then a run of NoChange rewards (r=0, no
    // Hebbian term) must pull it monotonically back up toward the prior.
    {
        NeuralPolicyResetWeights();
        AutoInputs busy = {};
        busy.free_frames = 900u;
        busy.total_frames = 1000u;
        busy.cpu_online = 4u;
        busy.loadavg_1min_q11 = 4u * 2048u * 8u; // load-per-cpu 8.0 (Q11)

        for (u64 t = 0u; t < 5u; ++t)
        {
            (void)NeuralPolicyDecideLive(busy, t);
            NeuralPolicyReward(t, AutoAction::ForceHealthScan, -1);
        }
        const i32 drifted = NeuralPolicyWeightsSnapshot().w2[2][2];
        EXPECT_TRUE(drifted < 32767);
        for (u64 t = 100u; t < 105u; ++t)
        {
            (void)NeuralPolicyDecideLive(busy, t);
            NeuralPolicyReward(t, AutoAction::ForceHealthScan, 0);
        }
        const i32 recovered = NeuralPolicyWeightsSnapshot().w2[2][2];
        EXPECT_TRUE(recovered > drifted); // decay climbing back toward prior
        EXPECT_TRUE(recovered <= 32767);  // never past the prior
    }

    // ----- A reward for an unrecorded decision is a no-op --------
    // No DecideLive at this tick -> no hidden context to credit -> weights
    // unchanged. Guards the ring-miss path.
    {
        NeuralPolicyResetWeights();
        const NetParams before = NeuralPolicyWeightsSnapshot();
        NeuralPolicyReward(99999u, AutoAction::MemReclaim, -1);
        const NetParams after = NeuralPolicyWeightsSnapshot();
        EXPECT_EQ(after.w2[0][0], before.w2[0][0]);
        EXPECT_EQ(after.b2[0], before.b2[0]);
    }

    // ----- Determinism: same weights + inputs -> same decision ---
    {
        NeuralPolicyResetWeights();
        const AutoActionSet a = NeuralPolicyDecideLive(lowmem, 1u);
        const AutoActionSet b = NeuralPolicyDecideLive(lowmem, 2u);
        EXPECT_EQ(a.count, b.count);
        EXPECT_TRUE(has(a, AutoAction::MemReclaim) == has(b, AutoAction::MemReclaim));
    }

    // ----- Epsilon-greedy exploration is bounded & deterministic --
    // epsilon=0 never perturbs the set; a forced draw (rand < epsilon)
    // toggles exactly one gate so the engine can sample an off-policy move.
    {
        NeuralPolicyResetWeights();
        AutoActionSet base = NeuralPolicyDecideLive(lowmem, 1u);
        AutoActionSet keep = base;
        NeuralPolicyExplore(keep, 0u, 0xFFFFu); // epsilon 0 -> no exploration
        EXPECT_EQ(keep.count, base.count);

        AutoActionSet flip = base;
        NeuralPolicyExplore(flip, 0xFFFFu, 0u); // epsilon max, draw hits -> flip
        EXPECT_NE(flip.count, base.count);
    }

    // ----- Circuit breaker trips after consecutive Worsened ------
    // kBreakerTrip consecutive Worsened on one action trips its breaker
    // for the cooldown window; an Improved resets the run; a peer action
    // is unaffected; the trip lapses once the cooldown elapses.
    {
        NeuralPolicyResetWeights();
        for (u64 t = 0u; t < kBreakerTrip; ++t)
        {
            (void)NeuralPolicyDecideLive(lowmem, t);
            NeuralPolicyReward(t, AutoAction::MemReclaim, -1);
        }
        const u64 trip_tick = kBreakerTrip;
        EXPECT_TRUE(NeuralPolicyActionBreakerTripped(AutoAction::MemReclaim, trip_tick));
        EXPECT_FALSE(NeuralPolicyActionBreakerTripped(AutoAction::ForceHealthScan, trip_tick));
        // Cooldown lapses -> breaker re-opens.
        EXPECT_FALSE(NeuralPolicyActionBreakerTripped(AutoAction::MemReclaim, trip_tick + kBreakerCooldownTicks + 1u));
    }

    // ----- Proposal scan surfaces a gate the learner abandoned ----
    // Pristine weights propose nothing. After the learner drives a gate
    // non-positive (ForceHealthScan under sustained high load), the scan
    // reports it as a reviewable proposal for the fix journal (DD#016).
    {
        NeuralPolicyResetWeights();
        PolicyProposal pr[8];
        EXPECT_EQ(NeuralPolicyProposalScan(pr, 8u, false), 0u);
        EXPECT_EQ(NeuralPolicyProposalScan(pr, 8u, true), 0u);

        AutoInputs busy = {};
        busy.free_frames = 900u;
        busy.total_frames = 1000u;
        busy.cpu_online = 4u;
        busy.loadavg_1min_q11 = 4u * 2048u * 8u;

        // After a SINGLE Worsened the gate has only drifted (not flipped):
        // the firehose (aggressive) surfaces it; the shielded scan does not.
        (void)NeuralPolicyDecideLive(busy, 0u);
        NeuralPolicyReward(0u, AutoAction::ForceHealthScan, -1);
        EXPECT_EQ(NeuralPolicyProposalScan(pr, 8u, false), 0u);
        EXPECT_TRUE(NeuralPolicyProposalScan(pr, 8u, true) >= 1u);

        // Sustained Worsened drives a full flip — now the shielded scan
        // reports the durable proposal too.
        for (u64 t = 1u; t < 60u; ++t)
        {
            (void)NeuralPolicyDecideLive(busy, t);
            NeuralPolicyReward(t, AutoAction::ForceHealthScan, -1);
        }
        const u32 n = NeuralPolicyProposalScan(pr, 8u, false);
        EXPECT_TRUE(n >= 1u);
        bool found = false;
        for (u32 i = 0; i < n; ++i)
        {
            if (pr[i].action == AutoAction::ForceHealthScan)
            {
                found = true;
                EXPECT_TRUE(pr[i].learned <= 0);
                EXPECT_TRUE(pr[i].prior > 0);
            }
        }
        EXPECT_TRUE(found);
    }

    return duetos_host_test::finish_main("test_neural_policy");
}
