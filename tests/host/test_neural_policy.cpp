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
using duetos::env::AutoAction;
using duetos::env::AutoActionSet;
using duetos::env::AutoInputs;
using duetos::env::ExtractFeatures;
using duetos::env::kNetHidden;
using duetos::env::kNetIn;
using duetos::env::kNetOut;
using duetos::env::NetForward;
using duetos::env::NetParams;
using duetos::env::NeuralPolicyDecide;

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

    return duetos_host_test::finish_main("test_neural_policy");
}
