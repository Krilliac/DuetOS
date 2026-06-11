#include "env/neural_policy.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

/*
 * Boot self-test for the imitation neural policy. Kept in its own TU so
 * neural_policy.cpp stays freestanding (the host test links it directly);
 * this TU pulls the kernel-only serial / panic surface.
 */

namespace duetos::env
{

void NeuralPolicySelfTest()
{
    // One unambiguous vector: 5% free, no thermal, no load. The imitation
    // net must propose exactly {MemReclaim} (mem-pressure detector), the
    // on-target echo of tests/host/test_neural_policy.cpp's coverage.
    AutoInputs in = {};
    in.free_frames = 50;
    in.total_frames = 1000;
    in.cpu_online = 4;

    const AutoActionSet s = NeuralPolicyDecide(in);

    bool mem = false;
    for (u32 i = 0; i < s.count; ++i)
    {
        if (s.actions[i] == AutoAction::MemReclaim)
        {
            mem = true;
        }
    }

    if (s.count != 1 || !mem)
    {
        arch::SerialWrite("[neural-policy] MISMATCH lowmem != {MemReclaim}\n");
        core::PanicWithValue("env/neural_policy", "neural-policy self-test mismatch", s.count);
    }

    // Slice-3 learning path — the on-target echo of the host test's reward
    // dynamics, and the only place the in-kernel DecideLive→Reward wiring is
    // exercised deterministically (a live boot only rewards when an action
    // actually Worsens). A Worsened reward on the action that fired must move
    // its output weight down. Restore the imitation prior afterward so the
    // engine starts its first real tick from the baseline.
    NeuralPolicyResetWeights();
    (void)NeuralPolicyDecideLive(in, 1);
    const i16 w_before = NeuralPolicyWeightsSnapshot().w2[0][0];
    NeuralPolicyReward(1, AutoAction::MemReclaim, -1);
    const i16 w_after = NeuralPolicyWeightsSnapshot().w2[0][0];
    NeuralPolicyResetWeights();
    if (!(w_after < w_before))
    {
        arch::SerialWrite("[neural-policy] MISMATCH reward did not move weight\n");
        core::PanicWithValue("env/neural_policy", "neural-policy learn self-test mismatch",
                             static_cast<u64>(static_cast<u32>(w_after)));
    }

    arch::SerialWrite("[neural-policy] selftest pass\n");
}

} // namespace duetos::env
