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

    arch::SerialWrite("[neural-policy] selftest pass\n");
}

} // namespace duetos::env
