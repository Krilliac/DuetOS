/*
 * DuetOS — Intel iGPU command encoders. See intel_gpu_cmds.h.
 *
 * Every encoder is proven at COMPILE time by the static_asserts below
 * — a wrong opcode, shift, or bit fails the build. IntelBatchExecProbe
 * (the dispatch) lives in intel_gpu.cpp with the ring statics and is
 * gated / silicon-unverified.
 */

#include "drivers/gpu/intel_gpu_cmds.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::drivers::gpu::intel
{

// MI_BATCH_BUFFER_START: opcode 0x31, len field 1 (3 dwords).
static_assert(kMiBatchBufferStart == 0x18800001u, "MI_BATCH_BUFFER_START header");
static_assert(EncodeBatchBufferStart(0x01234000ull, /*ggtt=*/true).dw[0] == 0x18800001u, "bb_start ggtt header");
static_assert(EncodeBatchBufferStart(0x01234000ull, /*ggtt=*/true).dw[1] == 0x01234000u, "bb_start addr lo");
static_assert(EncodeBatchBufferStart(((1ull << 32) | 0x01234000ull), true).dw[2] == 0x1u, "bb_start addr hi (48-bit)");
static_assert(EncodeBatchBufferStart(0x01234000ull, /*ggtt=*/false).dw[0] == 0x18800101u, "bb_start ppgtt bit8");
static_assert(kMiBatchBufferEnd == 0x05000000u, "MI_BATCH_BUFFER_END header");

// PIPE_CONTROL post-sync QW write.
static_assert(kGfxOpPipeControl6 == 0x7A000004u, "GFX_OP_PIPE_CONTROL(6) header");
static_assert(EncodePipeControlQwWrite(0x0ABCD000ull, 0x42ull).dw[0] == 0x7A000004u, "pipe_control header");
static_assert(EncodePipeControlQwWrite(0x0ABCD000ull, 0x42ull).dw[1] == 0x01104000u,
              "pipe_control flags (qw|gtt|stall)");
static_assert(EncodePipeControlQwWrite(0x0ABCD000ull, 0x42ull).dw[2] == 0x0ABCD000u, "pipe_control addr lo");
static_assert(EncodePipeControlQwWrite(0x0ABCD000ull, 0x42ull).dw[4] == 0x42u, "pipe_control value lo");

void IntelGpuCmdsSelfTest()
{
    // Encoders are compile-proven above; emit the grep-able sentinel
    // (and re-check at runtime for completeness).
    const BatchStartPacket bb = EncodeBatchBufferStart(0x01234000ull, /*ggtt=*/true);
    const PipeControlPacket pc = EncodePipeControlQwWrite(0x0ABCD000ull, 0x42ull);
    const bool ok = bb.dw[0] == 0x18800001u && bb.dw[1] == 0x01234000u && kMiBatchBufferEnd == 0x05000000u &&
                    pc.dw[0] == 0x7A000004u && pc.dw[1] == 0x01104000u;
    if (ok)
    {
        arch::SerialWrite("[gpu/intel/cmds] selftest PASS (MI_BATCH_BUFFER_START + PIPE_CONTROL compile-verified)\n");
        return;
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x434Du /* 'CM' */);
    arch::SerialWrite("[gpu/intel/cmds] selftest FAIL (command encoders)\n");
}

} // namespace duetos::drivers::gpu::intel
