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

// 2D BLT. Constants derived from the i915 macro EXPRESSIONS
// (client 0x2<<29, opcode 0x50/0x53<<22, depth 3<<24, ROP 0xF0/0xCC<<16,
// write A+RGB 3<<20) and computed here — a wrong shift fails the build.
static_assert(kXyColorBltCmd == 0x54000000u, "XY_COLOR_BLT client+opcode");
static_assert(kXySrcCopyBltCmd == 0x54C00000u, "XY_SRC_COPY_BLT client+opcode");
static_assert(kMiFlushDw == 0x13000001u, "MI_FLUSH_DW header");
constexpr ColorBltPacket kCbTest = EncodeColorBlt(0x800000ull, 7680u, 10u, 20u, 110u, 70u, 0xFF3366CCu);
static_assert(kCbTest.dw[0] == 0x54300005u, "color_blt BR00 (cmd|rgba|len5)");
static_assert(kCbTest.dw[1] == 0x03F01E00u, "color_blt BR13 (depth32|fill|pitch7680)");
static_assert(kCbTest.dw[2] == 0x0014000Au, "color_blt dst top-left (20,10)");
static_assert(kCbTest.dw[3] == 0x0046006Eu, "color_blt dst bot-right (70,110)");
static_assert(kCbTest.dw[6] == 0xFF3366CCu, "color_blt fill colour");
constexpr SrcCopyBltPacket kScTest =
    EncodeSrcCopyBlt(0x900000ull, 7680u, 100u, 100u, 164u, 164u, 0xA00000ull, 256u, 0u, 0u);
static_assert(kScTest.dw[0] == 0x54F00008u, "src_copy BR00 (cmd|rgba|len8)");
static_assert(kScTest.dw[1] == 0x03CC1E00u, "src_copy BR13 (depth32|srccopy|pitch)");
static_assert(kScTest.dw[7] == 0x100u, "src_copy src pitch");

void IntelGpuCmdsSelfTest()
{
    // Encoders are compile-proven above; emit the grep-able sentinel
    // (and re-check at runtime for completeness).
    const BatchStartPacket bb = EncodeBatchBufferStart(0x01234000ull, /*ggtt=*/true);
    const PipeControlPacket pc = EncodePipeControlQwWrite(0x0ABCD000ull, 0x42ull);
    const ColorBltPacket cb = EncodeColorBlt(0x800000ull, 7680u, 10u, 20u, 110u, 70u, 0xFF3366CCu);
    const bool ok = bb.dw[0] == 0x18800001u && bb.dw[1] == 0x01234000u && kMiBatchBufferEnd == 0x05000000u &&
                    pc.dw[0] == 0x7A000004u && pc.dw[1] == 0x01104000u && cb.dw[0] == 0x54300005u &&
                    cb.dw[1] == 0x03F01E00u && kMiFlushDw == 0x13000001u;
    if (ok)
    {
        arch::SerialWrite(
            "[gpu/intel/cmds] selftest PASS (MI_BATCH_BUFFER_START + PIPE_CONTROL + XY_COLOR_BLT compile-verified)\n");
        return;
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x434Du /* 'CM' */);
    arch::SerialWrite("[gpu/intel/cmds] selftest FAIL (command encoders)\n");
}

} // namespace duetos::drivers::gpu::intel
