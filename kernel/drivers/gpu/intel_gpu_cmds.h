#pragma once

#include "drivers/gpu/gpu.h"
#include "util/types.h"

/*
 * DuetOS — Intel iGPU command encoders + batch dispatch (Gen9–Gen12).
 *
 * The Render Command Streamer executes a stream of MI (Memory
 * Interface) instructions. Beyond the MI_NOOP / MI_STORE_DWORD_IMM the
 * existing scaffold proves, the next primitive is indirect execution:
 * the ring holds an MI_BATCH_BUFFER_START that points the engine at a
 * separate (GGTT-mapped) batch buffer, runs it to MI_BATCH_BUFFER_END,
 * and returns. A PIPE_CONTROL post-sync write is the completion
 * breadcrumb.
 *
 * The ENCODERS here are pure functions proven at compile time
 * (static_assert) + a device-independent boot self-test — a wrong
 * opcode/bit fails the build. The dispatch (IntelBatchExecProbe, in
 * intel_gpu.cpp where the ring lives) is gated on a live Intel device
 * and unverified on silicon (no Intel model in QEMU).
 */

namespace duetos::drivers::gpu::intel
{

// ---- MI_BATCH_BUFFER_START (Gen8+, 3 DWORDs) ----------------------
// MI_INSTR(0x31, flags=1) → opcode 0x31<<23 with length field 1 (the
// length field is total_dwords - 2). Bit 8 = address-space indicator:
// 0 = GGTT (the kernel-friendly path), 1 = PPGTT. The address is a
// full 48-bit value split lo/hi across DW1/DW2.
inline constexpr u32 kMiBatchBufferStart = (0x31u << 23) | 1u;
inline constexpr u32 kMiBatchPpgtt = 1u << 8;
inline constexpr u32 kMiBatchBufferEnd = 0x0Au << 23;
inline constexpr u32 kMiNoop = 0u;

struct BatchStartPacket
{
    u32 dw[3];
};

constexpr BatchStartPacket EncodeBatchBufferStart(u64 gpu_va, bool ggtt)
{
    return {{kMiBatchBufferStart | (ggtt ? 0u : kMiBatchPpgtt), static_cast<u32>(gpu_va & 0xFFFFFFFFu),
             static_cast<u32>((gpu_va >> 32) & 0xFFFFFFFFu)}};
}

// ---- PIPE_CONTROL post-sync QW write (Gen8+, 6 DWORDs) ------------
// The canonical RCS breadcrumb: write a monotonic seqno to a GGTT
// status address after the pipeline drains, so the CPU can poll it.
// GFX_OP_PIPE_CONTROL(len) = (3<<29)|(3<<27)|(2<<24)|(len-2).
inline constexpr u32 kGfxOpPipeControl6 = (0x3u << 29) | (0x3u << 27) | (0x2u << 24) | (6u - 2u);
inline constexpr u32 kPcQwWrite = 1u << 14;      // post-sync op = write QW
inline constexpr u32 kPcGlobalGttIvb = 1u << 24; // address is a GGTT address
inline constexpr u32 kPcCsStall = 1u << 20;      // stall the CS so the write is ordered

struct PipeControlPacket
{
    u32 dw[6];
};

constexpr PipeControlPacket EncodePipeControlQwWrite(u64 gpu_gtt_addr, u64 value)
{
    return {{kGfxOpPipeControl6, kPcQwWrite | kPcGlobalGttIvb | kPcCsStall,
             static_cast<u32>(gpu_gtt_addr & 0xFFFFFFFFu), static_cast<u32>((gpu_gtt_addr >> 32) & 0xFFFFFFFFu),
             static_cast<u32>(value & 0xFFFFFFFFu), static_cast<u32>((value >> 32) & 0xFFFFFFFFu)}};
}

// Real-hardware escalation rung 3: allocate a batch page, GGTT-map it,
// fill it with [MI_STORE_DWORD_IMM(cookie) ; MI_BATCH_BUFFER_END],
// dispatch it from the ring via MI_BATCH_BUFFER_START (GGTT), poll, and
// return the cookie read back from the (physical) scratch — proving
// GGTT translation + batch dispatch + execution together. Returns
// 0xFFFFFFFF on any failure / not-ready. Gated; real-HW only.
u32 IntelBatchExecProbe(u32 cookie);

// Pure boot self-test of the command encoders. Device-independent;
// PASSes under QEMU. Emits `[gpu/intel/cmds] selftest PASS`.
void IntelGpuCmdsSelfTest();

} // namespace duetos::drivers::gpu::intel
