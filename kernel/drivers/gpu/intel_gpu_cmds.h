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

// ---- 2D BLT engine (legacy blitter, present Gen9–Gen12) -----------
// The cheapest accelerated workload: solid fills + surface copies for
// GDI paint. 2D client = bits 31:29 = 0x2; opcode in bits 28:22. The
// XY_* macros do NOT bake in the DWORD-length field — the caller ORs
// (total_dwords - 2). On Gen8+ the surface base addresses are 48-bit,
// emitted as two DWORDs (lo, hi), so XY_COLOR_BLT is 7 DWORDs and
// XY_SRC_COPY_BLT is 10. (Computed constants below are derived from
// the i915 macro expressions, NOT a third party's hand-arithmetic.)
inline constexpr u32 kXyColorBltCmd = (2u << 29) | (0x50u << 22);   // 0x54000000
inline constexpr u32 kXySrcCopyBltCmd = (2u << 29) | (0x53u << 22); // 0x54C00000
inline constexpr u32 kBltDepth32 = 3u << 24;                        // 0x03000000 (32 bpp)
inline constexpr u32 kBltWriteRgba = 3u << 20;                      // 0x00300000 (write A+RGB)
inline constexpr u32 kBltRopFill = 0xF0u << 16;                     // 0x00F00000 (PATCOPY/solid)
inline constexpr u32 kBltRopSrcCopy = 0xCCu << 16;                  // 0x00CC0000 (SRCCOPY)

struct ColorBltPacket
{
    u32 dw[7];
};

// Solid-fill `argb` into the rect [x1,y1)..[x2,y2) of a 32-bpp linear
// surface at GPU VA `dst_va`, `pitch_bytes` stride. (x2,y2) exclusive.
constexpr ColorBltPacket EncodeColorBlt(u64 dst_va, u32 pitch_bytes, u32 x1, u32 y1, u32 x2, u32 y2, u32 argb)
{
    return {{kXyColorBltCmd | kBltWriteRgba | (7u - 2u), kBltDepth32 | kBltRopFill | (pitch_bytes & 0xFFFFu),
             (y1 << 16) | (x1 & 0xFFFFu), (y2 << 16) | (x2 & 0xFFFFu), static_cast<u32>(dst_va & 0xFFFFFFFFu),
             static_cast<u32>((dst_va >> 32) & 0xFFFFFFFFu), argb}};
}

struct SrcCopyBltPacket
{
    u32 dw[10];
};

// Copy the rect at dst (dx1,dy1)..(dx2,dy2) from src (sx1,sy1), both
// 32-bpp linear surfaces (GPU VAs + byte pitches). Write-channel +
// ROP=SRCCOPY; confirm the exact write-mask on first-HW bring-up.
constexpr SrcCopyBltPacket EncodeSrcCopyBlt(u64 dst_va, u32 dst_pitch, u32 dx1, u32 dy1, u32 dx2, u32 dy2, u64 src_va,
                                            u32 src_pitch, u32 sx1, u32 sy1)
{
    return {{kXySrcCopyBltCmd | kBltWriteRgba | (10u - 2u), kBltDepth32 | kBltRopSrcCopy | (dst_pitch & 0xFFFFu),
             (dy1 << 16) | (dx1 & 0xFFFFu), (dy2 << 16) | (dx2 & 0xFFFFu), static_cast<u32>(dst_va & 0xFFFFFFFFu),
             static_cast<u32>((dst_va >> 32) & 0xFFFFFFFFu), (sy1 << 16) | (sx1 & 0xFFFFu), (src_pitch & 0xFFFFu),
             static_cast<u32>(src_va & 0xFFFFFFFFu), static_cast<u32>((src_va >> 32) & 0xFFFFFFFFu)}};
}

// MI_FLUSH_DW (MI_INSTR 0x26, len 1) — the legacy blitter is cached, so
// a flush is required after a blit before the CPU / scanout reads the
// destination.
inline constexpr u32 kMiFlushDw = (0x26u << 23) | 1u;

// Real-hardware escalation rung 4: GGTT-map an OFFSCREEN 32-bpp
// surface, XY_COLOR_BLT a solid colour into it, MI_FLUSH_DW, then read
// a pixel back over the CPU mapping. Returns the read-back pixel (or
// 0xFFFFFFFF on not-ready / failure). Offscreen — never touches the
// live framebuffer. Gated; real-HW only.
u32 IntelBltColorFillProbe(u32 argb);

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
