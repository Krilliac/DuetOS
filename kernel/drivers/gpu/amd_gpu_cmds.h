#pragma once

#include "drivers/gpu/gpu.h"
#include "util/types.h"

/*
 * DuetOS — AMD GFX9+ PM4 command encoders.
 *
 * The CP (Command Processor) executes PM4 packets. The amd_gpu CP ring
 * is already programmed (CP_RB0_BASE/CNTL read-back verified), but the
 * CP cannot run a single packet until microcode (PFP/ME/CE) is uploaded
 * — that upload (streaming the firmware-blob dwords to
 * mmCP_*_UCODE_DATA) is the next gated slice. These encoders are the
 * PM4 vocabulary that microcode-loaded CP will execute.
 *
 * Encoders are proven at COMPILE time (static_assert) against values
 * derived from the amdgpu soc15d.h macro expressions — a wrong shift
 * fails the build. The dispatch (a gated PM4 probe) belongs in
 * amd_gpu.cpp with the CP ring statics and is real-hardware-only
 * (QEMU has no AMD GPU model). Works on GFX9 / GFX10 / GFX10.3, which
 * accept UNSIGNED microcode without PSP; GFX11+ needs PSP.
 */

namespace duetos::drivers::gpu::amd
{

// PM4 type-3 packet header: bits[31:30]=type(3), bits[29:16]=count,
// bits[15:8]=opcode, bits[7:0]=predicate/shadow. `count` = (body
// dwords - 1) per the amdgpu convention.
inline constexpr u32 kPacket3Type = 3u << 30;
inline constexpr u32 kPacket3Nop = 0x10;
inline constexpr u32 kPacket3WriteData = 0x37;

constexpr u32 EncodePacket3(u32 opcode, u32 count)
{
    return kPacket3Type | ((count & 0x3FFFu) << 16) | ((opcode & 0xFFu) << 8);
}

// WRITE_DATA DWORD-1 control fields (soc15d.h): DST_SEL<<8 (5=memory),
// WR_CONFIRM=1<<20, ENGINE_SEL<<30 (0=ME). For a memory write from ME
// with write-confirm.
inline constexpr u32 kWriteDataDstSelMem = 5u;
inline constexpr u32 kWriteDataWrConfirm = 1u << 20;
inline constexpr u32 kWriteDataEngineMe = 0u;
inline constexpr u32 kWriteDataControlMemMe =
    (kWriteDataDstSelMem << 8) | kWriteDataWrConfirm | (kWriteDataEngineMe << 30);

// A WRITE_DATA packet writing one DWORD `value` to 64-bit GPU address
// `dst`. 5 body dwords (header + control + addr_lo + addr_hi + data) →
// count = 5 - 2 = 3.
struct WriteDataPacket
{
    u32 dw[5];
};

constexpr WriteDataPacket EncodeWriteData(u64 dst, u32 value)
{
    return {{EncodePacket3(kPacket3WriteData, 3), kWriteDataControlMemMe, static_cast<u32>(dst & 0xFFFFFFFFu),
             static_cast<u32>((dst >> 32) & 0xFFFFFFFFu), value}};
}

// Pure boot self-test of the PM4 encoders. Device-independent; PASSes
// under QEMU. Emits `[gpu/amd/cmds] selftest PASS`.
void AmdGpuCmdsSelfTest();

} // namespace duetos::drivers::gpu::amd
