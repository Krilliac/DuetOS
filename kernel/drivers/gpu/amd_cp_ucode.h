#pragma once

#include "drivers/gpu/gpu.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — AMD GFX9 CP microcode upload (the gate that makes the CP
 * able to execute PM4). The amd_gpu CP ring is programmed but inert
 * until PFP/CE/ME (and RLC) microcode is loaded.
 *
 * GFX9 / GFX10 / GFX10.3 ship UNSIGNED microcode that the host streams
 * directly through the mmCP_*_UCODE_DATA register pairs — no PSP. (GFX11+
 * microcode is signed and needs PSP-mediated upload — a separate slice.)
 *
 * Register byte offsets are BAR5 = (GC_seg_base + dword_offset) * 4
 * (SOC15; Vega10 seg0=0x2000, seg1=0xA000), verified against
 * gc_9_0_offset.h (2026-05-29). The halt-mask constants are proven at
 * compile time; the upload itself is gated on a live AMD BAR5 and is
 * UNVERIFIED on silicon (no AMD model in QEMU) — it needs a real
 * Vega/Navi card.
 */

namespace duetos::drivers::gpu::amd
{

// Ucode-upload registers (BAR5 byte offsets, GFX9).
inline constexpr u64 kAmdRegCpPfpUcodeAddr = 0x5C050;  // dword 0x5814, seg1
inline constexpr u64 kAmdRegCpPfpUcodeData = 0x5C054;  // dword 0x5815
inline constexpr u64 kAmdRegCpCeUcodeAddr = 0x5C060;   // dword 0x5818
inline constexpr u64 kAmdRegCpCeUcodeData = 0x5C064;   // dword 0x5819
inline constexpr u64 kAmdRegCpMeRamWaddr = 0x5C058;    // dword 0x5816
inline constexpr u64 kAmdRegCpMeRamData = 0x5C05C;     // dword 0x5817
inline constexpr u64 kAmdRegCpMeCntl = 0x86D8;         // dword 0x01B6, seg0
inline constexpr u64 kAmdRegRlcCntl = 0x53000;         // dword 0x4C00, seg1
inline constexpr u64 kAmdRegRlcGpmUcodeAddr = 0x5C0F0; // dword 0x583C
inline constexpr u64 kAmdRegRlcGpmUcodeData = 0x5C0F4; // dword 0x583D

// CP_ME_CNTL halt bits (gc_9_0_sh_mask.h). Halt = set the bit; the CP
// must be halted (all three) before microcode upload, un-halted after.
inline constexpr u32 kAmdCeHalt = 1u << 24;                                 // 0x01000000
inline constexpr u32 kAmdPfpHalt = 1u << 26;                                // 0x04000000
inline constexpr u32 kAmdMeHalt = 1u << 28;                                 // 0x10000000
inline constexpr u32 kAmdCpHaltAll = kAmdCeHalt | kAmdPfpHalt | kAmdMeHalt; // 0x15000000
inline constexpr u32 kAmdRlcEnableF32 = 1u << 0;                            // RLC_CNTL.RLC_ENABLE_F32

// Halt the CP, stream PFP/CE/ME (+ RLC if present) microcode through
// the *_UCODE_DATA registers (ADDR auto-increments from 0; trailing
// version write per engine), then un-halt. Each engine's image is
// loaded via FwLoad + AmdGfxFwParse. Returns Ok iff PFP+CE+ME loaded;
// Err{NotFound} if a required image is missing. Gated; real-HW only.
::duetos::core::Result<void> AmdCpLoadMicrocode(void* bar5);

// Pure boot self-test of the halt-mask constants. Device-independent;
// PASSes under QEMU. Emits `[gpu/amd/ucode] selftest PASS`.
void AmdCpUcodeSelfTest();

} // namespace duetos::drivers::gpu::amd
