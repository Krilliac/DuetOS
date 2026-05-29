#pragma once

#include "drivers/gpu/gpu.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — AMD Radeon (GFX9+) driver scaffold, v0.
 *
 * AMD's GFX9 family (Vega, 2017) and later (RDNA 1/2/3) share a
 * MMIO register layout where the bulk of the registers live at
 * BAR5 — *not* BAR0 like Intel. BAR0 on these parts is the VRAM
 * framebuffer (multi-GiB), BAR2 is the doorbell aperture, and
 * BAR5 is the register file.
 *
 * BAR layout (GFX9..GFX11):
 *   BAR0  VRAM     — graphics framebuffer (size depends on SKU)
 *   BAR2  DOORBELL — kernel-driver→GPU doorbells (~2 MiB)
 *   BAR5  MMIO     — register file (~256 KiB)
 *
 * Because `gpu.cpp` only maps BAR0 in v0, this driver maps BAR5
 * itself the first time `Probe` runs against an AMD device.
 *
 * v0 scope:
 *   - `Probe(GpuInfo&)` — opportunistically map BAR5, read
 *     `mmGRBM_STATUS` (0x8010, dword) and `mmRLC_GPM_STAT`
 *     (0xC400 / 4) to confirm the GFX engine is alive, log
 *     the architecture identifier, and store the BAR5 pointer
 *     in a per-driver record so a future Bringup can reuse it.
 *     Also probes for the AMD GFX microcode files
 *     (`gfx_pfp.bin` / `gfx_me.bin` / `gfx_ce.bin` / `gfx_mec.bin`
 *     / `gfx_rlc.bin` / `sdma.bin`) under the open-firmware path
 *     policy so the boot log records which blobs the operator
 *     has dropped in; loads are advisory until a MEC firmware
 *     loader lands.
 *   - `Bringup(GpuInfo&)` — allocate a 4 KiB DMA-coherent CP
 *     (Command Processor) ring buffer in Zone::Dma32, program
 *     `mmCP_RB0_BASE` / `mmCP_RB0_BASE_HI` (split the 4 KiB-
 *     aligned ring base >> 8) and `mmCP_RB0_CNTL` (encodes
 *     log2(ring_dwords)-1 + RPTR_WR_ENA so software can manage
 *     RPTR without firmware), then read every register back to
 *     verify the writes stuck. On success the ring buffer is
 *     retained for the lifetime of the boot and `g_brought_up`
 *     flips to true; the CP itself stays inert until microcode
 *     is loaded — this slice gets us to the next gate (firmware
 *     push) without invoking it.
 *
 * Out of scope (v0):
 *   - Microcode push (MEC / PFP / ME / CE / RLC / SDMA). The
 *     ucode blobs are advisory probes only — the CP can't
 *     execute a single PM4 packet without them, so the
 *     "RPTR catches WPTR" liveness check Intel's RCS uses
 *     cannot fire here today.
 *   - VM PageTables / GART programming.
 *   - SMU (power-management coprocessor) interaction.
 *   - SMC interface for clock + voltage scaling.
 *   - DCN / DCE display pipe programming.
 *
 * Context: kernel. `Probe` is called from `gpu::RunVendorProbe`.
 * `Bringup` runs immediately after `Probe` when `mmio_live` is
 * true, mirroring the Intel path.
 */

namespace duetos::drivers::gpu::amd
{

// AMD GFX9+ MMIO register offsets (byte addressing, BAR5 base).
//
//   mmGRBM_STATUS     0x8010 — GRaphics Block Manager status
//                              (CP_BUSY, GFX_BUSY, etc.). 0x40000000
//                              when idle on RDNA2.
//   mmRLC_GPM_STAT    0xC400 — RLC graphics-power-management state
//   mmCP_RB0_CNTL     0xC100 — CP ring buffer 0 control
//                              (size, block, RPTR_WR_ENA)
//   mmCP_RB0_BASE     0xC104 — ring base, bits [39:8] of phys addr
//   mmCP_RB0_BASE_HI  0xC108 — ring base, bits [47:40]
//   mmCP_RB0_RPTR     0xC10C — ring read pointer (advanced by PFP
//                              when firmware is loaded; software-
//                              writable when RPTR_WR_ENA is set)
//   mmCP_RB0_WPTR     0xC114 — ring write pointer (host bumps this
//                              past each submitted packet)
// BAR5 byte offset = (GC_segment_base_dword + reg_dword_offset) * 4
// (SOC15 addressing; Vega10 GC seg0=0x2000, seg1=0xA000). Verified
// against gc_9_0_offset.h on 2026-05-29.
//
// CORRECTION (2026-05-29): the original CNTL/BASE pair below was
// SWAPPED and WPTR was wrong. gc_9_0_offset.h: CP_RB0_BASE=dword 0x1040
// → 0xC100, CP_RB0_CNTL=dword 0x1041 → 0xC104, CP_RB0_WPTR=dword 0x1054
// → 0xC150 (the old 0xC114 = dword 0x1045 is the RPTR_ADDR region, not
// WPTR). GRBM_STATUS=0x8010 and BASE_HI=0xC108 already matched.
// All unverified on silicon (no AMD model in QEMU) but now spec-correct.
inline constexpr u64 kAmdRegGrbmStatus = 0x8010;
inline constexpr u64 kAmdRegRlcGpmStat = 0xC400;
inline constexpr u64 kAmdRegCpRb0Base = 0xC100;   // dword 0x1040
inline constexpr u64 kAmdRegCpRb0Cntl = 0xC104;   // dword 0x1041
inline constexpr u64 kAmdRegCpRb0BaseHi = 0xC108; // dword 0x1042
inline constexpr u64 kAmdRegCpRb0Rptr = 0xC10C;   // dword 0x1043
inline constexpr u64 kAmdRegCpRb0Wptr = 0xC150;   // dword 0x1054

// CP_RB0_CNTL bitfields (GFX9..GFX11 stable layout).
//   RB_SIZE         [5:0]   log2(ring_size_in_dwords) - 1
//                           1024 dwords → 9
//   RB_BLKSZ        [13:8]  log2(block_size_in_dwords) - 1
//                           16 dwords block → 3
//   RB_RPTR_WR_ENA  [16]    1 = software writes to RPTR succeed;
//                           required when no PFP firmware is loaded
//                           or the ring is being inspected by a
//                           non-microcode owner.
inline constexpr u32 kAmdCpRbCntlSizeFor4KiB = 9u; // log2(1024) - 1
inline constexpr u32 kAmdCpRbCntlBlkszFor16Dw = 3u << 8;
inline constexpr u32 kAmdCpRbCntlRptrWrEna = 1u << 16;

// Cap the BAR5 map at 1 MiB. Real register files on GFX9+ are
// ~256 KiB; 1 MiB is plenty of headroom and keeps MMIO arena
// usage modest.
inline constexpr u64 kAmdMmioCap = 1ULL * 1024 * 1024;

inline constexpr u64 kAmdCpRingBytes = 4096;
inline constexpr u64 kAmdCpRingDwords = kAmdCpRingBytes / 4;

// Shared BAR5 register accessors (the AMD driver maps BAR5 itself;
// pass the pointer from MmioRegs()). Bounds-checked against the 1 MiB
// map cap. Used by amd_gpu and amd_cp_ucode.
inline u32 AmdReg32(void* bar5, u64 off)
{
    if (bar5 == nullptr || off + 4 > kAmdMmioCap)
        return 0xFFFFFFFFu;
    return *reinterpret_cast<volatile u32*>(static_cast<u8*>(bar5) + off);
}

inline void AmdReg32Write(void* bar5, u64 off, u32 value)
{
    if (bar5 == nullptr || off + 4 > kAmdMmioCap)
        return;
    *reinterpret_cast<volatile u32*>(static_cast<u8*>(bar5) + off) = value;
}

/// Run the v0 probe: map BAR5, read GRBM_STATUS + RLC_GPM_STAT,
/// log a one-line summary, and probe the firmware-loader for the
/// standard AMD GFX microcode blobs. Stores the BAR5 mapping in
/// driver state for later reuse. Idempotent (subsequent calls
/// reuse the existing map).
void Probe(GpuInfo& g);

/// Bring the CP ring online. Allocates a 4 KiB DMA-coherent ring
/// buffer in Zone::Dma32, programs `mmCP_RB0_BASE` /
/// `mmCP_RB0_BASE_HI` / `mmCP_RB0_CNTL`, and reads each register
/// back. On success `g_brought_up` flips to true, the ring buffer
/// is retained for the lifetime of the boot, and a
/// `[gpu/amd/cp] registers programmed …` summary is logged. On
/// register-decode failure (read-back doesn't match the write)
/// the ring is left disabled (CNTL ← 0), a `kGpuRingBringupFail`
/// probe fires with the readback value, the buffer is freed, and
/// `Unsupported` is returned. Idempotent — a second call after
/// success returns `AlreadyExists` without touching the engine.
::duetos::core::Result<void> Bringup(GpuInfo& g);

/// True iff a successful Bringup has run on at least one AMD
/// device this boot. Note this means "CP register file is
/// programmed and read-back-verified" — NOT "the CP is executing
/// PM4 packets" (that requires MEC / PFP / ME firmware push,
/// which is the next gate after this slice).
bool IsBroughtUp();

/// Diagnostic: kernel pointer to the mapped BAR5 register file,
/// or nullptr if Probe didn't map it. The next slice (firmware
/// loader / ring program) needs this without re-running PCI
/// BAR queries.
void* MmioRegs();

/// Boot self-test. Walks the GPU records discovered by
/// `gpu::GpuInit`; if an AMD display controller is present and
/// `IsBroughtUp()` returned true, emits the structural sentinel
/// `[gpu/amd/cp] selftest PASS (registers programmed,
/// firmware-pending)` that CI greps for. If no AMD controller is
/// present (typical QEMU smoke), emits
/// `[gpu/amd/cp] no AMD device — skipped`. If an AMD controller
/// IS present but bring-up did NOT succeed, emits a FAIL line +
/// fires `kBootSelftestFail`. Never panics — hardware that
/// doesn't expose a working CP today is a documented limitation,
/// not a kernel bug.
void AmdCpRingSelfTest();

} // namespace duetos::drivers::gpu::amd
