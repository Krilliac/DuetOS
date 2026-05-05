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
 *   - `Bringup(GpuInfo&)` — allocate a 4 KiB DMA-coherent CP
 *     (Command Processor) ring buffer, log the would-be ring
 *     program, return Unsupported. Real bring-up needs the
 *     Microcode (MEC firmware) blob loaded which we haven't
 *     plumbed.
 *
 * Out of scope (v0):
 *   - Microcode loading (MEC, RLC, SDMA firmware).
 *   - VM PageTables / GART programming.
 *   - SMU (power-management coprocessor) interaction.
 *   - SMC interface for clock + voltage scaling.
 *   - DCN / DCE display pipe programming.
 *
 * Context: kernel. `Probe` is called from `gpu::RunVendorProbe`.
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
inline constexpr u64 kAmdRegGrbmStatus = 0x8010;
inline constexpr u64 kAmdRegRlcGpmStat = 0xC400;
inline constexpr u64 kAmdRegCpRb0Cntl = 0xC100;
inline constexpr u64 kAmdRegCpRb0Base = 0xC104;
inline constexpr u64 kAmdRegCpRb0BaseHi = 0xC108;

// Cap the BAR5 map at 1 MiB. Real register files on GFX9+ are
// ~256 KiB; 1 MiB is plenty of headroom and keeps MMIO arena
// usage modest.
inline constexpr u64 kAmdMmioCap = 1ULL * 1024 * 1024;

inline constexpr u64 kAmdCpRingBytes = 4096;

/// Run the v0 probe: map BAR5, read GRBM_STATUS + RLC_GPM_STAT,
/// log a one-line summary. Stores the BAR5 mapping in driver
/// state for later reuse. Idempotent (subsequent calls reuse the
/// existing map).
void Probe(GpuInfo& g);

/// v0 ring scaffold. Allocates the would-be CP ring buffer,
/// logs the address, frees it, returns Unsupported. The actual
/// CP_RB0 program is left to a follow-up slice that lands the
/// MEC firmware loader.
::duetos::core::Result<void> Bringup(GpuInfo& g);

/// True iff a successful Bringup has run.
bool IsBroughtUp();

/// Diagnostic: kernel pointer to the mapped BAR5 register file,
/// or nullptr if Probe didn't map it. The next slice (firmware
/// loader / ring program) needs this without re-running PCI
/// BAR queries.
void* MmioRegs();

} // namespace duetos::drivers::gpu::amd
