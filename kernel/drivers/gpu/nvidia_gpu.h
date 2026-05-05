#pragma once

#include "drivers/gpu/gpu.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — NVIDIA GeForce (Turing+) driver scaffold, v0.
 *
 * NVIDIA's modern open-kernel-modules path covers Turing (TU10x,
 * 2018) and later. PMC_BOOT_0 at BAR0+0 has been a stable
 * architecture identifier since NV4 (1998); we read it for
 * diagnostics in `gpu.cpp` and re-read it here for completeness.
 *
 * BAR layout (Turing+):
 *   BAR0  REGS    — register file (16 MiB)
 *   BAR1  FB      — VRAM framebuffer aperture (256 MiB–16 GiB)
 *   BAR3  USERD   — user-mode doorbell pages (256 MiB)
 *
 * v0 scope:
 *   - `Probe(GpuInfo&)` — re-read PMC_BOOT_0 for self-test, then
 *     read PFIFO and PGRAPH base registers to confirm the
 *     engines are decoded. Pure observation.
 *   - `Bringup(GpuInfo&)` — allocate a 4 KiB host-system DMA
 *     buffer that would back a Channel's pushbuffer (PFIFO
 *     channel ring), log the address, return Unsupported.
 *
 * Out of scope (v0):
 *   - GSP firmware loading (NVIDIA's modern drivers run the GPU
 *     System Processor firmware to mediate kernel-driver access).
 *   - Channel allocation / context switching.
 *   - PGRAPH ctxsw register state save/restore.
 *   - Display Engine programming (modeset / cursor / OSD).
 *
 * Context: kernel. `Probe` is called from `gpu::RunVendorProbe`.
 */

namespace duetos::drivers::gpu::nvidia
{

// MMIO offsets we read in v0. All are stable across Turing+.
//
//   PMC_BOOT_0     0x000000 — chipset / arch / impl / revision
//   PMC_INTR_EN_0  0x000140 — top-level interrupt enable
//   PFIFO_INTR     0x002100 — host-channel scheduler interrupt status
//   PFB_PRI_RD     0x100000 — framebuffer subsystem read register
inline constexpr u64 kNvidiaRegPmcBoot0 = 0x000000;
inline constexpr u64 kNvidiaRegPmcIntrEn0 = 0x000140;
inline constexpr u64 kNvidiaRegPfifoIntr = 0x002100;
inline constexpr u64 kNvidiaRegPfbPriRd = 0x100000;

inline constexpr u64 kNvidiaPushbufBytes = 4096;

/// Run the v0 probe: read PMC_BOOT_0, PFIFO and PFB diagnostics,
/// log a one-line summary. The PMC_BOOT_0 read is also done in
/// `gpu.cpp::ProbeNvidiaRegisters` — we re-do it here so the
/// driver's view + the discovery layer's view are independent.
void Probe(GpuInfo& g);

/// v0 ring scaffold. Allocates a 4 KiB pushbuffer DMA region,
/// logs it, frees it, returns Unsupported. Real bring-up needs
/// the GSP firmware loader landed first.
::duetos::core::Result<void> Bringup(GpuInfo& g);

/// True iff a successful Bringup has run.
bool IsBroughtUp();

} // namespace duetos::drivers::gpu::nvidia
