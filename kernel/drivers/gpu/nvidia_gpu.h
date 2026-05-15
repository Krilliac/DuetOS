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
 *   - `Probe(GpuInfo&)` — read PMC_BOOT_0 / _42 / _8 for chip
 *     identification, PMC_INTR_EN_0 / PFIFO_INTR for engine
 *     liveness, PFB_PRI_RD for memory-subsystem decode. Walks the
 *     firmware loader for the GSP-related blobs (`gsp_rm.bin` /
 *     `gsp_log.bin` / `bootloader.bin`) and logs hits. Pure
 *     observation — NOT a single register is written.
 *   - `Bringup(GpuInfo&)` — allocate a 4 KiB host-system DMA
 *     buffer that would back a Channel's pushbuffer (PFIFO
 *     channel ring), log the address, return Unsupported.
 *     Unlike Intel's RCS (no firmware needed for `MI_NOOP`) and
 *     AMD's CP (a few configuration writes are safe without
 *     microcode), NVIDIA Turing+ requires the GSP RPC channel
 *     to be alive before any host-side write to a PFIFO /
 *     PGRAPH register is safe — there is no `MI_NOOP`-equivalent
 *     that bypasses GSP. So the slice stays observe-only until
 *     the GSP loader lands.
 *
 * Out of scope (v0):
 *   - GSP firmware loading + RPC channel (NVIDIA's modern drivers
 *     run the GPU System Processor firmware and talk to it over
 *     a mailbox / RPC ring to mediate every kernel-driver effect
 *     on the engine). The RPC schema is not publicly documented;
 *     the only reference is the open-source `nouveau` driver's
 *     reverse-engineered shim.
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
//   PMC_BOOT_0      0x000000 — chipset / arch / impl / revision
//   PMC_BOOT_42     0x00A100 — chip SKU / publisher metadata
//                              (added in Pascal; stable through
//                              Blackwell). Reads as 0 on pre-
//                              Pascal silicon.
//   PMC_BOOT_8      0x000280 — secondary revision dword
//                              (production stepping)
//   PMC_INTR_EN_0   0x000140 — top-level interrupt enable
//   PFIFO_INTR      0x002100 — host-channel scheduler interrupt
//   PFB_PRI_RD      0x100000 — framebuffer subsystem read register
//   PBUS_INTR_0     0x001100 — bus-controller interrupt status
inline constexpr u64 kNvidiaRegPmcBoot0 = 0x000000;
inline constexpr u64 kNvidiaRegPmcBoot42 = 0x00A100;
inline constexpr u64 kNvidiaRegPmcBoot8 = 0x000280;
inline constexpr u64 kNvidiaRegPmcIntrEn0 = 0x000140;
inline constexpr u64 kNvidiaRegPfifoIntr = 0x002100;
inline constexpr u64 kNvidiaRegPfbPriRd = 0x100000;
inline constexpr u64 kNvidiaRegPbusIntr0 = 0x001100;

inline constexpr u64 kNvidiaPushbufBytes = 4096;

/// Run the v0 probe: read PMC_BOOT_0 / _42 / _8, PFIFO + PFB +
/// PBUS diagnostics, log a one-line summary, and walk the
/// firmware-loader for the standard GSP blob names. The
/// PMC_BOOT_0 read is also done in `gpu.cpp::RunVendorProbe` —
/// we re-do it here so the driver's view and the discovery
/// layer's view are independent.
void Probe(GpuInfo& g);

/// v0 ring scaffold. Allocates a 4 KiB pushbuffer DMA region,
/// logs it, frees it, returns Unsupported. Unchanged from the
/// scaffold shape — every observable side-effect of a real
/// PFIFO channel needs the GSP RPC ring alive, which is the
/// multi-month gate this slice does NOT cross.
::duetos::core::Result<void> Bringup(GpuInfo& g);

/// True iff a successful Bringup has run. Always false today —
/// kept for symmetry with `intel::IsBroughtUp` / `amd::IsBroughtUp`
/// so callers can branch on "do we have a real GPU ring to
/// dispatch to?" with one predicate per vendor.
bool IsBroughtUp();

/// Boot self-test. Walks the GPU records discovered by
/// `gpu::GpuInit`; if an NVIDIA display controller is present,
/// emits the structural sentinel
/// `[gpu/nvidia/gsp] selftest PASS (device present, GSP RPC
/// gated)` — the slice that lands GSP push will flip this to a
/// real "channel alive" check. If no NVIDIA controller is present
/// (typical QEMU smoke), emits `[gpu/nvidia/gsp] no NVIDIA
/// device — skipped`. The sentinel is one of three CI greps for
/// to confirm the per-vendor surface stays alive.
void NvidiaGspSelfTest();

} // namespace duetos::drivers::gpu::nvidia
