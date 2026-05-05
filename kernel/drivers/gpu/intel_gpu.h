#pragma once

#include "drivers/gpu/gpu.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Intel iGPU (Gen9+) driver scaffold, v0.
 *
 * Intel integrated graphics from Skylake (Gen9, 2015) through
 * Alder Lake (Gen13, 2021) share a register-MMIO layout that's
 * stable enough to scaffold one driver against. The DG2 / Arc
 * discrete cards (Gen12.7) reuse the same register file with a
 * superset of features.
 *
 * BAR layout (Gen9 onwards):
 *   BAR0  GTTMMADR — registers (low 2 MiB) + GTT page-table
 *                    (rest, typically 8 MiB)
 *   BAR2  GMADR    — graphics memory aperture (128 MiB–1 GiB)
 *   BAR4  IOBAR    — VGA I/O backwards-compat (legacy port range)
 *
 * v0 scope:
 *   - `Probe(GpuInfo&)` — register-level identification: read a
 *     handful of dwords from BAR0 to confirm the device is alive
 *     and decode the architecture stepping. Pure observation.
 *   - `Bringup(GpuInfo&)` — allocate a 4 KiB DMA-coherent ring
 *     buffer for the Render Command Streamer (RCS, MMIO 0x2000),
 *     program the ring head/tail/start, fire a NOOP MI command
 *     into the ring as a sanity check, and stop. The ring is
 *     left armed but no real workloads are submitted. The whole
 *     bring-up is gated behind a `kCapDriverIntelGpu` style
 *     check — current call sites do not yet enable real
 *     hardware ring submission, so the function exits early
 *     with `Unsupported` until the register pokes have been
 *     validated on real silicon. The skeleton shows the bring-
 *     up shape so a follow-up slice can fill them in safely.
 *
 * Out of scope (v0):
 *   - Modeset (DDI / display-pipe programming, EDID consumption
 *     beyond what `drivers/gpu/edid.h` already does).
 *   - GTT page-table programming (we'd need a DRM-style virtual
 *     memory manager for guest GPU pointers).
 *   - Power management (RC6, freq scaling, package C-states).
 *   - Per-engine scheduler classes (RCS, BCS, VCS, VECS).
 *
 * Context: kernel. `Probe` is called from `gpu::RunVendorProbe`
 * during `GpuInit`. `Bringup` is gated.
 */

namespace duetos::drivers::gpu::intel
{

// Register offsets we read in v0. All are stable across Gen9..Gen13.
//
//   GEN_INFO        BAR0 + 0x0   — first liveness dword
//   GFX_MODE        BAR0 + 0x229C — RCS engine mode bits
//   PWR_WELL_CTL2   BAR0 + 0x45404 — power-well status
//   FUSE_STRAP      BAR0 + 0x42014 — display fuse + display version
inline constexpr u64 kIntelRegGenInfo = 0x0000;
inline constexpr u64 kIntelRegGfxMode = 0x229C;
inline constexpr u64 kIntelRegFuseStrap = 0x42014;
inline constexpr u64 kIntelRegPwrWellCtl2 = 0x45404;

// Render Command Streamer ring registers (Gen9+ canonical layout).
inline constexpr u64 kIntelRcsTail = 0x2030;  // RCS_TAIL
inline constexpr u64 kIntelRcsHead = 0x2034;  // RCS_HEAD
inline constexpr u64 kIntelRcsStart = 0x2038; // RCS_START (ring buffer GPA)
inline constexpr u64 kIntelRcsCtl = 0x203C;   // RCS_CTL
inline constexpr u32 kIntelRingEnable = 1u << 0;
inline constexpr u32 kIntelRingLengthMask = 0x1FF000u;

inline constexpr u64 kIntelRingBytes = 4096; // single-page ring

/// Run the v0 probe: liveness reads + arch decode. Populates
/// `g.probe_reg`, `g.mmio_live`, and `g.arch` in-place. Safe even
/// when the BAR map failed (skips the actual read).
void Probe(GpuInfo& g);

/// v0 ring scaffold. Allocates a 4 KiB DMA-coherent buffer, logs
/// the would-be ring program (without writing it), and returns
/// NotImplemented unless DUETOS_INTEL_GPU_RING is defined. The
/// scaffold is here so a follow-up slice can flip the build flag,
/// finish the actual register writes, and run a NOOP submission.
::duetos::core::Result<void> Bringup(GpuInfo& g);

/// True iff a successful Bringup has run. v0 always returns false
/// because Bringup currently exits early.
bool IsBroughtUp();

} // namespace duetos::drivers::gpu::intel
