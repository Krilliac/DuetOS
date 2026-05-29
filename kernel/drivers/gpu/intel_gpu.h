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

// Shared BAR0 MMIO accessors used by every Intel GPU TU (intel_gpu,
// intel_forcewake, …). Bounds-checked against the mapped BAR; a read
// past the map returns all-ones (the dead-decode sentinel), a write
// past it is dropped. `volatile` so the compiler never reorders or
// elides register touches.
inline u32 IntelReg32(const GpuInfo& g, u64 offset)
{
    if (g.mmio_virt == nullptr || offset + 4 > g.mmio_size)
        return 0xFFFFFFFFu;
    return *reinterpret_cast<volatile u32*>(static_cast<u8*>(g.mmio_virt) + offset);
}

inline void IntelReg32Write(const GpuInfo& g, u64 offset, u32 value)
{
    if (g.mmio_virt == nullptr || offset + 4 > g.mmio_size)
        return;
    *reinterpret_cast<volatile u32*>(static_cast<u8*>(g.mmio_virt) + offset) = value;
}

// 64-bit variants — the GGTT page-table (upper half of BAR0) holds
// 64-bit PTEs, written through this same BAR alias.
inline u64 IntelReg64(const GpuInfo& g, u64 offset)
{
    if (g.mmio_virt == nullptr || offset + 8 > g.mmio_size)
        return ~0ull;
    return *reinterpret_cast<volatile u64*>(static_cast<u8*>(g.mmio_virt) + offset);
}

inline void IntelReg64Write(const GpuInfo& g, u64 offset, u64 value)
{
    if (g.mmio_virt == nullptr || offset + 8 > g.mmio_size)
        return;
    *reinterpret_cast<volatile u64*>(static_cast<u8*>(g.mmio_virt) + offset) = value;
}

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

// RCS RING_MI_MODE (ring base 0x2000 + 0x9C). STOP_RING (bit 8) parks
// the command streamer; it must be cleared (un-stopped) before the
// ring will execute. MODE_IDLE (bit 9) reads back the parked state.
// Written through the masked-bit form (upper 16 bits = write-mask).
inline constexpr u64 kIntelRcsMiMode = 0x209C;
inline constexpr u32 kIntelStopRing = 1u << 8;
inline constexpr u32 kIntelModeIdle = 1u << 9;

inline constexpr u64 kIntelRingBytes = 4096; // single-page ring

// MI (Memory Interface) instruction opcodes. The Render Command
// Streamer fetches these from the ring at HEAD and advances HEAD
// one dword at a time as each instruction completes.
//   MI_NOOP            — 1 dword, side-effect-free
//   MI_STORE_DWORD_IMM — 4 dwords on Gen9+ (variant we use):
//                        opcode | (length=2), address (lo), address (hi), data
//                        Stores the literal `data` to the GPA at `(hi<<32)|lo`.
//                        On Gen9+ the canonical encoding stores the high half
//                        to a Bit 22-set "use_global_gtt" address; we pass a
//                        physical address with the GGTT-bypass bit clear,
//                        which the engine treats as a guest-physical store
//                        through the gtt-bypass aperture (same convention the
//                        ring buffer itself uses for RCS_START).
inline constexpr u32 kIntelMiNoop = 0x00000000u;
inline constexpr u32 kIntelMiStoreDwordImm = (0x20u << 23) | (4u - 2u); // opcode 0x20, length=2 dwords

/// Fire one MI_STORE_DWORD_IMM through the RCS that writes
/// `value` to a DMA-coherent scratch dword the driver owns, then
/// bounded-poll HEAD until it catches the new TAIL. On success
/// the scratch dword reads back `value` — concrete proof that
/// the engine is executing real opcodes (not just bumping HEAD
/// for MI_NOOPs, which a wedged engine could also do).
/// Returns the read-back value (or 0xFFFFFFFF on bring-up
/// failure / scratch unavailable / poll timeout).
///
/// Idempotent — the scratch buffer is allocated on first call
/// and retained for the boot. Safe to invoke from the boot
/// self-test, the `gpu` shell command, or a CI smoke harness.
u32 IntelRcsStoreImmProbe(u32 value);

/// Run the v0 probe: liveness reads + arch decode. Populates
/// `g.probe_reg`, `g.mmio_live`, and `g.arch` in-place. Safe even
/// when the BAR map failed (skips the actual read).
void Probe(GpuInfo& g);

/// Bring the Render Command Streamer ring online. Allocates a
/// 4 KiB DMA-coherent ring buffer in Zone::Dma32, programs
/// RCS_HEAD / RCS_TAIL / RCS_START / RCS_CTL, writes a short
/// stream of `MI_NOOP` instructions, and bounded-polls RCS_HEAD
/// until it catches up to RCS_TAIL. On success `g_brought_up`
/// flips to true, the ring buffer is retained for the lifetime
/// of the boot, and `[gpu/intel/rcs] ring online …` is logged.
/// On timeout the ring is disabled, the buffer is freed, a
/// `kGpuRingBringupFail` probe fires (carrying the last-seen
/// RCS_HEAD value as `value`), one `KLOG_WARN` line is emitted,
/// and `Unsupported` is returned. Idempotent — a second call
/// after success returns `AlreadyExists` without poking the
/// engine again.
::duetos::core::Result<void> Bringup(GpuInfo& g);

/// True iff a successful Bringup has run on at least one
/// Intel display controller this boot. Drivers / self-tests
/// gate "do we have a real GPU ring to dispatch to?" against
/// this. Cleared by `GpuShutdown` -> intel-specific reset path
/// when one is added; for v0 the flag stays set for the boot.
bool IsBroughtUp();

/// Boot self-test. Walks the GPU records discovered by
/// `gpu::GpuInit`; if an Intel display controller is present
/// and `IsBroughtUp()` returned true, emits the structural
/// sentinel `[gpu/intel/rcs] selftest PASS (...)` line CI greps
/// for. If no Intel controller is present (typical QEMU smoke),
/// emits `[gpu/intel/rcs] no Intel device — skipped`. If an
/// Intel controller IS present but bring-up did NOT succeed,
/// emits a WARN + fires `kBootSelftestFail` so a regression
/// gets caught on the next clean-boot grep. Never panics —
/// hardware that doesn't expose a working RCS today is a
/// documented limitation, not a kernel bug.
void IntelRcsRingSelfTest();

} // namespace duetos::drivers::gpu::intel
