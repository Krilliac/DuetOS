#pragma once

#include "mm/frame_allocator.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — memory zones (plan C1 + C1-followup).
 *
 * WHAT
 *   A `Zone` enum + an `AllocateZoneFrame(zone)` API that routes
 *   each request through `AllocateFrameInRange(max_phys)`. The
 *   max_phys ceiling is derived from the zone:
 *     - kZoneDma:    < 16 MiB (legacy ISA DMA window)
 *     - kZoneDma32:  < 4 GiB  (PCIe DMA addressable window)
 *     - kZoneNormal: no ceiling
 *     - kZoneMmio:   reserved enumerator, always returns kNullFrame
 *   The frame allocator's bitmap is shared across all zones — the
 *   constraint is enforced by clamping the highest searched index,
 *   so a Dma frame is genuinely below 16 MiB. Stats track
 *   allocs / frees / oom per zone.
 *
 * WHY
 *   Real DMA-capable drivers (NVMe, AHCI, e1000, USB xHCI all
 *   eventually) need physical memory below the 4 GiB / 16 MiB
 *   bar — which the legacy global allocator cannot promise from
 *   a single bitmap that covers 100% of available RAM without
 *   the in-range clamp this layer added.
 *
 * NOT IN SCOPE
 *   - Buddy allocator inside each zone — comes when a workload
 *     justifies the per-order free-list machinery.
 *   - Per-zone independent bitmaps. The shared bitmap + clamped
 *     search is sufficient at v0 RAM sizes; per-zone bitmaps land
 *     alongside the buddy work if/when a zone genuinely exhausts.
 *   - `kZoneMmio` actually carving out MMIO ranges.
 */

namespace duetos::mm
{

enum class Zone : u32
{
    Dma = 0,    ///< Physical addresses < 16 MiB (legacy ISA DMA).
    Dma32 = 1,  ///< Physical addresses < 4 GiB (most PCIe DMA).
    Normal = 2, ///< Everything else; default for kernel data.
    Mmio = 3,   ///< Reserved — currently never satisfied with RAM.

    Count
};

/// Stable name for a zone. "?" for out-of-range.
const char* ZoneName(Zone z);

/// Allocate one 4 KiB frame from `zone`. v0 forwards to the
/// global frame allocator regardless of zone. Returns
/// `kNullFrame` on out-of-memory; `kZoneMmio` always returns
/// `kNullFrame` (it's a reserved enumerator with no backing).
PhysAddr AllocateZoneFrame(Zone zone);

/// Free a frame previously returned by `AllocateZoneFrame`.
/// Idempotent w.r.t. zone bookkeeping (the frame allocator's
/// own free path runs unchanged).
void FreeZoneFrame(Zone zone, PhysAddr frame);

struct ZoneStats
{
    u64 allocs;
    u64 frees;
    u64 oom; ///< Allocate calls that returned kNullFrame.
};

/// Read per-zone stats. Diagnostic; racy under SMP.
ZoneStats ZoneStatsRead(Zone zone);

/// Boot-time self-test. For each zone:
///   - Allocate a frame, assert non-null (except kZoneMmio).
///   - Free it.
///   - Verify allocs/frees counters advanced.
/// Panics on mismatch.
void ZoneSelfTest();

} // namespace duetos::mm
