#pragma once

#include "mm/frame_allocator.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — memory zones, v0 scaffolding (plan C1).
 *
 * WHAT
 *   A `Zone` enum + a thin `AllocateZoneFrame(zone)` API that
 *   wraps the existing physical frame allocator. Today every
 *   request goes to the same single pool (matches v0
 *   frame_allocator's "single bitmap"); the zone parameter is
 *   recorded in stats but doesn't yet route to a separate
 *   underlying region.
 *
 * WHY
 *   Real DMA-capable drivers (NVMe, AHCI, e1000, USB xHCI all
 *   eventually) need physical memory below the 4 GiB / 16 MiB
 *   bar — which the kernel cannot promise from a single bitmap
 *   that covers 100% of available RAM. Landing the zone API
 *   first lets driver code call `AllocateZoneFrame(kZoneDma32)`
 *   right now; once a real per-zone pool exists, those calls
 *   start being honoured without any driver-side change.
 *
 * SCOPE FOR v0
 *   - 4 zones declared: kZoneDma (<16 MiB), kZoneDma32 (<4 GiB),
 *     kZoneNormal (everything else), kZoneMmio (reserved, never
 *     hands out RAM).
 *   - Forwarder implementation: every zone request allocates
 *     from the global pool. Stats track which zone an
 *     allocation was tagged with so an audit can spot DMA-
 *     starvation patterns.
 *   - Self-test: exercises every zone's allocate/free path
 *     and verifies stats advance.
 *
 * NOT IN SCOPE
 *   - Buddy allocator inside each zone — comes when a workload
 *     justifies the per-order free-list machinery.
 *   - Per-zone bitmaps. Today every zone shares the global
 *     bitmap; per-zone slicing happens at the same time as the
 *     buddy work.
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
