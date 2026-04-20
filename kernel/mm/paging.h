#pragma once

#include "../core/types.h"
#include "frame_allocator.h"

/*
 * CustomOS managed page-table API — v0.
 *
 * Sits on top of the boot PML4 installed by boot.S. Adds 4 KiB-granular
 * mapping for kernel virtual addresses outside the static higher-half
 * direct map, and a kernel MMIO virtual arena for device drivers that
 * need to address registers above 1 GiB of physical RAM (LAPIC at
 * 0xFEE00000, IOAPIC at 0xFEC00000, PCIe BARs, etc.).
 *
 * Memory layout (kernel virtual address space):
 *
 *   0x0000000000000000 .. 0x0000000040000000   identity map (1 GiB, boot only)
 *   ...                                          (low half — userland later)
 *   0xFFFFFFFF80000000 .. 0xFFFFFFFFC0000000   higher-half direct map (1 GiB)
 *   0xFFFFFFFFC0000000 .. 0xFFFFFFFFE0000000   kernel MMIO arena (512 MiB)
 *   0xFFFFFFFFE0000000 .. 0xFFFFFFFFFFFFFFFF   reserved for future use
 *
 * Scope limits that will be fixed in later commits:
 *   - Single global PML4 (the one boot.S installed). No per-process address
 *     spaces yet.
 *   - Cannot remap or split a 2 MiB PS-mapped region — those are the boot
 *     direct map and any attempt to MapPage inside [0..1 GiB] panics.
 *   - Not thread-safe. SMP bring-up will add a mutex. Page-table
 *     manipulation under a spinlock would be too much for v0; the heap
 *     thread-safety story will set the precedent.
 *   - Bump-allocator MMIO arena. UnmapMmio frees the page tables but does
 *     NOT reclaim the virtual range. Fragmentation is bounded by total
 *     driver lifetime, which is "forever" for the boot devices we care
 *     about — fine until proven otherwise.
 *
 * Context: kernel. Init runs once after KernelHeapInit. MapPage/UnmapPage
 * are then safe from any kernel code that is NOT in IRQ context.
 */

namespace customos::mm
{

/// Page-table entry flags (Intel SDM Vol. 3A §4.5).
enum PageFlags : u64
{
    kPagePresent = 1ULL << 0,
    kPageWritable = 1ULL << 1,
    kPageUser = 1ULL << 2,
    kPageWriteThru = 1ULL << 3,
    kPageCacheDisable = 1ULL << 4,
    kPageAccessed = 1ULL << 5,
    kPageDirty = 1ULL << 6,
    kPageHugeOrPat = 1ULL << 7, // PS in PDE/PDPTE; PAT in PTE
    kPageGlobal = 1ULL << 8,
    kPageNoExecute = 1ULL << 63, // requires EFER.NXE (set by us in PagingInit)
};

/// Convenience flag bundles for common kernel uses.
inline constexpr u64 kKernelData = kPagePresent | kPageWritable | kPageNoExecute;
inline constexpr u64 kKernelMmio = kPagePresent | kPageWritable | kPageCacheDisable | kPageNoExecute;
inline constexpr u64 kKernelCode = kPagePresent; // RO + executable

/// Base of the kernel MMIO arena. Distinct from the direct map so that
/// MMIO mappings never collide with (or are overwritten by) direct-map
/// addresses, and so that drivers can sanity-check "this is an MMIO
/// pointer" cheaply with a range comparison.
inline constexpr uptr kMmioArenaBase = 0xFFFFFFFFC0000000ULL;
inline constexpr u64 kMmioArenaBytes = 512ULL * 1024 * 1024;

/// Adopt the boot PML4, enable EFER.NXE so PageNoExecute mappings are
/// honoured, and prime internal bookkeeping. Panics on failure.
void PagingInit();

/// Install a 4 KiB mapping at `virt` for the given physical frame and
/// flags. `kPagePresent` is implied — callers should still pass it for
/// clarity. Allocates intermediate page tables on demand.
///
/// Panics if `virt` is already mapped, if `phys` or `virt` is not
/// 4 KiB-aligned, or if `virt` falls inside a 2 MiB-PS region (the boot
/// direct map). Returns nothing — failure is unrecoverable.
void MapPage(uptr virt, PhysAddr phys, u64 flags);

/// Remove the 4 KiB mapping at `virt`. Issues `invlpg` for the affected
/// page. Does NOT free intermediate page tables (those stay around in
/// case the next MMIO mapping wants the same PD/PT). Does NOT free the
/// physical frame — the caller owns the physical frame.
///
/// No-op (and silent) if `virt` is not currently mapped — drivers tearing
/// down on a path that may have failed mid-init shouldn't have to track
/// exactly which pages they got around to mapping.
void UnmapPage(uptr virt);

/// Map a contiguous physical region for MMIO access. Allocates a virtual
/// range out of the MMIO arena, installs `kKernelMmio` mappings for every
/// 4 KiB page, returns the base virtual address.
///
/// Returns 0 on failure (arena exhausted). `phys` is rounded down to a
/// page boundary; the returned virtual pointer is offset accordingly so
/// that `result + (phys & 0xFFF)` reaches the requested register address.
void* MapMmio(PhysAddr phys, u64 bytes);

/// Tear down a previous MapMmio allocation. The caller passes back the
/// virtual address MapMmio returned and the same byte count. Page tables
/// are left in place (see UnmapPage); the virtual range is not recycled.
void UnmapMmio(void* virt, u64 bytes);

/// Diagnostics counters; cheap (a couple of loads).
struct PagingStats
{
    u64 page_tables_allocated; // PML4/PDPT/PD/PT frames borrowed from the FA
    u64 mappings_installed;    // lifetime MapPage calls that succeeded
    u64 mappings_removed;      // lifetime UnmapPage calls that did anything
    u64 mmio_arena_used_bytes; // bump cursor offset from kMmioArenaBase
};
PagingStats PagingStatsRead();

/// Exercise MapMmio + write/read aliasing + UnmapMmio end-to-end. Prints
/// to COM1 and panics on inconsistency. Boot-time use only.
void PagingSelfTest();

/*
 * User-pointer copy helpers.
 *
 * Every kernel read/write through a user-supplied pointer goes through
 * CopyFromUser / CopyToUser. They validate that the pointer lies inside
 * the canonical low half, reject overflow / boundary-crossing lengths,
 * and — when SMAP is active — gate the actual byte-by-byte copy with
 * stac / clac so the CPU's SMAP check lets through the user access
 * only inside this one helper.
 *
 * Return true on success, false if the pointer is rejected. `len == 0`
 * is a trivial no-op that returns true. Zero-byte buffers aren't an
 * error and neither is a null kernel_dst / kernel_src when len == 0.
 *
 * v0 does NOT catch #PF during the copy: a user pointer that's in
 * range but unmapped (or mapped but pages unreachable) faults and the
 * kernel's trap dispatcher halts. Proper #PF recovery via a fault-
 * fixup table lands with the first syscall that can legitimately
 * trigger it.
 *
 * Context: kernel. Must NOT be called from interrupt context while the
 * current task isn't the one whose address space the user pointer lives
 * in (today there's only one address space, so that's trivially true;
 * the constraint lands with per-process page tables).
 */
bool CopyFromUser(void* kernel_dst, const void* user_src, u64 len);
bool CopyToUser(void* user_dst, const void* kernel_src, u64 len);

} // namespace customos::mm
