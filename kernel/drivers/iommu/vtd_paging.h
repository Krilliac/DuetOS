#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Intel VT-d second-level page-table builder (identity passthrough).
 *
 * Allocates the root table, a shared context table, and a shared
 * second-level page-table tree that identity-maps physical memory
 * 1:1 (IOVA == phys). Every device on every bus, by default, sees
 * an IOMMU context that maps any IOVA to the same physical address.
 *
 * Identity passthrough is the conservative default that lets us
 * turn the IOMMU on without breaking any existing DMA: drivers
 * keep handing the device physical addresses as before, and the
 * IOMMU translates them to themselves. The defense gain comes
 * once per-device contexts replace identity mappings — that's a
 * later slice.
 *
 * AGAW choice
 * -----------
 * v0 uses 3-level page tables (39-bit AGAW = bit 1 of SAGAW),
 * which is the only AGAW QEMU's intel-iommu emulator advertises.
 * Real Intel silicon mostly supports 48-bit (4-level) too, but
 * 3-level is sufficient for the 39-bit address space and the
 * lowest common denominator across emulation + hardware. A
 * 4-level fallback for IOMMUs that don't advertise 39-bit is a
 * future slice.
 *
 * Memory cost
 * -----------
 * - 1 root table page (4 KiB; 256 entries indexed by bus 0..255)
 * - 1 shared context table page (4 KiB; 256 entries for dev:func)
 * - 1 shared PDPT page (4 KiB; 512 entries, each a 1 GiB
 *   identity-mapping SP=1 leaf)
 *
 * Total: 12 KiB per IOMMU. All 256 root entries point to the SAME
 * context table — spec doesn't forbid this and it cuts the cost
 * from up to 1 MiB.
 *
 * Slice 27c — BUILD AND VERIFY ONLY. No write to any IOMMU
 * register; no GCMD.TE flip. The next slice (27d) does the enable.
 */

namespace duetos::drivers::iommu::vtd_paging
{

// Second-level page-table entry bit layout (Intel VT-d §9.4).
inline constexpr u64 kPteRead = 1ULL << 0;
inline constexpr u64 kPteWrite = 1ULL << 1;
// bits 2..6 reserved at non-root levels
inline constexpr u64 kPtePageSize = 1ULL << 7; // SP — 2 MiB at PD level, 1 GiB at PDPT level

// Root-Table-Entry bit layout (Intel VT-d §9.1).
inline constexpr u64 kRteLowPresent = 1ULL << 0;
// bits 12..63 of the LOW 64-bit word carry the context-table
// physical-page address. RTE is 16 bytes (low + high u64) but only
// the low half is used in legacy mode; high u64 is reserved.

// Context-Table-Entry bit layout (Intel VT-d §9.3).
inline constexpr u64 kCteLowPresent = 1ULL << 0;
inline constexpr u64 kCteLowFpd = 1ULL << 1; // Fault Processing Disable — keep 0
// bits 2..3: Translation Type
//   00 = legacy untranslated through second-level page tables (what we want)
//   01 = translated/untranslated/translation-request all through SLPT
//   10 = pass-through (skip translation entirely; identity)
//   11 = reserved
inline constexpr u64 kCteLowTtUntranslatedSlpt = 0ULL << 2;
inline constexpr u64 kCteLowTtPassThrough = 2ULL << 2;
// bits 12..63 of LOW = SLPT root physical page address
// HIGH 64-bit word: bits 0..2 = AW (Address Width):
//   0 = 30-bit (2-level)
//   1 = 39-bit (3-level)
//   2 = 48-bit (4-level)
//   3 = 57-bit (5-level)
//   4 = 64-bit (reserved)
inline constexpr u64 kCteHighAw3Level = 1ULL;
// bits 8..23 of HIGH = Domain Identifier; 0 is valid as the all-
// devices-share-one-domain id for identity passthrough.

inline constexpr u32 kRootTableEntries = 256;
inline constexpr u32 kContextTableEntries = 256;
inline constexpr u32 kPdptEntries = 512;
inline constexpr u64 kPageBytes = 4096;
inline constexpr u64 kGiB = 1ULL << 30;

struct VtdPagingState
{
    u64 root_table_phys;    // RTADDR value the IOMMU should be programmed with
    u64 context_table_phys; // shared across all 256 root entries
    u64 pdpt_phys;          // shared 2nd-level root (3-level / 39-bit AGAW)
    u32 agaw_levels;        // 3 (we only support 39-bit in v0)
};

/// Allocate the root + context + identity-mapping PDPT and wire
/// them together. Idempotent: a second call returns the same
/// VtdPagingState. Returns OutOfMemory if any of the three frame
/// allocations fails.
::duetos::core::Result<VtdPagingState> VtdPagingInit();

/// Read the current VtdPagingState (after a successful
/// VtdPagingInit). Returns BadState if VtdPagingInit hasn't run
/// (or failed).
::duetos::core::Result<VtdPagingState> VtdPagingGet();

/// Software walk that simulates exactly what the IOMMU hardware
/// would do for a translation request from source-id (bus:dev:func)
/// for IO virtual address `iova`. Returns the translated host
/// physical address. For identity passthrough, walk(b,d,f,iova) ==
/// iova for any (b,d,f) and any iova in the 0..512 GiB window.
/// Returns NotFound if the (bus, dev, func, iova) tuple does not
/// resolve through the cached state.
::duetos::core::Result<u64> VtdWalk(u8 bus, u8 dev, u8 func, u64 iova);

/// Boot-time self-test. Builds (or re-uses) the page tables,
/// walks a handful of (bus, dev, func, iova) tuples chosen to
/// exercise every level transition, and asserts identity.
/// Saves/restores live state so it's safe to call after
/// VtdPagingInit on a real boot. Emits `[vtd-paging-selftest] PASS`.
void VtdPagingSelfTest();

} // namespace duetos::drivers::iommu::vtd_paging
