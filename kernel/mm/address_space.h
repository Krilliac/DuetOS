#pragma once

#include "../core/types.h"
#include "frame_allocator.h"
#include "paging.h"

/*
 * CustomOS per-process address space — v0.
 *
 * An `AddressSpace` owns a PML4 frame and the user-half (PML4 entries
 * 0..255) page-table tree underneath it. The kernel half (entries
 * 256..511) is shared across every address space — at create time we
 * copy the boot PML4's kernel-half entries verbatim, so the new PML4
 * points at the same PDPTs the kernel-half is built on. New kernel-
 * half mappings (MMIO arena growth, heap growth) install PD/PT pages
 * BENEATH those shared PDPTs, so they're visible from every address
 * space without an explicit shootdown.
 *
 * Why this is the foundation of process sandboxing:
 *
 *   The user half of an AS is fully private. A page that isn't mapped
 *   in this AS's PML4 simply does not exist for code running with this
 *   AS active — the CPU's page walker returns "not present" and the
 *   access #PFs. There is no way for ring-3 code to touch another
 *   process's pages because those pages are not in any walk-reachable
 *   table from this PML4. The "the malicious EXE thinks its sandbox is
 *   the entire OS" property falls out for free: the EXE can probe
 *   every byte of the canonical low half (128 TiB) and find only what
 *   we mapped in for it.
 *
 * Lifecycle:
 *
 *   - `AddressSpaceCreate()` allocates a fresh PML4 frame, zeroes the
 *     user half, copies the boot PML4's kernel-half entries.
 *
 *   - `MapUserPage(as, virt, frame, flags)` installs a 4 KiB user-
 *     accessible mapping. `virt` MUST be in the canonical low half;
 *     `flags` MUST include `kPageUser` (panics otherwise — silently
 *     dropping the bit would create a user page the user couldn't
 *     touch, an obvious bug). The (virt, frame) pair is recorded so
 *     `AddressSpaceDestroy` can return the backing frame at teardown.
 *
 *   - `Activate(as)` writes CR3 with the AS's PML4 physical address.
 *     Per-CPU current-AS tracking elides the write when activating
 *     the already-active AS — the common kernel→kernel context
 *     switch hits this fast path.
 *
 *   - `AddressSpaceDestroy(as)` walks the user-region table,
 *     unmaps each page from this AS's PML4, returns each backing
 *     frame to the physical allocator, walks the user-half tables
 *     (PML4[0..255]) freeing intermediate PDPT/PD/PT frames, and
 *     finally frees the PML4 frame. Refcount semantics: each Task
 *     holds one reference; the reaper's release on task death drops
 *     the count, and only the last holder pays the destruction cost.
 *     v0 grows the count to 1 at create and decrements on release;
 *     multi-threaded processes (multiple Tasks per AS) become
 *     possible the day we add an AddressSpaceRetain call.
 *
 * Region table size cap (`kMaxUserVmRegionsPerAs`) bounds bookkeeping
 * to a fixed size on the AS struct so destroy is allocation-free. Any
 * user-mode workload that legitimately needs more (a real PE loader
 * mapping dozens of sections, a heap with hundreds of pages) gets a
 * size bump or a switch to a paged region table — both are
 * mechanical follow-ups behind a panic when the cap is hit.
 *
 * Context: kernel. AS create/map/destroy must NOT run in IRQ context
 * — they touch the kernel heap and the frame allocator, neither of
 * which is IRQ-safe today. AS Activate is safe from any context (a
 * single MOV-to-CR3) and is called from the scheduler's switch path
 * with interrupts disabled.
 */

namespace customos::mm
{

inline constexpr u64 kMaxUserVmRegionsPerAs = 32;

struct AddressSpaceUserRegion
{
    u64 vaddr;      // start of a 4 KiB user page
    PhysAddr frame; // backing frame returned by AllocateFrame
};

struct AddressSpace
{
    PhysAddr pml4_phys; // CR3 value (low 12 bits already zero)
    u64* pml4_virt;     // direct-map alias for kernel-side editing
    u64 refcount;       // tasks holding this AS

    // User-VM region table. Bounded by kMaxUserVmRegionsPerAs;
    // exceeding the cap panics. Destroy walks this table to return
    // every backing frame to the physical allocator.
    u8 region_count;
    AddressSpaceUserRegion regions[kMaxUserVmRegionsPerAs];
};

/// Allocate a fresh AS with a zeroed user half and the kernel half
/// copied from the boot PML4. Returns nullptr on frame-allocator
/// or kheap failure (no panic — callers may want to refuse the
/// process spawn cleanly).
AddressSpace* AddressSpaceCreate();

/// Install a user-accessible 4 KiB mapping at `virt` in `as`. `virt`
/// must be in the canonical low half and 4 KiB-aligned; `flags` must
/// include `kPageUser`. The (virt, frame) pair is recorded for
/// teardown; the caller must NOT separately FreeFrame(frame) — the
/// AS owns it now.
///
/// Panics on: virt in kernel half, virt unaligned, virt already
/// mapped in this AS, kPageUser missing from flags, region table
/// full, or page-table allocation failure.
///
/// IMPORTANT: this writes into `as`'s PML4 directly via the direct-
/// map alias — `as` does NOT need to be the active AS. That's how
/// a parent task on a different AS can populate a child AS before
/// switching the child task in.
void AddressSpaceMapUserPage(AddressSpace* as, u64 virt, PhysAddr frame, u64 flags);

/// Activate `as` by loading its PML4 into CR3 — but only if `as` is
/// not already the active AS on this CPU. Updates the per-CPU
/// current-AS tracker. `as == nullptr` selects the kernel AS (the
/// boot PML4); kernel-only tasks use this so kernel→kernel context
/// switches don't pay a CR3 write.
void AddressSpaceActivate(AddressSpace* as);

/// Currently-active AS on this CPU (nullptr = kernel AS / boot PML4).
AddressSpace* AddressSpaceCurrent();

/// Bump the refcount. Use when handing the AS to another holder
/// (e.g. a future thread spawn that shares the AS). v0 single-Task-
/// per-AS code paths don't need to call this — Create returns with
/// refcount=1 already, which is the count for the spawning task.
void AddressSpaceRetain(AddressSpace* as);

/// Drop a reference. When the last reference goes away, walks the
/// region table to return every backing frame, walks the user-half
/// page tables (PML4[0..255]) freeing intermediate PDPT/PD/PT
/// frames, then frees the PML4 frame itself. After release the
/// caller MUST NOT touch `as` again. nullptr is a no-op (the kernel
/// AS is never released).
void AddressSpaceRelease(AddressSpace* as);

/// Diagnostics — cheap snapshots.
struct AddressSpaceStats
{
    u64 created;      // lifetime AddressSpaceCreate calls that succeeded
    u64 destroyed;    // lifetime AS destructions (refcount hit 0)
    u64 cr3_switches; // lifetime CR3 writes (excludes elided same-AS switches)
    u64 live;         // currently-allocated AS count (created - destroyed)
};
AddressSpaceStats AddressSpaceStatsRead();

} // namespace customos::mm
