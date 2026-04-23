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

// Max user-page mappings per address space. Bumped from 32 → 128
// so a real-world PE (e.g. windows-kill.exe: 8 sections, 100
// imports, 16 heap pages) fits without hitting the region-table
// cap. 128 × 16 bytes/region = 2 KiB per AS — still cheap, and
// well under a page so the fixed-size table stays on the AS
// struct. Workloads beyond this still panic the loader, which is
// the behaviour we want while the region table is flat.
inline constexpr u64 kMaxUserVmRegionsPerAs = 128;

// Default frame budgets for the two canonical profiles. A new AS is
// created with one of these (or a caller-supplied value) and
// AddressSpaceMapUserPage refuses to install a new mapping once the
// AS's region_count meets the budget. The budget bounds how many
// 4 KiB user frames the process can own — a DoS-prevention layer
// on top of the fixed-size region table.
//
// kFrameBudgetSandbox = 8:
//   Enough for a code page + stack page + a handful of heap/shared
//   pages. Untrusted PE images that legitimately need more pages
//   get a custom larger budget at spawn time; no runtime request
//   path exists today.
//
// kFrameBudgetTrusted = kMaxUserVmRegionsPerAs:
//   The full region table is allowed. Kernel-shipped userland
//   runs under this profile.
inline constexpr u64 kFrameBudgetSandbox = 8;
inline constexpr u64 kFrameBudgetTrusted = kMaxUserVmRegionsPerAs;

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

    // Maximum number of user frames this AS is allowed to own.
    // MapUserPage rejects new mappings once region_count reaches
    // this budget, returning false to the caller (or panicking in
    // the v0 "panics on failure" API). Set at create time and
    // immutable — a process's policy can't be widened after it
    // starts running.
    u64 frame_budget;

    // User-VM region table. Bounded by kMaxUserVmRegionsPerAs (the
    // fixed-size array capacity); the AS's frame_budget caps usage
    // within that array to an even smaller number for untrusted
    // processes. Destroy walks the first `region_count` entries.
    u8 region_count;
    AddressSpaceUserRegion regions[kMaxUserVmRegionsPerAs];
};

/// Allocate a fresh AS with a zeroed user half and the kernel half
/// copied from the boot PML4. `frame_budget` caps how many user
/// frames this AS can map (via AddressSpaceMapUserPage); pick
/// `kFrameBudgetSandbox` for untrusted callers or
/// `kFrameBudgetTrusted` for kernel-shipped userland. Returns
/// nullptr on frame-allocator or kheap failure (no panic — callers
/// may want to refuse the process spawn cleanly).
AddressSpace* AddressSpaceCreate(u64 frame_budget);

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

/// Reverse of MapUserPage. Finds the `(virt, frame)` pair in the
/// regions table, clears the leaf PTE, returns the backing frame
/// to the physical allocator, and drops the region bookkeeping
/// entry. Returns true if the page was mapped in this AS and has
/// been released, false if `virt` was not one of this AS's
/// user-region entries (already unmapped, never mapped, or belongs
/// to a different AS). `virt` must be 4 KiB-aligned.
///
/// Safe to call on `as` whether or not it's currently active: the
/// kernel direct-map alias writes the PTE; TLB invalidation is
/// emitted only for the active CPU when `as` is the active AS.
bool AddressSpaceUnmapUserPage(AddressSpace* as, u64 virt);

/// Reverse of MapUserPage: given a user VA, return the physical
/// frame backing its containing page, or kNullFrame if unmapped.
/// Walks the AS's `regions` array (small N, linear scan). Used
/// by the PE loader to patch IAT slots from the kernel side
/// without touching page-table flags — the kernel's direct map
/// is always writable, so `PhysToVirt(LookupUserFrame(...))` is
/// the shortest path to "modify this page that's currently RO
/// in the user's view."
PhysAddr AddressSpaceLookupUserFrame(const AddressSpace* as, u64 virt);

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

/// Boot-time self-test: create two ASes, map a unique user page in
/// AS-A, verify the page is REACHABLE in AS-A's tables and
/// UNREACHABLE in AS-B's tables, and verify that
/// AddressSpaceActivate flips CR3 to the correct PML4 physical
/// address for each. Panics on any failure. Intended for use
/// during boot only.
///
/// Runs on the kernel's own kernel-half direct-mapped stack — safe
/// to call with interrupts either on or off, as long as no other
/// CPU is simultaneously using the same active-AS slot (single-CPU
/// at boot today).
void AddressSpaceSelfTest();

} // namespace customos::mm
