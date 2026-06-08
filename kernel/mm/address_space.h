#pragma once

#include "util/types.h"
#include "util/saturating.h"
#include "util/result.h"
#include "mm/frame_allocator.h"
#include "mm/paging.h"
#include "sync/rwlock.h"

/*
 * DuetOS per-process address space — v0.
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

namespace duetos::mm
{

// Hard cap on user-page mappings per address space. Grew 32 → 128 →
// 1024 → 8192 as the userland DLL preload set and real third-party
// PE32 images grew (NetSurf 3.11 is ~20 MiB of sections + 13 preloaded
// DLLs + stack + TEB + proc-env + Win32 thunks page).
//
// The region table is HEAP-ALLOCATED and grown on demand (see the
// `regions` field below): it starts at kInitialRegionCapacity and
// doubles up to the AS's frame_budget, never past this cap. So this
// number bounds the MAXIMUM a single process may reach — NOT a fixed
// per-process cost. A process that maps a handful of pages occupies a
// handful of 16-byte entries, not all 8192. (The prior design stored a
// flat inline 8192-entry array = 128 KiB on EVERY AddressSpace, which
// exhausted the 64 MiB kheap when the boot battery spawned dozens of
// ASes concurrently — see kernel/mm/kheap.h.)
inline constexpr u64 kMaxUserVmRegionsPerAs = 8192;

// Initial heap-allocated capacity of a fresh AS's region table, in
// entries (16 × sizeof(AddressSpaceUserRegion) = 256 bytes). Clamped
// down to frame_budget for tiny-budget sandbox ASes. Grown by doubling
// in AddressSpaceMapUserPage when full.
inline constexpr u16 kInitialRegionCapacity = 16;

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
    // tasks holding this AS. Saturating: a runaway Retain loop (or
    // attacker driving cross-process handle duplication) cannot wrap
    // the counter past 2^64 to zero and trigger a premature
    // teardown. Lifetime arithmetic on a 64-bit counter is
    // astronomical in practice; saturation closes the wrap-to-UAF
    // defense gap regardless.
    util::SatU64 refcount;

    // Maximum number of user frames this AS is allowed to own.
    // MapUserPage rejects new mappings once region_count reaches
    // this budget, returning false to the caller (or panicking in
    // the v0 "panics on failure" API). Set at create time and
    // immutable — a process's policy can't be widened after it
    // starts running.
    u64 frame_budget;

    // User-VM region table. The backing storage is HEAP-ALLOCATED and
    // grows on demand (kInitialRegionCapacity, doubling up to
    // frame_budget / kMaxUserVmRegionsPerAs) — so a process that maps
    // few pages costs few entries, not a flat 128 KiB. The AS's
    // frame_budget caps usage to an even smaller number for untrusted
    // processes. Destroy walks the first `region_count` entries; Release
    // frees the `regions` allocation.
    //
    // u16 (not u8): kMaxUserVmRegionsPerAs is 8192 — well past
    // 255. A 1.29 MiB PE like 7za.exe needs ~325 page mappings
    // for sections alone, plus per-process stack/TEB/heap/preloaded
    // DLLs. With a u8 counter the increment wrapped past 255 and
    // silently overwrote earlier rows; the page tables stayed
    // mapped, but AddressSpaceLookupUserFrame's linear scan over
    // `regions[0..region_count)` lost the early entries (.rdata,
    // IAT) and ResolveImports failed with "IAT slot VA not mapped".
    u16 region_count;
    // Allocated capacity of `regions` in entries (region_count <=
    // region_capacity <= frame_budget <= kMaxUserVmRegionsPerAs).
    u16 region_capacity;
    // Heap-allocated region table (region_capacity entries). Non-null
    // for any live AS; freed by AddressSpaceRelease.
    AddressSpaceUserRegion* regions;

    // Bitmask of CPU ids that currently have THIS AS loaded in CR3.
    // Bit (1u << cpu_id) is set by AddressSpaceActivate when a CPU
    // switches in, cleared when the same CPU switches to a different
    // AS. The TLB shootdown broadcast consults this mask and only
    // IPIs CPUs whose bit is set, avoiding wake-ups on peers that
    // have no cached TLB entries for the target AS. Updates use
    // atomic OR/AND so concurrent activates from different CPUs
    // compose. u32 covers the kMaxCpus=32 cap (acpi/acpi.h); growing
    // past that needs a wider mask.
    volatile u32 active_cpu_mask;
    u8 _pad_acm[4];

    // RwLock for concurrent access to `regions[]` + `region_count`
    // (plan B1-followup, 2026-04-28). Today every AS is owned by a
    // single Task — there's no real concurrency on this table, so
    // the lock is acquired but never contended. The day a Process
    // grows multi-threaded (multiple Tasks per AS), readers (page-
    // fault handlers walking the region list) take it shared while
    // writers (MapUserPage / UnmapUserPage / Destroy) take it
    // exclusive. Default-initialised to unclassified — tagging
    // with a canonical lockdep class IS a follow-up once another
    // RwLock joins the system to compare against.
    sync::RwLock regions_lock;
};

/// Allocate a fresh AS with a zeroed user half and the kernel half
/// copied from the boot PML4. `frame_budget` caps how many user
/// frames this AS can map (via AddressSpaceMapUserPage); pick
/// `kFrameBudgetSandbox` for untrusted callers or
/// `kFrameBudgetTrusted` for kernel-shipped userland. Returns
/// `Err{ErrorCode::OutOfMemory}` on frame-allocator or kheap failure
/// (no panic — callers may want to refuse the process spawn cleanly).
core::Result<AddressSpace*> AddressSpaceCreate(u64 frame_budget);

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

/// Install a leaf PTE for a frame the AS does NOT own — the
/// frame's lifetime is governed by some other ledger (e.g. a
/// Win32 section pool). Same safety checks as MapUserPage
/// (alignment, canonical low half, kPageUser, W^X, no
/// kPageGlobal) but does NOT touch the regions table — the
/// AS-destroy walker won't free this frame, and the AS
/// frame budget isn't consumed.
///
/// Returns true on success. Returns false if `virt` is
/// already mapped (no overwrite). Panics on the same
/// invariant violations as MapUserPage.
///
/// Pairs with AddressSpaceUnmapBorrowedPage. Callers MUST
/// keep their own ledger of the (virt, frame) pairs they
/// installed via this API — there is no kernel-side record.
bool AddressSpaceMapBorrowedPage(AddressSpace* as, u64 virt, PhysAddr frame, u64 flags);

/// Read the frame backing `virt` in `as` by walking the page
/// tables directly — independent of the regions table. Used
/// to identify section views (which install borrowed PTEs not
/// recorded in the regions ledger). Returns kNullFrame when
/// `virt` has no present PTE in `as`. `virt` must be 4 KiB-
/// aligned.
PhysAddr AddressSpaceProbePte(const AddressSpace* as, u64 virt);

/// Reverse of MapBorrowedPage: clear the leaf PTE at `virt`
/// in `as` without touching the regions table and without
/// freeing the backing frame. Returns true if a present
/// PTE was cleared, false if `virt` was already unmapped.
/// TLB invalidation is emitted on the active CPU only when
/// `as` is the active AS.
bool AddressSpaceUnmapBorrowedPage(AddressSpace* as, u64 virt);

/// Rewrite the leaf-PTE flag bits at `virt` in `as` to
/// `new_flags` (the same bit set MapUserPage / MapBorrowedPage
/// take — kPagePresent | kPageUser | kPageWritable | kPageNoExecute
/// in any combination, with the same W^X invariant). Preserves
/// the backing frame; only the protection bits change. Returns
/// true if the page was present and the PTE was rewritten,
/// false if `virt` is unmapped (no PTE to mutate).
///
/// TLB invalidation is emitted on the active CPU only when
/// `as` is the active AS — same contract as MapUserPage.
///
/// Panics on the same invariants MapUserPage enforces:
/// unaligned `virt`, `virt` outside the canonical low half,
/// W^X violation, kPageGlobal set on a user page, kPageUser
/// missing.
bool AddressSpaceProtectUserPage(AddressSpace* as, u64 virt, u64 new_flags);

/// Read the raw leaf PTE at `virt` in `as` (PML4 → PDPT → PD →
/// PT walk). Returns 0 if the page is unmapped (PTE absent or
/// chain broken). The high bits encode flags (Writable / NX /
/// User / etc.) and the middle bits encode the physical frame
/// — same layout the kernel writes via MapUserPage. Used by
/// AddressSpaceFork to re-apply parent flags on the child PTEs
/// without losing per-page protection.
u64 AddressSpaceProbePteRaw(const AddressSpace* as, u64 virt);

/// Duplicate `parent`'s user mappings into a fresh AS. Allocates
/// a new AS via AddressSpaceCreate(parent->frame_budget), walks
/// parent's regions ledger, allocates a fresh frame for each
/// page in the child, copies contents through the kernel
/// direct-map alias, and maps the new frame in the child with
/// the SAME PTE flags the parent's leaf PTE carried (preserves
/// W^X — code stays RX, data stays RW + NX). Returns
/// `Err{ErrorCode::InvalidArgument}` if `parent` is null, or
/// `Err{ErrorCode::OutOfMemory}` on allocation failure (and rolls
/// back any partially-installed child mappings via
/// AddressSpaceRelease before returning the error). Does NOT cover
/// borrowed-page mappings (Win32 sections) — they aren't in
/// the regions ledger; callers that need them must dup them
/// explicitly.
///
/// The caller owns the returned AS — must AddressSpaceRelease
/// it when done.
core::Result<AddressSpace*> AddressSpaceFork(const AddressSpace* parent);

/// Clear every user-region mapping in `as` without releasing
/// the AS itself. Walks `regions[0..region_count)`, unmaps each
/// leaf PTE, frees the backing frame back to the physical
/// allocator, and resets `region_count` to 0.
///
/// Used by execve() — replace the running process's image
/// in-place. PML4/PDPT/PD pages stay; the leaf PT pages are
/// retained so a subsequent ElfLoad can re-populate them.
///
/// Borrowed-page mappings (Win32 sections) are NOT touched —
/// they aren't in the regions ledger. Callers that need to
/// nuke section views must do that separately.
///
/// TLB invalidation on the active CPU when `as` is the active
/// AS — same contract as MapUserPage / UnmapUserPage.
void AddressSpaceClearUserMappings(AddressSpace* as);

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

/// Return the number of 4 KiB user pages currently mapped in `as`.
/// Each page in `region_count` represents exactly one 4 KiB frame.
/// Used by diagnostics (taskman MEM column) to show per-process
/// resident page count without reaching into AS internals.
/// Returns 0 for a null `as` (kernel-only tasks have no user AS).
inline u16 AddressSpaceUserPageCount(const AddressSpace* as)
{
    if (as == nullptr)
        return 0;
    return as->region_count;
}

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

// ---------------------------------------------------------------------------
// TLB shootdown — required for SMP page-protection downgrades and unmaps.
//
// Single-CPU `invlpg` flushes the only TLB that holds the mapping. The
// moment more than one CPU runs in the same AS (or has cached a kernel-
// half mapping that's being unmapped), every page-protection downgrade
// or unmap MUST broadcast an invalidation to those CPUs *before* the
// caller treats the page as no-longer-mapped. Otherwise a remote CPU
// keeps writing through its stale RW TLB entry to a frame that's been
// recycled — a classic UAF on the page granularity.
//
// wiki/security/Linux-CVE-Audit.md class FF.
//
// Today on uniprocessor: shootdown collapses to a local `invlpg` (already
// done by the caller paths). The API exists so the unmap/protect callers
// don't have to grow SMP-awareness scattered through their bodies — they
// call TlbShootdown* once and the helper decides what to do based on
// SmpCpusOnline().
// ---------------------------------------------------------------------------

/// Flush a single virtual address from every CPU's TLB that has `as`
/// active, including the current CPU. Safe to call before SMP comes
/// up — collapses to a local `invlpg` when only the BSP is online.
/// Must be called AFTER the PTE is cleared (or downgraded) in memory;
/// the helper does not synchronise with the page-table mutation.
void TlbShootdownAddr(AddressSpace* as, u64 virt);

/// Flush a contiguous virtual range `[virt, virt + len)`. Same rules
/// as TlbShootdownAddr. Caller is responsible for breaking the range
/// up into page-sized invalidations if the range is large enough that
/// a full CR3 reload would be cheaper — the helper does per-page
/// invlpg only.
void TlbShootdownRange(AddressSpace* as, u64 virt, u64 len);

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

} // namespace duetos::mm
