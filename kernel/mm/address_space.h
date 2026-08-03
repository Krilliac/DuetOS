#pragma once

#include "util/types.h"
#include "util/saturating.h"
#include "util/result.h"
#include "mm/frame_allocator.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

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
 *     finally frees the PML4 frame. Refcount semantics: a Process owns
 *     one AS reference regardless of how many Tasks share that Process.
 *     Tasks retain the Process, and the Process destructor drops its AS
 *     reference; only the last direct AS owner pays the destruction cost.
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
 *
 * Mutation locking:
 *
 *   - `mutation_lock` is the task-context transaction boundary for
 *     map, unmap, protect, fork, clear, and final teardown. It may span
 *     allocation, frame release, page copying, and TLB-shootdown waits.
 *   - `regions_lock` is the IRQ-saving structural lock. It protects
 *     page-table edits plus the regions pointer/count/capacity, and is
 *     held only for bounded, non-blocking commits or snapshots.
 *   - Lock order is mutation_lock -> regions_lock. Readers take only
 *     regions_lock. No allocator, scheduler, cross-subsystem call, or
 *     TLB IPI wait is allowed while regions_lock is held.
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
// handful of 24-byte entries, not all 8192. (The prior design stored a
// flat inline 8192-entry array = 128 KiB on EVERY AddressSpace, which
// exhausted the 64 MiB kheap when the boot battery spawned dozens of
// ASes concurrently — see kernel/mm/kheap.h.)
inline constexpr u64 kMaxUserVmRegionsPerAs = 8192;

// Initial heap-allocated capacity of a fresh AS's region table, in
// entries (16 × sizeof(AddressSpaceUserRegion) = 384 bytes). Together
// with the initial four-entry reservation ledger (96 bytes), fresh-AS
// ledger storage is 480 bytes. Clamped down to frame_budget for
// tiny-budget sandbox ASes. Grown by doubling in AddressSpaceMapUserPage
// when full.
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

// Borrowed mappings are committed as one bounded page-table transaction.
// A 1024-page cap keeps the IRQ-disabled structural commit finite while
// covering the largest v0 Win32 Section (4 MiB).
inline constexpr u64 kMaxBorrowedRangePages = 1024;

// User-VA reservations are sparse ownership capabilities rather than
// mappings. The current consumer is a task-owned guarded stack: reserving
// its full [guard_lo, top) window prevents an unrelated owned or borrowed
// mapper from occupying an as-yet-uncommitted page. The page bound keeps
// the no-present-PTE validation pass finite while covering the maximum
// 4 MiB stack reservation plus its four guard pages (1028 pages).
inline constexpr u64 kMaxUserVmReservationPages = kMaxUserVmRegionsPerAs;
inline constexpr u16 kInitialUserVmReservationCapacity = 4;
inline constexpr u16 kMaxUserVmReservationsPerAs = 64;

// A syscall may reserve a small output window before it performs a state
// transition whose result cannot be rolled back.  The lease is a logical PTE
// pin: unmap, protection downgrade, reservation replacement, and exec teardown
// refuse or wait while an overlapping lease is live.  No VM mutex stays held
// while the syscall blocks.  Four pages cover the largest native control
// result (including an unaligned first byte) while keeping validation and the
// direct-map copy strictly bounded under the structural spinlock.
inline constexpr u16 kAddressSpaceWriteLeaseCapacity = 32;
inline constexpr u16 kAddressSpaceWriteLeaseMaxPages = 4;

struct AddressSpace;
enum class AddressSpaceWriteLeaseStatus : u8;

/// Opaque, AS-scoped capability for one exact user-VA reservation. Token
/// values come from one kernel-global, non-wrapping source, so a stale token
/// cannot become valid if an AddressSpace allocation is destroyed and its
/// address is later reused. Tokens are minted only by
/// AddressSpaceReserveUserRange and become permanently stale when released.
/// Kernel callers may copy a token across a private loader -> Task boundary,
/// but cannot construct a non-zero token directly.
class AddressSpaceReservationToken
{
  public:
    constexpr AddressSpaceReservationToken() = default;
    constexpr bool IsValid() const { return owner_ != nullptr && value_ != 0; }

  private:
    explicit constexpr AddressSpaceReservationToken(AddressSpace* owner, u64 value) : owner_(owner), value_(value) {}

    AddressSpace* owner_ = nullptr;
    u64 value_ = 0;

    friend bool AddressSpaceReserveUserRange(AddressSpace*, u64, u64, AddressSpaceReservationToken*);
    friend bool AddressSpaceMapReservedUserPage(AddressSpace*, const AddressSpaceReservationToken&, u64, PhysAddr, u64);
    friend bool AddressSpaceReservationMatches(AddressSpace*, const AddressSpaceReservationToken&, u64, u64);
    friend bool AddressSpaceCommitUserReservation(AddressSpace*, const AddressSpaceReservationToken&, u64, u64);
    friend bool AddressSpaceCommitUserReservationReplacingOwnedRange(AddressSpace*, const AddressSpaceReservationToken&,
                                                                     u64, u64, u64, u64);
    friend bool AddressSpaceReleaseUserReservation(AddressSpace*, const AddressSpaceReservationToken&, u64, u64);
    friend void AddressSpaceSelfTest();
};

/// Opaque, non-transferable authority to write one exact, already-mapped user
/// range.  Token identities come from a boot-global non-wrapping source, so a
/// copied stale lease cannot revive after AddressSpace allocator reuse.  A
/// successful acquisition retains its AddressSpace until exact release.
class AddressSpaceWriteLease
{
  public:
    constexpr AddressSpaceWriteLease() = default;
    AddressSpaceWriteLease(const AddressSpaceWriteLease&) = delete;
    AddressSpaceWriteLease& operator=(const AddressSpaceWriteLease&) = delete;
    AddressSpaceWriteLease(AddressSpaceWriteLease&&) = delete;
    AddressSpaceWriteLease& operator=(AddressSpaceWriteLease&&) = delete;
    constexpr bool IsValid() const { return owner_ != nullptr && token_value_ != 0 && lo_ < hi_; }

  private:
    AddressSpace* owner_ = nullptr;
    u64 token_value_ = 0;
    u64 lo_ = 0;
    u64 hi_ = 0;

    friend AddressSpaceWriteLeaseStatus AddressSpaceAcquireWriteLease(AddressSpace*, u64, u64, AddressSpaceWriteLease*);
    friend bool AddressSpaceCopyToWriteLease(const AddressSpaceWriteLease&, u64, const void*, u64);
    friend bool AddressSpaceReleaseWriteLease(AddressSpaceWriteLease*);
};

enum class AddressSpaceWriteLeaseStatus : u8
{
    Ok = 0,
    InvalidArgument,
    Unmapped,
    NotWritable,
    CapacityExhausted,
    TokenExhausted,
    CorruptState,
};

struct AddressSpaceUserRegion
{
    u64 vaddr;                 // start of a 4 KiB user page
    PhysAddr frame;            // backing frame returned by AllocateFrame
    u64 reservation_token = 0; // 0=ordinary AS-owned page; otherwise exact reservation owner
};

// Consistent, pointer-free diagnostic view of the owned-region ledger.
// No region row or backing-frame identity escapes the structural lock.
struct AddressSpaceUserRegionSummary
{
    u16 page_count{};
    u64 min_vaddr{};
    u64 max_vaddr_exclusive{};
};

struct AddressSpaceUserReservation
{
    u64 lo;          // inclusive, page-aligned
    u64 hi;          // exclusive, page-aligned
    u64 token_value; // non-zero and never reused anywhere in this boot
};

struct AddressSpaceWriteLeaseRow
{
    u64 lo;          // exact inclusive user byte address
    u64 hi;          // exact exclusive user byte address
    u64 token_value; // zero when free; otherwise globally unique
};

static_assert(sizeof(AddressSpaceUserRegion) == 24, "user-region ledger cost changed");
static_assert(sizeof(AddressSpaceUserReservation) == 24, "user-reservation ledger cost changed");
static_assert(sizeof(AddressSpaceWriteLeaseRow) == 24, "write-lease ledger cost changed");

struct AddressSpace
{
    PhysAddr pml4_phys; // CR3 value (low 12 bits already zero)
    u64* pml4_virt;     // direct-map alias for kernel-side editing
    // Direct owners holding this AS (normally one Process). Checked retain
    // and release CAS loops reject both zero resurrection and saturation,
    // so lifetime arithmetic cannot wrap into a premature teardown.
    util::SatU64 refcount;

    // Maximum number of user frames this AS is allowed to own.
    // MapUserPage rejects new mappings once region_count reaches
    // this budget and returns false to the caller. Set at create
    // time and immutable — a process's policy can't be widened
    // after it starts running.
    u64 frame_budget;

    // User-VM region table. The backing storage is HEAP-ALLOCATED and
    // grows on demand (kInitialRegionCapacity, doubling up to
    // frame_budget / kMaxUserVmRegionsPerAs) — so a process that maps
    // few pages costs few entries, not a flat 128 KiB. The AS's
    // frame_budget caps usage to an even smaller number for untrusted
    // processes. Release walks the first `region_count` entries, then
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

    // Sparse user-VA ownership reservations. Protected by mutation_lock,
    // never regions_lock: every operation that creates, consumes, or
    // releases a token is task-context VM mutation work. The table grows
    // outside regions_lock and is freed with the AS. Token values come from
    // a kernel-global non-wrapping source, preventing allocator-address ABA.
    u16 reservation_count;
    u16 reservation_capacity;
    AddressSpaceUserReservation* reservations;

    // Exact writable user ranges pinned across fallible/state-changing
    // syscalls.  Acquisition takes mutation_lock -> write_leases_lock ->
    // regions_lock.  Release needs only write_leases_lock, allowing a lease to
    // quiesce while exec waits outside mutation_lock.  The fixed table avoids
    // allocation after input validation and bounds deliberate capacity use.
    u16 write_lease_count;
    u16 next_write_lease_hint;
    AddressSpaceWriteLeaseRow write_leases[kAddressSpaceWriteLeaseCapacity];
    mutable sync::SpinLock write_leases_lock;

    // Bitmask of CPU ids that currently have THIS AS loaded in CR3.
    // Bit (1u << cpu_id) is set by AddressSpaceActivate when a CPU
    // switches in, cleared only after that CPU has reloaded CR3 away
    // from the AS. The TLB shootdown barrier consults this mask and only
    // IPIs CPUs whose bit is set, avoiding wake-ups on peers that
    // have no cached TLB entries for the target AS. Updates use
    // atomic OR/AND so concurrent activates from different CPUs
    // compose. u32 covers the kMaxCpus=32 cap (acpi/acpi.h); growing
    // past that needs a wider mask.
    volatile u32 active_cpu_mask;
    u8 _pad_acm[4];

    // [task context, thread-safe] Serializes complete VM mutations,
    // including their prepare and retire phases. Slow work is legal
    // while this lock is held; it must always be acquired before
    // regions_lock when both are needed. Mutable so AddressSpaceFork
    // can stabilize a const parent while it copies owned frames.
    mutable sched::Mutex mutation_lock;

    // [any thread, bounded/IRQ-safe] Structural lock for page-table
    // edits and regions pointer/count/capacity snapshots. This remains
    // a spinlock because lookup is reachable while another subsystem
    // holds a spinlock; an RwLock reader could sleep in that path.
    // Never hold it across allocation/free, scheduling, page copying,
    // cross-subsystem calls, or a TLB-shootdown IPI wait.
    mutable sync::SpinLock regions_lock;
};

/// Allocate a fresh AS with a zeroed user half and the kernel half
/// copied from the boot PML4. `frame_budget` caps how many user
/// frames this AS can map (via AddressSpaceMapUserPage); pick
/// `kFrameBudgetSandbox` for untrusted callers or
/// `kFrameBudgetTrusted` for kernel-shipped userland. Returns
/// `Err{ErrorCode::OutOfMemory}` on frame-allocator or kheap failure
/// (no panic — callers may want to refuse the process spawn cleanly).
core::Result<AddressSpace*> AddressSpaceCreate(u64 frame_budget);

/// Mutation APIs below require scheduler-backed task context and may
/// sleep while another thread mutates the same AS. They must not be
/// called from IRQ/NMI context or while the caller holds a spinlock.
/// Read-only probe/lookup APIs remain bounded under regions_lock.
///
/// Install a user-accessible 4 KiB mapping at `virt` in `as`. `virt`
/// must be in the canonical low half and 4 KiB-aligned; `flags` must
/// include `kPageUser`. The (virt, frame) pair is recorded for
/// teardown; the caller must NOT separately FreeFrame(frame) — the
/// AS owns it now.
///
/// Panics on malformed arguments (virt in kernel half or unaligned, an
/// unaligned frame, missing kPageUser, W^X violation, or kPageGlobal).
/// Returns false for an already-mapped VA or recoverable resource refusal
/// (frame-budget exhaustion, region-table growth OOM, or page-table-walker
/// OOM); on false, ownership of `frame` remains with the caller.
///
/// IMPORTANT: this writes into `as`'s PML4 directly via the direct-
/// map alias — `as` does NOT need to be the active AS. That's how
/// a parent task on a different AS can populate a child AS before
/// switching the child task in.
bool AddressSpaceMapUserPage(AddressSpace* as, u64 virt, PhysAddr frame, u64 flags);

/// Transactionally reserve an unmapped, page-aligned user range [lo, hi).
/// The range must not overlap an existing reservation or any present owned
/// or borrowed PTE. On success, `out_token` receives the only capability
/// accepted by AddressSpaceMapReservedUserPage for this range. Ordinary
/// owned and borrowed maps reject every overlap until the token is released.
/// Returns false without a live reservation on conflict, table-cap/global
/// identity exhaustion, or reservation-ledger OOM. Task context only; never
/// call under a spinlock.
bool AddressSpaceReserveUserRange(AddressSpace* as, u64 lo, u64 hi, AddressSpaceReservationToken* out_token);

/// Map one AS-owned page inside the exact reservation named by `token`.
/// The frame is tagged with that token in the owned-region ledger so release
/// retires exactly this reservation's pages, never a foreign PTE that merely
/// occupies the same VA. A present PTE is always a refusal, not success.
/// Argument, W^X, frame-budget, and ownership-on-failure rules match
/// AddressSpaceMapUserPage.
bool AddressSpaceMapReservedUserPage(AddressSpace* as, const AddressSpaceReservationToken& token, u64 virt,
                                     PhysAddr frame, u64 flags);

/// True only when `token` is live in `as` and names exactly [lo, hi).
/// Used at the loader/scheduler handoff before a private Task is published.
bool AddressSpaceReservationMatches(AddressSpace* as, const AddressSpaceReservationToken& token, u64 lo, u64 hi);

/// Convert one fully populated exact reservation into ordinary AS-owned
/// mappings. Every page in [expected_lo, expected_hi) must be present and
/// tagged with `token`; partial reservations fail without mutation. On
/// success the row tags become ordinary ownership and the reservation is
/// retired atomically, allowing normal protect/unmap operations.
bool AddressSpaceCommitUserReservation(AddressSpace* as, const AddressSpaceReservationToken& token, u64 expected_lo,
                                       u64 expected_hi);

/// Atomically publish one fully populated exact destination reservation and
/// retire one disjoint, fully populated ordinary AS-owned source range. Both
/// ranges are validated in full before either changes: every destination page
/// must be tagged with `token`, and every source page must have exactly one
/// ordinary owned-ledger row whose PTE still names the recorded frame. A hole,
/// borrowed page, duplicate row, stale token, reservation overlap, or ledger /
/// PTE disagreement returns false with both ranges untouched. On success the
/// destination becomes ordinary ownership and the source pages, TLB entries,
/// frames, and now-empty page tables are retired before return. Task context
/// only; never call under a spinlock.
bool AddressSpaceCommitUserReservationReplacingOwnedRange(AddressSpace* as,
                                                          const AddressSpaceReservationToken& destination_token,
                                                          u64 destination_lo, u64 destination_hi, u64 source_lo,
                                                          u64 source_hi);

/// Retire every AS-owned page tagged with `token`, complete each required
/// TLB shootdown and frame/table release outside regions_lock, then remove
/// the exact [expected_lo, expected_hi) reservation. Returns false without
/// mutation for a stale token or range mismatch. The owning Task must already
/// be unreachable (or still private/current during creation/exec unwind).
bool AddressSpaceReleaseUserReservation(AddressSpace* as, const AddressSpaceReservationToken& token, u64 expected_lo,
                                        u64 expected_hi);

/// Reverse of MapUserPage. Finds the `(virt, frame)` pair in the
/// regions table, clears the leaf PTE, returns the backing frame
/// to the physical allocator, and drops the region bookkeeping
/// entry. Returns true if the page was mapped in this AS and has
/// been released, false if `virt` was not one of this AS's
/// user-region entries (already unmapped, never mapped, or belongs
/// to a different AS). `virt` must be 4 KiB-aligned and in the
/// canonical user half.
///
/// Safe to call on `as` whether or not it's currently active: the
/// kernel direct-map alias writes the PTE. Before the backing frame is
/// reused, TLB invalidation is broadcast to every CPU currently using
/// `as` (and performed locally when this CPU uses it).
bool AddressSpaceUnmapUserPage(AddressSpace* as, u64 virt);

/// Install a leaf PTE for a frame the AS does NOT own — the
/// frame's lifetime is governed by some other ledger (e.g. a
/// Win32 section pool). Same safety checks as MapUserPage
/// (alignment, canonical low half, kPageUser, W^X, no
/// kPageGlobal) but does NOT touch the regions table — the
/// AS-destroy walker won't free this frame, and the AS
/// frame budget isn't consumed.
///
/// Returns true on success. Returns false if `virt` is already mapped,
/// overlaps a live user-VA reservation, or page-table preparation runs out
/// of frames. Panics on the same invariant violations as MapUserPage.
///
/// Pairs with AddressSpaceUnmapBorrowedPage. Callers MUST
/// keep their own ledger of the (virt, frame) pairs they
/// installed via this API — there is no kernel-side record.
bool AddressSpaceMapBorrowedPage(AddressSpace* as, u64 virt, PhysAddr frame, u64 flags);

/// Atomically install `count` consecutive borrowed mappings beginning at
/// `virt`. Every leaf PTE and every required intermediate page table is
/// validated/prepared before the bounded structural commit. On false, no
/// leaf PTE from the range has been installed. `frames` must contain `count`
/// page-aligned physical frames and `count` must be in
/// [1, kMaxBorrowedRangePages]. Any overlap with a live reservation is a
/// clean all-or-nothing refusal.
bool AddressSpaceMapBorrowedRange(AddressSpace* as, u64 virt, const PhysAddr* frames, u64 count, u64 flags);

/// Read the frame backing `virt` in `as` by walking the page
/// tables directly — independent of the regions table. Used
/// to identify section views (which install borrowed PTEs not
/// recorded in the regions ledger). Returns kNullFrame when
/// `virt` has no present PTE in `as`. `virt` must be 4 KiB-
/// aligned. The returned frame is an unpinned snapshot: callers that
/// dereference it must separately exclude concurrent unmap/release.
PhysAddr AddressSpaceProbePte(const AddressSpace* as, u64 virt);

/// Reverse of MapBorrowedPage: clear the leaf PTE at `virt`
/// in `as` without touching the regions table and without
/// freeing the backing frame. Returns true if a present
/// PTE was cleared, false if `virt` was already unmapped.
/// Panics if `virt` is unaligned or outside the canonical user half.
/// TLB invalidation is broadcast to every CPU currently using `as`
/// before the caller may release or reuse the borrowed frame.
bool AddressSpaceUnmapBorrowedPage(AddressSpace* as, u64 virt);

/// Atomically clear `count` consecutive borrowed mappings only when every
/// present PTE still names the corresponding frame in `expected_frames`.
/// A mismatch, missing PTE, or invalid count returns false without clearing
/// any PTE. The function never frees the borrowed frames; after it returns
/// true, the range-wide TLB shootdown has completed and the owner may release
/// or reuse them.
bool AddressSpaceUnmapBorrowedRangeExpected(AddressSpace* as, u64 virt, const PhysAddr* expected_frames, u64 count);

/// Rewrite the leaf-PTE flag bits at `virt` in `as` to
/// `new_flags` (the same bit set MapUserPage / MapBorrowedPage
/// take — kPagePresent | kPageUser | kPageWritable | kPageNoExecute
/// in any combination, with the same W^X invariant). Preserves
/// the backing frame; only the protection bits change. Returns
/// true if the page is ordinary-owned by this AS, present, and the PTE was
/// rewritten; false if `virt` is unmapped, lies inside a live reservation, or
/// is a borrowed mapping owned by another subsystem. Reserved and borrowed
/// mappings must be protected through their owner's transaction so ownership,
/// frame, and W^X ledgers cannot diverge from the PTE.
///
/// TLB invalidation is broadcast to every CPU currently using `as`
/// before the mutation transaction completes.
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
/// without losing per-page protection. This is an unpinned snapshot;
/// it does not preserve the frame or permissions after return.
u64 AddressSpaceProbePteRaw(const AddressSpace* as, u64 virt);

/// Duplicate `parent`'s user mappings into a fresh AS. Allocates
/// a new AS via AddressSpaceCreate(parent->frame_budget), walks
/// parent's regions ledger, allocates a fresh frame for each
/// page in the child, copies contents through the kernel
/// direct-map alias, and maps the new frame in the child with
/// the SAME PTE flags the parent's leaf PTE carried (preserves
/// W^X — code stays RX, data stays RW + NX). Returns
/// `Err{ErrorCode::InvalidArgument}` if `parent` is null or its owned
/// region ledger disagrees with its page tables, or
/// `Err{ErrorCode::OutOfMemory}` on allocation failure (and rolls
/// back any partially-installed child mappings via
/// AddressSpaceRelease before returning the error). Does NOT cover
/// borrowed-page mappings (Win32 sections) — they aren't in
/// the regions ledger; callers that need them must dup them
/// explicitly. Reservations and their tokens are deliberately NOT
/// inherited: each copied region is mapped with reservation_token == 0,
/// including already-committed caller-stack pages. Linux fork/clone paths
/// do not attach an owned-stack descriptor to the child Task, so those Tasks
/// retain fixed/caller-stack semantics and cannot use the PE demand-growth
/// capability. Uncommitted reservation and guard pages are not copied.
///
/// The caller owns the returned AS — must AddressSpaceRelease
/// it when done.
core::Result<AddressSpace*> AddressSpaceFork(const AddressSpace* parent);

/// Clear every user-region mapping in `as` without releasing
/// the AS itself. Walks `regions[0..region_count)`, unmaps each
/// leaf PTE, frees the backing frame back to the physical
/// allocator, and resets `region_count` to 0.
///
/// Used by execve() — replace the running process's image in-place.
/// Intermediate user-half tables are pruned as their final leaf is
/// removed; a subsequent ElfLoad allocates only the paths it needs.
///
/// Borrowed-page mappings (Win32 sections) are NOT touched —
/// they aren't in the regions ledger. Callers that need to
/// nuke section views must do that separately.
///
/// The caller must first release every live user-VA reservation. execve's
/// guaranteed-single-task path does this by dropping the current Task's
/// owned stack token. A surviving token across whole-AS replacement is an
/// invariant violation, so this function asserts reservation_count == 0.
///
/// Each detached page is invalidated on every CPU currently using
/// `as` before its frame is returned to the allocator. Empty user-half
/// PT/PD/PDPT pages are pruned in the same transaction and retired only
/// after that shootdown, so sparse map/unmap churn cannot retain them
/// until final AS destruction.
void AddressSpaceClearUserMappings(AddressSpace* as);

/// Reverse of MapUserPage: given a user VA, return the physical
/// frame backing its containing page, or kNullFrame if unmapped.
/// Walks the AS's `regions` array (small N, linear scan). Used
/// by the PE loader to patch IAT slots from the kernel side
/// without touching page-table flags — the kernel's direct map
/// is always writable, so `PhysToVirt(LookupUserFrame(...))` is
/// the shortest path to "modify this page that's currently RO
/// in the user's view." The returned frame is an unpinned snapshot;
/// callers must separately exclude concurrent unmap/release.
PhysAddr AddressSpaceLookupUserFrame(const AddressSpace* as, u64 virt);

/// [task context, thread-safe] Copy one bounded range from `as`'s user
/// mapping into a trusted kernel buffer. The range must stay within one
/// 4 KiB page. Resolves the PTE and copies through its direct-map alias
/// while mutation_lock excludes concurrent unmap/remap; no raw frame or
/// pointer escapes the transaction. Returns false for an invalid range,
/// absent/non-user page, or null buffer.
bool AddressSpaceReadUserMemory(AddressSpace* as, u64 user_va, void* kernel_dst, u64 len);

/// [task context, thread-safe] Copy one bounded range from a trusted
/// kernel buffer into `as`'s user mapping. Same transaction and range
/// contract as AddressSpaceReadUserMemory, and additionally requires the
/// target leaf PTE to be writable. Returns false instead of bypassing a
/// read-only/RX mapping through the kernel direct map.
bool AddressSpaceWriteUserMemory(AddressSpace* as, u64 user_va, const void* kernel_src, u64 len);

/// [task context, thread-safe] Pin an exact, currently present and writable
/// user range without retaining mutation_lock after return.  The range may
/// span at most kAddressSpaceWriteLeaseMaxPages.  Overlapping unmap/protect,
/// reservation replacement/release, and exec teardown cannot retire or narrow
/// these PTEs until AddressSpaceReleaseWriteLease succeeds.
AddressSpaceWriteLeaseStatus AddressSpaceAcquireWriteLease(AddressSpace* as, u64 user_va, u64 len,
                                                           AddressSpaceWriteLease* out_lease);

/// Copy trusted bytes through the direct map while validating the exact live
/// lease and every leaf PTE. `offset + len` must remain inside the leased
/// range.  Validation of all pages precedes the first byte write, so a corrupt
/// mapping cannot produce a partial result.
bool AddressSpaceCopyToWriteLease(const AddressSpaceWriteLease& lease, u64 offset, const void* kernel_src, u64 len);

/// Consume one exact lease and drop its AddressSpace reference. Leases are
/// deliberately non-copyable/non-movable: a stale copy could otherwise retain
/// a raw owner pointer after the one ledger-held AddressSpace reference was
/// released. Forged and already-consumed objects are rejected without touching
/// ledger state.
bool AddressSpaceReleaseWriteLease(AddressSpaceWriteLease* lease);

/// [panic/stop diagnostics, bounded/IRQ-safe] Attempt one non-blocking
/// regions_lock acquisition and summarize the owned-region ledger. The
/// function never waits, allocates, logs, or calls another subsystem. It
/// returns false with a zeroed `out` when the lock is busy/self-held, the
/// arguments are invalid, or a panic-time invariant check cannot produce a
/// trustworthy snapshot. The caller must independently keep `as` alive for
/// the duration of this call; no pointer or frame receipt escapes it.
bool AddressSpaceTrySnapshotUserRegionSummary(const AddressSpace* as, AddressSpaceUserRegionSummary* out);

/// Activate `as` by loading its PML4 into CR3 — but only if `as` is
/// not already the active AS on this CPU. Updates the per-CPU
/// current-AS tracker. `as == nullptr` selects the kernel AS (the
/// boot PML4); kernel-only tasks use this so kernel→kernel context
/// switches don't pay a CR3 write.
void AddressSpaceActivate(AddressSpace* as);

/// [any thread, bounded/IRQ-safe] Return the number of owned 4 KiB user
/// pages currently mapped in `as`. Borrowed Section mappings are not part
/// of this ledger. Each page in `region_count` represents one owned frame.
/// Used by diagnostics (taskman MEM column) to show per-process
/// resident page count without reaching into AS internals.
/// Returns 0 for a null `as` (kernel-only tasks have no user AS).
inline u16 AddressSpaceUserPageCount(const AddressSpace* as)
{
    if (as == nullptr)
        return 0;
    sync::SpinLockGuard guard(as->regions_lock);
    return as->region_count;
}

/// Currently-active AS on this CPU (nullptr = kernel AS / boot PML4).
AddressSpace* AddressSpaceCurrent();

/// Bump the refcount when handing the AS to another direct owner. Normal
/// multi-Task processes do not call this: every Task retains the shared
/// Process, while that Process owns one AS reference. Create returns with
/// refcount=1 for the owner that adopts the new AS. Retaining zero or a
/// saturated counter is an invariant violation.
void AddressSpaceRetain(AddressSpace* as);

/// Drop a reference. When the last reference goes away, walks the
/// region table to return every backing frame, walks the user-half
/// page tables (PML4[0..255]) freeing intermediate PDPT/PD/PT
/// frames, then frees the PML4 frame itself. After release the
/// caller MUST NOT touch `as` again. nullptr is a no-op (the kernel
/// AS is never released). A last-reference release requires task
/// context because teardown takes mutation_lock and may sleep.
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
// On a uniprocessor the barrier collapses to local `invlpg`. On SMP it
// snapshots the exact sparse active/ready set and uses confirmed per-target
// IPI-call completion. Unmap/protect callers therefore need no scattered SMP
// policy and cannot mistake a soft timeout for permission to reclaim.
// ---------------------------------------------------------------------------

/// Flush a single virtual address from every IPI-ready CPU that had `as`
/// active at the barrier snapshot, including the current CPU. Safe before
/// SMP bring-up and collapses to local `invlpg` with no ready peer. Must be
/// called AFTER the PTE is cleared or downgraded. With a ready peer this is
/// a task-context operation that requires IF=1; migration is pinned while
/// the exact sparse target set is drained. The function does not return
/// until every target acknowledges, so backing frames and retired page-table
/// frames may be reused only after it returns. AP readiness is monotonic;
/// each excluded AP performs a full TLB flush before joining the domain.
void TlbShootdownAddr(AddressSpace* as, u64 virt);

/// Flush a contiguous virtual range `[virt, virt + len)`. Same confirmed
/// completion and caller-context rules as TlbShootdownAddr. The helper rounds
/// the range to whole pages and performs one `invlpg` per page on each target.
/// Zero length is a no-op; range overflow is a kernel invariant failure.
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
