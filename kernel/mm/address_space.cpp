/*
 * DuetOS — per-process address space: implementation.
 *
 * Companion to address_space.h — see there for the AddressSpace
 * struct and the kernel-half vs user-half split rules.
 *
 * WHAT
 *   An `AddressSpace` is one PML4 root + the bookkeeping needed
 *   to map/unmap pages into it. The kernel half (top 256 PML4
 *   entries) is shared across every AddressSpace via shared
 *   high-half tables installed at boot; the user half is
 *   per-process and zeroed at create time.
 *
 * HOW
 *   `Create` allocates a fresh PML4 frame, copies the kernel-
 *   half pointers from the boot PML4, and zeroes the user
 *   half. `Switch` writes CR3. `MapUserPage` /
 *   `UnmapUserPage` are thin wrappers that gate on "this VA
 *   is in the user half" before delegating to paging.cpp's
 *   walk-or-create.
 *
 *   Teardown (`Destroy`) walks the user half and frees every
 *   leaf frame, then every intermediate page-table frame, then
 *   the PML4 itself. The kernel half is left alone — it's
 *   shared.
 */

#include "mm/address_space.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "log/klog.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "util/string.h"

namespace duetos::mm
{

namespace
{

// Same magic numbers paging.cpp uses; duplicated rather than exported
// so paging.cpp's internal constants stay internal. If they ever
// drift, the static_asserts below catch it.
constexpr u64 kEntriesPerTable = 512;
constexpr u64 kAddrMask = 0x000FFFFFFFFFF000ULL;
constexpr u64 kKernelHalfFirstIndex = 256;

// Lifetime counters — maintained inside the public release/create
// paths. Plain globals because v0 has no AS allocator concurrency.
// Saturating: class BB (wrap-to-zero defense gap). Reported by
// inspect / health; never used for modular arithmetic.
constinit util::SatU64 g_created = 0;
constinit util::SatU64 g_destroyed = 0;
constinit util::SatU64 g_cr3_switches = 0;

[[noreturn]] void PanicAs(const char* message, u64 value)
{
    core::PanicWithValue("mm/as", message, value);
}

// Walker that mirrors WalkToPte in paging.cpp but operates on an
// arbitrary PML4 root — needed both for installing user mappings
// into a non-active AS and for tearing down user-half tables at
// destroy time. Can't share the paging.cpp implementation because
// it's anonymous-namespace local; the duplication is small (~30
// lines) and the alternative (exporting WalkToPte) would expand
// paging.h's surface for one consumer.
inline u64 IndexPml4(u64 v)
{
    return (v >> 39) & 0x1FF;
}
inline u64 IndexPdpt(u64 v)
{
    return (v >> 30) & 0x1FF;
}
inline u64 IndexPd(u64 v)
{
    return (v >> 21) & 0x1FF;
}
inline u64 IndexPt(u64 v)
{
    return (v >> 12) & 0x1FF;
}

inline void Invlpg(u64 v)
{
    asm volatile("invlpg (%0)" : : "r"(v) : "memory");
}

// Allocate a fresh page-table frame, zero it, return its kernel
// virtual alias, or nullptr when the physical frame pool is dry.
// Returning null (instead of panicking) lets the failure propagate
// up through WalkToPteIn to AddressSpaceMapUserPage, which fails
// the single user mapping gracefully — a userland exec hitting the
// frame ceiling must kill that process, never halt the kernel.
u64* AllocateTable()
{
    const PhysAddr frame = AllocateFrame();
    if (frame == kNullFrame)
    {
        return nullptr;
    }
    auto* table = static_cast<u64*>(PhysToVirt(frame));
    for (u64 i = 0; i < kEntriesPerTable; ++i)
    {
        table[i] = 0;
    }
    return table;
}

u64* WalkToPteIn(u64* pml4, u64 virt, bool create)
{
    const u64 i4 = IndexPml4(virt);
    const u64 i3 = IndexPdpt(virt);
    const u64 i2 = IndexPd(virt);
    const u64 i1 = IndexPt(virt);

    u64& pml4_entry = pml4[i4];
    if ((pml4_entry & kPagePresent) == 0)
    {
        if (!create)
        {
            return nullptr;
        }
        u64* new_pdpt = AllocateTable();
        if (new_pdpt == nullptr)
        {
            return nullptr; // frame pool dry — propagate, don't panic
        }
        const PhysAddr phys = VirtToPhys(new_pdpt);
        // PML4 entry must carry kPageUser when it covers a user-
        // accessible PT — without it the CPU page walker rejects
        // the user access at the PML4 level even if the leaf PTE
        // has User set. SMAP/SMEP gating still holds because
        // those check the leaf PTE's bits.
        pml4_entry = phys | kPagePresent | kPageWritable | kPageUser;
    }
    auto* pdpt = static_cast<u64*>(PhysToVirt(pml4_entry & kAddrMask));

    u64& pdpt_entry = pdpt[i3];
    if ((pdpt_entry & kPagePresent) == 0)
    {
        if (!create)
        {
            return nullptr;
        }
        u64* new_pd = AllocateTable();
        if (new_pd == nullptr)
        {
            return nullptr; // frame pool dry — propagate, don't panic
        }
        const PhysAddr phys = VirtToPhys(new_pd);
        pdpt_entry = phys | kPagePresent | kPageWritable | kPageUser;
    }
    if (pdpt_entry & kPageHugeOrPat)
    {
        PanicAs("AS walker hit a 1 GiB PS page", virt);
    }
    auto* pd = static_cast<u64*>(PhysToVirt(pdpt_entry & kAddrMask));

    u64& pd_entry = pd[i2];
    if ((pd_entry & kPagePresent) == 0)
    {
        if (!create)
        {
            return nullptr;
        }
        u64* new_pt = AllocateTable();
        if (new_pt == nullptr)
        {
            return nullptr; // frame pool dry — propagate, don't panic
        }
        const PhysAddr phys = VirtToPhys(new_pt);
        pd_entry = phys | kPagePresent | kPageWritable | kPageUser;
    }
    if (pd_entry & kPageHugeOrPat)
    {
        PanicAs("AS walker hit a 2 MiB PS page", virt);
    }
    auto* pt = static_cast<u64*>(PhysToVirt(pd_entry & kAddrMask));
    return &pt[i1];
}

// Release every PT/PD/PDPT frame reachable from PML4[0..255] of `pml4`.
// Walks to the leaf level only inside present entries; never touches
// the kernel half (PML4[256..511]) since those entries are SHARED with
// every other AS via the boot PML4's PDPTs — freeing them would yank
// the kernel address space out from under every running process.
void FreeUserHalfTables(u64* pml4)
{
    for (u64 i4 = 0; i4 < kKernelHalfFirstIndex; ++i4)
    {
        const u64 e4 = pml4[i4];
        if ((e4 & kPagePresent) == 0)
        {
            continue;
        }
        const PhysAddr pdpt_phys = e4 & kAddrMask;
        auto* pdpt = static_cast<u64*>(PhysToVirt(pdpt_phys));
        for (u64 i3 = 0; i3 < kEntriesPerTable; ++i3)
        {
            const u64 e3 = pdpt[i3];
            if ((e3 & kPagePresent) == 0 || (e3 & kPageHugeOrPat) != 0)
            {
                continue;
            }
            const PhysAddr pd_phys = e3 & kAddrMask;
            auto* pd = static_cast<u64*>(PhysToVirt(pd_phys));
            for (u64 i2 = 0; i2 < kEntriesPerTable; ++i2)
            {
                const u64 e2 = pd[i2];
                if ((e2 & kPagePresent) == 0 || (e2 & kPageHugeOrPat) != 0)
                {
                    continue;
                }
                FreeFrame(e2 & kAddrMask); // free the PT page
            }
            FreeFrame(pd_phys);
        }
        FreeFrame(pdpt_phys);
        pml4[i4] = 0;
    }
}

} // namespace

core::Result<AddressSpace*> AddressSpaceCreate(u64 frame_budget)
{
    KLOG_TRACE_SCOPE("mm/as", "AddressSpaceCreate");
    if (frame_budget == 0 || frame_budget > kMaxUserVmRegionsPerAs)
    {
        PanicAs("AddressSpaceCreate: frame_budget out of range [1..kMaxUserVmRegionsPerAs]", frame_budget);
    }

    auto* as = static_cast<AddressSpace*>(KMalloc(sizeof(AddressSpace)));
    if (as == nullptr)
    {
        // OOM during AddressSpace bookkeeping struct alloc — the
        // caller (typically ProcessCreate) returns nullptr upward
        // without a separate signal. Surface so a post-mortem can
        // tie the process-create failure to memory pressure.
        KLOG_ERROR("mm/as", "AddressSpaceCreate: KMalloc for AddressSpace struct failed");
        return core::Err{core::ErrorCode::OutOfMemory};
    }
    // Zero the chunk before populating. KMalloc returns memory still
    // carrying whatever was last in it — including the freed-payload
    // poison `kFreedPagePoison` (0xDE) from the C2 patch — and the
    // embedded `regions_lock` (RwLock) is otherwise default-initialised
    // by the field declaration. Without this, `Mutex.waiters.tail`
    // reads back as `0xdededededededede` and the first MutexLock
    // trying to enqueue a waiter dereferences a non-canonical pointer
    // and #GPs.
    memset(as, 0, sizeof(AddressSpace));

    const PhysAddr pml4_frame = AllocateFrame();
    if (pml4_frame == kNullFrame)
    {
        // Frame allocator exhausted while reserving the PML4 root —
        // every user process needs one, so a fresh-process spawn
        // under high memory pressure dies here silently. Cleanup
        // releases the struct alloc; we still return nullptr but
        // now the OOM is in the log.
        KLOG_ERROR("mm/as", "AddressSpaceCreate: AllocateFrame for PML4 root failed");
        KFree(as);
        return core::Err{core::ErrorCode::OutOfMemory};
    }

    auto* pml4 = static_cast<u64*>(PhysToVirt(pml4_frame));

    // PML4 layout for a per-process AS:
    //
    //   [0..255]    — zero. User-half, fully private. MapUserPage
    //                 installs fresh PDPTs/PDs/PTs on demand.
    //                 BUT: ring3_smoke's ASLR picker MUST keep user
    //                 bases >= 1 GiB — the boot PML4's PML4[0]
    //                 PDPT[0] covers [0, 1 GiB) with 2 MiB PS pages
    //                 (the boot stack + IST stacks + kernel image
    //                 live there), and the per-AS walker would
    //                 descend into a PS entry and panic. User VAs
    //                 above 1 GiB land in fresh private tables.
    //   [256..511]  — copied from boot PML4 (kernel-half direct map +
    //                 MMIO arena). Shared via copied PDPTs so future
    //                 kernel-half mapping changes propagate everywhere
    //                 without shootdown.
    u64* boot_pml4 = BootPml4Virt();
    for (u64 i = 0; i < kKernelHalfFirstIndex; ++i)
    {
        pml4[i] = 0;
    }
    for (u64 i = kKernelHalfFirstIndex; i < kEntriesPerTable; ++i)
    {
        pml4[i] = boot_pml4[i];
    }

    as->pml4_phys = pml4_frame;
    as->pml4_virt = pml4;
    as->refcount = 1;
    as->frame_budget = frame_budget;
    as->region_count = 0;
    for (u64 i = 0; i < kMaxUserVmRegionsPerAs; ++i)
    {
        as->regions[i] = AddressSpaceUserRegion{0, 0};
    }

    ++g_created;

    arch::SerialWrite("[as] created pml4_phys=");
    arch::SerialWriteHex(pml4_frame);
    arch::SerialWrite(" as=");
    arch::SerialWriteHex(reinterpret_cast<u64>(as));
    arch::SerialWrite("\n");

    return as;
}

void AddressSpaceMapUserPage(AddressSpace* as, u64 virt, PhysAddr frame, u64 flags)
{
    if (as == nullptr)
    {
        PanicAs("AddressSpaceMapUserPage with null AS", virt);
    }
    if ((virt & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceMapUserPage: unaligned virt", virt);
    }
    if ((frame & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceMapUserPage: unaligned phys", frame);
    }
    // Reject anything outside the canonical low half. A user mapping
    // installed in the kernel half would either silently land inside
    // shared kernel tables (corrupting every other AS's view of the
    // kernel) or hit the panic in the boot direct map. Refusing here
    // turns "obvious bug" into a named one.
    constexpr u64 kUserMax = 0x00007FFFFFFFFFFFULL;
    if (virt > kUserMax)
    {
        PanicAs("AddressSpaceMapUserPage: virt outside canonical low half", virt);
    }
    if ((flags & kPageUser) == 0)
    {
        PanicAs("AddressSpaceMapUserPage: flags missing kPageUser", flags);
    }
    // W^X enforcement — no user mapping may be BOTH writable AND
    // executable. That combination is the canonical shellcode-
    // injection substrate (write bytes to a page, then jump there).
    // A mapping that's writable must carry kPageNoExecute; a mapping
    // that's executable (NX clear) must NOT carry kPageWritable.
    // This applies to every caller of MapUserPage — loader, spawn,
    // future mprotect-equivalent, etc. Panicking here turns "I
    // accidentally introduced W+X in a new code path" into a boot-
    // time failure rather than a silent regression.
    //
    // The kernel's own mapping API (mm::MapPage) mirrors this
    // check; see paging.cpp.
    if ((flags & kPageWritable) != 0 && (flags & kPageNoExecute) == 0)
    {
        PanicAs("AddressSpaceMapUserPage: W^X violation (writable+exec user page)", flags);
    }
    // Reject kPageGlobal on user pages. A global mapping survives a
    // CR3 flush, so a user page marked global would remain in the
    // TLB across a process switch — cross-process leak. Kernel-half
    // mappings legitimately use global; user-half never should.
    if ((flags & kPageGlobal) != 0)
    {
        PanicAs("AddressSpaceMapUserPage: kPageGlobal on user page", flags);
    }
    // Take the regions lock exclusive across the whole mutation
    // (budget check + PTE write + TLB invalidate + region table
    // append). Today the AS is single-Task; the lock is
    // uncontended. The day a Process becomes multi-threaded
    // (multiple Tasks per AS), this exclusive guard already
    // serialises concurrent map/unmap callers correctly.
    // (B1-followup, 2026-04-28.)
    sync::RwLockExclusiveGuard guard(as->regions_lock);

    if (as->region_count >= as->frame_budget)
    {
        // Budget exhausted. Refusing the mapping is the safe
        // default — a runaway process cannot drain the frame
        // allocator past this point. NON-FATAL: leaving the page
        // unmapped makes the offending user process fault on first
        // access and get reaped by the ring-3 fault handler; the
        // kernel must not halt because one userland exec hit its
        // budget. (Previously a PanicAs — see the v0 note that
        // anticipated this needing a non-fatal variant.)
        KLOG_WARN_V("mm/as", "MapUserPage: frame budget exhausted — refusing mapping", as->region_count);
        return;
    }

    u64* pte = WalkToPteIn(as->pml4_virt, virt, /*create=*/true);
    if (pte == nullptr)
    {
        // Physical frame pool dry while building page tables for a
        // user mapping. NON-FATAL for the same reason as the budget
        // path: the unmapped page → user #PF → process reaped, not
        // a kernel halt. This is the fix for the intermittent
        // "AllocateFrame returned null inside AS walker" panic that
        // tripped under heavy back-to-back PE/ELF spawns.
        KLOG_WARN_V("mm/as", "MapUserPage: frame pool dry building page tables — refusing mapping", virt);
        return;
    }
    if (*pte & kPagePresent)
    {
        PanicAs("AddressSpaceMapUserPage: virt already mapped", virt);
    }
    *pte = (frame & kAddrMask) | (flags | kPagePresent);

    // Only invalidate the TLB if THIS AS is the one currently active
    // on this CPU. If we just edited a different AS's tables, the
    // CPU's TLB has nothing for that VA cached and the invlpg would
    // be wasted work. The activate path's MOV-to-CR3 will flush
    // every non-global entry on switch-in.
    if (AddressSpaceCurrent() == as)
    {
        Invlpg(virt);
    }

    as->regions[as->region_count] = AddressSpaceUserRegion{virt, frame};
    ++as->region_count;
}

namespace
{
// Inner unmap: drop the region at `idx`, clear its PTE, broadcast
// TLB shootdown, free the frame. Caller has already located the
// row — UnmapUserPage scans first, while ClearUserMappings hands
// in `region_count - 1` to avoid an O(n) scan on every teardown
// step.
void UnmapUserPageByIndex(AddressSpace* as, u16 idx)
{
    // Precondition the header comment describes but nothing
    // enforced: idx must address a live row. With region_count==0
    // the `u16(region_count - 1)` below wraps to 0xFFFF and the
    // compaction line writes 64 KiB past the table — silent heap
    // corruption. Always-on (not DEBUG_ASSERT): an OOB write into
    // the region table is a stability/security hole.
    KASSERT(as->region_count > 0, "mm/as", "UnmapUserPageByIndex on empty region table");
    KASSERT(idx < as->region_count, "mm/as", "UnmapUserPageByIndex idx out of range");

    const u64 virt = as->regions[idx].vaddr;
    const PhysAddr frame = as->regions[idx].frame;

    // Clear the leaf PTE. If the walk can't find one the tables
    // are corrupt relative to the region table — panic so the gap
    // is visible, rather than silently leaving the region list out
    // of sync with the page tables.
    u64* pte = WalkToPteIn(as->pml4_virt, virt, /*create=*/false);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
    {
        PanicAs("AddressSpaceUnmapUserPage: region table claims mapping but PTE absent", virt);
    }
    *pte = 0;

    // Flush both the local TLB (if this CPU is in `as`) AND every
    // peer CPU whose CR3 also maps `as`. On uniprocessor the helper
    // collapses to the local invlpg; on SMP it sends a TLB-shootdown
    // IPI and waits for ack. See wiki/security/Linux-CVE-Audit.md
    // class FF for the threat model — without the broadcast, a peer
    // CPU keeps writing through a stale RW TLB entry to a frame
    // that's been recycled into a different process.
    TlbShootdownAddr(as, virt);

    // Compact the region table — swap the dying slot with the last
    // in-use slot. Order doesn't matter; destroy walks `region_count`
    // entries.
    const u16 last = u16(as->region_count - 1);
    if (idx != last)
    {
        as->regions[idx] = as->regions[last];
    }
    --as->region_count;

    FreeFrame(frame);
}
} // namespace

bool AddressSpaceUnmapUserPage(AddressSpace* as, u64 virt)
{
    if (as == nullptr)
    {
        return false;
    }
    if ((virt & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceUnmapUserPage: unaligned virt", virt);
    }
    // Find the region. Linear scan over region_count — typical
    // region_count is small (≤128), and munmap is infrequent; this
    // stays cheaper than building an index.
    u16 found = u16(-1);
    for (u16 i = 0; i < as->region_count; ++i)
    {
        if (as->regions[i].vaddr == virt)
        {
            found = i;
            break;
        }
    }
    if (found == u16(-1))
    {
        return false;
    }
    UnmapUserPageByIndex(as, found);
    return true;
}

bool AddressSpaceMapBorrowedPage(AddressSpace* as, u64 virt, PhysAddr frame, u64 flags)
{
    if (as == nullptr)
    {
        PanicAs("AddressSpaceMapBorrowedPage with null AS", virt);
    }
    if ((virt & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceMapBorrowedPage: unaligned virt", virt);
    }
    if ((frame & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceMapBorrowedPage: unaligned phys", frame);
    }
    constexpr u64 kUserMax = 0x00007FFFFFFFFFFFULL;
    if (virt > kUserMax)
    {
        PanicAs("AddressSpaceMapBorrowedPage: virt outside canonical low half", virt);
    }
    if ((flags & kPageUser) == 0)
    {
        PanicAs("AddressSpaceMapBorrowedPage: flags missing kPageUser", flags);
    }
    if ((flags & kPageWritable) != 0 && (flags & kPageNoExecute) == 0)
    {
        PanicAs("AddressSpaceMapBorrowedPage: W^X violation", flags);
    }
    if ((flags & kPageGlobal) != 0)
    {
        PanicAs("AddressSpaceMapBorrowedPage: kPageGlobal on user page", flags);
    }
    u64* pte = WalkToPteIn(as->pml4_virt, virt, /*create=*/true);
    if (pte == nullptr)
    {
        // Frame pool dry building page tables — fail the borrow
        // (caller already handles false) rather than null-deref.
        KLOG_WARN_V("mm/as", "MapBorrowedPage: frame pool dry building page tables", virt);
        return false;
    }
    if (*pte & kPagePresent)
    {
        return false;
    }
    *pte = (frame & kAddrMask) | (flags | kPagePresent);
    if (AddressSpaceCurrent() == as)
    {
        Invlpg(virt);
    }
    return true;
}

PhysAddr AddressSpaceProbePte(const AddressSpace* as, u64 virt)
{
    if (as == nullptr)
        return kNullFrame;
    if ((virt & 0xFFF) != 0)
        PanicAs("AddressSpaceProbePte: unaligned virt", virt);
    u64* pte = WalkToPteIn(as->pml4_virt, virt, /*create=*/false);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
        return kNullFrame;
    return *pte & kAddrMask;
}

u64 AddressSpaceProbePteRaw(const AddressSpace* as, u64 virt)
{
    if (as == nullptr)
        return 0;
    if ((virt & 0xFFF) != 0)
        PanicAs("AddressSpaceProbePteRaw: unaligned virt", virt);
    u64* pte = WalkToPteIn(as->pml4_virt, virt, /*create=*/false);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
        return 0;
    return *pte;
}

AddressSpace* AddressSpaceFork(const AddressSpace* parent)
{
    if (parent == nullptr)
        return nullptr;
    auto child_r = AddressSpaceCreate(parent->frame_budget);
    if (!child_r)
        return nullptr;
    AddressSpace* child = child_r.value();
    for (u16 i = 0; i < parent->region_count; ++i)
    {
        const u64 va = parent->regions[i].vaddr;
        const PhysAddr parent_frame = parent->regions[i].frame;
        const u64 parent_pte = AddressSpaceProbePteRaw(parent, va);
        if (parent_pte == 0)
        {
            // Region table thinks `va` is mapped but the PTE
            // walk found nothing present. That means an unmap
            // path mutated the page tables without removing
            // the matching region entry — a kernel-internal
            // invariant break. Surface it loudly so the next
            // such bug is found at fork time, not days later
            // when the child segfaults on a missing page.
            KLOG_WARN_2V("mm/address_space", "AddressSpaceFork: region table out of sync with PTEs", "va", va,
                         "region_idx", static_cast<u64>(i));
            continue;
        }
        // Extract flags: mask out the address bits, keep the
        // protection / present / user / NX flags.
        const u64 flags = parent_pte & ~kAddrMask;
        const PhysAddr child_frame = AllocateFrame();
        if (child_frame == kNullFrame)
        {
            AddressSpaceRelease(child);
            return nullptr;
        }
        // Copy page contents through the direct-map alias.
        const void* src = PhysToVirt(parent_frame);
        void* dst = PhysToVirt(child_frame);
        memcpy(dst, src, kPageSize);
        const u16 region_count_before = child->region_count;
        AddressSpaceMapUserPage(child, va, child_frame, flags);
        if (child->region_count == region_count_before)
        {
            // Map refused (frame budget exhausted or page-table
            // pool dry — both non-fatal paths in MapUserPage that
            // return without installing). child_frame was allocated
            // above but is not in child->regions[], so
            // AddressSpaceRelease will never reclaim it. Free it
            // here, otherwise a fork near the frame budget leaks one
            // physical frame per skipped region under memory
            // pressure.
            FreeFrame(child_frame);
        }
    }
    return child;
}

void AddressSpaceClearUserMappings(AddressSpace* as)
{
    if (as == nullptr)
        return;
    // Pop entries off the tail. UnmapUserPageByIndex handles the
    // PTE clear + TLB shootdown + frame free + region-table
    // decrement; passing the index directly avoids the linear
    // scan AddressSpaceUnmapUserPage does, taking teardown from
    // O(n²) (each Unmap scans the full table to find the va we
    // already knew the index of) down to O(n).
    while (as->region_count > 0)
    {
        UnmapUserPageByIndex(as, u16(as->region_count - 1));
    }
}

bool AddressSpaceProtectUserPage(AddressSpace* as, u64 virt, u64 new_flags)
{
    if (as == nullptr)
        return false;
    if ((virt & 0xFFF) != 0)
        PanicAs("AddressSpaceProtectUserPage: unaligned virt", virt);
    constexpr u64 kUserMax = 0x00007FFFFFFFFFFFULL;
    if (virt > kUserMax)
        PanicAs("AddressSpaceProtectUserPage: virt outside canonical low half", virt);
    if ((new_flags & kPageUser) == 0)
        PanicAs("AddressSpaceProtectUserPage: flags missing kPageUser", new_flags);
    if ((new_flags & kPageWritable) != 0 && (new_flags & kPageNoExecute) == 0)
        PanicAs("AddressSpaceProtectUserPage: W^X violation", new_flags);
    if ((new_flags & kPageGlobal) != 0)
        PanicAs("AddressSpaceProtectUserPage: kPageGlobal on user page", new_flags);

    u64* pte = WalkToPteIn(as->pml4_virt, virt, /*create=*/false);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
        return false;
    const u64 frame = *pte & kAddrMask;
    *pte = frame | (new_flags | kPagePresent);
    // Protect downgrades (e.g. RW→RO) leave stale RW entries in
    // peer-CPU TLBs that allow writes through after the PTE was
    // already narrowed. Broadcast the shootdown. See class FF.
    TlbShootdownAddr(as, virt);
    return true;
}

bool AddressSpaceUnmapBorrowedPage(AddressSpace* as, u64 virt)
{
    if (as == nullptr)
    {
        return false;
    }
    if ((virt & 0xFFF) != 0)
    {
        PanicAs("AddressSpaceUnmapBorrowedPage: unaligned virt", virt);
    }
    u64* pte = WalkToPteIn(as->pml4_virt, virt, /*create=*/false);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
    {
        return false;
    }
    *pte = 0;
    TlbShootdownAddr(as, virt);
    return true;
}

void AddressSpaceActivate(AddressSpace* as)
{
    cpu::PerCpu* p = cpu::CurrentCpu();
    if (p->current_as == as)
    {
        return; // fast path: no-op same-AS switch
    }

    // Maintain the per-AS CPU mask used by TLB shootdown to scope
    // the IPI to peers that actually have this AS loaded. Clear
    // first, then set on the new AS — order matters so a concurrent
    // shootdown from a third CPU never sees us in both masks at
    // once (it could over-IPI us; correctness is preserved).
    const u32 bit = 1u << (p->cpu_id & 31u);
    AddressSpace* old_as = p->current_as;
    if (old_as != nullptr)
    {
        __atomic_fetch_and(&old_as->active_cpu_mask, ~bit, __ATOMIC_RELEASE);
    }
    if (as != nullptr)
    {
        __atomic_fetch_or(&as->active_cpu_mask, bit, __ATOMIC_ACQUIRE);
    }

    const PhysAddr cr3 = (as != nullptr) ? as->pml4_phys : BootPml4Phys();
    arch::WriteCr3(cr3);
    p->current_as = as;
    ++g_cr3_switches;
}

AddressSpace* AddressSpaceCurrent()
{
    return cpu::CurrentCpu()->current_as;
}

PhysAddr AddressSpaceLookupUserFrame(const AddressSpace* as, u64 virt)
{
    if (as == nullptr)
        return kNullFrame;
    const u64 page_va = virt & ~(kPageSize - 1);
    for (u16 i = 0; i < as->region_count; ++i)
    {
        if (as->regions[i].vaddr == page_va)
            return as->regions[i].frame;
    }
    return kNullFrame;
}

void AddressSpaceRetain(AddressSpace* as)
{
    if (as == nullptr)
    {
        return;
    }
    // Atomic CAS-loop retain — see ProcessRetain for the rationale.
    // Plain `++as->refcount` was a cross-CPU race that contributed
    // to the SMP=8 saturation UAF: a peer dropping the AS to 0
    // while this CPU was racing a retain could leave the AS
    // double-freed.
    while (true)
    {
        u64 cur = __atomic_load_n(&as->refcount.value, __ATOMIC_ACQUIRE);
        if (cur == 0)
        {
            PanicAs("AddressSpaceRetain on AS with refcount==0", reinterpret_cast<u64>(as));
        }
        const u64 next = cur + 1;
        if (__atomic_compare_exchange_n(&as->refcount.value, &cur, next, /*weak=*/false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            return;
        }
    }
}

void AddressSpaceRelease(AddressSpace* as)
{
    if (as == nullptr)
    {
        return;
    }
    // Atomic decrement-and-test — see ProcessRelease for the
    // rationale. Plain `--as->refcount` would let two CPUs both
    // observe refcount=1, both decrement to 0, and both enter
    // the page-table teardown path → double-free of every backing
    // frame.
    const u64 prev = __atomic_load_n(&as->refcount.value, __ATOMIC_ACQUIRE);
    if (prev == 0)
    {
        PanicAs("AddressSpaceRelease on AS with refcount==0", reinterpret_cast<u64>(as));
    }
    const u64 new_count = __atomic_sub_fetch(&as->refcount.value, 1, __ATOMIC_ACQ_REL);
    if (new_count != 0)
    {
        return;
    }

    // Last reference dropped. CRITICAL: if this AS is the currently-
    // active one on this CPU, switch back to the kernel AS BEFORE
    // freeing its tables — otherwise the next memory access would
    // walk freed page tables and the next interrupt would land on
    // a corrupt RSP0 stack. Reaper context is the canonical caller;
    // the reaper runs on its own task / AS, so this is normally a
    // no-op, but defensive switching is cheaper than diagnosing a
    // freed-page-table fault.
    if (AddressSpaceCurrent() == as)
    {
        AddressSpaceActivate(nullptr);
    }

    arch::SerialWrite("[as] destroying pml4_phys=");
    arch::SerialWriteHex(as->pml4_phys);
    arch::SerialWrite(" regions=");
    arch::SerialWriteHex(as->region_count);
    arch::SerialWrite("\n");

    // Return every backing frame the AS is responsible for. Walking
    // the regions table BEFORE the page tables is deliberate — we
    // don't actually need to UnmapPage from this AS's PML4 (we're
    // about to free the entire table tree), but draining the region
    // table makes the freed-frame ledger easy to audit in the
    // FrameAllocator stats: regions.count + page-table frames freed.
    // Return every backing frame the AS is responsible for. Walking
    // the regions table BEFORE the page tables is deliberate — we
    // don't actually need to UnmapPage from this AS's PML4 (we're
    // about to free the entire table tree), but draining the region
    // table makes the freed-frame ledger easy to audit in the
    // FrameAllocator stats: regions.count + page-table frames freed.
    for (u16 i = 0; i < as->region_count; ++i)
    {
        FreeFrame(as->regions[i].frame);
    }
    as->region_count = 0;
    arch::SerialWrite("[as] regions freed\n");

    // Free intermediate user-half tables, then the PML4 itself.
    FreeUserHalfTables(as->pml4_virt);
    arch::SerialWrite("[as] tables freed\n");
    FreeFrame(as->pml4_phys);
    arch::SerialWrite("[as] pml4 frame freed\n");

    KFree(as);
    arch::SerialWrite("[as] AddressSpace struct freed\n");
    ++g_destroyed;
    arch::SerialWrite("[as] release done\n");
}

AddressSpaceStats AddressSpaceStatsRead()
{
    return AddressSpaceStats{
        .created = g_created,
        .destroyed = g_destroyed,
        .cr3_switches = g_cr3_switches,
        .live = g_created - g_destroyed,
    };
}

void AddressSpaceSelfTest()
{
    KLOG_TRACE_SCOPE("mm/as", "AddressSpaceSelfTest");
    // Use a VA inside PDPT[1] of the low half — outside anything
    // ring3_smoke or any existing mapping touches. If ring3 ever
    // moves to the same VA range, bump this to stay disjoint.
    constexpr u64 kTestVa = 0x0000000050000000ULL;

    arch::SerialWrite("[mm/as] isolation self-test\n");

    auto a_r = AddressSpaceCreate(kFrameBudgetTrusted);
    if (!a_r)
    {
        PanicAs("self-test: AddressSpaceCreate failed for A", 0);
    }
    AddressSpace* a = a_r.value();
    auto b_r = AddressSpaceCreate(kFrameBudgetTrusted);
    if (!b_r)
    {
        PanicAs("self-test: AddressSpaceCreate failed for B", 0);
    }
    AddressSpace* b = b_r.value();

    const PhysAddr frame = AllocateFrame();
    if (frame == kNullFrame)
    {
        PanicAs("self-test: AllocateFrame failed", 0);
    }
    AddressSpaceMapUserPage(a, kTestVa, frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Walk a's tables directly — must find the PTE we just
    // installed, with Present + User bits set.
    u64* a_pte = WalkToPteIn(a->pml4_virt, kTestVa, /*create=*/false);
    if (a_pte == nullptr || (*a_pte & kPagePresent) == 0 || (*a_pte & kPageUser) == 0)
    {
        PanicAs("self-test: AS-A does not have the page we mapped", kTestVa);
    }

    // Walk b's tables at the same VA — must return nullptr (no
    // user-half tables exist for this VA in b's PML4 tree yet).
    // This is the CORE isolation assertion: two sibling ASes DO
    // NOT share a mapping installed in one of them.
    u64* b_pte = WalkToPteIn(b->pml4_virt, kTestVa, /*create=*/false);
    if (b_pte != nullptr && ((*b_pte) & kPagePresent) != 0)
    {
        PanicAs("self-test: AS-B SAW AS-A's private page — ISOLATION BROKEN", kTestVa);
    }

    // Deliberately NOT flipping CR3 here. kernel_main runs on the
    // boot stack (.bss.boot — low-half VA, reachable only via
    // PML4[0] of the boot PML4). New ASes copy ONLY the kernel
    // half (PML4[256..511]), so switching CR3 to a freshly-made
    // AS while on the boot stack would triple-fault on the next
    // stack access. The switch mechanics are instead proven by
    // ring3_smoke (two tasks in two ASes run to completion on
    // KMalloc'd kernel stacks, which ARE in the higher-half
    // direct map and thus reachable after CR3 flip).
    //
    // If a worker-thread-hosted flavour of this self-test is ever
    // wanted, spawn it via sched::SchedCreate after scheduler
    // bring-up — the worker's kernel stack is in kernel-half, so
    // the CR3 flip is safe from that context.

    AddressSpaceRelease(a);
    AddressSpaceRelease(b);

    arch::SerialWrite("[mm/as] isolation self-test OK\n");
}

// ---------------------------------------------------------------------------
// TLB shootdown. See address_space.h for the contract.
//
// Today (uniprocessor v0) the implementation is a local `invlpg` per page
// when the caller's CPU is in the target AS, plus a defensive `invlpg` on
// the same CPU when it's NOT — the latter is a no-op for the hardware
// (the entry can't be cached) but documents the intent.
//
// When SMP comes online, the broadcast path lights up: every AP whose
// current AS matches `as` is sent the TLB-shootdown IPI; the helper waits
// for each target to ack via a generation counter before returning, so
// the caller can rely on "shootdown done" semantics. The IPI vector and
// handler are owned by arch/x86_64/smp.{h,cpp}.
// ---------------------------------------------------------------------------

void TlbShootdownAddr(AddressSpace* as, u64 virt)
{
    // Local flush — fast path. AddressSpaceCurrent() == as means
    // the page we just unmapped is in this CPU's active CR3, so
    // its TLB definitely has a stale entry; invlpg evicts it.
    if (AddressSpaceCurrent() == as)
    {
        Invlpg(virt);
    }

    // Remote flush — broadcast to every AP whose CR3 matches `as`.
    // No-op when only the BSP is online. The arch layer owns the
    // per-CPU "current AS" lookup and the IPI vector encoding.
    arch::SmpTlbShootdownAddr(as, virt);
}

void TlbShootdownRange(AddressSpace* as, u64 virt, u64 len)
{
    const u64 page = 0x1000;
    const u64 end = virt + len;
    for (u64 v = virt & ~(page - 1); v < end; v += page)
    {
        if (AddressSpaceCurrent() == as)
        {
            Invlpg(v);
        }
    }
    arch::SmpTlbShootdownRange(as, virt, len);
}

} // namespace duetos::mm
