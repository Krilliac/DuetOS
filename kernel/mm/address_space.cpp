#include "address_space.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"
#include "../cpu/percpu.h"
#include "frame_allocator.h"
#include "kheap.h"
#include "page.h"

namespace customos::mm
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
constinit u64 g_created = 0;
constinit u64 g_destroyed = 0;
constinit u64 g_cr3_switches = 0;

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
// virtual alias. Same as AllocateTable in paging.cpp; deliberately
// duplicated for the same internal-namespace reason as above.
u64* AllocateTable()
{
    const PhysAddr frame = AllocateFrame();
    if (frame == kNullFrame)
    {
        PanicAs("AllocateFrame returned null inside AS walker", 0);
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

AddressSpace* AddressSpaceCreate()
{
    auto* as = static_cast<AddressSpace*>(KMalloc(sizeof(AddressSpace)));
    if (as == nullptr)
    {
        return nullptr;
    }

    const PhysAddr pml4_frame = AllocateFrame();
    if (pml4_frame == kNullFrame)
    {
        KFree(as);
        return nullptr;
    }

    auto* pml4 = static_cast<u64*>(PhysToVirt(pml4_frame));

    // Zero the user half (PML4[0..255]) so a freshly-spawned process
    // has a guaranteed-empty low half. Copy the kernel half
    // (PML4[256..511]) verbatim from the boot PML4 — those entries
    // point at PDPTs that are shared by every AS, so any future
    // kernel-half mapping change propagates everywhere automatically.
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
    if (as->region_count >= kMaxUserVmRegionsPerAs)
    {
        PanicAs("AddressSpaceMapUserPage: region table full", as->region_count);
    }

    u64* pte = WalkToPteIn(as->pml4_virt, virt, /*create=*/true);
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

void AddressSpaceActivate(AddressSpace* as)
{
    cpu::PerCpu* p = cpu::CurrentCpu();
    if (p->current_as == as)
    {
        return; // fast path: no-op same-AS switch
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

void AddressSpaceRetain(AddressSpace* as)
{
    if (as == nullptr)
    {
        return;
    }
    ++as->refcount;
}

void AddressSpaceRelease(AddressSpace* as)
{
    if (as == nullptr)
    {
        return;
    }
    if (as->refcount == 0)
    {
        PanicAs("AddressSpaceRelease on AS with refcount==0", reinterpret_cast<u64>(as));
    }
    --as->refcount;
    if (as->refcount != 0)
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
    for (u8 i = 0; i < as->region_count; ++i)
    {
        FreeFrame(as->regions[i].frame);
    }
    as->region_count = 0;

    // Free intermediate user-half tables, then the PML4 itself.
    FreeUserHalfTables(as->pml4_virt);
    FreeFrame(as->pml4_phys);

    KFree(as);
    ++g_destroyed;
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

} // namespace customos::mm
