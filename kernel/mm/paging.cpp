#include "paging.h"

#include "frame_allocator.h"
#include "page.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"

namespace customos::mm
{

namespace
{

using arch::Halt;
using arch::ReadCr3;
using arch::SerialWrite;
using arch::SerialWriteHex;

// Each page table is 512 entries of 8 bytes = 4 KiB.
constexpr u64 kEntriesPerTable = 512;
constexpr u64 kPageMask = kPageSize - 1;
constexpr u64 kAddrMask = 0x000FFFFFFFFFF000ULL; // bits 12..51 = phys frame

constinit u64* g_pml4 = nullptr; // virtual pointer to the active PML4
constinit u64 g_mmio_cursor = 0; // bump-allocator offset within MMIO arena
constinit u64 g_tables_allocated = 0;
constinit u64 g_mappings_installed = 0;
constinit u64 g_mappings_removed = 0;

[[noreturn]] void PanicPaging(const char* message, u64 value)
{
    SerialWrite("\n[panic] mm/paging: ");
    SerialWrite(message);
    SerialWrite(" value=");
    SerialWriteHex(value);
    SerialWrite("\n");
    Halt();
}

inline u64 IndexPml4(uptr v)
{
    return (v >> 39) & 0x1FF;
}
inline u64 IndexPdpt(uptr v)
{
    return (v >> 30) & 0x1FF;
}
inline u64 IndexPd(uptr v)
{
    return (v >> 21) & 0x1FF;
}
inline u64 IndexPt(uptr v)
{
    return (v >> 12) & 0x1FF;
}

inline void Invlpg(uptr v)
{
    asm volatile("invlpg (%0)" : : "r"(v) : "memory");
}

inline u64 ReadMsr(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (static_cast<u64>(hi) << 32) | lo;
}

inline void WriteMsr(u32 msr, u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFF);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

// Allocate a fresh page-table frame, zero it via the direct map, and return
// a virtual pointer into that frame. The physical address is recoverable
// from the entry stored by callers.
u64* AllocateTable()
{
    const PhysAddr frame = AllocateFrame();
    if (frame == kNullFrame)
    {
        PanicPaging("AllocateFrame returned null while building page tables", 0);
    }
    auto* table = static_cast<u64*>(PhysToVirt(frame));
    for (u64 i = 0; i < kEntriesPerTable; ++i)
    {
        table[i] = 0;
    }
    ++g_tables_allocated;
    return table;
}

// Walk to (or create) the PT for `virt`, returning a pointer to the PTE
// slot. `create` controls whether missing intermediate tables are allocated
// or treated as "no mapping" (returns nullptr).
u64* WalkToPte(uptr virt, bool create)
{
    const u64 i4 = IndexPml4(virt);
    const u64 i3 = IndexPdpt(virt);
    const u64 i2 = IndexPd(virt);
    const u64 i1 = IndexPt(virt);

    u64& pml4_entry = g_pml4[i4];
    if ((pml4_entry & kPagePresent) == 0)
    {
        if (!create)
            return nullptr;
        u64* new_pdpt = AllocateTable();
        const PhysAddr phys = VirtToPhys(new_pdpt);
        pml4_entry = phys | kPagePresent | kPageWritable;
    }
    auto* pdpt = static_cast<u64*>(PhysToVirt(pml4_entry & kAddrMask));

    u64& pdpt_entry = pdpt[i3];
    if ((pdpt_entry & kPagePresent) == 0)
    {
        if (!create)
            return nullptr;
        u64* new_pd = AllocateTable();
        const PhysAddr phys = VirtToPhys(new_pd);
        pdpt_entry = phys | kPagePresent | kPageWritable;
    }
    if (pdpt_entry & kPageHugeOrPat)
    {
        // 1 GiB PS page covers this address; can't split in v0.
        PanicPaging("WalkToPte hit a 1 GiB PS page", virt);
    }
    auto* pd = static_cast<u64*>(PhysToVirt(pdpt_entry & kAddrMask));

    u64& pd_entry = pd[i2];
    if ((pd_entry & kPagePresent) == 0)
    {
        if (!create)
            return nullptr;
        u64* new_pt = AllocateTable();
        const PhysAddr phys = VirtToPhys(new_pt);
        pd_entry = phys | kPagePresent | kPageWritable;
    }
    if (pd_entry & kPageHugeOrPat)
    {
        // 2 MiB PS page covers this address — boot direct map. Splitting
        // it would require new PT pages and a memmove of the existing 2
        // MiB worth of mappings. v0: callers must stay out of [0..1 GiB].
        PanicPaging("WalkToPte hit a 2 MiB PS page (direct map?)", virt);
    }
    auto* pt = static_cast<u64*>(PhysToVirt(pd_entry & kAddrMask));

    return &pt[i1];
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
void PagingInit()
{
    const u64 cr3 = ReadCr3();
    const PhysAddr pml4_phys = cr3 & kAddrMask;
    g_pml4 = static_cast<u64*>(PhysToVirt(pml4_phys));

    // Enable EFER.NXE so PageNoExecute mappings are honoured. Without this
    // bit, setting bit 63 in any PTE causes a #GP.
    constexpr u32 kEferMsr = 0xC0000080;
    constexpr u64 kEferNxeBit = 1ULL << 11;
    const u64 efer = ReadMsr(kEferMsr);
    if ((efer & kEferNxeBit) == 0)
    {
        WriteMsr(kEferMsr, efer | kEferNxeBit);
    }

    g_mmio_cursor = 0;
    g_tables_allocated = 0;
    g_mappings_installed = 0;
    g_mappings_removed = 0;

    SerialWrite("[mm] paging adopted boot PML4: cr3_phys=");
    SerialWriteHex(pml4_phys);
    SerialWrite(" pml4_virt=");
    SerialWriteHex(reinterpret_cast<u64>(g_pml4));
    SerialWrite("\n");
}

void MapPage(uptr virt, PhysAddr phys, u64 flags)
{
    if ((virt & kPageMask) != 0)
    {
        PanicPaging("MapPage: unaligned virtual address", virt);
    }
    if ((phys & kPageMask) != 0)
    {
        PanicPaging("MapPage: unaligned physical address", phys);
    }

    u64* pte = WalkToPte(virt, /*create=*/true);
    if (*pte & kPagePresent)
    {
        PanicPaging("MapPage: virtual address already mapped", virt);
    }

    *pte = (phys & kAddrMask) | (flags | kPagePresent);
    Invlpg(virt);
    ++g_mappings_installed;
}

void UnmapPage(uptr virt)
{
    if ((virt & kPageMask) != 0)
    {
        PanicPaging("UnmapPage: unaligned virtual address", virt);
    }

    u64* pte = WalkToPte(virt, /*create=*/false);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
    {
        return; // not mapped — silent no-op
    }

    *pte = 0;
    Invlpg(virt);
    ++g_mappings_removed;
}

void* MapMmio(PhysAddr phys, u64 bytes)
{
    if (bytes == 0)
    {
        return nullptr;
    }
    const u64 page_offset = phys & kPageMask;
    const PhysAddr base_phys = phys & ~kPageMask;
    const u64 total = (page_offset + bytes + kPageMask) & ~kPageMask;
    const u64 frames = total >> kPageSizeLog2;

    if (g_mmio_cursor + total > kMmioArenaBytes)
    {
        return nullptr; // arena exhausted
    }

    const uptr base_virt = kMmioArenaBase + g_mmio_cursor;
    g_mmio_cursor += total;

    for (u64 i = 0; i < frames; ++i)
    {
        MapPage(base_virt + i * kPageSize, base_phys + i * kPageSize, kKernelMmio);
    }

    return reinterpret_cast<void*>(base_virt + page_offset);
}

void UnmapMmio(void* virt, u64 bytes)
{
    if (virt == nullptr || bytes == 0)
    {
        return;
    }
    const uptr v = reinterpret_cast<uptr>(virt);
    const uptr base_virt = v & ~kPageMask;
    const u64 page_offset = v & kPageMask;
    const u64 total = (page_offset + bytes + kPageMask) & ~kPageMask;
    const u64 frames = total >> kPageSizeLog2;

    for (u64 i = 0; i < frames; ++i)
    {
        UnmapPage(base_virt + i * kPageSize);
    }
}

PagingStats PagingStatsRead()
{
    return PagingStats{
        .page_tables_allocated = g_tables_allocated,
        .mappings_installed = g_mappings_installed,
        .mappings_removed = g_mappings_removed,
        .mmio_arena_used_bytes = g_mmio_cursor,
    };
}

void PagingSelfTest()
{
    SerialWrite("[mm] paging self-test\n");

    // Allocate one frame, map it twice into the MMIO arena, and use the
    // second mapping to read what the first wrote. Proves: walker descent,
    // intermediate-table allocation, PTE install, TLB consistency.
    const PhysAddr frame = AllocateFrame();
    if (frame == kNullFrame)
    {
        PanicPaging("self-test: AllocateFrame returned null", 0);
    }

    auto* alias_a = static_cast<volatile u64*>(MapMmio(frame, kPageSize));
    auto* alias_b = static_cast<volatile u64*>(MapMmio(frame, kPageSize));
    if (alias_a == nullptr || alias_b == nullptr)
    {
        PanicPaging("self-test: MapMmio returned null", 0);
    }
    if (alias_a == alias_b)
    {
        PanicPaging("self-test: aliases share a virtual address", 0);
    }

    SerialWrite("  alias A    : ");
    SerialWriteHex(reinterpret_cast<u64>(alias_a));
    SerialWrite("\n");
    SerialWrite("  alias B    : ");
    SerialWriteHex(reinterpret_cast<u64>(alias_b));
    SerialWrite("\n");

    constexpr u64 kPattern = 0xA1B2C3D4DEADBEEFULL;
    alias_a[0] = kPattern;
    alias_a[127] = ~kPattern;

    if (alias_b[0] != kPattern || alias_b[127] != ~kPattern)
    {
        PanicPaging("self-test: aliased read did not see aliased write", 0);
    }

    UnmapMmio(const_cast<u64*>(alias_a), kPageSize);
    UnmapMmio(const_cast<u64*>(alias_b), kPageSize);
    FreeFrame(frame);

    const PagingStats s = PagingStatsRead();
    SerialWrite("  tables     : ");
    SerialWriteHex(s.page_tables_allocated);
    SerialWrite(" mappings_installed=");
    SerialWriteHex(s.mappings_installed);
    SerialWrite(" removed=");
    SerialWriteHex(s.mappings_removed);
    SerialWrite("\n");

    SerialWrite("[mm] paging self-test OK\n");
}

} // namespace customos::mm
