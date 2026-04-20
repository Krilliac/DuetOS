#include "paging.h"

#include "frame_allocator.h"
#include "page.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../core/panic.h"

namespace customos::mm
{

namespace
{

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
    core::PanicWithValue("mm/paging", message, value);
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

// CPUID.7.0 feature bits consulted by the SMEP / SMAP gate below.
// Bit positions per Intel SDM Vol. 2A "CPUID — CPU Identification".
constexpr u32 kCpuidLeaf7Ebx_Smep = 1U << 7;
constexpr u32 kCpuidLeaf7Ebx_Smap = 1U << 20;

// CR4 enable bits for the two kernel-protection features.
constexpr u64 kCr4_Smep = 1ULL << 20;
constexpr u64 kCr4_Smap = 1ULL << 21;

inline void ReadCpuidLeaf7_0(u32& ebx_out)
{
    u32 eax = 7, ebx = 0, ecx = 0, edx = 0;
    asm volatile("cpuid" : "+a"(eax), "+c"(ecx), "=b"(ebx), "=d"(edx));
    ebx_out = ebx;
}

inline u64 ReadCr4()
{
    u64 v;
    asm volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}

inline void WriteCr4(u64 v)
{
    asm volatile("mov %0, %%cr4" : : "r"(v) : "memory");
}

bool g_smap_enabled = false;

// Flip on SMEP (bit 20) and SMAP (bit 21) in CR4 if CPUID reports them.
// SMEP: kernel-mode code fetch from a user page #PFs — kills an entire
// class of "spray user shellcode, pivot to it via a ret-to-user bug"
// exploits. SMAP: kernel-mode data access to a user page #PFs UNLESS
// AC (RFLAGS.AC) is set via the stac instruction — forces every
// kernel→user touch to go through an explicit, auditable helper. The
// cost is ~nothing (both are 1-cycle CR4 flips + whatever stac/clac
// the copy helpers add). Both are present on any Intel CPU from
// Broadwell (2014) and any AMD CPU from Zen+ onwards; on older
// hardware we just stay in the pre-protection posture.
void EnableKernelProtectionBits()
{
    u32 leaf7_ebx = 0;
    ReadCpuidLeaf7_0(leaf7_ebx);

    u64 cr4 = ReadCr4();
    const u64 before = cr4;

    if ((leaf7_ebx & kCpuidLeaf7Ebx_Smep) != 0)
    {
        cr4 |= kCr4_Smep;
    }
    if ((leaf7_ebx & kCpuidLeaf7Ebx_Smap) != 0)
    {
        cr4 |= kCr4_Smap;
        g_smap_enabled = true;
    }

    if (cr4 != before)
    {
        WriteCr4(cr4);
    }

    SerialWrite("[mm] CR4 protection bits: SMEP=");
    SerialWrite((cr4 & kCr4_Smep) ? "on" : "off");
    SerialWrite(" SMAP=");
    SerialWrite((cr4 & kCr4_Smap) ? "on" : "off");
    SerialWrite("\n");
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

// Walk to (or create) the PT for `virt` inside the page-table tree
// rooted at `pml4`, returning a pointer to the PTE slot. `create`
// controls whether missing intermediate tables are allocated or
// treated as "no mapping" (returns nullptr).
//
// The pml4 argument is what makes per-process address spaces possible:
// the kernel can install a user mapping into AS X's tables while a
// task on AS Y is the active one — no CR3 flip required to populate.
// The kernel-half mappings inside `pml4` must alias the boot PML4's
// kernel-half entries (AddressSpaceCreate enforces this by copying
// indices 256..511 verbatim).
u64* WalkToPte(u64* pml4, uptr virt, bool create)
{
    const u64 i4 = IndexPml4(virt);
    const u64 i3 = IndexPdpt(virt);
    const u64 i2 = IndexPd(virt);
    const u64 i1 = IndexPt(virt);

    u64& pml4_entry = pml4[i4];
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

    EnableKernelProtectionBits();

    SerialWrite("[mm] paging adopted boot PML4: cr3_phys=");
    SerialWriteHex(pml4_phys);
    SerialWrite(" pml4_virt=");
    SerialWriteHex(reinterpret_cast<u64>(g_pml4));
    SerialWrite("\n");
}

// ---------------------------------------------------------------------------
// User-pointer copy helpers
//
// Every kernel read/write through a user-supplied pointer goes through
// these. They:
//
//   1. Reject pointers outside the canonical low half (anything with the
//      top bits set belongs to kernel space — a syscall passing such a
//      pointer is either malicious or broken, either way the answer is
//      "no").
//   2. Reject len == 0 as success (no-op copy) and any length that wraps
//      around or crosses the low/high-half boundary.
//   3. Gate the actual byte-by-byte copy with stac / clac when SMAP is
//      active, so the CPU's SMAP check lets through the user access only
//      inside this helper. A bug that tries to dereference user memory
//      anywhere else still #PFs.
//
// v0 intentionally does NOT catch #PF during the copy. If the user
// pointer is mapped but the target page is gone mid-copy, the trap
// dispatcher halts — exactly as it does today for any other kernel #PF.
// The proper fix is a __copy_user_fault_fixup table (one entry pointing
// at a "return false" label per copy loop); landing that alongside the
// first syscall that can legitimately trigger a page fault is the next
// natural slice.
// ---------------------------------------------------------------------------

bool IsUserAddressRange(u64 addr, u64 len)
{
    // Canonical low half ends at 0x00007FFF_FFFFFFFF on x86_64. Anything
    // above that is kernel (canonical high half) or the non-canonical
    // hole between them. We're strict on both ends: a user pointer must
    // fit, AND `addr + len` must not overflow OR cross the boundary.
    constexpr u64 kUserMax = 0x00007FFFFFFFFFFFULL;
    if (len == 0)
    {
        return true; // zero-byte copy is trivially valid
    }
    if (addr > kUserMax)
    {
        return false;
    }
    // Overflow check before computing addr + len.
    if (len > kUserMax)
    {
        return false;
    }
    if (addr + (len - 1) > kUserMax)
    {
        return false;
    }
    return true;
}

namespace
{

// Active PML4 = whatever CR3 currently points at. Used by the user-
// pointer validators so that a syscall coming out of process X reads
// X's tables, not some other process's. Reading CR3 once per syscall
// is cheap (a single instruction); caching it in per-CPU buys nothing
// because the syscall path already crossed at least one cacheline of
// per-CPU state on entry.
u64* ActivePml4()
{
    const u64 cr3 = arch::ReadCr3();
    return static_cast<u64*>(PhysToVirt(cr3 & kAddrMask));
}

// Page-table walk helper: returns true iff the 4 KiB page containing
// `virt` is present AND user-accessible in the ACTIVE address space.
// Missing intermediate tables (PDPT / PD / PT not allocated) are
// treated as "not mapped" — identical result to a PTE with Present=0.
bool PagePresentAndUser(u64* pml4, u64 virt)
{
    u64* pte = WalkToPte(pml4, virt, /*create=*/false);
    if (pte == nullptr)
    {
        return false;
    }
    constexpr u64 kNeed = kPagePresent | kPageUser;
    return (*pte & kNeed) == kNeed;
}

// Walks every 4 KiB page covered by [addr, addr+len) in the ACTIVE
// PML4 and returns true only if all of them are present with the
// user bit set. The "active PML4" anchor is what makes per-process
// isolation work: a syscall handler running on behalf of process X
// reads X's tables, so it cannot accidentally validate a pointer
// against process Y's mappings.
//
// Per-process tables now exist (Commit: per-process PML4) so an
// unmap from another CPU's task COULD race a copy in-flight on
// this CPU — but no AP runs user code today, so the window is
// still empty in practice. Revisit when SMP scheduler join lands
// alongside a __copy_user_fault_fixup table in the trap dispatcher.
bool IsUserRangeAccessible(u64 addr, u64 len)
{
    if (len == 0)
    {
        return true;
    }
    u64* pml4 = ActivePml4();
    const u64 start = addr & ~kPageMask;
    const u64 end = (addr + len - 1) & ~kPageMask;
    for (u64 p = start; p <= end; p += kPageSize)
    {
        if (!PagePresentAndUser(pml4, p))
        {
            return false;
        }
    }
    return true;
}

} // namespace

bool CopyFromUser(void* kernel_dst, const void* user_src, u64 len)
{
    const u64 src_addr = reinterpret_cast<u64>(user_src);
    if (!IsUserAddressRange(src_addr, len))
    {
        return false;
    }
    if (!IsUserRangeAccessible(src_addr, len))
    {
        return false;
    }
    auto* dst = static_cast<u8*>(kernel_dst);
    const auto* src = static_cast<const u8*>(user_src);

    if (g_smap_enabled)
    {
        asm volatile("stac" ::: "cc");
    }
    for (u64 i = 0; i < len; ++i)
    {
        dst[i] = src[i];
    }
    if (g_smap_enabled)
    {
        asm volatile("clac" ::: "cc");
    }
    return true;
}

bool CopyToUser(void* user_dst, const void* kernel_src, u64 len)
{
    const u64 dst_addr = reinterpret_cast<u64>(user_dst);
    if (!IsUserAddressRange(dst_addr, len))
    {
        return false;
    }
    if (!IsUserRangeAccessible(dst_addr, len))
    {
        return false;
    }
    auto* dst = static_cast<u8*>(user_dst);
    const auto* src = static_cast<const u8*>(kernel_src);

    if (g_smap_enabled)
    {
        asm volatile("stac" ::: "cc");
    }
    for (u64 i = 0; i < len; ++i)
    {
        dst[i] = src[i];
    }
    if (g_smap_enabled)
    {
        asm volatile("clac" ::: "cc");
    }
    return true;
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

    u64* pte = WalkToPte(g_pml4, virt, /*create=*/true);
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

    u64* pte = WalkToPte(g_pml4, virt, /*create=*/false);
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

u64* BootPml4Virt()
{
    return g_pml4;
}

PhysAddr BootPml4Phys()
{
    return VirtToPhys(g_pml4);
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
