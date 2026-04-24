#include "paging.h"

#include "frame_allocator.h"
#include "page.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"

namespace duetos::mm
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

// CPUID.7.0 feature bits consulted by the SMEP / SMAP / CET gates below.
// Bit positions per Intel SDM Vol. 2A "CPUID — CPU Identification".
constexpr u32 kCpuidLeaf7Ebx_Smep = 1U << 7;
constexpr u32 kCpuidLeaf7Ebx_Smap = 1U << 20;
constexpr u32 kCpuidLeaf7Edx_CetIbt = 1U << 20; // Indirect Branch Tracking

// CR4 enable bits for the kernel-protection features.
constexpr u64 kCr4_Smep = 1ULL << 20;
constexpr u64 kCr4_Smap = 1ULL << 21;
constexpr u64 kCr4_Cet = 1ULL << 23;

// CET MSRs.
constexpr u32 kIa32_S_Cet = 0x6A2;         // supervisor-mode CET config
constexpr u64 kCetMsr_EndbrEn = 1ULL << 2; // enable IBT (endbr64 enforcement)

inline void ReadCpuidLeaf7_0(u32& ebx_out, u32& edx_out)
{
    u32 eax = 7, ebx = 0, ecx = 0, edx = 0;
    asm volatile("cpuid" : "+a"(eax), "+c"(ecx), "=b"(ebx), "=d"(edx));
    ebx_out = ebx;
    edx_out = edx;
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
    u32 leaf7_edx = 0;
    ReadCpuidLeaf7_0(leaf7_ebx, leaf7_edx);

    // CR0.WP (bit 16) — Write Protect. With WP=0 (default), ring-0
    // stores bypass the page-table W bit: the kernel can overwrite
    // any page regardless of its RO flag. That defeats slice-10b's
    // kernel-image W^X — a buggy kernel pointer could silently
    // scribble .text. Setting WP=1 enforces W against ring 0 too,
    // so any write to a RO page #PFs whether the writer is user or
    // kernel. The existing W^X bundles (kKernelData, kKernelMmio,
    // kKernelCode) + ProtectKernelImage all respect this; this
    // flip closes the ring-0 escape hatch.
    u64 cr0 = arch::ReadCr0();
    constexpr u64 kCr0_Wp = 1ULL << 16;
    if ((cr0 & kCr0_Wp) == 0)
    {
        arch::WriteCr0(cr0 | kCr0_Wp);
    }

    u64 cr4 = ReadCr4();
    const u64 before = cr4;
    bool cet_ibt_on = false;

    if ((leaf7_ebx & kCpuidLeaf7Ebx_Smep) != 0)
    {
        cr4 |= kCr4_Smep;
    }
    if ((leaf7_ebx & kCpuidLeaf7Ebx_Smap) != 0)
    {
        cr4 |= kCr4_Smap;
        g_smap_enabled = true;
    }

    // CET / IBT — the hardware side of Control-Flow Integrity.
    // Compiler already emitted endbr64 at indirect-branch targets
    // (via -fcf-protection=branch in the toolchain + hand-written
    // endbr64 at asm entry points); turning on IA32_S_CET.ENDBR_EN
    // + CR4.CET makes the CPU raise #CP (vector 21) on any
    // indirect branch whose target isn't an endbr64. The write
    // order MUST be: set the MSR first (so the CPU has a valid
    // CET config), then flip CR4 (which activates the feature) —
    // reversed order triggers #GP.
    //
    // IBT only, for now. Shadow stacks (CET_SS) need per-task
    // SHSTK allocation + context-switch plumbing; separate slice.
    if ((leaf7_edx & kCpuidLeaf7Edx_CetIbt) != 0)
    {
        const u64 s_cet = ReadMsr(kIa32_S_Cet);
        WriteMsr(kIa32_S_Cet, s_cet | kCetMsr_EndbrEn);
        cr4 |= kCr4_Cet;
        cet_ibt_on = true;
    }

    if (cr4 != before)
    {
        WriteCr4(cr4);
    }

    SerialWrite("[mm] CR4 protection bits: SMEP=");
    SerialWrite((cr4 & kCr4_Smep) ? "on" : "off");
    SerialWrite(" SMAP=");
    SerialWrite((cr4 & kCr4_Smap) ? "on" : "off");
    SerialWrite(" CET/IBT=");
    SerialWrite(cet_ibt_on ? "on" : "off");
    SerialWrite(" CR0.WP=");
    SerialWrite((arch::ReadCr0() & kCr0_Wp) ? "on" : "off");
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
    KLOG_TRACE_SCOPE("mm/paging", "PagingInit");
    const u64 cr3 = ReadCr3();
    const PhysAddr pml4_phys = cr3 & kAddrMask;
    g_pml4 = static_cast<u64*>(PhysToVirt(pml4_phys));

    // Enable EFER.NXE so PageNoExecute mappings are honoured. Without this
    // bit, setting bit 63 in any PTE causes a #GP.
    //
    // Also enable EFER.SCE (bit 0) so the `syscall` instruction is
    // legal from ring 3. Without it, the Linux-ABI entry at
    // MSR_LSTAR is never reached — the CPU raises #UD on the
    // syscall opcode. MSR_LSTAR itself gets programmed separately
    // by linux::SyscallInit once per-CPU data is up.
    constexpr u32 kEferMsr = 0xC0000080;
    constexpr u64 kEferNxeBit = 1ULL << 11;
    constexpr u64 kEferSceBit = 1ULL << 0;
    const u64 efer = ReadMsr(kEferMsr);
    const u64 efer_want = efer | kEferNxeBit | kEferSceBit;
    if (efer != efer_want)
    {
        WriteMsr(kEferMsr, efer_want);
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
// If `need_writable` is true, the page must also carry the Writable
// bit — used by CopyToUser so a read-only user page fails the pre-
// walk cleanly instead of partially writing the first N bytes and
// then faulting on byte N+1 (the fault-fixup would recover the
// kernel, but any bytes already stored into user memory stay).
// Missing intermediate tables (PDPT / PD / PT not allocated) are
// treated as "not mapped" — identical result to a PTE with Present=0.
bool PagePresentAndUser(u64* pml4, u64 virt, bool need_writable)
{
    u64* pte = WalkToPte(pml4, virt, /*create=*/false);
    if (pte == nullptr)
    {
        return false;
    }
    u64 need = kPagePresent | kPageUser;
    if (need_writable)
    {
        need |= kPageWritable;
    }
    return (*pte & need) == need;
}

// Walks every 4 KiB page covered by [addr, addr+len) in the ACTIVE
// PML4 and returns true only if all of them are present with the
// user bit set (and, when `need_writable` is true, also writable).
// The "active PML4" anchor is what makes per-process isolation
// work: a syscall handler running on behalf of process X reads X's
// tables, so it cannot accidentally validate a pointer against
// process Y's mappings.
//
// Per-process tables now exist (Commit: per-process PML4) so an
// unmap from another CPU's task COULD race a copy in-flight on
// this CPU — but no AP runs user code today, so the window is
// still empty in practice. Revisit when SMP scheduler join lands
// alongside a __copy_user_fault_fixup table in the trap dispatcher.
bool IsUserRangeAccessible(u64 addr, u64 len, bool need_writable)
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
        if (!PagePresentAndUser(pml4, p, need_writable))
        {
            return false;
        }
    }
    return true;
}

} // namespace

// Defined in kernel/mm/user_copy.S. Both do the actual byte copy
// plus stac/clac around it. Their inner byte-mov instructions live
// inside [__copy_user_{from,to}_start, __copy_user_{from,to}_end)
// ranges that the trap dispatcher recognises as "recoverable": on
// a ring-0 #PF inside those ranges, TrapDispatch rewrites
// frame->rip to __copy_user_fault_fixup, which cleans up and
// returns 0 — the caller sees `false` without the kernel ever
// panicking.
//
// Return: non-zero on success (all bytes copied), zero on
// recovered fault (some prefix may have landed — partial copies
// aren't rolled back; the caller treats any failure as "don't
// trust any of the buffer").
extern "C" u64 _copy_user_from(void* kernel_dst, const void* user_src, u64 len);
extern "C" u64 _copy_user_to(void* user_dst, const void* kernel_src, u64 len);

bool CopyFromUser(void* kernel_dst, const void* user_src, u64 len)
{
    const u64 src_addr = reinterpret_cast<u64>(user_src);
    if (!IsUserAddressRange(src_addr, len))
    {
        return false;
    }
    // Pre-walk the PTEs to fail fast on obviously-bad pointers
    // (unmapped, supervisor-only). The asm helper's fault-fixup
    // is a SAFETY NET for the SMP / demand-paging case where a
    // page vanishes between pre-walk and copy; the pre-walk
    // itself keeps the common "bad ptr" path out of the fault
    // handler.
    if (!IsUserRangeAccessible(src_addr, len, /*need_writable=*/false))
    {
        return false;
    }
    if (len == 0)
    {
        return true;
    }
    return _copy_user_from(kernel_dst, user_src, len) != 0;
}

bool CopyToUser(void* user_dst, const void* kernel_src, u64 len)
{
    const u64 dst_addr = reinterpret_cast<u64>(user_dst);
    if (!IsUserAddressRange(dst_addr, len))
    {
        return false;
    }
    // Writable check matters for destinations: without it, a copy
    // into a buffer whose tail crosses into a read-only user page
    // would store the leading bytes (the head page being writable)
    // before faulting on the first byte of the RO page. The fault-
    // fixup unwinds cleanly for the kernel, but the caller gets
    // -1 with some prefix already in user memory — a subtle
    // TOCTOU-shaped surprise for any future syscall that wants
    // "all or nothing" semantics.
    if (!IsUserRangeAccessible(dst_addr, len, /*need_writable=*/true))
    {
        return false;
    }
    if (len == 0)
    {
        return true;
    }
    return _copy_user_to(user_dst, kernel_src, len) != 0;
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
    // W^X enforcement — same rule as AddressSpaceMapUserPage. A
    // kernel mapping that is both writable and executable is a
    // loaded gun; enforce the invariant at the single choke point
    // where kernel mappings are created. The defined kernel flag
    // bundles (kKernelData, kKernelMmio, kKernelCode) already obey
    // the rule, so this is a defensive check against ad-hoc
    // flag sets leaking into future driver / allocator code.
    if ((flags & kPageWritable) != 0 && (flags & kPageNoExecute) == 0)
    {
        PanicPaging("MapPage: W^X violation (writable+exec kernel page)", flags);
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
    KLOG_TRACE_SCOPE("mm/paging", "MapMmio");
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

// ---------------------------------------------------------------------------
// Kernel-image W^X — split PS-mapped direct map into 4 KiB pages.
// ---------------------------------------------------------------------------
//
// boot.S installs the first 1 GiB of physical memory into the kernel's
// higher half as 2 MiB PS-mapped pages. Every kernel byte (.text,
// .rodata, .data, .bss) thus gets R + W + X by default. ProtectKernelImage
// below walks the four kernel sections, splits each 2 MiB PS page that
// covers a section boundary or interior, then rewrites the per-4 KiB
// PTE flags to match the section's intended protection.

extern "C" u8 _text_start[];
extern "C" u8 _text_end[];
extern "C" u8 _rodata_start[];
extern "C" u8 _rodata_end[];
extern "C" u8 _data_start[];
extern "C" u8 _data_end[];
extern "C" u8 _bss_start[];
extern "C" u8 _bss_end[];

namespace
{

// Bring the arch::SerialWrite / SerialWriteHex names into scope for
// this anon namespace — paging.cpp's original anon block does the
// same via its own `using arch::...` directives, but those are
// confined to that block.
using arch::SerialWrite;
using arch::SerialWriteHex;

// Split the 2 MiB PS page covering `virt_2m_aligned` into 512 4 KiB
// PTEs. `virt_2m_aligned` must be the 2 MiB-aligned base of the PS
// region; the function is a no-op if the PD entry is already a
// pointer to a PT (not a PS page). Preserves the original PS
// entry's physical base and common flags (P/W/U — the PS bit
// itself is dropped since the new entry is a PT pointer).
void SplitPsPage(u64 virt_2m_aligned)
{
    const u64 i4 = IndexPml4(virt_2m_aligned);
    const u64 i3 = IndexPdpt(virt_2m_aligned);
    const u64 i2 = IndexPd(virt_2m_aligned);

    u64& pml4_entry = g_pml4[i4];
    if ((pml4_entry & kPagePresent) == 0)
    {
        PanicPaging("SplitPsPage: PML4 entry not present", virt_2m_aligned);
    }
    auto* pdpt = static_cast<u64*>(PhysToVirt(pml4_entry & kAddrMask));

    u64& pdpt_entry = pdpt[i3];
    if ((pdpt_entry & kPagePresent) == 0)
    {
        PanicPaging("SplitPsPage: PDPT entry not present", virt_2m_aligned);
    }
    if (pdpt_entry & kPageHugeOrPat)
    {
        PanicPaging("SplitPsPage: 1 GiB PS page at PDPT level (unsupported)", virt_2m_aligned);
    }
    auto* pd = static_cast<u64*>(PhysToVirt(pdpt_entry & kAddrMask));

    u64 pd_entry = pd[i2];
    if ((pd_entry & kPagePresent) == 0)
    {
        PanicPaging("SplitPsPage: PD entry not present", virt_2m_aligned);
    }
    if ((pd_entry & kPageHugeOrPat) == 0)
    {
        return; // already a PT pointer — nothing to split
    }

    // Preserve the PS page's physical base + per-entry flag bits
    // that carry over to 4 KiB entries (P/W/U/WT/CD/A/D/G/NX). The
    // PS bit itself is in a different slot on a PTE (it's the PAT
    // bit), so we explicitly clear the PS bit and let each 4 KiB
    // entry inherit only the common flags.
    const u64 ps_phys_base = pd_entry & 0x000FFFFFFFE00000ULL; // 2 MiB-aligned
    const u64 ps_flags = pd_entry & ~(0x000FFFFFFFE00000ULL | kPageHugeOrPat);

    u64* new_pt = AllocateTable();
    for (u64 i = 0; i < kEntriesPerTable; ++i)
    {
        new_pt[i] = (ps_phys_base + i * kPageSize) | ps_flags | kPagePresent;
    }

    const PhysAddr pt_phys = VirtToPhys(new_pt);
    // Install the new PT pointer with PERMISSIVE flags at the PD
    // level: the CPU AND-combines each level's W bit and OR-combines
    // each level's NX bit during a walk. Setting NX=1 or W=0 on the
    // PD pointer would restrict every leaf under it regardless of
    // the leaf PTE's own flags — so for .text to stay executable
    // AND .data/.bss to stay writable through the same PD, the PD
    // pointer must have W=1 and NX=0. The per-4 KiB PTE rewrite in
    // SetPteFlags4K is what actually enforces W^X at leaf granularity.
    pd[i2] = pt_phys | kPagePresent | kPageWritable;

    // Flush every 4 KiB entry the split covers so the CPU can't
    // keep using the cached 2 MiB TLB entry.
    for (u64 off = 0; off < 2ULL * 1024 * 1024; off += kPageSize)
    {
        Invlpg(virt_2m_aligned + off);
    }
}

// Apply `flags` to every 4 KiB page in [va_start, va_end). Both
// addresses must be 4 KiB-aligned on entry; the linker script uses
// ALIGN(4K) after every section to ensure this.
void ProtectRange(u64 va_start, u64 va_end, u64 flags, const char* name)
{
    if (va_start >= va_end)
    {
        return;
    }
    SerialWrite("[mm/paging] protecting ");
    SerialWrite(name);
    SerialWrite(" [");
    SerialWriteHex(va_start);
    SerialWrite(" .. ");
    SerialWriteHex(va_end);
    SerialWrite(") flags=");
    SerialWriteHex(flags);
    SerialWrite("\n");

    for (u64 v = va_start; v < va_end; v += kPageSize)
    {
        SetPteFlags4K(v, flags);
    }
}

} // namespace

// Overwrite the PTE flags for one 4 KiB page (keeping the physical
// base). Splits the parent 2 MiB PS if necessary. Panics if the
// page isn't mapped yet — we don't create mappings here, only
// adjust flags on existing ones.
//
// Lives at namespace scope (not in the anon block above) because
// the debug subsystem patches int3 bytes into .text and needs to
// flip per-page writability through this same API.
void SetPteFlags4K(u64 virt, u64 new_flags)
{
    if ((virt & kPageMask) != 0)
    {
        PanicPaging("SetPteFlags4K: unaligned virt", virt);
    }
    const u64 ps_base = virt & ~0x1FFFFFULL; // 2 MiB-aligned
    SplitPsPage(ps_base);

    u64* pte = WalkToPte(g_pml4, virt, /*create=*/false);
    if (pte == nullptr || (*pte & kPagePresent) == 0)
    {
        PanicPaging("SetPteFlags4K: page not mapped", virt);
    }
    const u64 phys = *pte & kAddrMask;
    *pte = phys | (new_flags | kPagePresent);
    Invlpg(virt);
}

void ProtectKernelImage()
{
    KLOG_TRACE_SCOPE("mm/paging", "ProtectKernelImage");
    // Flags for each section. .text is RO + executable; everything
    // else gets NX. .rodata stays non-writable too (constants); .data
    // and .bss are writable scratch/state for the kernel.
    constexpr u64 kText = kPagePresent;                                     // R + X
    constexpr u64 kRodata = kPagePresent | kPageNoExecute;                  // R
    constexpr u64 kDataBss = kPagePresent | kPageWritable | kPageNoExecute; // R + W

    ProtectRange(reinterpret_cast<u64>(_text_start), reinterpret_cast<u64>(_text_end), kText, ".text");
    ProtectRange(reinterpret_cast<u64>(_rodata_start), reinterpret_cast<u64>(_rodata_end), kRodata, ".rodata");
    ProtectRange(reinterpret_cast<u64>(_data_start), reinterpret_cast<u64>(_data_end), kDataBss, ".data");
    ProtectRange(reinterpret_cast<u64>(_bss_start), reinterpret_cast<u64>(_bss_end), kDataBss, ".bss");

    arch::SerialWrite("[mm/paging] kernel image W^X applied\n");
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
    KLOG_TRACE_SCOPE("mm/paging", "PagingSelfTest");
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

} // namespace duetos::mm
