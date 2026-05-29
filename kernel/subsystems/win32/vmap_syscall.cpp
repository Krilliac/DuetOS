#include "subsystems/win32/vmap_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "proc/process.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/paging.h"

namespace duetos::subsystems::win32
{

void DoVmap(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/vmap", "DoVmap: requested bytes", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        KLOG_WARN("win32/vmap", "DoVmap: no current Process");
        frame->rax = 0;
        return;
    }
    const u64 bytes = frame->rdi;
    if (bytes == 0)
    {
        KLOG_DEBUG("win32/vmap", "DoVmap: zero-byte request -> 0");
        frame->rax = 0;
        return;
    }
    const u64 pages = (bytes + mm::kPageSize - 1) / mm::kPageSize;
    if (pages == 0 || proc->vmap_pages_used + pages > core::Process::kWin32VmapCapPages)
    {
        KLOG_WARN_2V("win32/vmap", "DoVmap: arena cap exceeded", "pages", pages, "used",
                     static_cast<u64>(proc->vmap_pages_used));
        arch::SerialWrite("[sys] vmap oom pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" bytes=");
        arch::SerialWriteHex(bytes);
        arch::SerialWrite(" pages=");
        arch::SerialWriteHex(pages);
        arch::SerialWrite(" used=");
        arch::SerialWriteHex(proc->vmap_pages_used);
        arch::SerialWrite("\n");
        frame->rax = 0;
        return;
    }
    const u64 base = proc->vmap_base + proc->vmap_pages_used * mm::kPageSize;
    for (u64 i = 0; i < pages; ++i)
    {
        const mm::PhysAddr f = mm::AllocateFrame().value_or(mm::kNullFrame);
        if (f == mm::kNullFrame)
        {
            // OOM partway through — frames already mapped stay
            // mapped but their VA is unreachable to the caller.
            // Bump cursor anyway so stranded VAs are never reused
            // (simpler than unwinding; v0 accepts the leak).
            proc->vmap_pages_used += i;
            arch::SerialWrite("[sys] vmap partial-oom pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" mapped=");
            arch::SerialWriteHex(i);
            arch::SerialWrite("/");
            arch::SerialWriteHex(pages);
            arch::SerialWrite("\n");
            KLOG_ERROR_2V("win32/vmap", "DoVmap: partial-OOM (frames stranded)", "mapped", i, "wanted", pages);
            frame->rax = 0;
            return;
        }
        mm::AddressSpaceMapUserPage(proc->as, base + i * mm::kPageSize, f,
                                    mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute);
    }
    proc->vmap_pages_used += pages;
    arch::SerialWrite("[sys] vmap ok pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" va=");
    arch::SerialWriteHex(base);
    arch::SerialWrite(" pages=");
    arch::SerialWriteHex(pages);
    arch::SerialWrite("\n");
    KLOG_INFO_2V("win32/vmap", "DoVmap: ok", "va", base, "pages", pages);
    frame->rax = base;
}

void DoVunmap(arch::TrapFrame* frame)
{
    // v0: no-op with a range-validity check. A bump-only arena
    // can't free individual regions without turning into a real
    // allocator, so VirtualFree is documented as a leak.
    KLOG_TRACE_V("win32/vmap", "DoVunmap: va", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        KLOG_WARN("win32/vmap", "DoVunmap: no current Process");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 va = frame->rdi;
    const u64 arena_end = proc->vmap_base + core::Process::kWin32VmapCapPages * mm::kPageSize;
    if (va < proc->vmap_base || va >= arena_end)
    {
        KLOG_WARN_V("win32/vmap", "DoVunmap: VA outside arena", va);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = 0;
    KLOG_ONCE_INFO("win32/vmap", "DoVunmap: v0 leaks (no per-region free)");
}

// Win32 alloc-type / protection bits we recognise. The full set is
// well-documented in the SDK; we honour the ones whose semantics
// the kernel can enforce today.
namespace
{
constexpr u64 kMemCommit = 0x00001000ULL;
constexpr u64 kMemReserve = 0x00002000ULL;
constexpr u64 kMemDecommit = 0x00004000ULL;
constexpr u64 kMemRelease = 0x00008000ULL;
constexpr u64 kMemWriteWatch = 0x00200000ULL;

constexpr u64 kPageNoAccess = 0x01;
constexpr u64 kPageReadOnly = 0x02;
constexpr u64 kPageReadWrite = 0x04;
constexpr u64 kPageExecute = 0x10;
constexpr u64 kPageExecuteRead = 0x20;
constexpr u64 kPageExecuteReadWrite = 0x40;
constexpr u64 kPageGuard = 0x100;

// Translate Win32 protection to AS page flags. Returns true on
// success; out_flags receives kPagePresent + kPageUser plus the
// matching read / write / execute bits. NOACCESS is mapped as
// "Present + User + NX, no Writable" — caller traps on read too
// because we can't fully clear Present without confusing the
// region tracker. v0 enforces W^X: any *EXECUTE* protection is
// rejected here (vmap pages stay NX).
//
// PAGE_GUARD combos (e.g. PAGE_READWRITE | PAGE_GUARD) are
// recognised: out_is_guard is set true and out_flags is forced
// to the NOACCESS shape (no Writable) so the first touch traps.
// The fault handler then strips the guard bit and re-applies the
// base protection via `Win32VmapPageGuardClear` (see below).
bool Win32ProtToPageFlags(u64 prot, u64& out_flags, bool& out_is_guard)
{
    out_is_guard = (prot & kPageGuard) != 0;
    const u64 base = prot & ~kPageGuard;
    out_flags = mm::kPagePresent | mm::kPageUser | mm::kPageNoExecute;
    switch (base)
    {
    case kPageNoAccess:
        // Closest we can get without confusing the region tracker.
        // A guard / NOACCESS region traps on write (no Writable),
        // and a future slice can extend the AS layer to clear
        // Present too.
        return true;
    case kPageReadOnly:
        // If guard-armed, keep the no-Writable shape. Otherwise the
        // user explicitly asked for read-only.
        return true;
    case kPageReadWrite:
        // Guard-armed: drop the Writable bit so the first write
        // faults. Otherwise install Writable as usual.
        if (!out_is_guard)
            out_flags |= mm::kPageWritable;
        return true;
    case kPageExecute:
    case kPageExecuteRead:
    case kPageExecuteReadWrite:
        // W^X — refuse any executable mapping in the heap arena.
        return false;
    default:
        // Unrecognised protection bit combination.
        return false;
    }
}

// Back-compat shim for callers that don't need the guard bit.
bool Win32ProtToPageFlags(u64 prot, u64& out_flags)
{
    bool unused = false;
    return Win32ProtToPageFlags(prot, out_flags, unused);
}

// Find an existing region whose [base_va, base_va + pages*4096)
// covers `va`. Returns the slot index or kCap on miss.
u64 FindRegionContaining(const ::duetos::core::Process* proc, u64 va)
{
    using ::duetos::core::Process;
    for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
    {
        const auto& r = proc->vmap_regions[i];
        if (!r.in_use)
            continue;
        if (va >= r.base_va && va < r.base_va + static_cast<u64>(r.pages) * mm::kPageSize)
            return i;
    }
    return Process::kWin32VmapRegionCap;
}

u64 FindFreeRegionSlot(const ::duetos::core::Process* proc)
{
    using ::duetos::core::Process;
    for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
        if (!proc->vmap_regions[i].in_use)
            return i;
    return Process::kWin32VmapRegionCap;
}

// Allocate frames + map for the page indices in `commit_mask`.
// Returns true on full success. On partial OOM, unmaps the pages
// that were mapped and returns false; the region's
// committed_bits stays unchanged on failure.
bool CommitPages(::duetos::core::Process* proc, ::duetos::core::Process::Win32VmapRegion& r, u32 commit_mask,
                 u64 page_flags)
{
    using namespace ::duetos::mm;
    u32 mapped_mask = 0;
    for (u32 i = 0; i < r.pages; ++i)
    {
        if ((commit_mask & (1u << i)) == 0)
            continue;
        if ((r.committed_bits & (1u << i)) != 0)
            continue; // already committed — caller's race
        auto f_r = AllocateFrame();
        if (!f_r)
        {
            // Roll back.
            for (u32 j = 0; j < i; ++j)
                if ((mapped_mask & (1u << j)) != 0)
                    AddressSpaceUnmapUserPage(proc->as, r.base_va + j * kPageSize);
            return false;
        }
        const PhysAddr f = f_r.value();
        AddressSpaceMapUserPage(proc->as, r.base_va + i * kPageSize, f, page_flags);
        mapped_mask |= (1u << i);
    }
    r.committed_bits |= mapped_mask;
    return true;
}

void DecommitPages(::duetos::core::Process* proc, ::duetos::core::Process::Win32VmapRegion& r, u32 mask)
{
    for (u32 i = 0; i < r.pages; ++i)
    {
        if ((mask & (1u << i)) != 0 && (r.committed_bits & (1u << i)) != 0)
        {
            ::duetos::mm::AddressSpaceUnmapUserPage(proc->as, r.base_va + i * ::duetos::mm::kPageSize);
            r.committed_bits &= ~(1u << i);
        }
    }
}

} // namespace

void DoVirtualAlloc(arch::TrapFrame* frame)
{
    using ::duetos::core::Process;
    Process* proc = ::duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 size_bytes = frame->rdi;
    const u64 alloc_type = frame->rsi;
    const u64 protection = frame->rdx;
    const u64 hint_va = frame->r10;

    if (size_bytes == 0)
    {
        frame->rax = 0;
        return;
    }
    if ((alloc_type & kMemWriteWatch) != 0)
    {
        // Reject — same as the legacy path.
        frame->rax = 0;
        return;
    }

    const u32 pages = static_cast<u32>((size_bytes + mm::kPageSize - 1) / mm::kPageSize);
    if (pages == 0 || pages > Process::kWin32VmapRegionPagesMax)
    {
        frame->rax = 0;
        return;
    }

    u64 page_flags = 0;
    bool is_guard = false;
    if (!Win32ProtToPageFlags(protection, page_flags, is_guard))
    {
        frame->rax = 0;
        return;
    }

    const bool reserve_only = (alloc_type & kMemCommit) == 0 && (alloc_type & kMemReserve) != 0;
    const bool commit_into_existing = (alloc_type & kMemCommit) != 0 && (alloc_type & kMemReserve) == 0 && hint_va != 0;
    const bool reserve_and_commit = !reserve_only && !commit_into_existing;

    if (commit_into_existing)
    {
        // Find the matching region; commit the touched pages.
        const u64 idx = FindRegionContaining(proc, hint_va);
        if (idx == Process::kWin32VmapRegionCap)
        {
            frame->rax = 0;
            return;
        }
        auto& r = proc->vmap_regions[idx];
        const u64 first_page = (hint_va - r.base_va) / mm::kPageSize;
        const u64 last_page = first_page + pages;
        if (last_page > r.pages)
        {
            frame->rax = 0;
            return;
        }
        u32 commit_mask = 0;
        for (u64 i = first_page; i < last_page; ++i)
            commit_mask |= (1u << i);
        if (!CommitPages(proc, r, commit_mask, page_flags))
        {
            frame->rax = 0;
            return;
        }
        r.protection = static_cast<u32>(protection);
        if (is_guard)
            r.guard_bits |= commit_mask;
        else
            r.guard_bits &= ~commit_mask;
        frame->rax = r.base_va;
        return;
    }

    // Fresh reservation. Carve out a contiguous range from the
    // bump cursor.
    if (proc->vmap_pages_used + pages > Process::kWin32VmapCapPages)
    {
        frame->rax = 0;
        return;
    }
    const u64 slot = FindFreeRegionSlot(proc);
    if (slot == Process::kWin32VmapRegionCap)
    {
        frame->rax = 0;
        return;
    }

    auto& r = proc->vmap_regions[slot];
    r.in_use = true;
    r.base_va = proc->vmap_base + proc->vmap_pages_used * mm::kPageSize;
    r.pages = pages;
    r.protection = static_cast<u32>(protection);
    r.committed_bits = 0;
    r.guard_bits = 0;
    proc->vmap_pages_used += pages;

    if (reserve_and_commit)
    {
        u32 mask = 0;
        for (u32 i = 0; i < pages; ++i)
            mask |= (1u << i);
        if (!CommitPages(proc, r, mask, page_flags))
        {
            // Unwind the reservation. The bump cursor stays —
            // bump-only arena leaks on partial failure.
            r.in_use = false;
            r.base_va = 0;
            r.pages = 0;
            r.protection = 0;
            r.committed_bits = 0;
            r.guard_bits = 0;
            frame->rax = 0;
            return;
        }
        if (is_guard)
            r.guard_bits = mask;
    }
    frame->rax = r.base_va;
}

void DoVirtualFree(arch::TrapFrame* frame)
{
    using ::duetos::core::Process;
    Process* proc = ::duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 base_va = frame->rdi;
    const u64 size_bytes = frame->rsi;
    const u64 free_type = frame->rdx;

    if (base_va == 0)
    {
        frame->rax = 0;
        return;
    }

    const u64 idx = FindRegionContaining(proc, base_va);
    if (idx == Process::kWin32VmapRegionCap)
    {
        frame->rax = 0;
        return;
    }
    auto& r = proc->vmap_regions[idx];

    const bool release = (free_type & kMemRelease) != 0;
    const bool decommit = (free_type & kMemDecommit) != 0;
    if (release == decommit) // both or neither — illegal mix
    {
        frame->rax = 0;
        return;
    }

    if (release)
    {
        // Win32 contract: MEM_RELEASE requires size == 0 and
        // base_va == region.base_va.
        if (size_bytes != 0 || base_va != r.base_va)
        {
            frame->rax = 0;
            return;
        }
        u32 mask = 0;
        for (u32 i = 0; i < r.pages; ++i)
            mask |= (1u << i);
        DecommitPages(proc, r, mask);
        r.in_use = false;
        r.base_va = 0;
        r.pages = 0;
        r.protection = 0;
        r.committed_bits = 0;
        frame->rax = 1;
        return;
    }

    // MEM_DECOMMIT — unmap the touched pages, keep the
    // reservation slot.
    const u32 pages = (size_bytes == 0) ? r.pages : static_cast<u32>((size_bytes + mm::kPageSize - 1) / mm::kPageSize);
    const u64 first_page = (base_va - r.base_va) / mm::kPageSize;
    if (first_page + pages > r.pages)
    {
        frame->rax = 0;
        return;
    }
    u32 mask = 0;
    for (u64 i = first_page; i < first_page + pages; ++i)
        mask |= (1u << i);
    DecommitPages(proc, r, mask);
    frame->rax = 1;
}

void DoVirtualProtect(arch::TrapFrame* frame)
{
    using ::duetos::core::Process;
    Process* proc = ::duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 base_va = frame->rdi;
    const u64 size_bytes = frame->rsi;
    const u64 new_prot = frame->rdx;
    const u64 user_old_prot = frame->r10;

    if (base_va == 0 || size_bytes == 0)
    {
        frame->rax = 0;
        return;
    }
    const u64 idx = FindRegionContaining(proc, base_va);
    if (idx == Process::kWin32VmapRegionCap)
    {
        frame->rax = 0;
        return;
    }
    auto& r = proc->vmap_regions[idx];

    u64 new_flags = 0;
    bool is_guard = false;
    if (!Win32ProtToPageFlags(new_prot, new_flags, is_guard))
    {
        frame->rax = 0;
        return;
    }

    const u32 pages = static_cast<u32>((size_bytes + mm::kPageSize - 1) / mm::kPageSize);
    const u64 first_page = (base_va - r.base_va) / mm::kPageSize;
    if (first_page + pages > r.pages)
    {
        frame->rax = 0;
        return;
    }

    const u32 prev_prot = r.protection;
    if (user_old_prot != 0)
    {
        u32 v = prev_prot;
        if (!::duetos::mm::CopyToUser(reinterpret_cast<void*>(user_old_prot), &v, sizeof(v)))
        {
            frame->rax = 0;
            return;
        }
    }

    u32 touched_mask = 0;
    for (u32 i = 0; i < pages; ++i)
    {
        const u32 page_idx = static_cast<u32>(first_page) + i;
        if ((r.committed_bits & (1u << page_idx)) == 0)
            continue; // not committed — protection is a future-on-commit hint
        ::duetos::mm::AddressSpaceProtectUserPage(proc->as, r.base_va + page_idx * mm::kPageSize, new_flags);
        touched_mask |= (1u << page_idx);
    }
    r.protection = static_cast<u32>(new_prot);
    // Guard bookkeeping: any page just touched gets its guard bit
    // set or cleared in line with the new protection. Pages outside
    // the touched range keep whatever guard state they had — the
    // user only addressed a subrange, so their bits stay put.
    if (is_guard)
        r.guard_bits |= touched_mask;
    else
        r.guard_bits &= ~touched_mask;
    frame->rax = 1;
}

bool Win32VmapPageGuardClear(u64 cr2)
{
    using ::duetos::core::Process;
    Process* proc = ::duetos::core::CurrentProcess();
    if (proc == nullptr)
        return false;
    const u64 idx = FindRegionContaining(proc, cr2);
    if (idx == Process::kWin32VmapRegionCap)
        return false;
    auto& r = proc->vmap_regions[idx];
    const u64 page_off = (cr2 - r.base_va) / mm::kPageSize;
    if (page_off >= r.pages)
        return false;
    const u32 page_idx = static_cast<u32>(page_off);
    if ((r.guard_bits & (1u << page_idx)) == 0)
        return false; // not guard-armed
    if ((r.committed_bits & (1u << page_idx)) == 0)
        return false; // uncommitted — fault is legitimate
    // Strip the guard bit from the stored protection and re-derive
    // the page flags. If translation rejects (shouldn't — the base
    // was validated at alloc/protect time), bail and let the normal
    // fault path handle the access.
    const u64 base_prot = static_cast<u64>(r.protection) & ~kPageGuard;
    u64 base_flags = 0;
    if (!Win32ProtToPageFlags(base_prot, base_flags))
        return false;
    ::duetos::mm::AddressSpaceProtectUserPage(proc->as, r.base_va + page_idx * mm::kPageSize, base_flags);
    r.guard_bits &= ~(1u << page_idx);
    return true;
}

} // namespace duetos::subsystems::win32
