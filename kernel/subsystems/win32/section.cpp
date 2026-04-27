/*
 * Win32 section pool implementation.
 * See section.h for v0 scope + refcount semantics.
 */

#include "subsystems/win32/section.h"

#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "proc/process.h"

namespace duetos::subsystems::win32::section
{

namespace
{
Section g_pool[kSectionPoolCap];

inline u64 PageUp(u64 v)
{
    return (v + (mm::kPageSize - 1)) & ~(mm::kPageSize - 1);
}

void FreeSectionFrames(Section* s)
{
    if (s->frames == nullptr)
        return;
    for (u32 i = 0; i < s->num_pages; ++i)
    {
        if (s->frames[i] != mm::kNullFrame)
        {
            mm::FreeFrame(s->frames[i]);
            s->frames[i] = mm::kNullFrame;
        }
    }
    mm::KFree(s->frames);
    s->frames = nullptr;
}

// Translate a Win32 PAGE_* value into mm::kPage* PTE flags.
// The kernel-side PTE always carries kPageUser. W^X is
// enforced by AddressSpaceMapBorrowedPage; this function
// just maps the Win32 enum to the closest legal PTE flag set.
u64 ProtectToPteFlags(u32 win32_protect)
{
    constexpr u32 PAGE_READONLY = 0x02;
    constexpr u32 PAGE_READWRITE = 0x04;
    constexpr u32 PAGE_EXECUTE = 0x10;
    constexpr u32 PAGE_EXECUTE_READ = 0x20;
    constexpr u32 PAGE_EXECUTE_READWRITE = 0x40;

    u64 flags = mm::kPagePresent | mm::kPageUser;
    switch (win32_protect)
    {
    case PAGE_READONLY:
        flags |= mm::kPageNoExecute;
        break;
    case PAGE_READWRITE:
        flags |= mm::kPageWritable | mm::kPageNoExecute;
        break;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
        // RX — executable, not writable. W^X-safe.
        break;
    case PAGE_EXECUTE_READWRITE:
        // RWX is the canonical shellcode pattern. v0 refuses
        // — the W^X check in AddressSpaceMapBorrowedPage
        // would panic. Fall back to RW (NX). Process
        // hollowing tests can use NtProtectVirtualMemory
        // to flip pages to RX in a separate step (when that
        // syscall lands).
        flags |= mm::kPageWritable | mm::kPageNoExecute;
        break;
    default:
        // Unknown protection — treat as RW.
        flags |= mm::kPageWritable | mm::kPageNoExecute;
        break;
    }
    return flags;
}

} // namespace

i32 SectionCreate(u64 size_bytes, u32 page_protect)
{
    if (size_bytes == 0 || size_bytes > kSectionMaxBytes)
        return -1;
    const u64 aligned = PageUp(size_bytes);
    const u32 num_pages = static_cast<u32>(aligned / mm::kPageSize);

    u32 idx = kSectionPoolCap;
    for (u32 i = 0; i < kSectionPoolCap; ++i)
    {
        if (!g_pool[i].in_use)
        {
            idx = i;
            break;
        }
    }
    if (idx == kSectionPoolCap)
        return -1;

    Section& s = g_pool[idx];
    s.frames = static_cast<mm::PhysAddr*>(mm::KMalloc(sizeof(mm::PhysAddr) * num_pages));
    if (s.frames == nullptr)
        return -1;
    for (u32 i = 0; i < num_pages; ++i)
        s.frames[i] = mm::kNullFrame;
    for (u32 i = 0; i < num_pages; ++i)
    {
        const mm::PhysAddr f = mm::AllocateFrame();
        if (f == mm::kNullFrame)
        {
            // OOM mid-creation — roll back.
            for (u32 j = 0; j < i; ++j)
                mm::FreeFrame(s.frames[j]);
            mm::KFree(s.frames);
            s.frames = nullptr;
            return -1;
        }
        // Zero the frame — Windows guarantees fresh sections
        // come back zeroed, and the W^X-safe RW mapping that
        // every section view installs would leak previous
        // owners' data otherwise.
        u8* dst = static_cast<u8*>(mm::PhysToVirt(f));
        for (u64 k = 0; k < mm::kPageSize; ++k)
            dst[k] = 0;
        s.frames[i] = f;
    }
    s.in_use = true;
    s.num_pages = num_pages;
    s.refcount = 1; // new handle
    s.page_protect = page_protect;
    return static_cast<i32>(idx);
}

void SectionRetain(u32 idx)
{
    if (idx >= kSectionPoolCap)
        return;
    Section& s = g_pool[idx];
    if (!s.in_use)
        return;
    ++s.refcount;
}

void SectionRelease(u32 idx)
{
    if (idx >= kSectionPoolCap)
        return;
    Section& s = g_pool[idx];
    if (!s.in_use)
        return;
    if (s.refcount > 0)
        --s.refcount;
    if (s.refcount == 0)
    {
        FreeSectionFrames(&s);
        s.in_use = false;
        s.num_pages = 0;
        s.page_protect = 0;
    }
}

bool SectionMap(u32 idx, mm::AddressSpace* target_as, u64 base_va, u32 view_protect)
{
    if (idx >= kSectionPoolCap || target_as == nullptr || (base_va & 0xFFF) != 0)
        return false;
    Section& s = g_pool[idx];
    if (!s.in_use)
        return false;
    const u64 flags = ProtectToPteFlags(view_protect);
    for (u32 i = 0; i < s.num_pages; ++i)
    {
        const u64 va = base_va + static_cast<u64>(i) * mm::kPageSize;
        if (!mm::AddressSpaceMapBorrowedPage(target_as, va, s.frames[i], flags))
        {
            // PTE conflict — roll back the partial map so the AS
            // doesn't end up with a half-installed view.
            for (u32 j = 0; j < i; ++j)
            {
                mm::AddressSpaceUnmapBorrowedPage(target_as, base_va + static_cast<u64>(j) * mm::kPageSize);
            }
            return false;
        }
    }
    return true;
}

bool SectionUnmap(u32 idx, mm::AddressSpace* target_as, u64 base_va)
{
    if (idx >= kSectionPoolCap || target_as == nullptr || (base_va & 0xFFF) != 0)
        return false;
    Section& s = g_pool[idx];
    if (!s.in_use)
        return false;
    bool all_mapped = true;
    for (u32 i = 0; i < s.num_pages; ++i)
    {
        const u64 va = base_va + static_cast<u64>(i) * mm::kPageSize;
        if (!mm::AddressSpaceUnmapBorrowedPage(target_as, va))
            all_mapped = false;
    }
    return all_mapped;
}

u64 SectionViewSize(u32 idx)
{
    if (idx >= kSectionPoolCap)
        return 0;
    const Section& s = g_pool[idx];
    if (!s.in_use)
        return 0;
    return static_cast<u64>(s.num_pages) * mm::kPageSize;
}

i32 SectionUnmapAtVa(mm::AddressSpace* target_as, u64 base_va)
{
    if (target_as == nullptr || (base_va & 0xFFF) != 0)
        return -1;
    const mm::PhysAddr first = mm::AddressSpaceProbePte(target_as, base_va);
    if (first == mm::kNullFrame)
        return -1;
    for (u32 i = 0; i < kSectionPoolCap; ++i)
    {
        const Section& s = g_pool[i];
        if (!s.in_use || s.num_pages == 0 || s.frames == nullptr)
            continue;
        if (s.frames[0] != first)
            continue;
        SectionUnmap(i, target_as, base_va);
        return static_cast<i32>(i);
    }
    return -1;
}

i32 LookupSectionHandle(core::Process* caller, u64 handle)
{
    if (caller == nullptr)
        return -1;
    if (handle < core::Process::kWin32SectionBase)
        return -1;
    const u64 slot = handle - core::Process::kWin32SectionBase;
    if (slot >= core::Process::kWin32SectionCap)
        return -1;
    if (!caller->win32_section_handles[slot].in_use)
        return -1;
    return static_cast<i32>(caller->win32_section_handles[slot].pool_index);
}

} // namespace duetos::subsystems::win32::section
