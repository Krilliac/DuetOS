/*
 * Win32 section pool implementation.
 * See section.h for v0 scope + refcount semantics.
 */

#include "subsystems/win32/section.h"

#include "log/klog.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "proc/process.h"
#include "sync/spinlock.h"

namespace duetos::subsystems::win32::section
{

namespace
{
Section g_pool[kSectionPoolCap];

// Guards the pool's SLOT-OWNERSHIP state — `in_use` and `refcount` —
// on an SMP kernel. Nothing synchronised these before, which left two
// concrete races:
//
//   * SectionCreate scanned for `!in_use` and only set `in_use = true`
//     AFTER the frames-table KMalloc and every AllocateFrame + page
//     zeroing. Two CPUs in NtCreateSection therefore selected the SAME
//     slot with near-certainty under load, and the loser's frames table
//     was leaked while both processes were handed the same section.
//   * SectionRelease did a non-atomic `--refcount` and then tore the
//     section down at zero. Two concurrent releases could both observe
//     zero and both tear the section down — a double free of every
//     physical frame in the section, handing those frames to two future
//     owners at once.
//
// Scope is deliberately narrow: the claim and the refcount transitions
// only. The heavy work in SectionCreate (KMalloc + per-page
// AllocateFrame + zeroing) runs OUTSIDE the lock, so this never holds a
// spinlock across an allocation. Lock order is section -> frame
// allocator / kheap; nothing in mm takes this lock, so that edge cannot
// invert.
constinit duetos::sync::SpinLock g_section_lock{};

inline u64 PageUp(u64 v)
{
    return (v + (mm::kPageSize - 1)) & ~(mm::kPageSize - 1);
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
        KLOG_ONCE_WARN("subsystems/win32/section", "PAGE_EXECUTE_READWRITE refused (W^X) — downgraded to RW+NX");
        flags |= mm::kPageWritable | mm::kPageNoExecute;
        break;
    default:
        // Unknown protection — treat as RW.
        KLOG_WARN_V("subsystems/win32/section", "unknown PAGE_* protect, treating as RW",
                    static_cast<u64>(win32_protect));
        flags |= mm::kPageWritable | mm::kPageNoExecute;
        break;
    }
    return flags;
}

} // namespace

i32 SectionCreate(u64 size_bytes, u32 page_protect)
{
    if (size_bytes == 0 || size_bytes > kSectionMaxBytes)
    {
        KLOG_WARN_V("subsystems/win32/section", "SectionCreate: size_bytes out of range, size_bytes=", size_bytes);
        return -1;
    }
    const u64 aligned = PageUp(size_bytes);
    const u32 num_pages = static_cast<u32>(aligned / mm::kPageSize);

    // Find AND claim a free slot under the lock, so no peer CPU can
    // pick the same one while we allocate. `refcount = 0` marks the
    // slot as reserved-but-not-yet-live; it becomes 1 only once the
    // section is fully constructed below, and Retain/Release both
    // refuse to act on a zero-refcount slot.
    u32 idx = kSectionPoolCap;
    {
        duetos::sync::SpinLockGuard guard(g_section_lock);
        for (u32 i = 0; i < kSectionPoolCap; ++i)
        {
            if (!g_pool[i].in_use)
            {
                idx = i;
                g_pool[i].in_use = true;
                g_pool[i].refcount = 0;
                g_pool[i].frames = nullptr;
                g_pool[i].num_pages = 0;
                g_pool[i].has_writable_view = false;
                g_pool[i].has_executable_view = false;
                break;
            }
        }
    }
    if (idx == kSectionPoolCap)
    {
        KLOG_ERROR_V("subsystems/win32/section", "SectionCreate: pool exhausted, capacity",
                     static_cast<u64>(kSectionPoolCap));
        return -1;
    }

    Section& s = g_pool[idx];
    s.frames = static_cast<mm::PhysAddr*>(mm::KMalloc(sizeof(mm::PhysAddr) * num_pages));
    if (s.frames == nullptr)
    {
        KLOG_ERROR_V("subsystems/win32/section", "SectionCreate: KMalloc for frames table failed (OOM); pages",
                     static_cast<u64>(num_pages));
        // Release the slot we claimed above, or this failure leaks it
        // out of the pool permanently.
        duetos::sync::SpinLockGuard guard(g_section_lock);
        s.in_use = false;
        return -1;
    }
    for (u32 i = 0; i < num_pages; ++i)
        s.frames[i] = mm::kNullFrame;
    for (u32 i = 0; i < num_pages; ++i)
    {
        const mm::PhysAddr f = mm::AllocateFrame().value_or(mm::kNullFrame);
        if (f == mm::kNullFrame)
        {
            // OOM mid-creation — roll back.
            KLOG_ERROR_2V("subsystems/win32/section", "SectionCreate: AllocateFrame OOM mid-creation — rolling back",
                          "page_index", static_cast<u64>(i), "of", static_cast<u64>(num_pages));
            for (u32 j = 0; j < i; ++j)
                mm::FreeFrame(s.frames[j]);
            mm::KFree(s.frames);
            s.frames = nullptr;
            // Same as the KMalloc failure above: hand the claimed slot
            // back, otherwise an OOM here burns a pool entry forever.
            duetos::sync::SpinLockGuard guard(g_section_lock);
            s.in_use = false;
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
    // Publish the finished section. `in_use` was already set when the
    // slot was claimed; flipping refcount 0 -> 1 under the lock is what
    // makes it live to Retain/Release.
    {
        duetos::sync::SpinLockGuard guard(g_section_lock);
        s.num_pages = num_pages;
        s.refcount = 1; // new handle
        s.page_protect = page_protect;
        s.has_writable_view = false;
        s.has_executable_view = false;
    }
    return static_cast<i32>(idx);
}

void SectionRetain(u32 idx)
{
    if (idx >= kSectionPoolCap)
    {
        // OOB handle index — caller minted the handle outside the
        // section pool or a Win32 thunk corrupted it before reaching
        // us. Log once per call site so the first occurrence pins
        // the buggy caller, then drop the retain so the section
        // pool doesn't run a phantom refcount.
        KLOG_ONCE_WARN_V("subsystems/win32/section", "SectionRetain idx out of range", idx);
        return;
    }
    Section& s = g_pool[idx];
    duetos::sync::SpinLockGuard guard(g_section_lock);
    // refcount == 0 with in_use set means the slot is CLAIMED but still
    // being constructed by SectionCreate — not a live section yet.
    if (!s.in_use || s.refcount == 0)
        return;
    ++s.refcount;
}

void SectionRelease(u32 idx)
{
    if (idx >= kSectionPoolCap)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/section", "SectionRelease idx out of range", idx);
        return;
    }
    Section& s = g_pool[idx];

    // Decide the teardown under the lock, but PERFORM it outside.
    //
    // Deciding under the lock is what makes the double free impossible:
    // exactly one caller can observe the 1 -> 0 transition, and it
    // clears `in_use` before releasing, so a concurrent release sees a
    // free slot and bails. Performing it outside keeps up to
    // kSectionMaxBytes/4K == 1024 FreeFrame calls off an IRQs-disabled
    // spinlock hold.
    mm::PhysAddr* doomed_frames = nullptr;
    u32 doomed_pages = 0;
    {
        duetos::sync::SpinLockGuard guard(g_section_lock);
        if (!s.in_use || s.refcount == 0)
            return;
        --s.refcount;
        if (s.refcount != 0)
            return;
        // Last reference: take exclusive ownership of the frames table
        // and retire the slot in the same critical section.
        doomed_frames = s.frames;
        doomed_pages = s.num_pages;
        s.frames = nullptr;
        s.in_use = false;
        s.num_pages = 0;
        s.page_protect = 0;
        s.has_writable_view = false;
        s.has_executable_view = false;
    }

    if (doomed_frames != nullptr)
    {
        for (u32 i = 0; i < doomed_pages; ++i)
        {
            if (doomed_frames[i] != mm::kNullFrame)
                mm::FreeFrame(doomed_frames[i]);
        }
        mm::KFree(doomed_frames);
    }
}

bool SectionMap(u32 idx, mm::AddressSpace* target_as, u64 base_va, u32 view_protect)
{
    if (idx >= kSectionPoolCap || target_as == nullptr || (base_va & 0xFFF) != 0)
    {
        KLOG_WARN_V("subsystems/win32/section",
                    "SectionMap: bad args (idx oor / null AS / unaligned VA); base_va=", base_va);
        return false;
    }
    Section& s = g_pool[idx];
    if (!s.in_use)
    {
        KLOG_WARN_V("subsystems/win32/section", "SectionMap: idx not in use, idx=", static_cast<u64>(idx));
        return false;
    }
    // SEC-004
    // W^X across the whole section's view history. ProtectToPteFlags downgrades
    // PAGE_EXECUTE_READWRITE to RW+NX for a single view, but it cannot see the
    // other views of the same frames. Reject a view that would grant EXECUTE on
    // a section that has ever had a writable view, and vice versa, so the
    // write-here / execute-there aliasing bypass can never form.
    constexpr u32 PAGE_READWRITE = 0x04;
    constexpr u32 PAGE_EXECUTE = 0x10;
    constexpr u32 PAGE_EXECUTE_READ = 0x20;
    constexpr u32 PAGE_EXECUTE_READWRITE = 0x40;
    constexpr u32 PAGE_WRITECOPY = 0x08;
    const bool wants_write = (view_protect == PAGE_READWRITE) || (view_protect == PAGE_WRITECOPY) ||
                             (view_protect == PAGE_EXECUTE_READWRITE);
    const bool wants_exec = (view_protect == PAGE_EXECUTE) || (view_protect == PAGE_EXECUTE_READ) ||
                            (view_protect == PAGE_EXECUTE_READWRITE);
    if ((wants_exec && s.has_writable_view) || (wants_write && s.has_executable_view))
    {
        KLOG_WARN_V("subsystems/win32/section",
                    "SectionMap: W^X — refusing aliased writable+executable view; view_protect=",
                    static_cast<u64>(view_protect));
        return false;
    }
    const u64 flags = ProtectToPteFlags(view_protect);
    for (u32 i = 0; i < s.num_pages; ++i)
    {
        const u64 va = base_va + static_cast<u64>(i) * mm::kPageSize;
        if (!mm::AddressSpaceMapBorrowedPage(target_as, va, s.frames[i], flags))
        {
            // PTE conflict — roll back the partial map so the AS
            // doesn't end up with a half-installed view.
            KLOG_ERROR_2V("subsystems/win32/section", "SectionMap: MapBorrowedPage PTE conflict — rolling back partial",
                          "page", static_cast<u64>(i), "va", va);
            for (u32 j = 0; j < i; ++j)
            {
                mm::AddressSpaceUnmapBorrowedPage(target_as, base_va + static_cast<u64>(j) * mm::kPageSize);
            }
            return false;
        }
    }
    // SEC-004
    // Record this view's W/X disposition only after the whole map committed,
    // so a rolled-back partial map never poisons the section's history. The
    // installed PTE is RW+NX whenever ProtectToPteFlags saw a writable request
    // (incl. the RWX downgrade), so track has_writable_view off wants_write.
    if (wants_write)
        s.has_writable_view = true;
    if (wants_exec && !wants_write)
        s.has_executable_view = true;
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
