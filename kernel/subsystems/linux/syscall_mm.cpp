/*
 * DuetOS — Linux ABI: memory-management handlers.
 *
 * Sibling TU of syscall.cpp. Houses brk / mmap / munmap /
 * mprotect / madvise / mremap / msync / mincore / mlock /
 * munlock / mlockall / munlockall.
 *
 * v0 supports MAP_PRIVATE + MAP_ANONYMOUS (the canonical malloc
 * shape) and MAP_PRIVATE + file-backed (private writable copy of
 * a regular FAT32 file). MAP_SHARED is rejected — that would
 * need a page cache + writeback we don't have. mprotect /
 * madvise / mremap / msync / mincore / mlock validate inputs the
 * way Linux does but mostly accept as no-op since there's no
 * swap and no page reclaim.
 */

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/serial.h"
#include "proc/process.h"
#include "fs/fat32.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Linux mmap flag bits we care about (asm-generic definitions,
// matches x86_64 too).
constexpr u64 kMapPrivate = 0x02;
constexpr u64 kMapAnonymous = 0x20;

// Page-align `x` up. Our cluster size is 4 KiB, matching FAT32's
// native page; the mmap / brk paths map 4 KiB frames directly,
// so all lengths round up to a 4 KiB boundary before allocation.
u64 PageUp(u64 x)
{
    return (x + 0xFFFu) & ~0xFFFull;
}

} // namespace

// Linux: madvise(addr, len, advice). v0 has no page reclaim or
// readahead — every advice is a no-op. We still validate inputs.
// The most common bad-input case is a non-page-aligned addr; mirror
// Linux's -EINVAL on that.
i64 DoMadvise(u64 addr, u64 len, u64 advice)
{
    constexpr u64 kPageSize = 4096;
    if ((addr & (kPageSize - 1)) != 0)
        return kEINVAL;
    if (addr + len < addr)
        return kEINVAL;
    (void)advice;
    return 0;
}

// Linux: mprotect(addr, len, prot). v0 maps all user pages RW
// and has no MapProtect helper, so the protections themselves
// stay advisory — but the call validates inputs the way Linux
// does so a buggy program sees -EINVAL instead of a phantom
// success.
//
// Validation:
//   * addr must be page-aligned (4 KiB).
//   * (addr + len) must not overflow.
//   * The whole range must lie in the canonical low half — same
//     gate CopyFromUser uses to refuse kernel-VA pointers.
//   * len == 0 is success in Linux; mirror that.
//   * prot has 4 valid bits (PROT_READ=1, PROT_WRITE=2,
//     PROT_EXEC=4, PROT_NONE=0; PROT_GROWSDOWN/UP at 0x01000000
//     and 0x02000000 are accepted by Linux so musl's stack-
//     guard tweak doesn't get rejected).
i64 DoMprotect(u64 addr, u64 len, u64 prot)
{
    constexpr u64 kPageSize = 4096;
    constexpr u64 kProtValid = 0x7 | 0x01000000ull | 0x02000000ull;
    if (len == 0)
        return 0;
    if ((addr & (kPageSize - 1)) != 0)
        return kEINVAL;
    if ((prot & ~kProtValid) != 0)
        return kEINVAL;
    if (addr + len < addr)
        return kEINVAL;
    constexpr u64 kUserMaxExclusive = 0x0000800000000000ull;
    if (addr >= kUserMaxExclusive || (addr + len) > kUserMaxExclusive)
        return kEINVAL;
    return 0;
}

// Linux: brk(addr). Three cases:
//   addr == 0 -> return current brk (the `sbrk(0)` query path).
//   addr < linux_brk_base -> ignore, return current. Linux
//     doesn't shrink past the initial segment end.
//   addr > linux_brk_current -> map fresh RW+U+NX pages to extend
//     the heap; return the new brk on success. Allocation failure
//     partway through is "treat as unchanged", which is what Linux
//     does — the caller checks the return == the requested addr.
i64 DoBrk(u64 new_brk)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->abi_flavor != core::kAbiLinux)
    {
        return 0;
    }
    if (new_brk == 0)
    {
        return static_cast<i64>(p->linux_brk_current);
    }
    if (new_brk < p->linux_brk_base)
    {
        return static_cast<i64>(p->linux_brk_current);
    }
    const u64 cur_aligned = PageUp(p->linux_brk_current);
    const u64 new_aligned = PageUp(new_brk);
    if (new_aligned > cur_aligned)
    {
        for (u64 va = cur_aligned; va < new_aligned; va += mm::kPageSize)
        {
            const mm::PhysAddr frame = mm::AllocateFrame();
            if (frame == mm::kNullFrame)
            {
                p->linux_brk_current = va;
                return static_cast<i64>(p->linux_brk_current);
            }
            mm::AddressSpaceMapUserPage(p->as, va, frame,
                                        mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute);
        }
    }
    p->linux_brk_current = new_brk;
    arch::SerialWrite("[linux] brk -> ");
    arch::SerialWriteHex(p->linux_brk_current);
    arch::SerialWrite("\n");
    return static_cast<i64>(p->linux_brk_current);
}

// Linux: mmap(addr, len, prot, flags, fd, offset). v0 supports
// two cases:
//   1. Anonymous + private (musl malloc, static CRT bss growth).
//   2. File-backed + private (MAP_PRIVATE without MAP_ANONYMOUS,
//      a regular fd). Loads the requested file extent into a
//      private writable copy.
i64 DoMmap(u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off)
{
    (void)addr;
    if ((flags & kMapPrivate) == 0)
        return kEINVAL;
    if (len == 0)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->abi_flavor != core::kAbiLinux)
        return kENOSYS;

    const u64 aligned = PageUp(len);
    const u64 base = p->linux_mmap_cursor;

    u64 pte_flags = mm::kPagePresent | mm::kPageUser | mm::kPageWritable;
    constexpr u64 kProtExec = 0x4;
    if ((prot & kProtExec) == 0)
        pte_flags |= mm::kPageNoExecute;

    if ((flags & kMapAnonymous) != 0)
    {
        for (u64 va = base; va < base + aligned; va += mm::kPageSize)
        {
            const mm::PhysAddr frame = mm::AllocateFrame();
            if (frame == mm::kNullFrame)
                return kENOMEM;
            mm::AddressSpaceMapUserPage(p->as, va, frame, pte_flags);
        }
        p->linux_mmap_cursor += aligned;
        arch::SerialWrite("[linux] mmap anon -> ");
        arch::SerialWriteHex(base);
        arch::SerialWrite(" len=");
        arch::SerialWriteHex(aligned);
        arch::SerialWrite("\n");
        return static_cast<i64>(base);
    }

    // File-backed.
    if (fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state != 2)
        return kEBADF;

    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kEIO;

    static u8 file_scratch[4096];
    fs::fat32::DirEntry entry;
    for (u64 i = 0; i < sizeof(entry.name); ++i)
        entry.name[i] = 0;
    entry.attributes = 0;
    entry.first_cluster = p->linux_fds[fd].first_cluster;
    entry.size_bytes = p->linux_fds[fd].size;
    const i64 read_total = fs::fat32::Fat32ReadFile(v, &entry, file_scratch, sizeof(file_scratch));
    if (read_total < 0)
        return kEIO;
    const u64 file_size = static_cast<u64>(read_total);

    for (u64 page_idx = 0; page_idx * mm::kPageSize < aligned; ++page_idx)
    {
        const u64 va = base + page_idx * mm::kPageSize;
        const mm::PhysAddr frame = mm::AllocateFrame();
        if (frame == mm::kNullFrame)
            return kENOMEM;
        u8* dst = static_cast<u8*>(mm::PhysToVirt(frame));
        const u64 page_off_in_file = off + page_idx * mm::kPageSize;
        if (page_off_in_file < file_size)
        {
            u64 to_copy = file_size - page_off_in_file;
            if (to_copy > mm::kPageSize)
                to_copy = mm::kPageSize;
            for (u64 i = 0; i < to_copy; ++i)
                dst[i] = file_scratch[page_off_in_file + i];
        }
        mm::AddressSpaceMapUserPage(p->as, va, frame, pte_flags);
    }
    p->linux_mmap_cursor += aligned;
    arch::SerialWrite("[linux] mmap file fd=");
    arch::SerialWriteHex(fd);
    arch::SerialWrite(" -> ");
    arch::SerialWriteHex(base);
    arch::SerialWrite(" len=");
    arch::SerialWriteHex(aligned);
    arch::SerialWrite(" off=");
    arch::SerialWriteHex(off);
    arch::SerialWrite("\n");
    return static_cast<i64>(base);
}

// Linux: munmap(addr, len). Walks every 4 KiB page in
// [addr, addr+len) and asks the AS to release it. Pages that
// weren't mapped by mmap() (or were already unmapped) are silently
// ignored — matches Linux's relaxed behaviour where munmap of an
// un-mapped range is a no-op rather than -EINVAL.
i64 DoMunmap(u64 addr, u64 len)
{
    if (len == 0)
        return 0;
    if ((addr & 0xFFF) != 0)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->as == nullptr)
        return kEINVAL;
    const u64 aligned_len = (len + 0xFFF) & ~u64(0xFFF);
    u64 freed = 0;
    for (u64 off = 0; off < aligned_len; off += mm::kPageSize)
    {
        if (mm::AddressSpaceUnmapUserPage(p->as, addr + off))
            ++freed;
    }
    arch::SerialWrite("[linux] munmap addr=");
    arch::SerialWriteHex(addr);
    arch::SerialWrite(" len=");
    arch::SerialWriteHex(aligned_len);
    arch::SerialWrite(" pages_released=");
    arch::SerialWriteHex(freed);
    arch::SerialWrite("\n");
    return 0;
}

// Linux: mremap(old_addr, old_size, new_size, flags, new_addr).
// v0 has no mremap engine. If the request shrinks, accept and
// keep the original VA — every page above new_size stays mapped
// but the caller agreed to ignore them. Otherwise -ENOMEM.
i64 DoMremap(u64 old_addr, u64 old_len, u64 new_len, u64 flags, u64 new_addr)
{
    constexpr u64 kPageSize = 4096;
    if ((old_addr & (kPageSize - 1)) != 0)
        return kEINVAL;
    if (old_len == 0 || new_len == 0)
        return kEINVAL;
    if (new_len <= old_len)
    {
        return static_cast<i64>(old_addr);
    }
    (void)flags;
    (void)new_addr;
    return kENOMEM;
}

// msync(): write-back of a memory mapping. v0 mmap is anonymous-
// only; there's nothing to flush. Validate flags so a bug that
// passes garbage gets a clean -EINVAL.
//   MS_ASYNC      = 1
//   MS_INVALIDATE = 2
//   MS_SYNC       = 4
i64 DoMsync(u64 addr, u64 len, u64 flags)
{
    constexpr u64 kPageSize = 4096;
    constexpr u64 kMsValid = 0x7;
    if ((addr & (kPageSize - 1)) != 0)
        return kEINVAL;
    if ((flags & ~kMsValid) != 0)
        return kEINVAL;
    // MS_ASYNC and MS_SYNC are mutually exclusive.
    if ((flags & 0x1) && (flags & 0x4))
        return kEINVAL;
    (void)len;
    return 0;
}

// mincore(addr, len, vec): mark every page in [addr, addr+len)
// as resident by writing 1 to each byte of the user vec. v0
// has no swap and no page reclaim, so every mapped page IS
// resident. Bad address surfaces as EFAULT.
i64 DoMincore(u64 addr, u64 len, u64 user_vec)
{
    (void)addr;
    if (user_vec == 0)
        return kEFAULT;
    const u64 pages = (len + 0xFFFu) / 0x1000u;
    if (pages == 0)
        return 0;
    constexpr u64 kMaxPages = 4096;
    const u64 to_mark = (pages > kMaxPages) ? kMaxPages : pages;
    static u8 ones[kMaxPages];
    for (u64 i = 0; i < to_mark; ++i)
        ones[i] = 1;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_vec), ones, to_mark))
        return kEFAULT;
    return 0;
}

// mlock / munlock / mlockall / munlockall: pin pages in RAM.
// v0 has no swap and no page reclaim — every mapped page is
// already pinned, so the call is semantically a no-op. We still
// validate inputs so a malformed call sees -EINVAL / -ENOMEM
// instead of silent success — matches Linux's behaviour and lets
// libc abort early when the caller hands in garbage.
i64 DoMlock(u64 addr, u64 len)
{
    constexpr u64 kPageSize = 4096;
    constexpr u64 kUserMaxExclusive = 0x0000800000000000ull;
    if (len == 0)
        return 0;
    if ((addr & (kPageSize - 1)) != 0)
        return kEINVAL;
    if (addr + len < addr)
        return kEINVAL;
    if (addr >= kUserMaxExclusive || (addr + len) > kUserMaxExclusive)
        return kENOMEM;
    return 0;
}
i64 DoMunlock(u64 addr, u64 len)
{
    return DoMlock(addr, len);
}
// MCL_CURRENT (1), MCL_FUTURE (2), MCL_ONFAULT (4) are the only
// flags Linux accepts; any other bit is -EINVAL.
i64 DoMlockall(u64 flags)
{
    constexpr u64 kMclValid = 0x7;
    if ((flags & ~kMclValid) != 0 || flags == 0)
        return kEINVAL;
    return 0;
}
i64 DoMunlockall()
{
    return 0;
}

} // namespace duetos::subsystems::linux::internal
