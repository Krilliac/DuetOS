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
#include "fs/fat32.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "util/defer.h"
#include "util/nospec.h"

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
    if (x > (~u64(0) - 0xFFFu))
        return 0; // caller treats an unrepresentable span as invalid
    return (x + 0xFFFu) & ~0xFFFull;
}

// Copy one same-address-space byte range without allowing an unpinned
// physical-frame snapshot or direct-map pointer to escape the VM mutation
// transaction. The direction matches memmove: a destination beginning
// inside and above the source is copied from the end, every other shape is
// copied from the beginning. Each transaction is bounded by both source and
// destination page boundaries because the AddressSpace copy API deliberately
// refuses cross-page ranges.
bool CopyUserRangeOverlapSafe(mm::AddressSpace* as, u64 source, u64 destination, u64 length)
{
    constexpr u64 kUserMaxExclusive = 0x0000800000000000ULL;
    if (length == 0 || source == destination)
        return true;
    if (as == nullptr || source >= kUserMaxExclusive || destination >= kUserMaxExclusive ||
        length > (kUserMaxExclusive - source) || length > (kUserMaxExclusive - destination))
    {
        return false;
    }

    u8 bounce[mm::kPageSize];
    const u64 source_end = source + length;
    const bool copy_backward = destination > source && destination < source_end;
    if (!copy_backward)
    {
        u64 copied = 0;
        while (copied < length)
        {
            const u64 source_va = source + copied;
            const u64 destination_va = destination + copied;
            const u64 source_room = mm::kPageSize - (source_va & (mm::kPageSize - 1));
            const u64 destination_room = mm::kPageSize - (destination_va & (mm::kPageSize - 1));
            u64 chunk = length - copied;
            if (chunk > sizeof(bounce))
                chunk = sizeof(bounce);
            if (chunk > source_room)
                chunk = source_room;
            if (chunk > destination_room)
                chunk = destination_room;
            if (!mm::AddressSpaceReadUserMemory(as, source_va, bounce, chunk) ||
                !mm::AddressSpaceWriteUserMemory(as, destination_va, bounce, chunk))
            {
                return false;
            }
            copied += chunk;
        }
        return true;
    }

    u64 remaining = length;
    while (remaining != 0)
    {
        const u64 source_end_va = source + remaining;
        const u64 destination_end_va = destination + remaining;
        const u64 source_room = ((source_end_va - 1) & (mm::kPageSize - 1)) + 1;
        const u64 destination_room = ((destination_end_va - 1) & (mm::kPageSize - 1)) + 1;
        u64 chunk = remaining;
        if (chunk > sizeof(bounce))
            chunk = sizeof(bounce);
        if (chunk > source_room)
            chunk = source_room;
        if (chunk > destination_room)
            chunk = destination_room;
        remaining -= chunk;
        if (!mm::AddressSpaceReadUserMemory(as, source + remaining, bounce, chunk) ||
            !mm::AddressSpaceWriteUserMemory(as, destination + remaining, bounce, chunk))
        {
            return false;
        }
    }
    return true;
}

} // namespace

// Linux: madvise(addr, len, advice).
//
// v0 has no page reclaim or readahead — most advice values are
// genuinely no-ops on our system. The exceptions worth honoring
// are the data-clearing ones: a process that issues MADV_DONTNEED
// / MADV_FREE / MADV_REMOVE expects subsequent reads to return
// zero (anonymous mappings) or trigger a re-read from backing
// store (file mappings — sub-GAP since v0 has no file-backed
// mmap). For anonymous mappings we zero the requested range,
// matching the contract callers actually depend on (jemalloc /
// glibc free arenas use MADV_DONTNEED to reclaim large blocks).
//
// Invalid-input shapes (Linux-conformant -EINVAL):
//   - addr not page-aligned
//   - addr + len overflows
i64 DoMadvise(u64 addr, u64 len, u64 advice)
{
    constexpr u64 kPageSize = 4096;
    constexpr u64 kMadvNormal = 0;
    constexpr u64 kMadvRandom = 1;
    constexpr u64 kMadvSequential = 2;
    constexpr u64 kMadvWillneed = 3;
    constexpr u64 kMadvDontneed = 4;
    constexpr u64 kMadvFree = 8;
    constexpr u64 kMadvRemove = 9;
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "madvise ENTRY; addr", addr);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "  len", len);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "  advice", advice);
    if ((addr & (kPageSize - 1)) != 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "madvise: addr not page-aligned -> EINVAL", addr);
        return kEINVAL;
    }
    if (addr + len < addr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "madvise: addr+len overflow -> EINVAL", addr);
        return kEINVAL;
    }
    if (len == 0)
        return 0;

    switch (advice)
    {
    case kMadvNormal:
    case kMadvRandom:
    case kMadvSequential:
    case kMadvWillneed:
        // No reclaim or readahead policy — accept silently.
        return 0;
    case kMadvDontneed:
    case kMadvFree:
    case kMadvRemove:
    {
        // Zero each mapped page in the range. CopyToUser refuses
        // pointers outside the canonical low half AND fails for
        // unmapped pages — both shapes are silently skipped, which
        // matches Linux's "best-effort" madvise contract for
        // these advice values.
        u8 zeros[256] = {};
        u64 va = addr;
        const u64 end = addr + len;
        while (va < end)
        {
            // madvise(MADV_REMOVE/MADV_DONTNEED) is best-effort per
            // Linux's contract — a partial zero is acceptable, and
            // touching an unmapped page in the range is silently
            // skipped (the comment above describes the rationale).
            // The CopyToUser return is intentionally dropped because
            // any single chunk failing simply means "that page wasn't
            // present" — the next loop iteration handles the next
            // page, and the syscall's success return reflects the
            // overall best-effort attempt.
            const u64 chunk = (end - va < sizeof(zeros)) ? (end - va) : sizeof(zeros);
            (void)mm::CopyToUser(reinterpret_cast<void*>(va), zeros, chunk);
            va += chunk;
        }
        return 0;
    }
    default:
        // Unknown advice — Linux returns -EINVAL.
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "madvise: unknown advice value -> EINVAL", advice);
        return kEINVAL;
    }
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
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "mprotect ENTRY; addr", addr);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "  len", len);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "  prot", prot);
    if (len == 0)
        return 0;
    if ((addr & (kPageSize - 1)) != 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "mprotect: addr not page-aligned -> EINVAL", addr);
        return kEINVAL;
    }
    if ((prot & ~kProtValid) != 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "mprotect: prot has reserved bits -> EINVAL", prot);
        return kEINVAL;
    }
    if (addr + len < addr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "mprotect: addr+len overflow -> EINVAL", addr);
        return kEINVAL;
    }
    constexpr u64 kUserMaxExclusive = 0x0000800000000000ull;
    if (addr >= kUserMaxExclusive || (addr + len) > kUserMaxExclusive)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "mprotect: addr in kernel half -> EINVAL", addr);
        return kEINVAL;
    }
    // v0 accepts mprotect as advisory — surface this once so an
    // analyst tracing W^X violations doesn't get fooled by the
    // success return.
    KLOG_ONCE_WARN("linux/mm", "mprotect accepted as ADVISORY (no real PTE flag flip in v0)");
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
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "brk ENTRY; new_brk", new_brk);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->abi_flavor != core::kAbiLinux)
    {
        KLOG_DEBUG_A(::duetos::core::LogArea::Linux, "linux/mm", "brk: not a Linux ABI process — returning 0");
        return 0;
    }
    core::ScopedProcessRuntimeAccess runtime_access(p);
    if (!runtime_access)
        return 0;
    if (new_brk == 0)
    {
        return static_cast<i64>(p->linux_brk_current);
    }
    if (new_brk < p->linux_brk_base)
    {
        return static_cast<i64>(p->linux_brk_current);
    }
    // Reject brk targets in the kernel half — without this an
    // unprivileged Linux ABI process can pass new_brk =
    // 0xFFFFFFFF80000000 and drive AddressSpaceMapUserPage into
    // PanicAs (kernel DoS via mm/address_space.cpp:315). Real Linux
    // returns the current brk on failure rather than -1.
    constexpr u64 kBrkUserMaxExclusive = 0x0000800000000000ULL;
    if (new_brk >= kBrkUserMaxExclusive)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "brk: new_brk in kernel half — refused", new_brk);
        return static_cast<i64>(p->linux_brk_current);
    }
    const u64 cur_aligned = PageUp(p->linux_brk_current);
    const u64 new_aligned = PageUp(new_brk);
    if (cur_aligned == 0 || new_aligned == 0)
        return static_cast<i64>(p->linux_brk_current);
    if (new_aligned > cur_aligned)
    {
        for (u64 va = cur_aligned; va < new_aligned; va += mm::kPageSize)
        {
            const mm::PhysAddr frame = mm::AllocateFrame().value_or(mm::kNullFrame);
            if (frame == mm::kNullFrame)
            {
                // Partial-brk contract: report the page-aligned
                // boundary we actually reached. Invariant held:
                // every page below linux_brk_current stays mapped,
                // and `va` is the first UNmapped page, so the next
                // grow resumes here with no overlap (no leak, no
                // double-map panic). Caller detects the short grow
                // via ret < requested. Do NOT "round up" this value.
                p->linux_brk_current = va;
                KLOG_ERROR_AV(::duetos::core::LogArea::Linux, "linux/mm",
                              "brk: AllocateFrame OOM mid-grow; partial brk", va);
                return static_cast<i64>(p->linux_brk_current);
            }
            if (!mm::AddressSpaceMapUserPage(p->as, va, frame,
                                             mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute))
            {
                mm::FreeFrame(frame);
                p->linux_brk_current = va;
                KLOG_ERROR_AV(::duetos::core::LogArea::Linux, "linux/mm",
                              "brk: AddressSpaceMapUserPage refused; partial brk", va);
                return static_cast<i64>(p->linux_brk_current);
            }
        }
    }
    p->linux_brk_current = new_brk;
    KLOG_INFO_AV(::duetos::core::LogArea::Linux, "linux/mm", "brk OK; new brk", p->linux_brk_current);
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
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "mmap ENTRY; len", len);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "  prot", prot);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "  flags", flags);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "  fd", fd);
    (void)addr;
    if ((flags & kMapPrivate) == 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm",
                     "mmap: MAP_SHARED rejected (v0 has no page cache); flags", flags);
        return kEINVAL;
    }
    if (len == 0)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Linux, "linux/mm", "mmap: len=0 -> EINVAL");
        return kEINVAL;
    }
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->abi_flavor != core::kAbiLinux)
        return kENOSYS;
    core::ScopedProcessRuntimeAccess runtime_access(p);
    if (!runtime_access)
        return kESRCH;
    // RWX detector — Linux mmap with PROT_EXEC | PROT_WRITE is a
    // canonical JIT-or-shellcode pattern; surface it for analysts.
    constexpr u64 kProtWrite = 0x2;
    constexpr u64 kProtExec = 0x4;
    if ((prot & kProtWrite) != 0 && (prot & kProtExec) != 0)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Linux, "linux/mm",
                    "mmap with PROT_WRITE|PROT_EXEC (RWX) — JIT or shellcode pattern");
    }

    const u64 aligned = PageUp(len);
    const u64 base = p->linux_mmap_cursor;

    // Defense-in-depth: refuse if the requested mapping would extend
    // beyond the canonical user low half. Without this an extreme
    // `len` driven by a runaway caller could push `va` into the
    // kernel half and trigger AddressSpaceMapUserPage's PanicAs.
    constexpr u64 kMmapUserMaxExclusive = 0x0000800000000000ULL;
    if (aligned == 0 || base >= kMmapUserMaxExclusive || aligned > (kMmapUserMaxExclusive - base))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "mmap: span exits user range -> ENOMEM; aligned",
                     aligned);
        return kENOMEM;
    }

    u64 pte_flags = mm::kPagePresent | mm::kPageUser | mm::kPageWritable;
    if ((prot & kProtExec) == 0)
        pte_flags |= mm::kPageNoExecute;

    if ((flags & kMapAnonymous) != 0)
    {
        const u64 anonymous_end = base + aligned;
        mm::AddressSpaceReservationToken anonymous_reservation{};
        if (!mm::AddressSpaceReserveUserRange(p->as, base, anonymous_end, &anonymous_reservation))
            return kENOMEM;
        DUETOS_DEFER_NAMED(release_anonymous_mapping, (void)mm::AddressSpaceReleaseUserReservation(
                                                          p->as, anonymous_reservation, base, anonymous_end));
        for (u64 va = base; va < base + aligned; va += mm::kPageSize)
        {
            const mm::PhysAddr frame = mm::AllocateFrame().value_or(mm::kNullFrame);
            if (frame == mm::kNullFrame)
            {
                KLOG_ERROR_AV(::duetos::core::LogArea::Linux, "linux/mm", "mmap anon: AllocateFrame OOM at va", va);
                // The exact reservation defer retires every page already
                // tagged by this attempt and leaves the cursor reusable.
                return kENOMEM;
            }
            if (!mm::AddressSpaceMapReservedUserPage(p->as, anonymous_reservation, va, frame, pte_flags))
            {
                mm::FreeFrame(frame);
                return kENOMEM;
            }
        }
        if (!mm::AddressSpaceCommitUserReservation(p->as, anonymous_reservation, base, anonymous_end))
            return kENOMEM;
        release_anonymous_mapping.dismiss();
        p->linux_mmap_cursor += aligned;
        KLOG_INFO_AV(::duetos::core::LogArea::Linux, "linux/mm", "mmap anon OK; base", base);
        KLOG_INFO_AV(::duetos::core::LogArea::Linux, "linux/mm", "  aligned len", aligned);
        return static_cast<i64>(base);
    }

    // File-backed.
    if (fd >= 16)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "mmap file: fd out of range -> EBADF; fd", fd);
        return kEBADF;
    }
    if ((off & (mm::kPageSize - 1)) != 0 || off > ~u64{0} - aligned)
        return kEINVAL;

    const u64 file_mapping_end = base + aligned;
    mm::AddressSpaceReservationToken file_mapping_reservation{};
    if (!mm::AddressSpaceReserveUserRange(p->as, base, file_mapping_end, &file_mapping_reservation))
        return kENOMEM;
    DUETOS_DEFER_NAMED(release_file_mapping, (void)mm::AddressSpaceReleaseUserReservation(
                                                 p->as, file_mapping_reservation, base, file_mapping_end));
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);

    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 2, &acquired))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "mmap file: fd not open -> EBADF; fd", fd);
        return kEBADF;
    }
    DUETOS_DEFER(core::LinuxFdAcquiredRelease(&acquired));

    core::LinuxFdIoGuard io_guard{};
    if (!core::LinuxFdIoGuardEnter(&acquired, &io_guard))
        return kEBADF;
    DUETOS_DEFER(core::LinuxFdIoGuardExit(&io_guard));

    core::Process::LinuxFd snapshot{};
    if (!core::LinuxFdRefreshRetainedRegular(&acquired, &io_guard, &snapshot))
        return kEBADF;

    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kEIO;

    fs::fat32::DirEntry entry;
    for (u64 i = 0; i < sizeof(entry.name); ++i)
        entry.name[i] = 0;
    entry.attributes = 0;
    entry.first_cluster = snapshot.first_cluster;
    entry.size_bytes = snapshot.size;

    for (u64 page_idx = 0; page_idx * mm::kPageSize < aligned; ++page_idx)
    {
        const u64 va = base + page_idx * mm::kPageSize;
        const mm::PhysAddr frame = mm::AllocateFrame().value_or(mm::kNullFrame);
        if (frame == mm::kNullFrame)
        {
            // The reservation cleanup retires every page already tagged by
            // this mapping attempt and keeps the cursor reusable.
            return kENOMEM;
        }
        const u64 page_off_in_file = off + page_idx * mm::kPageSize;
        if (page_off_in_file < snapshot.size)
        {
            void* destination = mm::PhysToVirt(frame);
            if (fs::fat32::Fat32ReadAt(v, &entry, page_off_in_file, destination, mm::kPageSize) < 0)
            {
                mm::FreeFrame(frame);
                return kEIO;
            }
        }
        if (!mm::AddressSpaceMapReservedUserPage(p->as, file_mapping_reservation, va, frame, pte_flags))
        {
            mm::FreeFrame(frame);
            return kENOMEM;
        }
    }
    if (!mm::AddressSpaceCommitUserReservation(p->as, file_mapping_reservation, base, file_mapping_end))
        return kENOMEM;
    release_file_mapping.dismiss();
    p->linux_mmap_cursor += aligned;
    KLOG_INFO_AV(::duetos::core::LogArea::Linux, "linux/mm", "mmap file OK; base", base);
    KLOG_INFO_AV(::duetos::core::LogArea::Linux, "linux/mm", "  fd", fd);
    KLOG_INFO_AV(::duetos::core::LogArea::Linux, "linux/mm", "  aligned len", aligned);
    KLOG_INFO_AV(::duetos::core::LogArea::Linux, "linux/mm", "  file offset", off);
    return static_cast<i64>(base);
}

// Linux: munmap(addr, len). Walks every 4 KiB page in
// [addr, addr+len) and asks the AS to release it. Pages that
// weren't mapped by mmap() (or were already unmapped) are silently
// ignored — matches Linux's relaxed behaviour where munmap of an
// un-mapped range is a no-op rather than -EINVAL.
i64 DoMunmap(u64 addr, u64 len)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "munmap ENTRY; addr", addr);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/mm", "  len", len);
    if (len == 0)
        return 0;
    if ((addr & 0xFFF) != 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/mm", "munmap: addr not page-aligned -> EINVAL", addr);
        return kEINVAL;
    }
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->as == nullptr)
        return kEINVAL;
    core::ScopedProcessRuntimeAccess runtime_access(p);
    if (!runtime_access)
        return kESRCH;
    const u64 aligned_len = PageUp(len);
    if (aligned_len == 0)
        return kEINVAL;
    constexpr u64 kUserMaxExclusive = 0x0000800000000000ULL;
    if (addr >= kUserMaxExclusive || aligned_len > (kUserMaxExclusive - addr))
        return kEINVAL;
    u64 freed = 0;
    for (u64 off = 0; off < aligned_len; off += mm::kPageSize)
    {
        if (mm::AddressSpaceUnmapUserPage(p->as, addr + off))
            ++freed;
    }
    KLOG_INFO_AV(::duetos::core::LogArea::Linux, "linux/mm", "munmap OK; addr", addr);
    KLOG_INFO_AV(::duetos::core::LogArea::Linux, "linux/mm", "  pages_released", freed);
    return 0;
}

// Linux: mremap(old_addr, old_size, new_size, flags, new_addr).
// v0 has no mremap engine. If the request shrinks, accept and
// keep the original VA — every page above new_size stays mapped
// but the caller agreed to ignore them. Otherwise -ENOMEM.
// Linux: mremap(old_addr, old_len, new_len, flags, new_addr).
//
// flags:
//   MREMAP_MAYMOVE = 0x1 — kernel may relocate the mapping if it
//     can't grow in place. Without this flag, growth requires
//     contiguous free VA at the existing position; v0's mmap
//     cursor is bump-only so we can never grow in place and
//     return -ENOMEM as Linux does.
//   MREMAP_FIXED   = 0x2 — caller-supplied target VA. Not
//     implemented in v0 (would need a fixed-VA reservation
//     check in the address space).
//
// Three cases handled:
//   shrink (new_len < old_len): unmap pages in the tail
//     [old_addr + new_len, old_addr + old_len), return old_addr.
//   same  (new_len == old_len): no-op, return old_addr.
//   grow with MAYMOVE: allocate a fresh range at the linux_mmap
//     cursor (same shape as DoMmap anonymous), copy through the
//     mutation-serialized AddressSpace API, unmap the old range,
//     return the new base.
i64 DoMremap(u64 old_addr, u64 old_len, u64 new_len, u64 flags, u64 new_addr)
{
    constexpr u64 kPageSize = 4096;
    constexpr u64 kMremapMaymove = 0x1;
    constexpr u64 kMremapFixed = 0x2;
    (void)new_addr;

    if ((old_addr & (kPageSize - 1)) != 0)
        return kEINVAL;
    if (old_len == 0 || new_len == 0)
        return kEINVAL;
    if ((flags & kMremapFixed) != 0)
        return kEINVAL; // sub-GAP — fixed VA not honored

    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->as == nullptr || p->abi_flavor != core::kAbiLinux)
        return kEINVAL;
    core::ScopedProcessRuntimeAccess runtime_access(p);
    if (!runtime_access)
        return kESRCH;

    const u64 old_aligned = PageUp(old_len);
    const u64 new_aligned = PageUp(new_len);
    if (old_aligned == 0 || new_aligned == 0)
        return kEINVAL;
    constexpr u64 kMremapUserMaxExclusive = 0x0000800000000000ULL;
    if (old_addr >= kMremapUserMaxExclusive || old_aligned > (kMremapUserMaxExclusive - old_addr))
        return kEFAULT;
    const u64 old_pages = old_aligned / kPageSize;
    const u64 new_pages = new_aligned / kPageSize;

    if (new_pages == old_pages)
        return static_cast<i64>(old_addr);

    if (new_pages < old_pages)
    {
        const u64 tail_va = old_addr + new_pages * kPageSize;
        for (u64 i = 0; i < (old_pages - new_pages); ++i)
            (void)mm::AddressSpaceUnmapUserPage(p->as, tail_va + i * kPageSize);
        return static_cast<i64>(old_addr);
    }

    // new_pages > old_pages — needs MAYMOVE.
    if ((flags & kMremapMaymove) == 0)
        return kENOMEM;

    const u64 base = p->linux_mmap_cursor;
    const u64 pte_flags = mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute;

    // Defense-in-depth — same kUserMax gate as DoMmap. If new_pages
    // is large enough to push the mapping into the kernel half,
    // refuse before AddressSpaceMapUserPage panics.
    if (base >= kMremapUserMaxExclusive || new_aligned > (kMremapUserMaxExclusive - base))
        return kENOMEM;

    const u64 destination_end = base + new_aligned;
    const u64 source_end = old_addr + old_aligned;
    if (base < source_end && destination_end > old_addr)
        return kENOMEM;
    mm::AddressSpaceReservationToken destination_reservation{};
    if (!mm::AddressSpaceReserveUserRange(p->as, base, destination_end, &destination_reservation))
        return kENOMEM;
    DUETOS_DEFER_NAMED(release_destination, (void)mm::AddressSpaceReleaseUserReservation(p->as, destination_reservation,
                                                                                         base, destination_end));

    // Allocate new frames for the entire new range.
    for (u64 i = 0; i < new_pages; ++i)
    {
        const mm::PhysAddr fr = mm::AllocateFrame().value_or(mm::kNullFrame);
        if (fr == mm::kNullFrame)
        {
            // The reservation cleanup retires only pages tagged with this
            // exact token; it cannot tear down a peer's replacement mapping.
            return kENOMEM;
        }
        if (!mm::AddressSpaceMapReservedUserPage(p->as, destination_reservation, base + i * kPageSize, fr, pte_flags))
        {
            mm::FreeFrame(fr);
            return kENOMEM;
        }
    }

    // Keep the source intact until every bounded read/write transaction has
    // succeeded. A missing source page is EFAULT, and any failure releases
    // the exact destination reservation so the operation is failure-atomic.
    if (!CopyUserRangeOverlapSafe(p->as, old_addr, base, old_aligned))
        return kEFAULT;

    if (!mm::AddressSpaceCommitUserReservationReplacingOwnedRange(p->as, destination_reservation, base, destination_end,
                                                                  old_addr, source_end))
        return kENOMEM;
    release_destination.dismiss();

    p->linux_mmap_cursor += new_aligned;
    arch::SerialWrite("[linux] mremap MAYMOVE old=");
    arch::SerialWriteHex(old_addr);
    arch::SerialWrite(" old_pages=");
    arch::SerialWriteHex(old_pages);
    arch::SerialWrite(" -> new=");
    arch::SerialWriteHex(base);
    arch::SerialWrite(" new_pages=");
    arch::SerialWriteHex(new_pages);
    arch::SerialWrite("\n");
    return static_cast<i64>(base);
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
    if (user_vec == 0)
        return kEFAULT;
    if ((addr & (mm::kPageSize - 1)) != 0)
        return kEINVAL;
    if (len == 0)
        return 0;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->as == nullptr)
        return kEINVAL;
    core::ScopedProcessRuntimeAccess runtime_access(p);
    if (!runtime_access)
        return kESRCH;
    const u64 aligned_len = PageUp(len);
    if (aligned_len == 0)
        return kEINVAL;
    constexpr u64 kUserMaxExclusive = 0x0000800000000000ULL;
    if (addr >= kUserMaxExclusive || aligned_len > (kUserMaxExclusive - addr))
        return kEFAULT;
    const u64 pages = aligned_len / mm::kPageSize;
    constexpr u64 kMaxPages = 4096;
    if (pages > kMaxPages)
        return kENOMEM;
    for (u64 i = 0; i < pages; ++i)
    {
        if (mm::AddressSpaceProbePte(p->as, addr + i * mm::kPageSize) == mm::kNullFrame)
            return kEFAULT;
    }
    u8 ones[kMaxPages]; // per-call, not process-shared static
    for (u64 i = 0; i < pages; ++i)
        ones[i] = 1;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_vec), ones, pages))
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

// =============================================================
// membarrier + mlock2 — small mm-adjacent calls.
// =============================================================

// membarrier(cmd, flags) — synchronise memory barriers across
// threads. cmd=0 is MEMBARRIER_CMD_QUERY which reports the
// bitmask of supported commands. v0 supports none, so QUERY
// returns 0 (which IS the documented "no commands" response).
// Other commands: -EINVAL. Real callers handle this by
// falling back to atomic-fence intrinsics they generate
// themselves.
i64 DoMembarrier(u64 cmd, u64 flags)
{
    (void)flags;
    if (cmd == 0)
        return 0;
    return kEINVAL;
}

// mlock2(addr, len, flags) — pin pages. v0 doesn't swap, so
// pinning is implicit; accept the call as advisory.
i64 DoMlock2(u64 addr, u64 len, u64 flags)
{
    (void)addr;
    (void)len;
    (void)flags;
    return 0;
}

} // namespace duetos::subsystems::linux::internal
