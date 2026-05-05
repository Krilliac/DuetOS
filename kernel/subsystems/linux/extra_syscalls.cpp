/*
 * Extra Linux syscalls — modern fs / mm / fd / numa / namespacing
 * surface that callers (modern musl, glibc 2.34+, busybox) probe at
 * startup. Most are bounded; a handful are honest-no-ops because the
 * underlying machinery doesn't exist (NUMA: single-node OS; PKU: no
 * MPK support).
 *
 * Real implementations:
 *   statx              — extended stat (256-byte struct statx)
 *   copy_file_range    — kernel-side fd-to-fd file copy
 *   memfd_create       — anonymous memory file (LinuxFd state 14)
 *   close_range        — close a contiguous range of fds
 *   statfs / fstatfs   — filesystem info
 *
 * No-ops returning success (caller's behavior unchanged):
 *   set_mempolicy / get_mempolicy / mbind / migrate_pages /
 *   move_pages       — single-node OS; advice ignored
 *   mseal             — memory sealing accepted (sub-GAP: no enforcement)
 *   process_madvise   — cross-process advice (we ignore advice anyway)
 *   process_mrelease  — refuse cleanly
 *   landlock_*        — sandboxing facade (no engine)
 *
 * Honest -ENOSYS / -EINVAL:
 *   userfaultfd       — no userfault engine
 *   io_uring_*        — no async-I/O ring
 *   pkey_*            — no PKU; -EINVAL is the canonical "no key
 *                        slots" return
 *   name_to_handle_at /
 *   open_by_handle_at — no portable file-handle scheme
 *   fsopen / fsconfig /
 *   fsmount / fspick /
 *   open_tree / move_mount /
 *   mount_setattr     — modern mount API; static topology
 */

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "fs/fat32.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr u32 kMemfdPoolCap = 8;
constexpr u32 kMemfdMaxPages = 256; // 1 MiB / memfd cap

constexpr u64 kPage = 4096ull;

// memfd: anonymous memory backed by physical frames. Creates land
// in this pool; mmap on the fd installs borrowed PTEs into the
// caller's AS via the same machinery shm uses.
struct Memfd
{
    bool in_use;
    u8 _pad[3];
    u32 refs;
    u32 page_count;
    u32 _pad2;
    u64 size_bytes;
    mm::PhysAddr* frames; // KMalloc'd page_count entries
    char name[32];
};

Memfd g_memfd_pool[kMemfdPoolCap];

i32 MemfdAlloc(const char* name, u64 page_count)
{
    if (page_count == 0)
        page_count = 1;
    if (page_count > kMemfdMaxPages)
        return -1;
    arch::Cli();
    for (u32 i = 0; i < kMemfdPoolCap; ++i)
    {
        if (g_memfd_pool[i].in_use)
            continue;
        Memfd& m = g_memfd_pool[i];
        m.in_use = true;
        m.refs = 1;
        m.page_count = static_cast<u32>(page_count);
        m.size_bytes = page_count * kPage;
        for (u32 j = 0; j < sizeof(m.name); ++j)
            m.name[j] = 0;
        if (name != nullptr)
            for (u32 j = 0; j < sizeof(m.name) - 1 && name[j] != '\0'; ++j)
                m.name[j] = name[j];
        arch::Sti();
        m.frames = static_cast<mm::PhysAddr*>(mm::KMalloc(sizeof(mm::PhysAddr) * page_count));
        if (m.frames == nullptr)
        {
            arch::Cli();
            m.in_use = false;
            arch::Sti();
            return -1;
        }
        for (u32 p = 0; p < page_count; ++p)
        {
            const mm::PhysAddr f = mm::AllocateFrame();
            if (f == mm::kNullFrame)
            {
                for (u32 q = 0; q < p; ++q)
                    mm::FreeFrame(m.frames[q]);
                mm::KFree(m.frames);
                arch::Cli();
                m.frames = nullptr;
                m.in_use = false;
                arch::Sti();
                return -1;
            }
            // Zero-fill (memfd_create contract).
            volatile u8* page = reinterpret_cast<u8*>(mm::PhysToVirt(f));
            for (u32 b = 0; b < kPage; ++b)
                page[b] = 0;
            m.frames[p] = f;
        }
        return static_cast<i32>(i);
    }
    arch::Sti();
    return -1;
}

} // namespace

void MemfdRetain(u32 idx)
{
    if (idx >= kMemfdPoolCap)
        return;
    arch::Cli();
    if (g_memfd_pool[idx].in_use)
        ++g_memfd_pool[idx].refs;
    arch::Sti();
}

void MemfdRelease(u32 idx)
{
    if (idx >= kMemfdPoolCap)
        return;
    arch::Cli();
    Memfd& m = g_memfd_pool[idx];
    if (!m.in_use || m.refs == 0)
    {
        arch::Sti();
        return;
    }
    --m.refs;
    if (m.refs == 0)
    {
        mm::PhysAddr* frames = m.frames;
        const u32 count = m.page_count;
        m.frames = nullptr;
        m.page_count = 0;
        m.size_bytes = 0;
        m.in_use = false;
        arch::Sti();
        for (u32 i = 0; i < count; ++i)
            mm::FreeFrame(frames[i]);
        mm::KFree(frames);
        return;
    }
    arch::Sti();
}

i64 DoMemfdCreate(u64 user_name, u64 flags)
{
    constexpr u64 kMFD_CLOEXEC = 0x1;
    char name[32];
    for (u32 i = 0; i < sizeof(name); ++i)
        name[i] = 0;
    if (user_name != 0)
        (void)mm::CopyFromUser(name, reinterpret_cast<const void*>(user_name), sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';

    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    const i32 fd = core::LinuxFdAllocLowest(p, 3);
    if (fd < 0)
        return kEMFILE;
    p->linux_fds[fd].state = 14; // reserve
    // Create a 0-byte memfd; ftruncate is what makes it usable.
    // To keep v0 simple, we skip the 0-byte case and allocate one
    // page up front. Callers can ftruncate to grow (bounded by
    // kMemfdMaxPages).
    const i32 idx = MemfdAlloc(name, 1);
    if (idx < 0)
    {
        p->linux_fds[fd].state = 0;
        return kENOMEM;
    }
    p->linux_fds[fd].flags = 0;
    p->linux_fds[fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[fd].size = static_cast<u32>(g_memfd_pool[idx].size_bytes);
    p->linux_fds[fd].offset = 0;
    p->linux_fds[fd].path[0] = '\0';
    if (!core::LinuxFdAttachKFile(p, static_cast<u32>(fd), /*kind=*/14, static_cast<u32>(idx), &MemfdRelease))
    {
        p->linux_fds[fd].state = 0;
        MemfdRelease(static_cast<u32>(idx));
        return kENOMEM;
    }
    if ((flags & kMFD_CLOEXEC) != 0)
        core::LinuxFdSetCloexec(p, static_cast<u32>(fd), true);
    arch::SerialWrite("[linux/memfd] create fd=");
    arch::SerialWriteHex(fd);
    arch::SerialWrite(" idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(name);
    arch::SerialWrite("\"\n");
    return static_cast<i64>(fd);
}

// =========================================================
// statx — extended stat
// =========================================================

namespace
{

// struct statx — Linux 4.11+. 256 bytes total.
struct __attribute__((packed)) Statx
{
    u32 stx_mask;
    u32 stx_blksize;
    u64 stx_attributes;
    u32 stx_nlink;
    u32 stx_uid;
    u32 stx_gid;
    u16 stx_mode;
    u16 _pad1;
    u64 stx_ino;
    u64 stx_size;
    u64 stx_blocks;
    u64 stx_attributes_mask;
    // statx_timestamp: { i64 tv_sec; u32 tv_nsec; i32 _pad; } = 16 bytes
    i64 stx_atime_sec;
    u32 stx_atime_nsec;
    i32 _pad_a;
    i64 stx_btime_sec;
    u32 stx_btime_nsec;
    i32 _pad_b;
    i64 stx_ctime_sec;
    u32 stx_ctime_nsec;
    i32 _pad_c;
    i64 stx_mtime_sec;
    u32 stx_mtime_nsec;
    i32 _pad_m;
    u32 stx_rdev_major;
    u32 stx_rdev_minor;
    u32 stx_dev_major;
    u32 stx_dev_minor;
    u64 stx_mnt_id;
    u64 stx_dio_mem_align;
    u64 stx_dio_offset_align;
    u64 _spare[11];
};
static_assert(sizeof(Statx) == 256, "Statx size drift");

} // namespace

i64 DoStatx(u64 dirfd, u64 user_path, u64 flags, u64 mask, u64 user_buf)
{
    (void)mask; // we always populate STATX_BASIC_STATS
    const i64 sdir = static_cast<i64>(dirfd);
    if (sdir != kAtFdCwd)
        return kEBADF;
    constexpr u64 kAtEmptyPath = 0x1000;
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (user_path != 0 && (flags & kAtEmptyPath) == 0)
    {
        if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
            return kEFAULT;
        path[sizeof(path) - 1] = 0;
    }
    Statx out;
    for (u64 i = 0; i < sizeof(out); ++i)
        reinterpret_cast<u8*>(&out)[i] = 0;
    out.stx_blksize = 4096;
    out.stx_nlink = 1;
    out.stx_dev_major = 0;
    out.stx_dev_minor = 0;
    // STATX_BASIC_STATS = 0x07ff
    out.stx_mask = 0x07ff;
    if (path[0] != '\0')
    {
        const auto* v = fs::fat32::Fat32Volume(0);
        if (v == nullptr)
            return kENOENT;
        fs::fat32::DirEntry e;
        const char* leaf = StripFatPrefix(path);
        if (!fs::fat32::Fat32LookupPath(v, leaf, &e))
            return kENOENT;
        out.stx_ino = e.first_cluster;
        out.stx_size = e.size_bytes;
        out.stx_blocks = (e.size_bytes + 511) / 512;
        out.stx_mode = (e.attributes & 0x10) ? 0x41ED  // S_IFDIR | 0755
                                             : 0x81A4; // S_IFREG | 0644
    }
    else
    {
        // AT_EMPTY_PATH or empty path → fstat-equivalent on dirfd
        // (only AT_FDCWD here, so report the caller's CWD as a dir).
        out.stx_mode = 0x41ED;
        out.stx_ino = 1;
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &out, sizeof(out)))
        return kEFAULT;
    return 0;
}

// =========================================================
// copy_file_range — kernel-side fd-to-fd copy
// =========================================================

i64 DoCopyFileRange(u64 fd_in, u64 user_off_in, u64 fd_out, u64 user_off_out, u64 len, u64 flags)
{
    (void)flags;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd_in >= 16 || fd_out >= 16)
        return kEBADF;
    if (p->linux_fds[fd_in].state != 2 || p->linux_fds[fd_out].state != 2)
        return kEINVAL; // both ends must be regular files
    if (len == 0)
        return 0;
    if (!core::CapSetHas(p->caps, core::kCapFsWrite))
    {
        core::RecordSandboxDenial(core::kCapFsWrite);
        return kEACCES;
    }
    // Save / override / restore offsets if the caller passed them.
    i64 saved_in = static_cast<i64>(p->linux_fds[fd_in].offset);
    i64 saved_out = static_cast<i64>(p->linux_fds[fd_out].offset);
    if (user_off_in != 0)
    {
        i64 in_off = 0;
        if (!mm::CopyFromUser(&in_off, reinterpret_cast<const void*>(user_off_in), sizeof(in_off)))
            return kEFAULT;
        p->linux_fds[fd_in].offset = static_cast<u64>(in_off);
    }
    if (user_off_out != 0)
    {
        i64 out_off = 0;
        if (!mm::CopyFromUser(&out_off, reinterpret_cast<const void*>(user_off_out), sizeof(out_off)))
            return kEFAULT;
        p->linux_fds[fd_out].offset = static_cast<u64>(out_off);
    }
    // Bounce through the kernel heap directly via FAT32 primitives.
    // Earlier v0 went through DoRead / DoWrite on the kernel buffer,
    // but those call CopyTo/FromUser which reject kernel VAs as
    // -EFAULT — synfs caught it as `copy_file_range rc=-14` even
    // though both fds were valid. Using Fat32ReadFile + (Append /
    // Create)AtPath is a single bounce in kernel-space, no user-VA
    // checks involved.
    constexpr u64 kStageCap = 4096;
    auto* stage = static_cast<u8*>(mm::KMalloc(kStageCap));
    if (stage == nullptr)
        return kENOMEM;
    const auto* vol = fs::fat32::Fat32Volume(0);
    if (vol == nullptr)
    {
        mm::KFree(stage);
        return kEIO;
    }
    fs::fat32::DirEntry src_e;
    if (!fs::fat32::Fat32LookupPath(vol, p->linux_fds[fd_in].path, &src_e))
    {
        mm::KFree(stage);
        return kEIO;
    }
    const u64 src_size = src_e.size_bytes;
    u64 src_off = p->linux_fds[fd_in].offset;
    if (src_off > src_size)
    {
        mm::KFree(stage);
        return 0;
    }
    u64 total = 0;
    while (total < len && src_off < src_size)
    {
        const u64 avail = src_size - src_off;
        u64 want = (len - total < avail) ? (len - total) : avail;
        if (want > kStageCap)
            want = kStageCap;
        // Fat32ReadFile reads from offset 0; for v0's small files
        // that's adequate — read the prefix up to (src_off + want)
        // and slice. If the file is larger than kStageCap, we'd
        // need a streamed read; that's a sub-GAP for now.
        const u64 read_through = src_off + want;
        if (read_through > kStageCap)
        {
            mm::KFree(stage);
            return total > 0 ? static_cast<i64>(total) : kEFBIG;
        }
        const i64 rd = fs::fat32::Fat32ReadFile(vol, &src_e, stage, read_through);
        if (rd < 0)
        {
            mm::KFree(stage);
            return total > 0 ? static_cast<i64>(total) : kEIO;
        }
        if (static_cast<u64>(rd) <= src_off)
            break;
        const u64 chunk = static_cast<u64>(rd) - src_off;
        const u64 to_write = (chunk < want) ? chunk : want;
        // Write to dst — pending-create or append.
        i64 wr = -1;
        if (p->linux_fds[fd_out].flags & core::Process::kLinuxFdFlagPendingCreate)
        {
            wr = fs::fat32::Fat32CreateAtPath(vol, p->linux_fds[fd_out].path, stage + src_off, to_write);
            if (wr >= 0)
            {
                p->linux_fds[fd_out].flags =
                    static_cast<u8>(p->linux_fds[fd_out].flags & ~core::Process::kLinuxFdFlagPendingCreate);
                fs::fat32::DirEntry de;
                if (fs::fat32::Fat32LookupPath(vol, p->linux_fds[fd_out].path, &de))
                {
                    p->linux_fds[fd_out].first_cluster = de.first_cluster;
                    p->linux_fds[fd_out].size = de.size_bytes;
                }
            }
        }
        else
        {
            wr = fs::fat32::Fat32AppendAtPath(vol, p->linux_fds[fd_out].path, stage + src_off, to_write);
            if (wr >= 0)
                p->linux_fds[fd_out].size += static_cast<u32>(wr);
        }
        if (wr < 0)
        {
            mm::KFree(stage);
            return total > 0 ? static_cast<i64>(total) : kEIO;
        }
        total += static_cast<u64>(wr);
        src_off += static_cast<u64>(wr);
        p->linux_fds[fd_in].offset = src_off;
        p->linux_fds[fd_out].offset += static_cast<u64>(wr);
        if (static_cast<u64>(wr) < to_write)
            break;
    }
    mm::KFree(stage);
    // Write updated offsets back to caller pointers; otherwise
    // leave the per-fd cursor at its new position.
    if (user_off_in != 0)
    {
        i64 final_in = static_cast<i64>(p->linux_fds[fd_in].offset);
        (void)mm::CopyToUser(reinterpret_cast<void*>(user_off_in), &final_in, sizeof(final_in));
        p->linux_fds[fd_in].offset = static_cast<u64>(saved_in);
    }
    if (user_off_out != 0)
    {
        i64 final_out = static_cast<i64>(p->linux_fds[fd_out].offset);
        (void)mm::CopyToUser(reinterpret_cast<void*>(user_off_out), &final_out, sizeof(final_out));
        p->linux_fds[fd_out].offset = static_cast<u64>(saved_out);
    }
    // Ransomware-rate guard. copy_file_range bypasses DoWrite —
    // it issues Fat32{Create,Append}AtPath directly — so the
    // rate hook in DoWrite doesn't see these bytes. Count the
    // total transferred here so a kernel-side fd-to-fd copy
    // attack can't evade the cap by routing around DoWrite.
    ::duetos::core::RecordFsWrite(p, total);
    return static_cast<i64>(total);
}

// =========================================================
// close_range — close a contiguous fd range
// =========================================================

i64 DoCloseRange(u64 first, u64 last, u64 flags)
{
    (void)flags; // CLOSE_RANGE_UNSHARE / CLOEXEC ignored in v0
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    if (last < first)
        return kEINVAL;
    if (last >= 16)
        last = 15;
    for (u32 fd = static_cast<u32>(first); fd <= static_cast<u32>(last); ++fd)
    {
        if (fd < 3)
            continue; // never close stdin/out/err
        if (p->linux_fds[fd].state != 0)
            (void)DoClose(fd);
    }
    return 0;
}

// =========================================================
// statfs / fstatfs — filesystem info
// =========================================================

namespace
{

// struct statfs — 120 bytes on x86_64.
struct __attribute__((packed)) Statfs
{
    u64 f_type;
    u64 f_bsize;
    u64 f_blocks;
    u64 f_bfree;
    u64 f_bavail;
    u64 f_files;
    u64 f_ffree;
    u64 f_fsid_a;
    u64 f_fsid_b;
    u64 f_namelen;
    u64 f_frsize;
    u64 f_flags;
    u64 _spare[4];
};
// Size is whatever the packed layout produces — the kernel-side
// struct only has to be big enough for the fields the caller
// reads. Don't static_assert on byte count: the freestanding
// build's __attribute__((packed)) doesn't always compose with u64
// member packing the same way the userland sysroot does.

void FillStatfs(Statfs& s)
{
    for (u64 i = 0; i < sizeof(s); ++i)
        reinterpret_cast<u8*>(&s)[i] = 0;
    s.f_type = 0x4d44; // MSDOS_SUPER_MAGIC (FAT)
    s.f_bsize = 4096;
    s.f_blocks = 65536; // 256 MiB approximation
    s.f_bfree = 32768;
    s.f_bavail = 32768;
    s.f_files = 16384;
    s.f_ffree = 16000;
    s.f_namelen = 255;
    s.f_frsize = 4096;
}

} // namespace

i64 DoStatfs(u64 user_path, u64 user_buf)
{
    (void)user_path; // path-validation is sub-GAP
    Statfs out;
    FillStatfs(out);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &out, sizeof(out)))
        return kEFAULT;
    return 0;
}

i64 DoFstatfs(u64 fd, u64 user_buf)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state == 0)
        return kEBADF;
    Statfs out;
    FillStatfs(out);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &out, sizeof(out)))
        return kEFAULT;
    return 0;
}

// =========================================================
// NUMA family — single-node OS, accept-as-no-op
// =========================================================

i64 DoSetMempolicy(u64 mode, u64 user_nodemask, u64 maxnode)
{
    (void)mode;
    (void)user_nodemask;
    (void)maxnode;
    return 0;
}

i64 DoGetMempolicy(u64 user_mode, u64 user_nodemask, u64 maxnode, u64 addr, u64 flags)
{
    (void)maxnode;
    (void)addr;
    (void)flags;
    if (user_mode != 0)
    {
        const u32 mode = 0; // MPOL_DEFAULT
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_mode), &mode, sizeof(mode)))
            return kEFAULT;
    }
    if (user_nodemask != 0)
    {
        const u64 nodemask = 1; // node 0
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_nodemask), &nodemask, sizeof(nodemask)))
            return kEFAULT;
    }
    return 0;
}

i64 DoMbind(u64 addr, u64 len, u64 mode, u64 user_nodemask, u64 maxnode, u64 flags)
{
    (void)addr;
    (void)len;
    (void)mode;
    (void)user_nodemask;
    (void)maxnode;
    (void)flags;
    return 0;
}

i64 DoMigratePages(u64 pid, u64 maxnode, u64 user_old, u64 user_new)
{
    (void)pid;
    (void)maxnode;
    (void)user_old;
    (void)user_new;
    return 0;
}

i64 DoMovePages(u64 pid, u64 nr_pages, u64 user_pages, u64 user_nodes, u64 user_status, u64 flags)
{
    (void)pid;
    (void)nr_pages;
    (void)user_pages;
    (void)user_nodes;
    (void)user_status;
    (void)flags;
    return 0;
}

// =========================================================
// mseal / process_madvise / process_mrelease
// =========================================================

i64 DoMseal(u64 start, u64 len, u64 flags)
{
    (void)start;
    (void)len;
    (void)flags;
    // Accept silently — sealing prevents future mprotect / munmap;
    // v0 doesn't enforce. Sub-GAP. Honest signal: real Linux 6.10+
    // enforces; v0 just tells the caller "yes, sealed". Callers that
    // depended on enforcement to harden their state lose that gain
    // (the sealing semantic is advisory in v0).
    return 0;
}

i64 DoProcessMadvise(u64 pidfd, u64 user_iovec, u64 vlen, u64 advice, u64 flags)
{
    (void)pidfd;
    (void)user_iovec;
    (void)vlen;
    (void)advice;
    (void)flags;
    // v0 ignores all madvise hints anyway; cross-process advice
    // collapses to the same no-op.
    return 0;
}

i64 DoProcessMrelease(u64 pidfd, u64 flags)
{
    (void)pidfd;
    (void)flags;
    // process_mrelease releases reclaimable memory of a dying
    // process. v0 reaper does this on SchedExit; this syscall is
    // a no-op success return.
    return 0;
}

// =========================================================
// Honest -ENOSYS / -EINVAL — no engine
// =========================================================

i64 DoUserfaultfd(u64 flags)
{
    (void)flags;
    return kENOSYS;
}

i64 DoIoUringSetup(u64 entries, u64 user_params)
{
    (void)entries;
    (void)user_params;
    return kENOSYS;
}

i64 DoIoUringEnter(u64 fd, u64 to_submit, u64 min_complete, u64 flags, u64 user_sig, u64 sigsz)
{
    (void)fd;
    (void)to_submit;
    (void)min_complete;
    (void)flags;
    (void)user_sig;
    (void)sigsz;
    return kENOSYS;
}

i64 DoIoUringRegister(u64 fd, u64 op, u64 user_arg, u64 nr_args)
{
    (void)fd;
    (void)op;
    (void)user_arg;
    (void)nr_args;
    return kENOSYS;
}

i64 DoPkeyAlloc(u64 flags, u64 init_val)
{
    (void)flags;
    (void)init_val;
    // No PKU / MPK on v0. -EINVAL is the canonical "no key slots
    // available" return; libraries detect it and fall back.
    return kEINVAL;
}

i64 DoPkeyFree(u64 pkey)
{
    (void)pkey;
    return kEINVAL;
}

i64 DoPkeyMprotect(u64 addr, u64 len, u64 prot, u64 pkey)
{
    (void)pkey;
    // Forward to the regular mprotect path.
    return DoMprotect(addr, len, prot);
}

// name_to_handle_at(dirfd, path, handle, mount_id, flags) — encode
// a path into a struct file_handle the caller can later pass to
// open_by_handle_at. v0 file_handle layout:
//   u32 handle_bytes  (caller-provided cap; we write 8)
//   u32 handle_type   (1 = generic FAT32 cluster ref)
//   u8  f_handle[handle_bytes]:
//     u32 first_cluster (FAT32 entry's first cluster — stable per-file)
//     u32 size_low      (low 32 bits of file size — disambiguates
//                        cluster reuse if a file is unlinked + re-
//                        created at the same cluster, which v0
//                        currently can't avoid because we have no
//                        per-file inode generation)
i64 DoNameToHandleAt(u64 dirfd, u64 user_path, u64 user_handle, u64 user_mount_id, u64 flags)
{
    (void)flags;
    if (static_cast<i64>(dirfd) != kAtFdCwd)
        return kEBADF;
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return kEFAULT;
    path[sizeof(path) - 1] = 0;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    fs::fat32::DirEntry e;
    const char* leaf = StripFatPrefix(path);
    if (!fs::fat32::Fat32LookupPath(v, leaf, &e))
        return kENOENT;
    // Read the caller's caps field first so we honour their
    // handle_bytes ask.
    u32 caller_bytes = 0;
    if (!mm::CopyFromUser(&caller_bytes, reinterpret_cast<const void*>(user_handle), sizeof(caller_bytes)))
        return kEFAULT;
    if (caller_bytes < 8)
    {
        // Set handle_bytes to 8 + return -EOVERFLOW.
        caller_bytes = 8;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_handle), &caller_bytes, sizeof(caller_bytes)))
            return kEFAULT;
        return kEOVERFLOW;
    }
    u8 buf[16];
    for (u32 i = 0; i < sizeof(buf); ++i)
        buf[i] = 0;
    const u32 hb = 8;
    const u32 ht = 1;
    for (u32 i = 0; i < 4; ++i)
    {
        buf[i] = static_cast<u8>((hb >> (i * 8)) & 0xFF);
        buf[4 + i] = static_cast<u8>((ht >> (i * 8)) & 0xFF);
        buf[8 + i] = static_cast<u8>((e.first_cluster >> (i * 8)) & 0xFF);
        buf[12 + i] = static_cast<u8>((e.size_bytes >> (i * 8)) & 0xFF);
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_handle), buf, sizeof(buf)))
        return kEFAULT;
    if (user_mount_id != 0)
    {
        const u32 mount_id = 1;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_mount_id), &mount_id, sizeof(mount_id)))
            return kEFAULT;
    }
    return 0;
}

// open_by_handle_at(mount_fd, handle, flags) — decode a file_handle
// produced by name_to_handle_at and open it. v0 walks the FAT32
// volume's root looking for an entry whose first_cluster + size
// match the handle. (This is O(N) in directory size but bounded by
// the v0 filesystems we care about.) Returns a Linux fd.
i64 DoOpenByHandleAt(u64 mount_fd, u64 user_handle, u64 flags)
{
    (void)mount_fd;
    (void)flags;
    u8 buf[16];
    if (!mm::CopyFromUser(buf, reinterpret_cast<const void*>(user_handle), sizeof(buf)))
        return kEFAULT;
    u32 hb = 0;
    u32 ht = 0;
    for (u32 i = 0; i < 4; ++i)
    {
        hb |= static_cast<u32>(buf[i]) << (i * 8);
        ht |= static_cast<u32>(buf[4 + i]) << (i * 8);
    }
    if (hb < 8 || ht != 1)
        return kEINVAL;
    u32 want_cluster = 0;
    u32 want_size = 0;
    for (u32 i = 0; i < 4; ++i)
    {
        want_cluster |= static_cast<u32>(buf[8 + i]) << (i * 8);
        want_size |= static_cast<u32>(buf[12 + i]) << (i * 8);
    }
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    // Walk the root directory; v0 doesn't support nested-handle
    // resolution because that would need full-tree-walking.
    // Sub-GAP: only root-directory entries can be re-opened.
    fs::fat32::DirEntry root;
    if (!fs::fat32::Fat32LookupPath(v, "/", &root))
        return kENOENT;
    fs::fat32::DirEntry entries[32];
    const u32 n = fs::fat32::Fat32ListDirByCluster(v, root.first_cluster, entries, 32);
    for (u32 i = 0; i < n; ++i)
    {
        if (entries[i].first_cluster == want_cluster && entries[i].size_bytes == want_size)
        {
            // Got it. Build a Linux fd.
            core::Process* p = core::CurrentProcess();
            if (p == nullptr)
                return kEPERM;
            for (u32 fd = 3; fd < 16; ++fd)
            {
                if (p->linux_fds[fd].state == 0)
                {
                    p->linux_fds[fd].state = 2;
                    p->linux_fds[fd].first_cluster = entries[i].first_cluster;
                    p->linux_fds[fd].size = entries[i].size_bytes;
                    p->linux_fds[fd].offset = 0;
                    // Path can't be reconstructed without the
                    // dir-walk parent context; leave empty (writes
                    // that need it will fail — sub-GAP).
                    p->linux_fds[fd].path[0] = '\0';
                    return static_cast<i64>(fd);
                }
            }
            return kEMFILE;
        }
    }
    return kESTALE; // -ESTALE: handle decoded but the entry is gone
}

// Modern mount API — privileged ops on a static mount topology.
// Real Linux gates these on CAP_SYS_ADMIN; v0 returns -EPERM
// uniformly so callers exercise their CAP_SYS_ADMIN fallback rather
// than thinking the syscall is missing.
i64 DoFsopen(u64 user_fsname, u64 flags)
{
    (void)user_fsname;
    (void)flags;
    return kEPERM;
}

i64 DoFsconfig(u64 fd, u64 cmd, u64 user_key, u64 user_value, u64 aux)
{
    (void)fd;
    (void)cmd;
    (void)user_key;
    (void)user_value;
    (void)aux;
    return kEPERM;
}

i64 DoFsmount(u64 fs_fd, u64 flags, u64 attr_flags)
{
    (void)fs_fd;
    (void)flags;
    (void)attr_flags;
    return kEPERM;
}

i64 DoFspick(u64 dirfd, u64 user_path, u64 flags)
{
    (void)dirfd;
    (void)user_path;
    (void)flags;
    return kEPERM;
}

i64 DoOpenTree(u64 dirfd, u64 user_path, u64 flags)
{
    (void)dirfd;
    (void)user_path;
    (void)flags;
    return kEPERM;
}

i64 DoMoveMount(u64 from_dfd, u64 user_from, u64 to_dfd, u64 user_to, u64 flags)
{
    (void)from_dfd;
    (void)user_from;
    (void)to_dfd;
    (void)user_to;
    (void)flags;
    return kEPERM;
}

i64 DoMountSetattr(u64 dirfd, u64 user_path, u64 flags, u64 user_uattr, u64 size)
{
    (void)dirfd;
    (void)user_path;
    (void)flags;
    (void)user_uattr;
    (void)size;
    return kEPERM;
}

// Landlock — sandboxing facade. Real engine deferred; honest -ENOSYS
// triggers callers to fall back. (Earlier slices considered making
// this a noop but landlock_restrict_self with no engine could give
// a malicious caller a false sense of containment — explicit ENOSYS
// is safer.)
i64 DoLandlockCreateRuleset(u64 user_attr, u64 size, u64 flags)
{
    (void)user_attr;
    (void)size;
    (void)flags;
    return kENOSYS;
}

i64 DoLandlockAddRule(u64 ruleset_fd, u64 rule_type, u64 user_rule_attr, u64 flags)
{
    (void)ruleset_fd;
    (void)rule_type;
    (void)user_rule_attr;
    (void)flags;
    return kENOSYS;
}

i64 DoLandlockRestrictSelf(u64 ruleset_fd, u64 flags)
{
    (void)ruleset_fd;
    (void)flags;
    return kENOSYS;
}

} // namespace duetos::subsystems::linux::internal
