/*
 * DuetOS — Linux ABI: file-table handlers.
 *
 * Sibling TU of syscall.cpp. Houses open / close / stat / fstat
 * / lstat / access / openat / newfstatat.
 *
 * v0 backs every open file by an entry in core::Process::linux_fds
 * (16-slot table). open snapshots the FAT32 directory entry into
 * the slot at first use; close clears the slot. stat / fstat /
 * lstat fill a 144-byte Linux struct stat from the entry; lstat
 * aliases stat (no symlinks). openat / newfstatat enforce the
 * AT_FDCWD-only restriction via AtFdCwdOnly — per-fd directory
 * state is a future slice.
 *
 * Read / write / lseek / pread / pwrite / readv / writev /
 * fsync / ioctl live in their own io slice; this file is purely
 * the slot-table + metadata surface.
 */

#include "subsystems/linux/syscall_internal.h"
#include "subsystems/linux/fanotify.h"
#include "subsystems/linux/inotify.h"
#include "subsystems/linux/syscall_async_io.h"
#include "subsystems/linux/syscall_pipe.h"
#include "subsystems/linux/syscall_socket.h"

#include "proc/process.h"
#include "fs/fat32.h"
#include "mm/address_space.h"
#include "security/canary.h"
#include "subsystems/win32/dir_syscall.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Fill a Linux struct stat from the given FAT32 directory entry.
// Layout matches uapi/asm-generic/stat.h for x86_64 (144 bytes).
// Times are zeroed — no RTC integration yet.
void FillStatFromEntry(const fs::fat32::DirEntry& e, u8* out_144)
{
    for (u64 i = 0; i < 144; ++i)
        out_144[i] = 0;
    auto put_u64 = [&](u64 off, u64 v)
    {
        for (u64 i = 0; i < 8; ++i)
            out_144[off + i] = static_cast<u8>(v >> (i * 8));
    };
    auto put_u32 = [&](u64 off, u32 v)
    {
        for (u64 i = 0; i < 4; ++i)
            out_144[off + i] = static_cast<u8>(v >> (i * 8));
    };
    // st_dev = 0 (no device namespace yet).
    put_u64(0, 0);
    // st_ino = first_cluster — stable identity per on-disk entry.
    put_u64(8, e.first_cluster);
    // st_nlink = 1 for files, 1 for dirs (no hard links).
    put_u64(16, 1);
    // st_mode: dir or regular file, default permissions rw-r--r-- / rwxr-xr-x.
    const u32 mode = (e.attributes & 0x10) ? 0x41EDu  /* S_IFDIR | 0755 */
                                           : 0x81A4u; /* S_IFREG | 0644 */
    put_u32(24, mode);
    // st_uid/gid/rdev = 0.
    // st_size at offset 48.
    put_u64(48, e.size_bytes);
    // st_blksize at offset 56.
    put_u64(56, 4096);
    // st_blocks (in 512-byte units) at offset 64.
    put_u64(64, (u64(e.size_bytes) + 511) / 512);
    // times: all zero — RTC integration follows.
}

} // namespace

// Linux: open(path, flags, mode). v0 scope:
//   - Read-only. Any write/create/truncate flag bits in `flags`
//     are silently ignored; the FAT32 entry has to exist already.
//   - Only FAT32 volume 0. Path may be absolute ("/HELLO.TXT"),
//     mount-prefixed ("/fat/HELLO.TXT"), or bare ("HELLO.TXT").
// Returns the new fd on success, -errno otherwise.
i64 DoOpen(u64 user_path, u64 flags, u64 mode)
{
    (void)mode;
    // Linux open flags we care about for the FAT32-backed v0 path.
    // kSysOpen and kSysOpenat both come through here, so the same
    // bits mean the same thing.
    constexpr u64 kO_CREAT = 0x40;
    constexpr u64 kO_EXCL = 0x80;
    constexpr u64 kO_TRUNC = 0x200;
    constexpr u64 kO_CLOEXEC = 0x80000;
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
    {
        return kEFAULT;
    }
    path[sizeof(path) - 1] = 0;
    bool has_nul = false;
    for (u32 i = 0; i < sizeof(path); ++i)
    {
        if (path[i] == 0)
        {
            has_nul = true;
            break;
        }
    }
    if (!has_nul)
    {
        return kENAMETOOLONG;
    }

    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
    {
        return kENOENT;
    }
    fs::fat32::DirEntry entry;
    const char* leaf = StripFatPrefix(path);
    bool exists = fs::fat32::Fat32LookupPath(v, leaf, &entry);
    bool pending_create = false;
    if (!exists)
    {
        if ((flags & kO_CREAT) == 0)
        {
            return kENOENT;
        }
        // Canary wall: O_CREAT means "create this path". Same
        // policy as Win32 SYS_FILE_CREATE — refuse if the path
        // is a canary or has a suspicious extension.
        if (::duetos::security::CanaryCheck(leaf, "open-O_CREAT"))
            return kEACCES;
        // Persistence-drop detector. Advisory by default; the
        // counter bumps even when the writer is allowed through.
        if (::duetos::security::PersistenceCheck(leaf, "open-O_CREAT"))
            return kEACCES;
        // O_CREAT path: don't physically create the file yet —
        // FAT32's AppendInDir explicitly refuses to grow zero-byte
        // files (first_cluster<2 guards in fat32_write.cpp), so a
        // 0-byte create followed by a write would fail with -EIO.
        // Mark the fd as pending-create; DoWrite then routes the
        // FIRST extending write through Fat32CreateAtPath, which
        // allocates clusters as part of the create. cap_gate gated
        // kCapFsWrite at the syscall entry; the caller is allowed.
        pending_create = true;
        // Synthesise a dir-entry shape so the fd-bind code below
        // sees zero size + zero first_cluster.
        for (u64 i = 0; i < sizeof(entry.name); ++i)
            entry.name[i] = 0;
        entry.attributes = 0;
        entry.first_cluster = 0;
        entry.size_bytes = 0;
    }
    else if ((flags & kO_EXCL) != 0 && (flags & kO_CREAT) != 0)
    {
        // O_CREAT|O_EXCL on an existing file is an error.
        return -17 /*-EEXIST*/;
    }
    // O_TRUNC on an existing regular file is a sub-GAP — Fat32 has
    // a TruncateAtPath but it can't shrink past first_cluster<2
    // either. Real callers rarely combine O_TRUNC with non-empty
    // existing files in synxtest/synfs scope; revisit when one does.
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
    {
        return kEIO;
    }
    if (entry.attributes & 0x10)
    {
        // Directory open — allocate a snapshot via the win32 dir
        // pool and bind a Linux fd (state 11). The path passed to
        // SysDirOpenKernel must include the "/disk/0/" prefix that
        // routes to FAT32; DoOpen has already stripped that prefix
        // off `leaf`, so re-construct.
        char dir_path[80];
        for (u32 i = 0; i < sizeof(dir_path); ++i)
            dir_path[i] = 0;
        const char dprefix[] = "/disk/0/";
        u32 di = 0;
        while (dprefix[di] != '\0' && di < sizeof(dir_path) - 1)
        {
            dir_path[di] = dprefix[di];
            ++di;
        }
        // Skip leading '/' on `leaf` to avoid doubling.
        const char* lc = leaf;
        if (lc[0] == '/')
            ++lc;
        u32 li = 0;
        while (lc[li] != '\0' && di + 1 < sizeof(dir_path))
        {
            dir_path[di] = lc[li];
            ++di;
            ++li;
        }
        dir_path[di] = '\0';
        const i64 dh = ::duetos::subsystems::win32::SysDirOpenKernel(dir_path);
        if (dh < 0)
            return kENOMEM;
        const u32 dslot = static_cast<u32>(dh) - static_cast<u32>(core::Process::kWin32DirBase);
        const i32 fd = core::LinuxFdAllocLowest(p, 3);
        if (fd < 0)
        {
            ::duetos::subsystems::win32::SysDirClose(p, static_cast<u64>(dh));
            return kEMFILE;
        }
        p->linux_fds[fd].state = 11;
        p->linux_fds[fd].first_cluster = dslot;
        p->linux_fds[fd].size = 0;
        p->linux_fds[fd].offset = 0;
        p->linux_fds[fd].path[0] = '\0';
        if ((flags & kO_CLOEXEC) != 0)
            core::LinuxFdSetCloexec(p, static_cast<u32>(fd), true);
        return static_cast<i64>(fd);
    }
    // Stamp the canary flag at open time — same wall the Win32
    // SYS_FILE_OPEN path uses (see file_route.cpp). Pending-
    // create paths already failed the CanaryCheck above (the
    // O_CREAT branch ran the matcher before falling here), so
    // those handles are by-construction not canaries; existing
    // files we just check.
    const bool open_canary = !pending_create && ::duetos::security::CanaryMatchesPath(leaf);
    const i32 fd = core::LinuxFdAllocLowest(p, 3);
    if (fd < 0)
        return kEMFILE;
    p->linux_fds[fd].state = 2;
    u8 fd_flags = pending_create ? core::Process::kLinuxFdFlagPendingCreate : 0;
    if (open_canary)
        fd_flags |= core::Process::kLinuxFdFlagCanary;
    p->linux_fds[fd].flags = fd_flags;
    p->linux_fds[fd].first_cluster = entry.first_cluster;
    p->linux_fds[fd].size = entry.size_bytes;
    p->linux_fds[fd].offset = 0;
    // Remember the (stripped) volume-relative path so
    // sys_write can call Fat32AppendAtPath on extend.
    u32 pi = 0;
    while (leaf[pi] != 0 && pi + 1 < sizeof(p->linux_fds[fd].path))
    {
        p->linux_fds[fd].path[pi] = leaf[pi];
        ++pi;
    }
    p->linux_fds[fd].path[pi] = 0;
    if ((flags & kO_CLOEXEC) != 0)
        core::LinuxFdSetCloexec(p, static_cast<u32>(fd), true);
    return static_cast<i64>(fd);
}

// Linux: close(fd). Marks the slot unused. No destructor work
// for FAT32-backed regular files (snapshotted at open). For
// pool-backed kinds (states 3..15) the per-pool release is
// driven by the slot's KFile sidecar (`kf_handle`) when one is
// attached: `LinuxFdClose` calls `HandleTableRemove`, the
// resulting `KObjectRelease` fires `KFileDestroy`, and that
// dispatches to the per-pool release callback (e.g.
// `PipeReleaseRead`) registered when the slot was created.
// Un-migrated kinds (no KFile sidecar) fall through to the
// legacy explicit `*Release` calls below — kept for the
// states whose creators haven't been migrated yet.
i64 DoClose(u64 fd)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
    {
        return kEBADF;
    }
    // fd 0/1/2 are reserved-tty, never file handles; refuse close.
    if (fd < 3 || p->linux_fds[fd].state == 0)
    {
        return kEBADF;
    }
    const u8 state = p->linux_fds[fd].state;
    const u32 idx = p->linux_fds[fd].first_cluster;
    const bool has_kfile = p->linux_fds[fd].kf_handle != ::duetos::ipc::kHandleInvalid;

    // Legacy explicit *Release for kinds whose creators still
    // wire pool refs by hand. Skipped for migrated kinds — the
    // KFile sidecar's destroy callback drops the ref instead.
    if (!has_kfile)
    {
        if (state == 3)
            PipeReleaseRead(idx);
        else if (state == 4)
            PipeReleaseWrite(idx);
        else if (state == 5)
            EventfdRelease(idx);
        else if (state == 6)
            SocketFdRelease(idx);
        else if (state == 7)
            TimerfdRelease(idx);
        else if (state == 8)
            SignalfdRelease(idx);
        else if (state == 9)
            EpollRelease(idx);
        else if (state == 10)
            InotifyRelease(idx);
        else if (state == 11)
            ::duetos::subsystems::win32::SysDirClose(p, idx + core::Process::kWin32DirBase);
        else if (state == 12)
        {
            // pidfd: drop the ProcessRetain that pidfd_open took.
            // The target may already be reaped — Release tolerates a
            // null target lookup (no ref to drop).
            core::Process* target = sched::SchedFindProcessByPid(idx);
            if (target != nullptr)
                core::ProcessRelease(target);
        }
        else if (state == 13)
        {
            // POSIX MQ: drop the per-handle refcount. Frees the ring
            // when refs == 0 AND mq_unlink already happened.
            PosixMqRelease(idx);
        }
        else if (state == 14)
        {
            // memfd: drop the per-handle refcount. Frees the frame
            // array when refs == 0 (no one holds the fd anymore).
            MemfdRelease(idx);
        }
        else if (state == 15)
        {
            // fanotify instance: drop refcount; frees on last release.
            FanotifyRelease(idx);
        }
    }

    // Centralised slot teardown — also drops the KFile ref when
    // a sidecar is attached (firing the per-pool release callback
    // for migrated kinds).
    core::LinuxFdClose(p, static_cast<u32>(fd));
    return 0;
}

// Linux: stat(path, buf) / lstat(path, buf).
// Looks up the path in FAT32 volume 0, fills a struct stat, copies
// it to user. Treats symlinks as regular files (we have none).
i64 DoStat(u64 user_path, u64 user_buf)
{
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return kEFAULT;
    path[sizeof(path) - 1] = 0;

    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    fs::fat32::DirEntry entry;
    if (!fs::fat32::Fat32LookupPath(v, StripFatPrefix(path), &entry))
        return kENOENT;

    u8 sbuf[144];
    FillStatFromEntry(entry, sbuf);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), sbuf, sizeof(sbuf)))
        return kEFAULT;
    return 0;
}

// Linux: fstat(fd, buf). Synthesises a DirEntry from the fd's
// cached state; doesn't re-read the directory.
i64 DoFstat(u64 fd, u64 user_buf)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    const auto state = p->linux_fds[fd].state;
    fs::fat32::DirEntry entry;
    for (u64 i = 0; i < sizeof(entry.name); ++i)
        entry.name[i] = 0;
    if (state == 1)
    {
        // tty — character-device-ish. Mode S_IFCHR | 0600 = 020600 = 0x2180.
        u8 sbuf[144];
        for (u64 i = 0; i < sizeof(sbuf); ++i)
            sbuf[i] = 0;
        // st_mode at 24:
        sbuf[24] = 0x80;
        sbuf[25] = 0x21;
        // st_nlink=1 at 16:
        sbuf[16] = 1;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), sbuf, sizeof(sbuf)))
            return kEFAULT;
        return 0;
    }
    if (state != 2)
        return kEBADF;
    entry.attributes = 0;
    entry.first_cluster = p->linux_fds[fd].first_cluster;
    entry.size_bytes = p->linux_fds[fd].size;
    u8 sbuf[144];
    FillStatFromEntry(entry, sbuf);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), sbuf, sizeof(sbuf)))
        return kEFAULT;
    return 0;
}

// lstat is identical to stat in v0 — there are no symlinks.
i64 DoLstat(u64 user_path, u64 user_buf)
{
    return DoStat(user_path, user_buf);
}

// Linux: access(path, mode). v0 implements as a presence probe —
// if FAT32LookupPath finds the entry, return 0 (success); else
// -ENOENT. The `mode` bits (R_OK, W_OK, X_OK, F_OK) are ignored:
// everything in FAT32 is effectively rwx from the Linux task's
// perspective.
i64 DoAccess(u64 user_path, u64 mode)
{
    (void)mode;
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return kEFAULT;
    path[sizeof(path) - 1] = 0;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    fs::fat32::DirEntry entry;
    return fs::fat32::Fat32LookupPath(v, StripFatPrefix(path), &entry) ? 0 : kENOENT;
}

// Linux: openat(dirfd, pathname, flags, mode). Modern glibc's
// `open()` is usually `openat(AT_FDCWD, ...)` under the hood —
// this handler is what real compiled-C binaries actually hit.
// v0 only honours AT_FDCWD; any other dirfd is -EBADF until
// per-fd directory state lands (same limitation fchdir has).
i64 DoOpenat(i64 dirfd, u64 user_path, u64 flags, u64 mode)
{
    if (dirfd != kAtFdCwd)
        return kEBADF;
    return DoOpen(user_path, flags, mode);
}

// Linux: newfstatat(dirfd, pathname, statbuf, flags).
// Shape: if AT_EMPTY_PATH (0x1000) is set + dirfd is a valid fd,
// stat the fd (≡ fstat). Else resolve `pathname` relative to
// dirfd (we only accept AT_FDCWD for now). No-follow-symlink
// flag (0x100) is accepted + ignored — we have no symlinks.
i64 DoNewFstatat(i64 dirfd, u64 user_path, u64 user_buf, u64 flags)
{
    constexpr u64 kAtEmptyPath = 0x1000;
    if ((flags & kAtEmptyPath) != 0)
    {
        if (dirfd < 0)
            return kEBADF;
        return DoFstat(static_cast<u64>(dirfd), user_buf);
    }
    if (dirfd != kAtFdCwd)
        return kEBADF;
    return DoStat(user_path, user_buf);
}

// =============================================================
// creat + openat2 — re-shapes of open/openat for legacy and
// extended-flags callers.
// =============================================================

// creat(path, mode) — equivalent to open(path,
// O_CREAT|O_WRONLY|O_TRUNC, mode). Linux's libc stopped using
// this ages ago but ld.so and a couple of legacy build tools
// still reach for it on bootstrap.
i64 DoCreat(u64 user_path, u64 mode)
{
    constexpr u64 kOCreat = 0x40;
    constexpr u64 kOWrOnly = 0x1;
    constexpr u64 kOTrunc = 0x200;
    return DoOpen(user_path, kOCreat | kOWrOnly | kOTrunc, mode);
}

// openat2(dirfd, path, how_struct, how_size) — extended openat
// where the open arguments are bundled in a `struct open_how`
// (flags, mode, resolve). v0 reads the first two fields and
// passes them to DoOpenat; resolve flags (RESOLVE_NO_SYMLINKS,
// RESOLVE_BENEATH, ...) are advisory and quietly ignored.
i64 DoOpenat2(i64 dirfd, u64 user_path, u64 user_how, u64 how_size)
{
    if (how_size < 24)
        return kEINVAL;
    struct OpenHow
    {
        u64 flags;
        u64 mode;
        u64 resolve;
    } how = {};
    const u64 to_copy = how_size < sizeof(how) ? how_size : sizeof(how);
    if (!mm::CopyFromUser(&how, reinterpret_cast<const void*>(user_how), to_copy))
        return kEFAULT;
    return DoOpenat(dirfd, user_path, how.flags, how.mode);
}

} // namespace duetos::subsystems::linux::internal
