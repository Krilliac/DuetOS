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

#include "syscall_internal.h"

#include "../../core/process.h"
#include "../../fs/fat32.h"
#include "../../mm/address_space.h"

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
    (void)flags;
    (void)mode;
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
    if (!fs::fat32::Fat32LookupPath(v, leaf, &entry))
    {
        return kENOENT;
    }
    if (entry.attributes & 0x10)
    {
        return kEISDIR;
    }

    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
    {
        return kEIO;
    }
    for (u32 i = 3; i < 16; ++i)
    {
        if (p->linux_fds[i].state == 0)
        {
            p->linux_fds[i].state = 2;
            p->linux_fds[i].first_cluster = entry.first_cluster;
            p->linux_fds[i].size = entry.size_bytes;
            p->linux_fds[i].offset = 0;
            // Remember the (stripped) volume-relative path so
            // sys_write can call Fat32AppendAtPath on extend.
            u32 pi = 0;
            while (leaf[pi] != 0 && pi + 1 < sizeof(p->linux_fds[i].path))
            {
                p->linux_fds[i].path[pi] = leaf[pi];
                ++pi;
            }
            p->linux_fds[i].path[pi] = 0;
            return static_cast<i64>(i);
        }
    }
    return kEMFILE;
}

// Linux: close(fd). Marks the slot unused. No destructor work —
// FAT32 entries are snapshotted into the fd at open() time; a
// close doesn't touch disk.
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
    p->linux_fds[fd].state = 0;
    p->linux_fds[fd].first_cluster = 0;
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
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

} // namespace duetos::subsystems::linux::internal
