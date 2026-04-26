/*
 * DuetOS — Linux ABI: filesystem-mutating handlers.
 *
 * Sibling TU of syscall.cpp. Houses every Linux call that
 * mutates the FAT32 namespace or pretends to mutate filesystem
 * metadata:
 *
 *   - chmod / fchmod / chown / fchown / lchown — no-op (no
 *     permission / uid / gid model) but verify target exists.
 *   - utime — no-op (no time model) but verify target exists.
 *   - mknod — -EPERM (no special-file machinery).
 *   - truncate / ftruncate — Fat32TruncateAtPath.
 *   - unlink — Fat32DeleteAtPath.
 *   - mkdir / rmdir — Fat32MkdirAtPath / Fat32RmdirAtPath.
 *   - The *at-family (mkdirat / unlinkat / linkat / symlinkat /
 *     renameat / renameat2 / fchownat / futimesat / fchmodat /
 *     faccessat / faccessat2 / utimensat) delegates to the
 *     non-*at handler when dirfd == AT_FDCWD.
 *
 * All path-touching handlers consume CopyAndStripFatPath from
 * syscall_pathutil.cpp. The *at delegations call AtFdCwdOnly first.
 */

#include "syscall_internal.h"

#include "../../core/process.h"
#include "../../fs/fat32.h"

namespace duetos::subsystems::linux::internal
{

// chmod / fchmod / chown / fchown / lchown: v0 has no permission
// model and no uid/gid model. Accept the call but verify the
// target exists — install scripts that chmod a missing file
// expect -ENOENT, not silent success that masks a typo'd path.
i64 DoChmod(u64 user_path, u64 mode)
{
    (void)mode;
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return 0;
    fs::fat32::DirEntry probe;
    if (!fs::fat32::Fat32LookupPath(v, leaf, &probe))
        return kENOENT;
    return 0;
}
i64 DoFchmod(u64 fd, u64 mode)
{
    (void)mode;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state == 0)
        return kEBADF;
    return 0;
}
i64 DoChown(u64 user_path, u64 uid, u64 gid)
{
    (void)uid;
    (void)gid;
    return DoChmod(user_path, 0);
}
i64 DoFchown(u64 fd, u64 uid, u64 gid)
{
    (void)uid;
    (void)gid;
    return DoFchmod(fd, 0);
}
i64 DoLchown(u64 user_path, u64 uid, u64 gid)
{
    return DoChown(user_path, uid, gid);
}

// utime(path, buf): set atime/mtime on a file. v0 doesn't track
// either, so accept as no-op — but verify the path is real before
// pretending success. A program that utimes a nonexistent file
// expects -ENOENT, not silent success.
i64 DoUtime(u64 user_path, u64 user_buf)
{
    (void)user_buf;
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return 0; // No FAT32 — pretend success (path may be ramfs).
    fs::fat32::DirEntry probe;
    if (!fs::fat32::Fat32LookupPath(v, leaf, &probe))
        return kENOENT;
    return 0;
}

// mknod(path, mode, dev): create a special file (FIFO, char,
// block, etc.). v0 has none of these. -EPERM is the standard
// "you don't have CAP_MKNOD" return; honest enough.
i64 DoMknod(u64 user_path, u64 mode, u64 dev)
{
    (void)user_path;
    (void)mode;
    (void)dev;
    return kEPERM;
}

// truncate(path, length): shrink/grow a file to `length` bytes.
i64 DoTruncate(u64 user_path, u64 length)
{
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    const i64 rc = fs::fat32::Fat32TruncateAtPath(v, leaf, length);
    if (rc < 0)
        return kEIO;
    return 0;
}

// ftruncate(fd, length): same as truncate but by fd. Use the
// cached path on the LinuxFd entry.
i64 DoFtruncate(u64 fd, u64 length)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state != 2)
        return kEBADF;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    const i64 rc = fs::fat32::Fat32TruncateAtPath(v, p->linux_fds[fd].path, length);
    if (rc < 0)
        return kEIO;
    // Keep the cached size in sync — a future read/write needs it.
    p->linux_fds[fd].size = static_cast<u32>(length);
    return 0;
}

// unlink(path): delete a file. Returns 0 on success, -ENOENT
// if the file doesn't exist.
i64 DoUnlink(u64 user_path)
{
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    if (!fs::fat32::Fat32DeleteAtPath(v, leaf))
        return kENOENT;
    return 0;
}

// mkdir(path, mode): create a directory. Mode is ignored (no
// permission model).
i64 DoMkdir(u64 user_path, u64 mode)
{
    (void)mode;
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    if (!fs::fat32::Fat32MkdirAtPath(v, leaf))
        return kEIO;
    return 0;
}

// rmdir(path): remove an empty directory.
i64 DoRmdir(u64 user_path)
{
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    if (!fs::fat32::Fat32RmdirAtPath(v, leaf))
        return kEIO;
    return 0;
}

// *at-family delegations. Every one of these routes through the
// non-*at handler when dirfd == AT_FDCWD, or returns -EBADF.

// mkdirat(dirfd, path, mode)
i64 DoMkdirat(i64 dirfd, u64 user_path, u64 mode)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    return DoMkdir(user_path, mode);
}

// unlinkat(dirfd, path, flags): flags & AT_REMOVEDIR -> rmdir.
i64 DoUnlinkat(i64 dirfd, u64 user_path, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    if (flags & kAtRemoveDir)
        return DoRmdir(user_path);
    return DoUnlink(user_path);
}

// linkat / symlinkat / renameat / renameat2 — all map onto the
// non-*at stubs that already return -ENOSYS.
i64 DoLinkat(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(olddirfd); rv != 0)
        return rv;
    if (const i64 rv = AtFdCwdOnly(newdirfd); rv != 0)
        return rv;
    (void)flags;
    return DoLink(oldpath, newpath);
}
i64 DoSymlinkat(u64 target, i64 newdirfd, u64 linkpath)
{
    if (const i64 rv = AtFdCwdOnly(newdirfd); rv != 0)
        return rv;
    return DoSymlink(target, linkpath);
}
i64 DoRenameat(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath)
{
    if (const i64 rv = AtFdCwdOnly(olddirfd); rv != 0)
        return rv;
    if (const i64 rv = AtFdCwdOnly(newdirfd); rv != 0)
        return rv;
    return DoRename(oldpath, newpath);
}
i64 DoRenameat2(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath, u64 flags)
{
    (void)flags;
    return DoRenameat(olddirfd, oldpath, newdirfd, newpath);
}

// fchownat / futimesat / fchmodat / faccessat — identity/ACL
// mutations the caller wants; v0 has no permission model, so
// the non-*at versions are already no-ops. Delegate.
i64 DoFchownat(i64 dirfd, u64 user_path, u64 uid, u64 gid, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    (void)flags;
    return DoChown(user_path, uid, gid);
}
i64 DoFutimesat(i64 dirfd, u64 user_path, u64 user_times)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    return DoUtime(user_path, user_times);
}
i64 DoFchmodat(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    (void)flags;
    return DoChmod(user_path, mode);
}
i64 DoFaccessat(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    (void)flags;
    return DoAccess(user_path, mode);
}
i64 DoFaccessat2(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    return DoFaccessat(dirfd, user_path, mode, flags);
}

// utimensat(dirfd, path, times, flags): set atime/mtime to
// nanosecond-precision values. No time-tracking in v0, but mirror
// utime's path-validation flow so a typo'd path surfaces -ENOENT
// and a bogus dirfd surfaces -EBADF.
i64 DoUtimensat(i64 dirfd, u64 user_path, u64 user_times, u64 flags)
{
    if (dirfd != kAtFdCwd && user_path != 0)
        return kEBADF;
    (void)user_times;
    (void)flags;
    if (user_path != 0)
    {
        // path-relative form: validate the target exists when it
        // looks like a FAT32 path. NUL path means "use the dirfd
        // directly" — accept since we already validated the fd.
        char kbuf[64];
        const char* leaf = nullptr;
        if (!CopyAndStripFatPath(user_path, kbuf, leaf))
            return kEFAULT;
        const auto* v = fs::fat32::Fat32Volume(0);
        if (v != nullptr)
        {
            fs::fat32::DirEntry probe;
            if (!fs::fat32::Fat32LookupPath(v, leaf, &probe))
                return kENOENT;
        }
    }
    return 0;
}

} // namespace duetos::subsystems::linux::internal
