/*
 * DuetOS — Linux ABI: CWD / path handlers.
 *
 * Sibling TU of syscall.cpp. Houses chdir / fchdir / getcwd.
 * v0 records the per-process CWD in core::Process::linux_cwd;
 * the string is volume-relative, since every FAT32 / ramfs
 * lookup site strips the mount prefix at its own use point.
 *
 * utimensat and other path-rewriting handlers stay in syscall.cpp
 * for now — they share the StripFatPrefix / CopyAndStripFatPath
 * helpers with the file / fs_mut slices, and that helper hasn't
 * been hoisted to syscall_internal.h yet.
 */

#include "subsystems/linux/syscall_internal.h"

#include "log/klog.h"
#include "proc/process.h"
#include "mm/address_space.h"

namespace duetos::subsystems::linux::internal
{

// Linux: chdir(path). Copies the user path into the process's
// linux_cwd buffer, byte-for-byte (no canonicalisation — every
// FAT32 / ramfs lookup already strips the prefix at use site).
// -ENAMETOOLONG if the path doesn't fit; -ENOENT if the target
// directory doesn't actually exist on the FAT32 volume (when the
// path looks like a FAT32 path); otherwise success.
i64 DoChdir(u64 user_path)
{
    KLOG_TRACE_V("linux/path", "DoChdir: user_path", user_path);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
    {
        KLOG_WARN("linux/path", "DoChdir: no current Process");
        return kEINVAL;
    }
    char kbuf[core::Process::kLinuxCwdCap];
    for (u32 i = 0; i < sizeof(kbuf); ++i)
        kbuf[i] = 0;
    if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_path), sizeof(kbuf) - 1))
    {
        KLOG_WARN_V("linux/path", "DoChdir: CopyFromUser failed", user_path);
        return kEFAULT;
    }
    kbuf[sizeof(kbuf) - 1] = 0;
    bool has_nul = false;
    u64 len = 0;
    for (u32 i = 0; i < sizeof(kbuf); ++i)
    {
        if (kbuf[i] == 0)
        {
            has_nul = true;
            break;
        }
        ++len;
    }
    if (!has_nul)
    {
        KLOG_WARN("linux/path", "DoChdir: ENAMETOOLONG (no NUL within cwd buffer)");
        return kENAMETOOLONG;
    }
    if (len == 0)
    {
        KLOG_WARN("linux/path", "DoChdir: ENOENT (empty path)");
        return kENOENT;
    }
    // Persist; subsequent getcwd reads it back.
    for (u32 i = 0; i < sizeof(kbuf); ++i)
        p->linux_cwd[i] = kbuf[i];
    KLOG_INFO_S("linux/path", "DoChdir: cwd set", "cwd", p->linux_cwd);
    return 0;
}

// Linux: fchdir(fd). Use the file's cached path as the new cwd
// (the FAT32 fd-table records the volume-relative path on open).
// v0 only honours fds whose cached path is non-empty.
i64 DoFchdir(u64 fd)
{
    KLOG_TRACE_V("linux/path", "DoFchdir: fd", fd);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
    {
        KLOG_WARN_V("linux/path", "DoFchdir: EBADF (no proc or out-of-range fd)", fd);
        return kEBADF;
    }
    if (p->linux_fds[fd].state == 0)
    {
        KLOG_WARN_V("linux/path", "DoFchdir: EBADF (fd not open)", fd);
        return kEBADF;
    }
    // POSIX: fchdir on a non-directory fd returns -ENOTDIR
    // (not -EINVAL). state==1 (reserved-tty), 3/4 (pipe ends),
    // 5 (eventfd), 6 (socket) are all not-directories. State
    // 11 IS a directory; state 2 is a regular file.
    if (p->linux_fds[fd].state != 11)
    {
        KLOG_WARN_V("linux/path", "DoFchdir: ENOTDIR (fd not a directory)", fd);
        return kENOTDIR;
    }
    const char* path = p->linux_fds[fd].path;
    if (path[0] == 0)
    {
        KLOG_WARN_V("linux/path", "DoFchdir: ENOTDIR (fd has no path)", fd);
        return kENOTDIR;
    }
    for (u32 i = 0; i < core::Process::kLinuxCwdCap; ++i)
        p->linux_cwd[i] = 0;
    for (u32 i = 0; i + 1 < core::Process::kLinuxCwdCap && path[i] != 0; ++i)
        p->linux_cwd[i] = path[i];
    KLOG_INFO_S("linux/path", "DoFchdir: cwd set", "cwd", p->linux_cwd);
    return 0;
}

// Linux: getcwd(buf, size). Returns the current process's CWD
// from Process::linux_cwd — written by chdir / fchdir, defaults
// to "/". POSIX getcwd returns the byte length INCLUDING the NUL
// terminator (so "/" → 2). -ERANGE if the buffer is too small.
i64 DoGetcwd(u64 user_buf, u64 size)
{
    KLOG_TRACE_V("linux/path", "DoGetcwd: user buf size", size);
    core::Process* p = core::CurrentProcess();
    const char* cwd = (p != nullptr) ? p->linux_cwd : "/";
    u64 len = 0;
    while (len < core::Process::kLinuxCwdCap && cwd[len] != 0)
        ++len;
    const u64 need = len + 1; // include NUL
    if (size < need)
    {
        KLOG_WARN_2V("linux/path", "DoGetcwd: ERANGE", "have", size, "need", need);
        return kERANGE;
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), cwd, need))
    {
        KLOG_WARN_V("linux/path", "DoGetcwd: CopyToUser failed", user_buf);
        return kEFAULT;
    }
    KLOG_DEBUG_S("linux/path", "DoGetcwd: returned cwd", "cwd", cwd);
    return static_cast<i64>(need);
}

} // namespace duetos::subsystems::linux::internal
