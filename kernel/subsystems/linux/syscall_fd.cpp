/*
 * DuetOS — Linux ABI: file-descriptor handlers.
 *
 * Sibling TU of syscall.cpp. Houses dup / dup2 / dup3 / fcntl.
 * v0 stores per-fd state in core::Process::linux_fds[16] and
 * treats each slot as an INDEPENDENT copy on dup — real Linux
 * dup() would share the file description (one shared offset +
 * flag set), but our workloads don't hit the difference yet.
 */

#include "subsystems/linux/syscall_internal.h"

#include "proc/process.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Copy one fd slot into another (same process). Used by dup /
// dup2 / F_DUPFD. v0 semantics: the new fd is an INDEPENDENT
// copy — state + first_cluster + size + offset + path all
// mirrored.
void CopyFdSlot(const core::Process::LinuxFd& src, core::Process::LinuxFd& dst)
{
    dst.state = src.state;
    dst.first_cluster = src.first_cluster;
    dst.size = src.size;
    dst.offset = src.offset;
    for (u32 i = 0; i < sizeof(dst.path); ++i)
        dst.path[i] = src.path[i];
}

} // namespace

// Linux: dup(fd). Allocate the lowest unused slot ≥ 3 and copy
// the source fd into it. Returns the new fd or -EMFILE if full.
i64 DoDup(u64 fd)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    for (u32 i = 3; i < 16; ++i)
    {
        if (p->linux_fds[i].state == 0)
        {
            CopyFdSlot(p->linux_fds[fd], p->linux_fds[i]);
            return static_cast<i64>(i);
        }
    }
    return kEMFILE;
}

// Linux: dup2(oldfd, newfd). If newfd == oldfd, returns newfd.
// Else closes newfd if in use, then copies. Returns newfd.
i64 DoDup2(u64 oldfd, u64 newfd)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || oldfd >= 16 || newfd >= 16)
        return kEBADF;
    if (p->linux_fds[oldfd].state == 0)
        return kEBADF;
    if (oldfd == newfd)
        return static_cast<i64>(newfd);
    // newfd < 3 (stdin/stdout/stderr) — dup2 onto a tty slot is
    // legal in Linux (shell redirection pattern). Since we track
    // tty slots as state=1 (not a file), just overwrite.
    CopyFdSlot(p->linux_fds[oldfd], p->linux_fds[newfd]);
    return static_cast<i64>(newfd);
}

// Linux: dup3(oldfd, newfd, flags). Same as dup2 but requires
// oldfd != newfd (else -EINVAL) and optionally takes O_CLOEXEC
// (0x80000). We don't track CLOEXEC so the flag is accepted but
// a no-op. Everything else is DoDup2.
i64 DoDup3(u64 oldfd, u64 newfd, u64 flags)
{
    if (oldfd == newfd)
        return kEINVAL;
    constexpr u64 kOCloexec = 0x80000;
    if ((flags & ~kOCloexec) != 0)
        return kEINVAL;
    return DoDup2(oldfd, newfd);
}

// Linux: fcntl(fd, cmd, arg). v0 supports:
//   F_DUPFD (0)      — dup the fd, returning a slot >= arg.
//   F_GETFD (1)      — returns 0 (no per-fd flags stored).
//   F_SETFD (2)      — accepts + returns 0.
//   F_GETFL (3)      — returns O_RDWR (2) for any live fd.
//   F_SETFL (4)      — accepts + returns 0.
// Everything else returns -EINVAL.
i64 DoFcntl(u64 fd, u64 cmd, u64 arg)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    switch (cmd)
    {
    case 0: // F_DUPFD
    {
        const u32 start = (arg < 3) ? 3 : (arg >= 16 ? 16 : static_cast<u32>(arg));
        for (u32 i = start; i < 16; ++i)
        {
            if (p->linux_fds[i].state == 0)
            {
                CopyFdSlot(p->linux_fds[fd], p->linux_fds[i]);
                return static_cast<i64>(i);
            }
        }
        return kEMFILE;
    }
    case 1: // F_GETFD
        return 0;
    case 2: // F_SETFD
        return 0;
    case 3:       // F_GETFL
        return 2; // O_RDWR
    case 4:       // F_SETFL
        return 0;
    default:
        return kEINVAL;
    }
}

} // namespace duetos::subsystems::linux::internal
