/*
 * DuetOS — Linux ABI: file-descriptor handlers.
 *
 * Sibling TU of syscall.cpp. Houses dup / dup2 / dup3 / fcntl.
 * dup / dup2 / dup3 / F_DUPFD / F_DUPFD_CLOEXEC route through
 * `LinuxFdDup` so a per-fd KFile sidecar (when present) is
 * shared via `HandleTableDuplicate` — both fds hold one ref to
 * the underlying pool, and the per-pool release callback fires
 * only when both close. Pre-migration v0 dup() leaked the
 * shared pool ref; the helper closes that gap.
 *
 * F_SETFD / FD_CLOEXEC honour `LinuxFdSetCloexec`; F_GETFD
 * reads it via `LinuxFdGetCloexec`. F_DUPFD_CLOEXEC stamps the
 * cloexec bit on the fresh fd. The `LinuxFdCloseOnExec` helper
 * walks the fd table at exec-time and drops every cloexec slot
 * — wired in execve when that handler lands; today exists for
 * the boot-time self-test.
 */

#include "subsystems/linux/syscall_internal.h"

#include "log/klog.h"
#include "proc/process.h"
#include "util/nospec.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// O_CLOEXEC bit value matching musl + glibc. Same constant as
// the open() / pipe2() / dup3() flag bit and the per-create
// CLOEXEC flag for eventfd / timerfd / signalfd / inotify /
// memfd / socket. Centralised here so the dup3 / F_DUPFD_CLOEXEC
// arms agree on the encoding.
constexpr u64 kOCloexec = 0x80000;

// FD_CLOEXEC argument bit for fcntl(F_SETFD, ...). Linux defines
// FD_CLOEXEC = 1 (a separate value space from O_CLOEXEC).
constexpr u64 kFdCloexec = 1;

} // namespace

// Linux: dup(fd). Allocate the lowest unused slot ≥ 3, share
// the source fd's KFile via HandleTableDuplicate, and copy the
// per-slot snapshot fields. Returns the new fd or -EMFILE if
// full / -EBADF if oldfd isn't open.
i64 DoDup(u64 fd)
{
    KLOG_TRACE_V("linux/fd", "DoDup: fd", fd);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
    {
        KLOG_WARN_V("linux/fd", "DoDup: EBADF (fd out of range or no Process)", fd);
        return kEBADF;
    }
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
    if (p->linux_fds[fd].state == 0)
    {
        KLOG_WARN_V("linux/fd", "DoDup: EBADF (fd not open)", fd);
        return kEBADF;
    }
    const i32 newfd = core::LinuxFdAllocLowest(p, 3);
    if (newfd < 0)
    {
        KLOG_WARN("linux/fd", "DoDup: EMFILE (no free slot >= 3)");
        return kEMFILE;
    }
    if (!core::LinuxFdDup(p, static_cast<u32>(fd), static_cast<u32>(newfd)))
    {
        KLOG_WARN_V("linux/fd", "DoDup: HandleTable full -> EMFILE", static_cast<u64>(newfd));
        return kEMFILE;
    }
    // Linux semantics: dup() always produces a non-cloexec fd.
    // LinuxFdDup already strips the bit on the destination.
    KLOG_DEBUG_V("linux/fd", "DoDup: granted new fd", static_cast<u64>(newfd));
    return static_cast<i64>(newfd);
}

// Linux: dup2(oldfd, newfd). If newfd == oldfd, returns newfd.
// Else closes newfd if in use, then duplicates the fd (KFile
// shared via HandleTableDuplicate when present). Returns newfd.
i64 DoDup2(u64 oldfd, u64 newfd)
{
    KLOG_TRACE_V("linux/fd", "DoDup2: oldfd", oldfd);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || oldfd >= 16 || newfd >= 16)
    {
        KLOG_WARN_2V("linux/fd", "DoDup2: EBADF", "oldfd", oldfd, "newfd", newfd);
        return kEBADF;
    }
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    oldfd = util::MaskedIndex(oldfd, 16);
    newfd = util::MaskedIndex(newfd, 16);
    if (p->linux_fds[oldfd].state == 0)
    {
        KLOG_WARN_V("linux/fd", "DoDup2: EBADF (oldfd not open)", oldfd);
        return kEBADF;
    }
    if (oldfd == newfd)
    {
        KLOG_DEBUG_V("linux/fd", "DoDup2: oldfd == newfd, no-op", newfd);
        return static_cast<i64>(newfd);
    }
    // newfd < 3 (stdin/stdout/stderr) — dup2 onto a tty slot is
    // legal in Linux (shell redirection pattern). LinuxFdDup
    // closes any existing slot at newfd first via LinuxFdClose,
    // which also strips the reserved-tty state cleanly.
    if (!core::LinuxFdDup(p, static_cast<u32>(oldfd), static_cast<u32>(newfd)))
    {
        KLOG_WARN_2V("linux/fd", "DoDup2: HandleTable full -> EMFILE", "oldfd", oldfd, "newfd", newfd);
        return kEMFILE;
    }
    KLOG_INFO_2V("linux/fd", "DoDup2: ok", "oldfd", oldfd, "newfd", newfd);
    return static_cast<i64>(newfd);
}

// Linux: dup3(oldfd, newfd, flags). Same as dup2 but requires
// oldfd != newfd (else -EINVAL) and accepts O_CLOEXEC. We honour
// O_CLOEXEC by stamping `kLinuxFdFlagCloexec` on the destination
// after the dup completes — closes the pre-migration sub-GAP.
i64 DoDup3(u64 oldfd, u64 newfd, u64 flags)
{
    if (oldfd == newfd)
        return kEINVAL;
    if ((flags & ~kOCloexec) != 0)
        return kEINVAL;
    const i64 r = DoDup2(oldfd, newfd);
    if (r < 0)
        return r;
    if ((flags & kOCloexec) != 0)
    {
        core::LinuxFdSetCloexec(core::CurrentProcess(), static_cast<u32>(newfd), true);
    }
    return r;
}

// Linux: fcntl(fd, cmd, arg). v0 supports:
//   F_DUPFD (0)             — dup the fd, returning a slot >= arg.
//   F_GETFD (1)             — returns FD_CLOEXEC bit if set, else 0.
//   F_SETFD (2)             — write FD_CLOEXEC bit; other bits ignored.
//   F_GETFL (3)             — returns O_RDWR (2) for any live fd.
//   F_SETFL (4)             — accepts + returns 0.
//   F_DUPFD_CLOEXEC (1030)  — F_DUPFD + stamp FD_CLOEXEC on dst.
// Other cmds either accept-as-no-op or return -EINVAL per Linux.
i64 DoFcntl(u64 fd, u64 cmd, u64 arg)
{
    KLOG_TRACE_V("linux/fd", "DoFcntl: fd", fd);
    KLOG_DEBUG_V("linux/fd", "DoFcntl: cmd", cmd);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
    {
        KLOG_WARN_V("linux/fd", "DoFcntl: EBADF (out-of-range fd or no Process)", fd);
        return kEBADF;
    }
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
    if (p->linux_fds[fd].state == 0)
    {
        KLOG_WARN_V("linux/fd", "DoFcntl: EBADF (fd not open)", fd);
        return kEBADF;
    }
    switch (cmd)
    {
    case 0: // F_DUPFD
    {
        const u32 lo = (arg < 3) ? 3u : static_cast<u32>(arg);
        const i32 newfd = core::LinuxFdAllocLowest(p, lo);
        if (newfd < 0)
            return kEMFILE;
        if (!core::LinuxFdDup(p, static_cast<u32>(fd), static_cast<u32>(newfd)))
            return kEMFILE;
        return static_cast<i64>(newfd);
    }
    case 1: // F_GETFD
        return core::LinuxFdGetCloexec(p, static_cast<u32>(fd)) ? kFdCloexec : 0;
    case 2: // F_SETFD
        core::LinuxFdSetCloexec(p, static_cast<u32>(fd), (arg & kFdCloexec) != 0);
        return 0;
    case 3:       // F_GETFL
        return 2; // O_RDWR
    case 4:       // F_SETFL
        return 0;
    case 1030: // F_DUPFD_CLOEXEC — F_DUPFD + stamp cloexec on dst.
    {
        const u32 lo = (arg < 3) ? 3u : static_cast<u32>(arg);
        const i32 newfd = core::LinuxFdAllocLowest(p, lo);
        if (newfd < 0)
            return kEMFILE;
        if (!core::LinuxFdDup(p, static_cast<u32>(fd), static_cast<u32>(newfd)))
            return kEMFILE;
        core::LinuxFdSetCloexec(p, static_cast<u32>(newfd), true);
        return static_cast<i64>(newfd);
    }
    case 5: // F_GETLK — record-locking query. v0 has no
        // record locks; report "no conflict" (l_type
        // F_UNLCK==2) by leaving the user-supplied
        // struct alone. Return 0 = success.
        return 0;
    case 6: // F_SETLK — try to acquire lock without blocking.
        return 0;
    case 7: // F_SETLKW — acquire (blocking). v0 doesn't block.
        return 0;
    case 8: // F_SETOWN — async-IO recipient. Accepted no-op.
        return 0;
    case 9: // F_GETOWN
        return 0;
    case 10: // F_SETSIG — async-IO signum. Accepted no-op.
        return 0;
    case 11: // F_GETSIG
        return 0;
    case 1024: // F_SETLEASE — file lease. We don't lease; -EINVAL
        return kEINVAL;
    case 1025:    // F_GETLEASE
        return 2; // F_UNLCK — no lease held
    case 1026:    // F_NOTIFY — directory notification (deprecated;
                  // inotify is the modern replacement). Accept as
                  // no-op success.
        return 0;
    case 1031: // F_SETPIPE_SZ — pipe buffer resize. Our pipes
               // are fixed-size; honour the request as no-op.
        return 0;
    case 1032: // F_GETPIPE_SZ — return our pipe capacity (4 KiB).
        return 4096;
    case 1033: // F_ADD_SEALS — memfd seals. v0 doesn't enforce.
        return 0;
    case 1034: // F_GET_SEALS
        return 0;
    default:
        KLOG_WARN_V("linux/fd", "DoFcntl: EINVAL unsupported cmd", cmd);
        return kEINVAL;
    }
}

} // namespace duetos::subsystems::linux::internal
