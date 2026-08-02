/*
 * DuetOS — Linux ABI: file-descriptor handlers.
 *
 * Sibling TU of syscall.cpp. Houses dup / dup2 / dup3 / fcntl.
 * dup / dup2 / dup3 / F_DUPFD / F_DUPFD_CLOEXEC route through
 * the failure-atomic Linux fd transaction core. A duplicate
 * retains the exact source KFile/OFD identity before publishing
 * the destination, and displaced cleanup runs after fd and
 * handle-table locks are gone.
 *
 * F_SETFD / FD_CLOEXEC use generation-checked acquired receipts,
 * and F_DUPFD_CLOEXEC stamps cloexec at publication. The
 * `LinuxFdCloseOnExec` helper
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

// Linux allows F_SETFL to change these open-file-description flags while
// preserving the access mode and immutable open-time status bits.
constexpr u32 kFSetFlMutableMask = 0x400 /* O_APPEND */ | 0x800 /* O_NONBLOCK */ | 0x2000 /* O_ASYNC */ |
                                   0x4000 /* O_DIRECT */ | 0x40000 /* O_NOATIME */;

} // namespace

// Linux: dup(fd). Atomically duplicate into the lowest unused slot
// >= 3. Returns the new fd or -EMFILE if full / -EBADF if oldfd
// isn't open.
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
    core::LinuxFdAcquired source{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &source))
    {
        KLOG_WARN_V("linux/fd", "DoDup: EBADF (fd not open)", fd);
        return kEBADF;
    }
    core::LinuxFdAcquiredRelease(&source);
    const i32 newfd = core::LinuxFdDuplicateLowest(p, static_cast<u32>(fd), 3, false);
    if (newfd < 0)
    {
        KLOG_WARN("linux/fd", "DoDup: EMFILE (no free slot >= 3)");
        return kEMFILE;
    }
    // Linux semantics: dup() always produces a non-cloexec fd.
    // LinuxFdDuplicateLowest strips the bit at publication.
    KLOG_DEBUG_V("linux/fd", "DoDup: granted new fd", static_cast<u64>(newfd));
    return static_cast<i64>(newfd);
}

// Linux: dup2(oldfd, newfd). If newfd == oldfd, returns newfd.
// Otherwise failure-atomically replaces newfd with the retained
// source identity and returns newfd.
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
    core::LinuxFdAcquired source{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(oldfd), 0, &source))
    {
        KLOG_WARN_V("linux/fd", "DoDup2: EBADF (oldfd not open)", oldfd);
        return kEBADF;
    }
    core::LinuxFdAcquiredRelease(&source);
    if (oldfd == newfd)
    {
        KLOG_DEBUG_V("linux/fd", "DoDup2: oldfd == newfd, no-op", newfd);
        return static_cast<i64>(newfd);
    }
    // newfd < 3 (stdin/stdout/stderr) is legal in Linux (shell
    // redirection). Exact import replaces the reserved tty row at
    // the same atomic publish point as any other destination.
    if (!core::LinuxFdDuplicateExact(p, static_cast<u32>(oldfd), static_cast<u32>(newfd), false))
    {
        KLOG_WARN_2V("linux/fd", "DoDup2: HandleTable full -> EMFILE", "oldfd", oldfd, "newfd", newfd);
        return kEMFILE;
    }
    KLOG_INFO_2V("linux/fd", "DoDup2: ok", "oldfd", oldfd, "newfd", newfd);
    return static_cast<i64>(newfd);
}

// Linux: dup3(oldfd, newfd, flags). Same as dup2 but requires
// oldfd != newfd (else -EINVAL) and accepts O_CLOEXEC. We honour
// O_CLOEXEC at the destination publication point.
i64 DoDup3(u64 oldfd, u64 newfd, u64 flags)
{
    if (oldfd == newfd)
        return kEINVAL;
    if ((flags & ~kOCloexec) != 0)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || oldfd >= 16 || newfd >= 16)
        return kEBADF;
    oldfd = util::MaskedIndex(oldfd, 16);
    newfd = util::MaskedIndex(newfd, 16);
    core::LinuxFdAcquired source{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(oldfd), 0, &source))
        return kEBADF;
    core::LinuxFdAcquiredRelease(&source);
    if (!core::LinuxFdDuplicateExact(p, static_cast<u32>(oldfd), static_cast<u32>(newfd), (flags & kOCloexec) != 0))
        return kEMFILE;
    return static_cast<i64>(newfd);
}

// Linux: fcntl(fd, cmd, arg). v0 supports:
//   F_DUPFD (0)             — dup the fd, returning a slot >= arg.
//   F_GETFD (1)             — returns FD_CLOEXEC bit if set, else 0.
//   F_SETFD (2)             — write FD_CLOEXEC bit; other bits ignored.
//   F_GETFL (3)             — returns shared OFD status flags.
//   F_SETFL (4)             — changes the mutable status-flag subset.
//   F_DUPFD_CLOEXEC (1030)  — F_DUPFD with atomic FD_CLOEXEC.
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
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
    {
        KLOG_WARN_V("linux/fd", "DoFcntl: EBADF (fd not open)", fd);
        return kEBADF;
    }
    const auto finish = [&acquired](i64 result)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    };
    switch (cmd)
    {
    case 0: // F_DUPFD
    {
        if (arg >= 16)
            return finish(kEINVAL);
        const u32 lo = (arg < 3) ? 3u : static_cast<u32>(arg);
        const i32 newfd = core::LinuxFdDuplicateLowest(p, static_cast<u32>(fd), lo, false);
        return finish(newfd < 0 ? kEMFILE : static_cast<i64>(newfd));
    }
    case 1: // F_GETFD
        return finish((acquired.snapshot.flags & core::Process::kLinuxFdFlagCloexec) != 0 ? kFdCloexec : 0);
    case 2: // F_SETFD
        return finish(
            core::LinuxFdSetCloexecAcquired(p, static_cast<u32>(fd), &acquired, (arg & kFdCloexec) != 0) ? 0 : kEBADF);
    case 3: // F_GETFL
    {
        // The three boot-time tty descriptors predate OFD publication. Keep
        // their historical O_RDWR answer; prepared descriptors use the
        // serialized shared-OFD path below.
        if (acquired.snapshot.ofd == 0)
            return finish(2); // O_RDWR
        core::LinuxFdIoGuard guard{};
        u32 status_flags = 0;
        if (!core::LinuxFdIoGuardEnter(&acquired, &guard))
            return finish(kEBADF);
        const bool got_flags = core::LinuxFdIoGuardGetStatusFlags(&guard, &status_flags);
        core::LinuxFdIoGuardExit(&guard);
        return finish(got_flags ? static_cast<i64>(status_flags) : kEBADF);
    }
    case 4: // F_SETFL
    {
        if (acquired.snapshot.ofd == 0)
            return finish(0);
        core::LinuxFdIoGuard guard{};
        u32 old_flags = 0;
        if (!core::LinuxFdIoGuardEnter(&acquired, &guard))
            return finish(kEBADF);
        bool updated = core::LinuxFdIoGuardGetStatusFlags(&guard, &old_flags);
        if (updated)
        {
            const u32 requested = static_cast<u32>(arg) & kFSetFlMutableMask;
            updated = core::LinuxFdIoGuardSetStatusFlags(&guard, (old_flags & ~kFSetFlMutableMask) | requested);
        }
        core::LinuxFdIoGuardExit(&guard);
        return finish(updated ? 0 : kEBADF);
    }
    case 1030: // F_DUPFD_CLOEXEC — F_DUPFD + stamp cloexec on dst.
    {
        if (arg >= 16)
            return finish(kEINVAL);
        const u32 lo = (arg < 3) ? 3u : static_cast<u32>(arg);
        const i32 newfd = core::LinuxFdDuplicateLowest(p, static_cast<u32>(fd), lo, true);
        return finish(newfd < 0 ? kEMFILE : static_cast<i64>(newfd));
    }
    case 5: // F_GETLK — record-locking query. v0 has no
        // record locks; report "no conflict" (l_type
        // F_UNLCK==2) by leaving the user-supplied
        // struct alone. Return 0 = success.
        return finish(0);
    case 6: // F_SETLK — try to acquire lock without blocking.
        return finish(0);
    case 7: // F_SETLKW — acquire (blocking). v0 doesn't block.
        return finish(0);
    case 8: // F_SETOWN — async-IO recipient. Accepted no-op.
        return finish(0);
    case 9: // F_GETOWN
        return finish(0);
    case 10: // F_SETSIG — async-IO signum. Accepted no-op.
        return finish(0);
    case 11: // F_GETSIG
        return finish(0);
    case 1024: // F_SETLEASE — file lease. We don't lease; -EINVAL
        return finish(kEINVAL);
    case 1025:            // F_GETLEASE
        return finish(2); // F_UNLCK — no lease held
    case 1026:            // F_NOTIFY — directory notification (deprecated;
                          // inotify is the modern replacement). Accept as
                          // no-op success.
        return finish(0);
    case 1031: // F_SETPIPE_SZ — pipe buffer resize. Our pipes
               // are fixed-size; honour the request as no-op.
        return finish(0);
    case 1032: // F_GETPIPE_SZ — return our pipe capacity (4 KiB).
        return finish(4096);
    case 1033: // F_ADD_SEALS — memfd seals. v0 doesn't enforce.
        return finish(0);
    case 1034: // F_GET_SEALS
        return finish(0);
    default:
        KLOG_WARN_V("linux/fd", "DoFcntl: EINVAL unsupported cmd", cmd);
        return finish(kEINVAL);
    }
}

} // namespace duetos::subsystems::linux::internal
