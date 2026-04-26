/*
 * DuetOS — Linux ABI: stub handlers.
 *
 * Sibling TU of syscall.cpp. Houses the entry points for
 * subsystems v0 has no machinery for yet: pipes, fork/wait,
 * eventfd / timerfd / signalfd, epoll, inotify, plus the
 * page-cache-hint pair (fadvise64 / readahead).
 *
 * Each returns the canonical Linux errno for "we don't have that
 * subsystem":
 *   - pipe / pipe2          → -ENFILE (no pipe machinery)
 *   - wait4 / waitid        → -ECHILD (no fork, no children)
 *   - eventfd / timerfd_*   → -ENOSYS
 *   - signalfd / signalfd4  → -ENOSYS
 *   - epoll_*               → -ENOSYS
 *   - inotify_*             → -ENOSYS
 *   - fadvise64 / readahead → 0 after fd validation (no readahead
 *                             engine, but the caller still expects
 *                             -EBADF for a bad fd).
 *
 * Other stub families (ptrace / syslog / mount / sync / rename /
 * link / symlink / set_thread_area / ioprio_*) live in syscall.cpp
 * for now — they're interleaved with non-stub handlers and were
 * left in place to keep this slice surgical.
 */

#include "syscall_internal.h"

#include "../../core/process.h"

namespace duetos::subsystems::linux::internal
{

// pipe / pipe2: no pipe machinery yet — return -ENFILE so musl's
// "create my CLOEXEC pipe pair" probe at startup falls back
// gracefully. -ENOSYS would also work but Linux returns -ENFILE
// when the system pipe-fd table is exhausted, which is a closer
// fit for "we don't have any pipes to give you."
i64 DoPipe(u64 user_fds)
{
    (void)user_fds;
    return kENFILE;
}
i64 DoPipe2(u64 user_fds, u64 flags)
{
    (void)user_fds;
    (void)flags;
    return kENFILE;
}

// wait4(pid, status, options, rusage) / waitid(idtype, id, info,
// options, rusage). v0 has no fork → no children → -ECHILD is the
// canonical "you have no children to wait for" return.
i64 DoWait4(u64 pid, u64 user_status, u64 options, u64 user_rusage)
{
    (void)pid;
    (void)user_status;
    (void)options;
    (void)user_rusage;
    return kECHILD;
}
i64 DoWaitid(u64 idtype, u64 id, u64 user_info, u64 options, u64 user_rusage)
{
    (void)idtype;
    (void)id;
    (void)user_info;
    (void)options;
    (void)user_rusage;
    return kECHILD;
}

// eventfd / eventfd2 / timerfd_* / signalfd / signalfd4:
// no eventfd / timerfd / signalfd machinery yet. -ENOSYS so
// libraries fall back to their pipe-based polyfill.
i64 DoEventfd(u64 initval, u64 flags)
{
    (void)initval;
    (void)flags;
    return kENOSYS;
}
i64 DoTimerfdCreate(u64 clockid, u64 flags)
{
    (void)clockid;
    (void)flags;
    return kENOSYS;
}
i64 DoTimerfdSettime(u64 fd, u64 flags, u64 user_new, u64 user_old)
{
    (void)fd;
    (void)flags;
    (void)user_new;
    (void)user_old;
    return kENOSYS;
}
i64 DoTimerfdGettime(u64 fd, u64 user_curr)
{
    (void)fd;
    (void)user_curr;
    return kENOSYS;
}
i64 DoSignalfd(u64 fd, u64 user_mask, u64 sigsetsize, u64 flags)
{
    (void)fd;
    (void)user_mask;
    (void)sigsetsize;
    (void)flags;
    return kENOSYS;
}

// fadvise64(fd, offset, len, advice): readahead / dontneed hint.
// No readahead engine — accept the call as a no-op so callers
// that fadvise their input files at startup don't bail. Validate
// the fd so a bogus call sees -EBADF.
i64 DoFadvise64(u64 fd, u64 offset, u64 len, u64 advice)
{
    (void)offset;
    (void)len;
    (void)advice;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state == 0)
        return kEBADF;
    return 0;
}

// readahead(fd, offset, count): explicitly populate the page
// cache for a file extent. No page cache → no work to do →
// validate the fd and return 0.
i64 DoReadahead(u64 fd, u64 offset, u64 count)
{
    (void)offset;
    (void)count;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state == 0)
        return kEBADF;
    return 0;
}

// epoll / inotify: no event-poll or filesystem-watch machinery.
// -ENOSYS lets autoconf-y libraries detect the gap and fall back.
i64 DoEpollCreate(u64 size)
{
    (void)size;
    return kENOSYS;
}
i64 DoEpollCreate1(u64 flags)
{
    (void)flags;
    return kENOSYS;
}
i64 DoEpollCtl(u64 epfd, u64 op, u64 fd, u64 event)
{
    (void)epfd;
    (void)op;
    (void)fd;
    (void)event;
    return kENOSYS;
}
i64 DoEpollWait(u64 epfd, u64 events, u64 maxevents, u64 timeout_ms)
{
    (void)epfd;
    (void)events;
    (void)maxevents;
    (void)timeout_ms;
    return kENOSYS;
}
i64 DoEpollPwait(u64 epfd, u64 events, u64 maxevents, u64 timeout_ms, u64 sigmask, u64 sigsetsize)
{
    (void)sigmask;
    (void)sigsetsize;
    return DoEpollWait(epfd, events, maxevents, timeout_ms);
}
i64 DoInotifyInit()
{
    return kENOSYS;
}
i64 DoInotifyInit1(u64 flags)
{
    (void)flags;
    return kENOSYS;
}

// ---------------------------------------------------------------
// Compat / tracing / mount / link / rename stub group.
// ---------------------------------------------------------------

// ptrace(request, pid, addr, data): process tracing. v0 has no
// ptrace machinery. -EPERM is the "tracing not permitted" return
// Linux gives to unprivileged callers.
i64 DoPtrace(u64 request, u64 pid, u64 addr, u64 data)
{
    (void)request;
    (void)pid;
    (void)addr;
    (void)data;
    return kEPERM;
}

// syslog(type, bufp, len): kernel log read/control. Every type
// is a no-op success in v0 — kernel log lives on COM1, not in a
// user-readable ring buffer. Returns 0 for "nothing written".
i64 DoSyslog(u64 type, u64 bufp, u64 len)
{
    (void)type;
    (void)bufp;
    (void)len;
    return 0;
}

// vhangup: revoke the controlling terminal. No tty model — 0.
i64 DoVhangup()
{
    return 0;
}

// acct(filename): BSD process accounting. We do no accounting.
i64 DoAcct(u64 filename)
{
    (void)filename;
    return 0;
}

// mount(source, target, fstype, flags, data): mount a filesystem.
// v0 mounts FAT32 volume 0 implicitly at boot and does not expose
// a user-mode mount API. -EPERM is the appropriate return.
i64 DoMount(u64 source, u64 target, u64 fstype, u64 flags, u64 data)
{
    (void)source;
    (void)target;
    (void)fstype;
    (void)flags;
    (void)data;
    return kEPERM;
}
i64 DoUmount2(u64 target, u64 flags)
{
    (void)target;
    (void)flags;
    return kEPERM;
}

// sync / syncfs: flush cached writes to backing store. v0 FAT32
// writes are synchronous (no page cache), so there's nothing to
// flush.
i64 DoSync()
{
    return 0;
}
i64 DoSyncfs(u64 fd)
{
    (void)fd;
    return 0;
}

// rename(old, new) / link(old, new) / symlink(target, linkpath):
// no rename / link primitive in fat32 v0. -ENOSYS tells musl
// "this operation is not available on this kernel" — clearer
// than an -EPERM "you're not allowed" lie.
i64 DoRename(u64 old_path, u64 new_path)
{
    (void)old_path;
    (void)new_path;
    return kENOSYS;
}
i64 DoLink(u64 old_path, u64 new_path)
{
    (void)old_path;
    (void)new_path;
    return kENOSYS;
}
i64 DoSymlink(u64 target, u64 linkpath)
{
    (void)target;
    (void)linkpath;
    return kENOSYS;
}

// set_thread_area / get_thread_area: x86_32 LDT entry for TLS.
// 64-bit code uses arch_prctl(ARCH_SET_FS) instead. Reject cleanly.
i64 DoSetThreadArea(u64 u_info)
{
    (void)u_info;
    return kEINVAL;
}
i64 DoGetThreadArea(u64 u_info)
{
    (void)u_info;
    return kEINVAL;
}

// ioprio_get / ioprio_set: per-process I/O priority. Flat
// scheduler; accept + return 0 (the default "BE / nice=4" level).
i64 DoIoprioGet(u64 which, u64 who)
{
    (void)which;
    (void)who;
    return 0;
}
i64 DoIoprioSet(u64 which, u64 who, u64 ioprio)
{
    (void)which;
    (void)who;
    (void)ioprio;
    return 0;
}

} // namespace duetos::subsystems::linux::internal
