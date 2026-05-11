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

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "util/nospec.h"

namespace duetos::subsystems::linux::internal
{

// pipe / pipe2: no pipe machinery yet — return -ENFILE so musl's
// "create my CLOEXEC pipe pair" probe at startup falls back
// gracefully. -ENOSYS would also work but Linux returns -ENFILE
// when the system pipe-fd table is exhausted, which is a closer
// fit for "we don't have any pipes to give you."
// DoPipe / DoPipe2 moved to syscall_pipe.cpp.

// wait4 / waitid: drain the per-process linux_child_exits queue.
// fork() now sets child->linux_parent_pid = parent->pid; when a
// child Process hits ProcessRelease's last-ref drop, it pushes a
// LinuxChildExit{pid, exit_code, exit_signal} onto the parent's
// queue and wakes linux_wait_wq. This handler scans the queue
// for a match against `pid` (or any child if pid <= 0), drains the
// matching entry, encodes the wait-status word the same shape musl
// expects (WIFEXITED + 8-bit exit code), and returns the child PID.
//
// Sub-GAPs: process-group / session matching (pid == 0 / pid <= -1
// as group selectors) collapse to "any child" — no pgid model
// in v0. WCONTINUED / WUNTRACED ignored — no stop / continue
// state-machine. rusage is filled with zeros.
namespace
{

constexpr u32 kWNOHANG = 0x1;
constexpr i64 kWaitPidAny = -1;

// Return queue index of the matching entry, or -1 if none.
// `target_pid > 0` matches that exact pid; <= 0 matches any.
i32 FindChildExitMatchLocked(core::Process* p, i64 target_pid)
{
    for (u64 i = 0; i < p->linux_child_exit_count; ++i)
    {
        if (target_pid <= 0 || static_cast<i64>(p->linux_child_exits[i].pid) == target_pid)
            return static_cast<i32>(i);
    }
    return -1;
}

void DrainChildExitLocked(core::Process* p, u32 idx, core::Process::LinuxChildExit& out)
{
    out = p->linux_child_exits[idx];
    // Compact: shift the tail down so the queue stays dense.
    for (u64 i = idx + 1; i < p->linux_child_exit_count; ++i)
        p->linux_child_exits[i - 1] = p->linux_child_exits[i];
    --p->linux_child_exit_count;
}

i32 EncodeWStatus(const core::Process::LinuxChildExit& exit)
{
    if (exit.was_signaled)
        return static_cast<i32>(exit.exit_signal & 0x7F);  // WIFSIGNALED + WTERMSIG
    return static_cast<i32>((exit.exit_code & 0xFF) << 8); // WIFEXITED + WEXITSTATUS
}

} // namespace

i64 DoWait4(u64 pid, u64 user_status, u64 options, u64 user_rusage)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kECHILD;
    const i64 target_pid = static_cast<i64>(pid);
    const bool nonblocking = (options & kWNOHANG) != 0;
    while (true)
    {
        arch::Cli();
        i32 found = FindChildExitMatchLocked(p, target_pid);
        if (found < 0)
        {
            // POSIX rule: if the caller has NO children at all
            // (no live ones AND no zombies queued), wait4 returns
            // -ECHILD immediately, regardless of WNOHANG. The
            // earlier "block until something registers" was a
            // bug — it deadlocked single-process exercisers
            // (synfull's wait4 probe) waiting for a child that
            // would never exist.
            arch::Sti();
            const u64 live_children = sched::SchedCountChildrenOfPid(p->pid);
            if (live_children == 0)
                return kECHILD;
            arch::Cli();
            // Children exist but none have exited. WNOHANG returns
            // 0 (no exit available); blocking parks on the wait
            // queue.
            if (nonblocking)
            {
                arch::Sti();
                return 0;
            }
            sched::WaitQueueBlock(&p->linux_wait_wq);
            continue;
        }
        core::Process::LinuxChildExit exit;
        DrainChildExitLocked(p, static_cast<u32>(found), exit);
        arch::Sti();
        if (user_status != 0)
        {
            const i32 wstatus = EncodeWStatus(exit);
            if (!mm::CopyToUser(reinterpret_cast<void*>(user_status), &wstatus, sizeof(wstatus)))
                return kEFAULT;
        }
        if (user_rusage != 0)
        {
            // struct rusage is 144 bytes; zero-fill is honest given
            // the v0 absence of per-process accounting.
            u8 zero[144];
            for (u32 i = 0; i < sizeof(zero); ++i)
                zero[i] = 0;
            if (!mm::CopyToUser(reinterpret_cast<void*>(user_rusage), zero, sizeof(zero)))
                return kEFAULT;
        }
        arch::SerialWrite("[linux/wait4] reaped pid=");
        arch::SerialWriteHex(exit.pid);
        arch::SerialWrite(" code=");
        arch::SerialWriteHex(exit.exit_code);
        arch::SerialWrite("\n");
        return static_cast<i64>(exit.pid);
    }
}

i64 DoWaitid(u64 idtype, u64 id, u64 user_info, u64 options, u64 user_rusage)
{
    // idtype: P_PID = 1, P_PGID = 2, P_ALL = 0. v0 collapses every
    // selector to "match this child's pid" (P_PID) or "any child"
    // (others) — no pgid model. WNOHANG honoured.
    constexpr u64 kPPid = 1;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kECHILD;
    const i64 target_pid = (idtype == kPPid) ? static_cast<i64>(id) : kWaitPidAny;
    const bool nonblocking = (options & kWNOHANG) != 0;
    while (true)
    {
        arch::Cli();
        i32 found = FindChildExitMatchLocked(p, target_pid);
        if (found < 0)
        {
            // POSIX rule (mirrored from DoWait4 above): no
            // children at all -> -ECHILD immediately, regardless
            // of WNOHANG. Without this, a single-process exerciser
            // calling waitid blocks forever on linux_wait_wq for
            // a child that will never register.
            arch::Sti();
            const u64 live_children = sched::SchedCountChildrenOfPid(p->pid);
            if (live_children == 0)
                return kECHILD;
            arch::Cli();
            if (nonblocking)
            {
                arch::Sti();
                if (user_info != 0)
                {
                    u8 zero[128];
                    for (u32 i = 0; i < sizeof(zero); ++i)
                        zero[i] = 0;
                    (void)mm::CopyToUser(reinterpret_cast<void*>(user_info), zero, sizeof(zero));
                }
                return 0;
            }
            sched::WaitQueueBlock(&p->linux_wait_wq);
            continue;
        }
        core::Process::LinuxChildExit exit;
        DrainChildExitLocked(p, static_cast<u32>(found), exit);
        arch::Sti();
        if (user_info != 0)
        {
            // struct siginfo_t — first 32 bytes carry si_signo /
            // si_errno / si_code / si_pid / si_uid / si_status / etc.
            // Encode the minimum musl reads: si_signo = SIGCHLD (17),
            // si_pid = exit.pid, si_status = exit_code.
            struct __attribute__((packed))
            {
                i32 si_signo;
                i32 si_errno;
                i32 si_code;
                i32 _pad0;
                u32 si_pid;
                u32 si_uid;
                i32 si_status;
                u8 _pad1[100];
            } info{};
            info.si_signo = 17; // SIGCHLD
            info.si_pid = static_cast<u32>(exit.pid);
            info.si_status = static_cast<i32>(exit.exit_code & 0xFF);
            info.si_code = exit.was_signaled ? 2 /*CLD_KILLED*/ : 1 /*CLD_EXITED*/;
            if (!mm::CopyToUser(reinterpret_cast<void*>(user_info), &info, sizeof(info)))
                return kEFAULT;
        }
        if (user_rusage != 0)
        {
            u8 zero[144];
            for (u32 i = 0; i < sizeof(zero); ++i)
                zero[i] = 0;
            if (!mm::CopyToUser(reinterpret_cast<void*>(user_rusage), zero, sizeof(zero)))
                return kEFAULT;
        }
        return 0; // waitid returns 0 on success (pid is in si_pid)
    }
}

// eventfd / eventfd2 moved to syscall_pipe.cpp.
// timerfd_create / timerfd_settime / timerfd_gettime / signalfd
// moved to syscall_async_io.cpp — backed by real expirations
// counters, scheduler-tick conversions, and per-instance wait
// queues. signalfd is a slot-only facade in v0 (no signal-delivery
// engine; reads return -EAGAIN per the GAP).

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
    if (p == nullptr || fd >= 16)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
    if (p->linux_fds[fd].state == 0)
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
    if (p == nullptr || fd >= 16)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    return 0;
}

// epoll moved to syscall_async_io.cpp.
// inotify moved to inotify.cpp — real ring + watch table + FS-
// mutation publish-subscribe through fs::routing.

// ---------------------------------------------------------------
// Compat / tracing / mount / link / rename stub group.
// ---------------------------------------------------------------

// ptrace(request, pid, addr, data): process tracing. v0 cap-
// gates on kCapDebug — same gate that protects cross-AS VM
// access. Without the cap, return -EPERM (the "tracing not
// permitted" answer Linux gives unprivileged callers). With
// the cap, requests that would do real work return -ENOSYS
// because the ptrace state machine itself doesn't exist;
// callers needing cross-process introspection use the
// kernel-side SYS_PROCESS_VM_READ / WRITE / SYS_THREAD_GET /
// SET_CONTEXT directly via the native ABI today.
i64 DoPtrace(u64 request, u64 pid, u64 addr, u64 data)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr || !core::CapSetHas(proc->caps, core::kCapDebug))
    {
        core::RecordSandboxDenial(core::kCapDebug);
        return kEPERM;
    }
    (void)request;
    (void)pid;
    (void)addr;
    (void)data;
    // Cap-cleared callers reach the real engine, which doesn't
    // exist yet — return -ENOSYS so the caller can distinguish
    // "you're not allowed" (-EPERM, no cap) from "kernel doesn't
    // have it" (-ENOSYS).
    return kENOSYS;
}

// syslog(type, bufp, len): kernel log read/control. v0 has no
// user-readable klog ring (kernel log lives on COM1 only), so:
//   - SYSLOG_ACTION_READ_ALL (3): writes a canned single-line
//     banner so a `dmesg` shaped probe gets non-empty output.
//   - SYSLOG_ACTION_READ_CLEAR (4): same as READ_ALL.
//   - SYSLOG_ACTION_SIZE_BUFFER (10): returns the banner len.
//   - SYSLOG_ACTION_SIZE_UNREAD (9): returns 0 (already drained).
//   - everything else: 0 (success no-op — close, open, console
//     enable/disable, set-loglevel; all are nominal on v0).
i64 DoSyslog(u64 type, u64 bufp, u64 len)
{
    static const char k_banner[] = "<6>DuetOS klog: serial-only on COM1; user-readable ring TBD\n";
    constexpr u64 kBannerLen = sizeof(k_banner) - 1;
    constexpr u64 kSyslogReadAll = 3;
    constexpr u64 kSyslogReadClear = 4;
    constexpr u64 kSyslogSizeUnread = 9;
    constexpr u64 kSyslogSizeBuffer = 10;
    if (type == kSyslogReadAll || type == kSyslogReadClear)
    {
        if (bufp == 0)
            return kEFAULT;
        const u64 to_copy = (len < kBannerLen) ? len : kBannerLen;
        if (!mm::CopyToUser(reinterpret_cast<void*>(bufp), k_banner, to_copy))
            return kEFAULT;
        return static_cast<i64>(to_copy);
    }
    if (type == kSyslogSizeBuffer)
        return static_cast<i64>(kBannerLen);
    if (type == kSyslogSizeUnread)
        return 0;
    return 0;
}

// vhangup: revoke the controlling terminal. Linux requires
// CAP_SYS_TTY_CONFIG; an unprivileged caller gets -EPERM. We
// don't model that capability so unconditional -EPERM matches
// the user-visible behaviour of an unprivileged Linux process.
i64 DoVhangup()
{
    return kEPERM;
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

// DoRename moved to syscall_fs_mut.cpp (now wires through to
// fat32 Fat32RenameAtPath via the §11.9 mutation primitives).
//
// link / symlink: FAT32 has no hardlink concept and v0 has no
// symlink storage. -EOPNOTSUPP is the spec-correct errno when
// the FS doesn't support the operation (POSIX EPERM is also
// allowed; we pick the more specific EOPNOTSUPP so glibc's
// "fall back to copy-then-rename" path activates instead of
// the "you're not allowed" error message).
i64 DoLink(u64 old_path, u64 new_path)
{
    (void)old_path;
    (void)new_path;
    return kEOPNOTSUPP;
}
i64 DoSymlink(u64 target, u64 linkpath)
{
    (void)target;
    (void)linkpath;
    return kEOPNOTSUPP;
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
