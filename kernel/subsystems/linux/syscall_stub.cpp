/*
 * DuetOS — Linux ABI: child-reaping + page-cache-hint +
 * compat/tracing/mount stub handlers.
 *
 * Sibling TU of syscall.cpp. The subsystems this file used to
 * stub with -ENOSYS now have real homes elsewhere:
 *   - pipe / pipe2, eventfd / eventfd2  → syscall_pipe.cpp
 *   - timerfd_* / signalfd / epoll_*    → syscall_async_io.cpp
 *   - inotify_*                         → inotify.cpp (real ring
 *                                         + watch table wired to
 *                                         fs::routing mutations)
 *
 * What still lives here:
 *   - wait4 / waitid        → real: atomically consume durable
 *                             parent-owned child relation rows;
 *                             -ECHILD is selector-specific and
 *                             blocking uses a sequence-aware SMP
 *                             predicate/enqueue handoff. See the
 *                             GAP notes on the handlers (no pgid
 *                             model, rusage zero-filled, no
 *                             stop/continue).
 *   - fadvise64 / readahead → 0 after fd validation (no readahead
 *                             engine, but a bad fd still sees
 *                             -EBADF).
 *   - compat / tracing / mount group: ptrace (cap-gated, engine
 *                             absent), syslog (canned banner),
 *                             vhangup, acct, mount / umount2,
 *                             sync / syncfs, link / symlink,
 *                             set_thread_area / get_thread_area,
 *                             ioprio_get / ioprio_set. Each
 *                             returns the spec-correct errno for
 *                             "v0 has no machinery for this" (see
 *                             the per-handler comments).
 */

#include "subsystems/linux/syscall_internal.h"

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

// wait4 / waitid atomically scan and consume parent-owned relation rows.
// fork reserves a Live row before scheduler publication; only the child's
// post-teardown Exited publication can make that same row waitable. Blocking
// snapshots the parent's monotonic event sequence under the relation lock,
// then the scheduler rechecks it while atomically enqueueing the caller.
//
// Sub-GAPs: process-group / session matching (pid == 0 / pid <= -1
// as group selectors) collapse to "any child" — no pgid model
// in v0. WCONTINUED / WUNTRACED ignored — no stop / continue
// state-machine. rusage is filled with zeros.
namespace
{

constexpr u32 kWNOHANG = 0x1;
constexpr i64 kWaitPidAny = -1;

i32 EncodeWStatus(const core::Process::LinuxChildExit& exit)
{
    if (exit.was_signaled)
        return static_cast<i32>(exit.exit_signal & 0x7F);  // WIFSIGNALED + WTERMSIG
    return static_cast<i32>((exit.exit_code & 0xFF) << 8); // WIFEXITED + WEXITSTATUS
}

} // namespace

i64 DoWait4(u64 pid, u64 user_status, u64 options, u64 user_rusage)
{
    // Linux rejects unknown options bits with -EINVAL. WUNTRACED (0x2)
    // and WCONTINUED (0x8) are recognised but unimplemented in v0 —
    // we accept them silently and fall back to the WNOHANG/blocking
    // semantics only — but unknown bits past 0xF are a caller error
    // that must surface so a misuse doesn't get swallowed.
    constexpr u32 kWUNTRACED = 0x2;
    constexpr u32 kWCONTINUED = 0x8;
    constexpr u64 kValidOptions = kWNOHANG | kWUNTRACED | kWCONTINUED;
    if ((options & ~kValidOptions) != 0)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kECHILD;
    const i64 target_pid = static_cast<i64>(pid);
    const bool nonblocking = (options & kWNOHANG) != 0;
    while (true)
    {
        core::Process::LinuxChildExit exit{};
        u64 observed_sequence = 0;
        const core::LinuxChildWaitResult wait_result =
            core::ProcessPollLinuxChild(p, target_pid, &exit, &observed_sequence);
        if (wait_result != core::LinuxChildWaitResult::Exited)
        {
            // ECHILD is derived from the exact registered selector, not task
            // counts. waitpid(specific_pid) therefore rejects a nonexistent
            // child even while an unrelated child remains Live.
            if (wait_result == core::LinuxChildWaitResult::NoMatchingChild)
                return kECHILD;
            if (nonblocking)
                return 0;

            // The sequence recheck and scheduler enqueue share one
            // g_sched_lock hold. Whether this call blocks or observes a raced
            // producer, the loop must rescan the relation table.
            const sched::WaitQueueBlockResult block_result = core::ProcessWaitForLinuxChildEvent(p, observed_sequence);
            if (block_result == sched::WaitQueueBlockResult::Cancelled)
                return kEINTR;
            continue;
        }
        // GAP: status is consumed before user writeback. A faulting status or
        // rusage pointer returns EFAULT after reaping; add a claim/commit seam
        // if Linux-compatible retry-on-EFAULT behavior becomes necessary.
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
    // idtype: P_PID = 1, P_PGID = 2, P_ALL = 0. v0 collapses P_PGID
    // to "any child" because there is no pgid model, while P_PID remains
    // an exact positive-PID selector. WNOHANG is honoured.
    constexpr u64 kPAll = 0;
    constexpr u64 kPPid = 1;
    constexpr u64 kPPgid = 2;
    constexpr u64 kMaxSignedPid = 0x7FFFFFFFFFFFFFFFull;
    constexpr u64 kWExited = 0x4;
    constexpr u64 kSupportedOptions = kWNOHANG | kWExited;
    if (idtype != kPAll && idtype != kPPid && idtype != kPPgid)
        return kEINVAL;
    if (idtype == kPPid && (id == 0 || id > kMaxSignedPid))
        return kEINVAL;
    // Only exit events exist today. Requiring WEXITED prevents WSTOPPED- or
    // WCONTINUED-only calls from consuming an unrelated terminal row, while
    // the supported mask rejects WNOWAIT until poll has a non-consuming mode.
    if ((options & kWExited) == 0 || (options & ~kSupportedOptions) != 0)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kECHILD;
    const i64 target_pid = (idtype == kPPid) ? static_cast<i64>(id) : kWaitPidAny;
    const bool nonblocking = (options & kWNOHANG) != 0;
    while (true)
    {
        core::Process::LinuxChildExit exit{};
        u64 observed_sequence = 0;
        const core::LinuxChildWaitResult wait_result =
            core::ProcessPollLinuxChild(p, target_pid, &exit, &observed_sequence);
        if (wait_result != core::LinuxChildWaitResult::Exited)
        {
            if (wait_result == core::LinuxChildWaitResult::NoMatchingChild)
                return kECHILD;
            if (nonblocking)
            {
                if (user_info != 0)
                {
                    u8 zero[128];
                    for (u32 i = 0; i < sizeof(zero); ++i)
                        zero[i] = 0;
                    // waitid(WNOHANG) zeroes *infop to indicate "no
                    // children waiting". A faulting writeback violates
                    // the contract — the caller would read uninitialised
                    // siginfo_t and interpret it as a real child status.
                    if (!mm::CopyToUser(reinterpret_cast<void*>(user_info), zero, sizeof(zero)))
                        return kEFAULT;
                }
                return 0;
            }
            const sched::WaitQueueBlockResult block_result = core::ProcessWaitForLinuxChildEvent(p, observed_sequence);
            if (block_result == sched::WaitQueueBlockResult::Cancelled)
                return kEINTR;
            continue;
        }
        // GAP: as in wait4, the terminal row is consumed before user
        // writeback, so EFAULT cannot currently be retried.
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
            info.si_status =
                exit.was_signaled ? static_cast<i32>(exit.exit_signal & 0x7F) : static_cast<i32>(exit.exit_code & 0xFF);
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
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    core::LinuxFdAcquiredRelease(&acquired);
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
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    core::LinuxFdAcquiredRelease(&acquired);
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
    if (proc == nullptr || !core::ProcessHasCap(proc, core::kCapDebug))
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
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    fd = util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    core::LinuxFdAcquiredRelease(&acquired);
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
