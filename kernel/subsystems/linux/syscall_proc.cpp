/*
 * DuetOS — Linux ABI: process-control handlers.
 *
 * Sibling TU of syscall.cpp. Houses exit / exit_group / getpid /
 * gettid / sched_yield / tgkill / kill / getppid / getpgid /
 * getsid / setpgid / getpgrp / setsid.
 *
 * v0 has no fork / no signals / no session model. exit_group is
 * the canonical teardown path (single-thread-per-process means
 * SYS_exit and SYS_exit_group share the same scheduler call);
 * tgkill / kill targeting self exits, anything else returns
 * -ESRCH; everything else is either getpid or a flat-namespace
 * no-op returning 0 (or 1 for getppid, init-like).
 */

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "diag/log_names.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

i64 DoExitGroup(u64 status)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    KLOG_INFO_V("linux/proc", "DoExitGroup: status", status);
    SerialWrite("[linux] exit_group status=");
    SerialWriteHex(status);
    SerialWrite("\n");
    // Stash the exit code on the Process so the eventual
    // ProcessRelease teardown can pass it to a waiting parent.
    // Linux encodes the 8-bit status in bits 8..15 of wstatus when
    // WIFEXITED is true; we keep the raw status here and let
    // wait4 do the encoding.
    if (core::Process* p = core::CurrentProcess(); p != nullptr)
    {
        p->linux_exit_code = static_cast<u32>(status & 0xFF);
        p->linux_was_signaled = false;
        p->linux_exit_signal = 0;
    }
    // Wake every pidfd poller before SchedExit transitions us
    // into TaskState::Dead. The waiter's predicate
    // (LinuxFdEpollReady on a state-12 fd) will see
    // SchedIsPidZombie === true on this exact wakeup, so the
    // first scheduled poll completes with EPOLLIN instead of
    // sleeping again.
    LinuxPidfdExitWake();
    sched::SchedExit();
    // sched::SchedExit is [[noreturn]]; this line is unreachable.
    return 0;
}

// Linux exit(status) has process-wide semantics for a single-thread
// process, which is exactly all we support in v0. Route it through
// exit_group so both numbers share the same teardown path.
i64 DoExit(u64 status)
{
    KLOG_INFO_V("linux/proc", "DoExit: status", status);
    return DoExitGroup(status);
}

// Linux getpid() returns the TGID — in our v0 single-thread-per-
// process model this is the Process pid (Process::pid, the same id
// SchedFindProcessByPid resolves against). Returning CurrentTaskId()
// here would hand back the scheduler task tid, which is a different
// counter; the immediate symptom was pidfd_open(getpid()) coming
// back -ESRCH because the tid never matched any Process->pid.
i64 DoGetPid()
{
    KLOG_TRACE("linux/proc", "DoGetPid: query");
    if (core::Process* p = core::CurrentProcess(); p != nullptr)
        return static_cast<i64>(p->pid);
    return static_cast<i64>(sched::CurrentTaskId());
}

// Linux: gettid returns the per-thread ID (kernel task tid). In a
// single-thread-per-process model getpid() == gettid() conceptually,
// but the underlying counters in DuetOS are distinct (Process::pid
// vs. Task::id), so keep this on CurrentTaskId().
i64 DoGetTid()
{
    KLOG_TRACE("linux/proc", "DoGetTid: query");
    return static_cast<i64>(sched::CurrentTaskId());
}

// Linux: sched_yield. Direct passthrough to the native scheduler.
i64 DoSchedYield()
{
    KLOG_TRACE("linux/proc", "DoSchedYield: voluntary preempt");
    sched::SchedYield();
    return 0;
}

// Linux: tgkill(tgid, tid, sig). Used by musl's abort() to send
// SIGABRT to itself. v0 has no signal delivery — if the target
// is self, just exit with an abort-ish status; any other tid
// returns -ESRCH.
// Linux: tgkill(tgid, tid, sig). v0 collapses to the per-process
// signal-delivery model — tid identifies the task whose owning
// Process is the delivery target. tgid is accepted but only
// validated at the per-task lookup; mismatches surface as -ESRCH.
i64 DoTgkill(u64 tgid, u64 tid, u64 sig)
{
    KLOG_INFO_2V("linux/proc", "DoTgkill", "tid", tid, "sig", sig);
    (void)tgid;
    if (sig == 0)
    {
        // Existence-probe form: verify the tid is alive.
        sched::Task* t = sched::SchedFindTaskByTid(tid);
        return (t != nullptr) ? 0 : kESRCH;
    }
    sched::Task* t = sched::SchedFindTaskByTid(tid);
    if (t == nullptr)
    {
        KLOG_WARN_V("linux/proc", "DoTgkill: ESRCH (tid not found)", tid);
        return kESRCH;
    }
    core::Process* target = sched::TaskProcess(t);
    if (target == nullptr)
    {
        KLOG_WARN_V("linux/proc", "DoTgkill: ESRCH (kernel-only task)", tid);
        return kESRCH; // kernel-only task — no Linux process to signal
    }
    return LinuxSignalDeliver(target, static_cast<u32>(sig));
}

// Linux: kill(pid, sig). pid > 0 → deliver to the matching process.
// pid == 0 → process group (collapsed to the caller's process in
// v0). pid == -1 → broadcast (rejected — too easy to misuse with
// no real process tree). pid < -1 → process group (-pid).
i64 DoKill(u64 pid, u64 sig)
{
    KLOG_INFO_2V("linux/proc", "DoKill", "pid", pid, "sig", sig);
    const i64 spid = static_cast<i64>(pid);
    if (sig == 0)
    {
        // Existence probe.
        if (spid <= 0)
            return 0;
        return (sched::SchedFindProcessByPid(static_cast<u64>(spid)) != nullptr) ? 0 : kESRCH;
    }
    core::Process* target = nullptr;
    if (spid > 0)
        target = sched::SchedFindProcessByPid(static_cast<u64>(spid));
    else if (spid == 0)
        target = core::CurrentProcess();
    else
    {
        KLOG_WARN_V("linux/proc", "DoKill: group/broadcast not supported, pid", pid);
        return kESRCH; // group / broadcast forms not supported in v0 (sub-GAP)
    }
    if (target == nullptr)
    {
        KLOG_WARN_V("linux/proc", "DoKill: ESRCH (target not found)", pid);
        return kESRCH;
    }
    return LinuxSignalDeliver(target, static_cast<u32>(sig));
}

// Linux: getppid / getpgid / getsid / setpgid. v0 has a flat
// process namespace with no session/pg model; return 1 (init-
// like) for ppid and 0 for everything else. setpgid accepts and
// is silently a no-op.
i64 DoGetPpid()
{
    return 1;
}
i64 DoGetPgid(u64 pid)
{
    // v0 has no session/pgid model. Linux convention: each
    // process's pgid defaults to its pid (single-process group).
    // Returning the calling process's pid for pid==0 (the
    // self-query convention) gives a sensible answer for any
    // glibc routine that does `setpgid(0, getpgid(0))`.
    if (pid == 0)
    {
        const auto* p = core::CurrentProcess();
        return (p != nullptr) ? static_cast<i64>(p->pid) : 0;
    }
    // pid != 0: lookup the target. v0 hasn't built a real
    // pgid table, so report pid itself (each process is its
    // own group leader). -ESRCH if pid doesn't exist.
    if (sched::SchedFindProcessByPid(pid) == nullptr)
        return kESRCH;
    return static_cast<i64>(pid);
}
i64 DoGetSid(u64 pid)
{
    // Same shape as getpgid — each process is its own session
    // leader in v0.
    if (pid == 0)
    {
        const auto* p = core::CurrentProcess();
        return (p != nullptr) ? static_cast<i64>(p->pid) : 0;
    }
    if (sched::SchedFindProcessByPid(pid) == nullptr)
        return kESRCH;
    return static_cast<i64>(pid);
}
i64 DoSetPgid(u64 pid, u64 pgid)
{
    (void)pid;
    (void)pgid;
    return 0;
}

i64 DoGetpgrp()
{
    return 0;
}

// setsid: create a new session. No session model in v0 — accept
// as no-op success. Linux returns the new sid; 0 is fine as a
// stand-in.
i64 DoSetsid()
{
    return 0;
}

// =============================================================
// Signal/scheduler entry points whose v0 implementation is a
// thin shape-adjustment over an existing handler. Real callers
// see "the syscall worked" — the discarded payload (siginfo for
// queueinfo variants, extended attrs for sched_setattr) is the
// documented sub-GAP.
// =============================================================

// tkill(tid, sig) — single-thread variant of tgkill. Modern
// Linux kernels treat it as tgkill(getpid(), tid, sig). Our
// DoTgkill ignores tgid for the purpose of tid -> Process::pid
// lookup, so passing 0 is harmless.
i64 DoTkill(u64 tid, u64 sig)
{
    return DoTgkill(0, tid, sig);
}

// rt_tgsigqueueinfo(tgid, tid, sig, info) — tgkill that also
// delivers a siginfo payload. v0 has no siginfo delivery, so
// we drop the info pointer and route to tgkill.
i64 DoRtTgsigqueueinfo(u64 tgid, u64 tid, u64 sig, u64 user_info)
{
    (void)user_info;
    return DoTgkill(tgid, tid, sig);
}

// rt_sigqueueinfo(tgid, sig, info) — process-wide sibling of
// rt_tgsigqueueinfo. v0 treats tid==tgid since the process
// model is single-threaded.
i64 DoRtSigqueueinfo(u64 tgid, u64 sig, u64 user_info)
{
    (void)user_info;
    return DoTgkill(tgid, tgid, sig);
}

// sched_setattr / sched_getattr — extended scheduler policy
// surface (SCHED_DEADLINE etc.). The v0 scheduler is MLFQ-style
// and doesn't expose deadline attributes; -EINVAL matches the
// Linux response when the requested policy isn't supported.
i64 DoSchedSetattr(u64 pid, u64 attr, u64 flags)
{
    (void)pid;
    (void)attr;
    (void)flags;
    return kEINVAL;
}
i64 DoSchedGetattr(u64 pid, u64 attr, u64 size, u64 flags)
{
    (void)pid;
    (void)attr;
    (void)size;
    (void)flags;
    return kEINVAL;
}

} // namespace duetos::subsystems::linux::internal
