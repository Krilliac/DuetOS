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
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

i64 DoExitGroup(u64 status)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
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
    sched::SchedExit();
    // sched::SchedExit is [[noreturn]]; this line is unreachable.
    return 0;
}

// Linux exit(status) has process-wide semantics for a single-thread
// process, which is exactly all we support in v0. Route it through
// exit_group so both numbers share the same teardown path.
i64 DoExit(u64 status)
{
    return DoExitGroup(status);
}

// Linux getpid() / gettid() on our current single-thread-per-process
// model both map to the scheduler task ID. Keep them separate helpers
// anyway so the dispatch table names track the Linux ABI directly and
// the syscall coverage generator can see a concrete DoGetPid handler.
i64 DoGetPid()
{
    return static_cast<i64>(sched::CurrentTaskId());
}

// Linux: gettid. v0 has one task per process, so tid == pid.
i64 DoGetTid()
{
    return static_cast<i64>(sched::CurrentTaskId());
}

// Linux: sched_yield. Direct passthrough to the native scheduler.
i64 DoSchedYield()
{
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
    (void)tgid;
    if (sig == 0)
    {
        // Existence-probe form: verify the tid is alive.
        sched::Task* t = sched::SchedFindTaskByTid(tid);
        return (t != nullptr) ? 0 : kESRCH;
    }
    sched::Task* t = sched::SchedFindTaskByTid(tid);
    if (t == nullptr)
        return kESRCH;
    core::Process* target = sched::TaskProcess(t);
    if (target == nullptr)
        return kESRCH; // kernel-only task — no Linux process to signal
    return LinuxSignalDeliver(target, static_cast<u32>(sig));
}

// Linux: kill(pid, sig). pid > 0 → deliver to the matching process.
// pid == 0 → process group (collapsed to the caller's process in
// v0). pid == -1 → broadcast (rejected — too easy to misuse with
// no real process tree). pid < -1 → process group (-pid).
i64 DoKill(u64 pid, u64 sig)
{
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
        return kESRCH; // group / broadcast forms not supported in v0 (sub-GAP)
    if (target == nullptr)
        return kESRCH;
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
    (void)pid;
    return 0;
}
i64 DoGetSid(u64 pid)
{
    (void)pid;
    return 0;
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

} // namespace duetos::subsystems::linux::internal
