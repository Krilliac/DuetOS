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

#include "arch/x86_64/serial.h"
#include "diag/log_names.h"
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
i64 DoTgkill(u64 tgid, u64 tid, u64 sig)
{
    (void)tgid;
    if (tid != sched::CurrentTaskId())
        return kESRCH;
    arch::SerialWrite("[linux] tgkill -> self; interpreting as abort. sig=");
    arch::SerialWriteHex(sig);
    arch::SerialWrite(" (");
    arch::SerialWrite(::duetos::core::LinuxSignalName(sig));
    arch::SerialWrite(")\n");
    sched::SchedExit();
    return 0;
}

// Linux: kill(pid, sig). Same as tgkill in this single-threaded
// world — if targeting self, exit; else -ESRCH. A real signal
// implementation would look up the target Process and deliver
// via its sig queue.
i64 DoKill(u64 pid, u64 sig)
{
    if (pid != sched::CurrentTaskId())
        return kESRCH;
    arch::SerialWrite("[linux] kill(self) sig=");
    arch::SerialWriteHex(sig);
    arch::SerialWrite(" (");
    arch::SerialWrite(::duetos::core::LinuxSignalName(sig));
    arch::SerialWrite(")\n");
    sched::SchedExit();
    return 0;
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
