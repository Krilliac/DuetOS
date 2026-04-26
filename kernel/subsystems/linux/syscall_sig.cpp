/*
 * DuetOS — Linux ABI: signal handlers.
 *
 * Sibling TU of syscall.cpp. Houses the rt_sigaction /
 * rt_sigprocmask / sigaltstack / rt_sigreturn / rt_sigpending /
 * rt_sigsuspend / rt_sigtimedwait entry points.
 *
 * v0 has no actual signal delivery. The handlers persist state
 * where the caller probes it back (sigaction slot table, signal
 * mask) and otherwise either accept the call as a no-op (sigaltstack)
 * or return -EINTR (sigsuspend / sigtimedwait) so libc paths make
 * forward progress instead of -ENOSYS-crashing. rt_sigreturn on a
 * task without a signal frame is a fatal protocol violation: kill
 * the task rather than silently returning.
 */

#include "syscall_internal.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/process.h"
#include "../../mm/address_space.h"
#include "../../sched/sched.h"

namespace duetos::subsystems::linux::internal
{

// Linux: rt_sigaction(signum, new_act, old_act, sigsetsize).
// Persists per-process disposition for `signum` so a caller that
// installs SIG_IGN and then queries the slot back gets the same
// value. We don't actually deliver signals yet, but musl + glibc
// race startup paths inspect the slot table to decide e.g.
// whether SIGPIPE is SIG_IGN'd — returning the previous value
// matters even though we never actually raise a signal.
//
// Linux sigaction layout (offsets into the user struct):
//   0x00  sa_handler (u64) or sa_sigaction
//   0x08  sa_flags (u64)
//   0x10  sa_restorer (u64)
//   0x18  sa_mask (u64, first u64 of the sigset)
i64 DoRtSigaction(u64 signum, u64 new_act, u64 old_act, u64 sigsetsize)
{
    (void)sigsetsize; // we always store a single u64 mask
    if (signum == 0 || signum >= core::Process::kLinuxSignalCount)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEINVAL;

    core::Process::LinuxSigAction& slot = p->linux_sigactions[signum];

    // Emit the previous value first — the syscall contract is
    // "atomic" so the oldact captures state from BEFORE the new
    // one is applied.
    if (old_act != 0)
    {
        u64 out[4] = {slot.handler_va, slot.flags, slot.restorer_va, slot.mask};
        if (!mm::CopyToUser(reinterpret_cast<void*>(old_act), out, sizeof(out)))
            return kEFAULT;
    }
    if (new_act != 0)
    {
        u64 in[4] = {0, 0, 0, 0};
        if (!mm::CopyFromUser(in, reinterpret_cast<const void*>(new_act), sizeof(in)))
            return kEFAULT;
        slot.handler_va = in[0];
        slot.flags = in[1];
        slot.restorer_va = in[2];
        slot.mask = in[3];
    }
    return 0;
}

// Linux: rt_sigprocmask(how, set, oldset, sigsetsize).
//   how == 0 SIG_BLOCK   — mask |= set
//   how == 1 SIG_UNBLOCK — mask &= ~set
//   how == 2 SIG_SETMASK — mask  = set
// No delivery yet; we just persist the mask so a subsequent
// rt_sigprocmask with set=NULL returns the value we stored.
i64 DoRtSigprocmask(u64 how, u64 user_set, u64 user_oldset, u64 sigsetsize)
{
    (void)sigsetsize;
    constexpr u64 kSigBlock = 0;
    constexpr u64 kSigUnblock = 1;
    constexpr u64 kSigSetMask = 2;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEINVAL;
    const u64 prev = p->linux_signal_mask;
    if (user_oldset != 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_oldset), &prev, sizeof(prev)))
            return kEFAULT;
    }
    if (user_set != 0)
    {
        u64 set = 0;
        if (!mm::CopyFromUser(&set, reinterpret_cast<const void*>(user_set), sizeof(set)))
            return kEFAULT;
        switch (how)
        {
        case kSigBlock:
            p->linux_signal_mask = prev | set;
            break;
        case kSigUnblock:
            p->linux_signal_mask = prev & ~set;
            break;
        case kSigSetMask:
            p->linux_signal_mask = set;
            break;
        default:
            return kEINVAL;
        }
    }
    return 0;
}

// Linux: sigaltstack(ss, old_ss). Stub — no signal delivery so
// no alt-stack semantics are observable. Returns 0.
i64 DoSigaltstack(u64 ss, u64 old_ss)
{
    (void)ss;
    (void)old_ss;
    return 0;
}

// Linux: rt_sigreturn. Called by user-mode signal trampolines
// at the end of a signal handler. Without signal delivery
// there's no frame to unwind; if a program ever calls this
// unexpectedly, kill it so we don't silently return garbage.
i64 DoRtSigreturn()
{
    arch::SerialWrite("[linux] rt_sigreturn on task without signal frame — exiting\n");
    sched::SchedExit();
    return 0;
}

// rt_sigpending(set, sigsetsize). No signal delivery yet → no
// pending signals → write a zeroed mask.
i64 DoRtSigpending(u64 user_set, u64 sigsetsize)
{
    (void)sigsetsize;
    if (user_set == 0)
        return kEFAULT;
    const u64 zero = 0;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_set), &zero, sizeof(zero)))
        return kEFAULT;
    return 0;
}

// rt_sigsuspend / sigtimedwait. Without signal delivery these
// would block forever; -EINTR mirrors what a signal-aware caller
// would see, prompting most libc paths to retry.
i64 DoRtSigsuspend(u64 user_mask, u64 sigsetsize)
{
    (void)user_mask;
    (void)sigsetsize;
    return kEINTR;
}
i64 DoRtSigtimedwait(u64 user_mask, u64 user_info, u64 user_ts, u64 sigsetsize)
{
    (void)user_mask;
    (void)user_info;
    (void)user_ts;
    (void)sigsetsize;
    return kEINTR;
}

} // namespace duetos::subsystems::linux::internal
