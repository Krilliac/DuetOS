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

#include "subsystems/linux/syscall_internal.h"
#include "subsystems/linux/signal_deliver.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "proc/process.h"
#include "mm/address_space.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

// =====================================================
// Real signal delivery — v0
// =====================================================
//
// Default-action delivery only. Fatal signals (SIGTERM/SIGKILL/
// SIGINT/SIGABRT/SIGSEGV/SIGFPE/SIGBUS/SIGHUP/SIGQUIT/SIGPIPE/
// SIGUSR1/SIGUSR2) terminate the target process via
// SchedKillByProcess; non-fatal signals sit in the pending bitmap
// where signalfd / rt_sigpending can observe them. User-installed
// handlers (sigaction with handler_va not in {SIG_DFL=0,
// SIG_IGN=1}) are recorded as pending but not invoked — real
// trampoline + sigreturn is its own slice.

bool LinuxSignalIsFatalDefault(u32 signum)
{
    constexpr u32 kSIGHUP = 1;
    constexpr u32 kSIGINT = 2;
    constexpr u32 kSIGQUIT = 3;
    constexpr u32 kSIGABRT = 6;
    constexpr u32 kSIGBUS = 7;
    constexpr u32 kSIGFPE = 8;
    constexpr u32 kSIGKILL = 9;
    constexpr u32 kSIGUSR1 = 10;
    constexpr u32 kSIGSEGV = 11;
    constexpr u32 kSIGUSR2 = 12;
    constexpr u32 kSIGPIPE = 13;
    constexpr u32 kSIGTERM = 15;
    switch (signum)
    {
    case kSIGHUP:
    case kSIGINT:
    case kSIGQUIT:
    case kSIGABRT:
    case kSIGBUS:
    case kSIGFPE:
    case kSIGKILL:
    case kSIGUSR1:
    case kSIGSEGV:
    case kSIGUSR2:
    case kSIGPIPE:
    case kSIGTERM:
        return true;
    default:
        return false;
    }
}

i64 LinuxSignalDeliver(core::Process* target, u32 signum)
{
    if (target == nullptr)
        return kEINVAL;
    if (signum == 0 || signum >= core::Process::kLinuxSignalCount)
        return kEINVAL;
    constexpr u32 kSIGKILL = 9;
    constexpr u32 kSIGSTOP = 19;
    constexpr u64 kSigDfl = 0;
    constexpr u64 kSigIgn = 1;
    const u64 handler = target->linux_sigactions[signum].handler_va;
    // SIGKILL / SIGSTOP cannot be ignored or caught — they always
    // get the default kernel action. Mirror Linux's sigprocmask /
    // sigaction restriction here so a malicious caller can't shield
    // a target from SIGKILL by installing SIG_IGN.
    const bool force_default = (signum == kSIGKILL || signum == kSIGSTOP);
    if (!force_default && handler == kSigIgn)
    {
        // Drop silently — Linux semantics. Don't even mark the
        // signal pending; SIG_IGN means "the kernel discards it
        // before it reaches the bitmap."
        return 0;
    }
    arch::Cli();
    target->linux_pending_signals |= (1ULL << signum);
    sched::WaitQueueWakeAll(&target->linux_signal_wq);
    arch::Sti();
    arch::SerialWrite("[linux/signal] deliver pid=");
    arch::SerialWriteHex(target->pid);
    arch::SerialWrite(" sig=");
    arch::SerialWriteHex(signum);
    arch::SerialWrite(" handler=");
    arch::SerialWriteHex(handler);
    arch::SerialWrite("\n");
    if (force_default || handler == kSigDfl)
    {
        if (LinuxSignalIsFatalDefault(signum) || signum == kSIGKILL)
        {
            // Stamp the signaled-exit metadata BEFORE killing so
            // ProcessRelease's parent-notify path (in proc/process.cpp)
            // sees the right was_signaled / exit_signal and forwards
            // them to the parent's wait4.
            target->linux_was_signaled = true;
            target->linux_exit_signal = static_cast<u8>(signum & 0x7F);
            target->linux_exit_code = 0;
            (void)sched::SchedKillByProcess(target);
            return 0;
        }
        // Non-fatal default: just leaves the bit set in the pending
        // bitmap. signalfd / rt_sigpending will observe it.
        return 0;
    }
    // User handler installed. v0 doesn't run it (no trampoline);
    // the bit stays set so signalfd_read can drain it. Real handler
    // delivery is a follow-up slice. Sub-GAP.
    return 0;
}

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
    // POSIX: SIGKILL (9) and SIGSTOP (19) MUST NOT have user-installable
    // handlers. Linux rejects with -EINVAL at the syscall boundary. We
    // do force-default these at delivery time (signal_deliver.cpp:148),
    // but storing the user-supplied handler still pollutes the slot
    // table — subsequent rt_sigaction queries observe it, and a future
    // refactor that loses the force-default check would suddenly start
    // dispatching the handler. Reject up-front so the contract holds
    // independent of the delivery path's defenses.
    constexpr u32 kSIGKILL = 9;
    constexpr u32 kSIGSTOP = 19;
    if (signum == kSIGKILL || signum == kSIGSTOP)
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
        // POSIX: SIGKILL and SIGSTOP can never be blocked. Linux
        // silently strips them from any incoming mask; mirror that
        // so the stored mask never observably blocks them, even
        // briefly.
        constexpr u32 kSIGKILL = 9;
        constexpr u32 kSIGSTOP = 19;
        constexpr u64 kUnblockable = (1ULL << kSIGKILL) | (1ULL << kSIGSTOP);
        set &= ~kUnblockable;
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

// Linux: rt_sigreturn. Called by the user-mode trampoline (sa_restorer)
// at the end of a signal handler. The trap frame on entry has its rsp
// pointing at the LinuxSignalFrame the kernel wrote in
// LinuxSignalCheckAndDeliver; this handler restores every saved
// register and the signal mask so iretq lands the original syscall
// caller exactly where it was, with the original syscall's rax
// preserved.
//
// If the slot table doesn't have a recorded delivery for this pid,
// or the magic header on the user stack is corrupt, treat as a
// fatal protocol violation and kill the task — better than letting
// a malicious user program fabricate a bogus frame and inject
// arbitrary register state.
i64 DoRtSigreturn(arch::TrapFrame* frame)
{
    if (!LinuxSignalRestoreFrame(frame))
    {
        arch::SerialWrite("[linux] rt_sigreturn on task without saved frame — exiting\n");
        sched::SchedExit();
        return 0;
    }
    // The dispatcher will write rv into frame->rax; we already
    // restored frame->rax to the original syscall's value. Return
    // the same value so that overwrite is a no-op.
    return static_cast<i64>(frame->rax);
}

// rt_sigpending(set, sigsetsize). Reads the per-process pending
// bitmap that LinuxSignalDeliver populates. The mask the caller
// has blocked via rt_sigprocmask doesn't filter the bitmap; in
// real Linux, blocked-and-pending IS the result, which is exactly
// what we report.
i64 DoRtSigpending(u64 user_set, u64 sigsetsize)
{
    (void)sigsetsize;
    if (user_set == 0)
        return kEFAULT;
    core::Process* p = core::CurrentProcess();
    const u64 pending = (p != nullptr) ? p->linux_pending_signals : 0;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_set), &pending, sizeof(pending)))
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
