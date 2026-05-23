/*
 * Linux signal delivery — user-handler trampoline + sigreturn.
 *
 * Implementation: see signal_deliver.h for the design rationale.
 *
 * The on-user-stack signal frame layout below is internal to the
 * kernel — userland never sees it directly (SA_SIGINFO callers see
 * siginfo_t / ucontext_t pointers but those are sub-GAPs in v0).
 * We can change the layout freely as long as the magic + size are
 * synchronized between LinuxSignalCheckAndDeliver and
 * LinuxSignalRestoreFrame.
 */

#include "subsystems/linux/signal_deliver.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "mm/paging.h"
#include "proc/process.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Magic sentinel — 'DUETOSSF' as a u64 (little-endian: F S S O T E U D)
constexpr u64 kSignalFrameMagic = 0x4653534F54455544ULL;

// SA_RESTORER — sigaction flag set by glibc / musl when they
// supply their own user-mode trampoline that issues
// rt_sigreturn. Without it, v0 has no user-mode pad we can route
// the handler return through.
constexpr u64 kSaRestorer = 0x04000000;

// SIG_DFL / SIG_IGN sentinels (Linux). Handler VAs equal to one
// of these are NOT user-installed handlers.
constexpr u64 kSigDfl = 0;
constexpr u64 kSigIgn = 1;

constexpr u32 kSIGKILL = 9;
constexpr u32 kSIGSTOP = 19;

// Signal frame written onto the user stack just below the
// retaddr slot that the handler's `ret` will pop. Layout is
// 16-byte aligned at the top so the handler sees an x86-64 ABI-
// shaped stack on entry (SP % 16 == 8 right at handler's `push
// rbp`-equivalent).
struct alignas(16) LinuxSignalFrame
{
    u64 magic; // kSignalFrameMagic — gates rt_sigreturn

    // Saved trap frame — every byte iretq cares about plus the
    // GPRs the dispatcher loaded into the TrapFrame layout.
    u64 saved_r15;
    u64 saved_r14;
    u64 saved_r13;
    u64 saved_r12;
    u64 saved_r11;
    u64 saved_r10;
    u64 saved_r9;
    u64 saved_r8;
    u64 saved_rbp;
    u64 saved_rdi;
    u64 saved_rsi;
    u64 saved_rdx;
    u64 saved_rcx;
    u64 saved_rbx;
    u64 saved_rax; // syscall return value the caller will see post-handler
    u64 saved_rip;
    u64 saved_rflags;
    u64 saved_rsp;
    u64 saved_cs;
    u64 saved_ss;

    // Per-process state captured at delivery time. rt_sigreturn
    // restores `signal_mask` so the kernel's transient mask
    // changes during the handler are reverted.
    u64 saved_signal_mask;

    // Diagnostic — what signal triggered this delivery. Useful
    // for serial logging at sigreturn time.
    u64 signum;
};

// Round-up alignment helper. Kept inline to avoid a TU-private
// helper header.
constexpr u64 AlignDown16(u64 x)
{
    return x & ~static_cast<u64>(0xF);
}

// Per-Process top-of-frame pointer recorded by Deliver and
// consumed by Restore. Not stored in Process directly to keep
// the signal-delivery state contained — a 1-deep stack is
// adequate for v0 (no nested delivery).
//
// Indexed by pid % kSlots; collisions get a logged warning and
// fall back to "no saved frame." A real per-Process slot would
// live in proc/process.h; deferring that until SMP makes the
// slot-collision risk worth fixing.
constexpr u32 kSlots = 64;
struct DeliverySlot
{
    u64 pid;
    u64 user_frame_va;
};
DeliverySlot g_slots[kSlots] = {};

void SlotPut(u64 pid, u64 frame_va)
{
    DeliverySlot& s = g_slots[pid % kSlots];
    if (s.pid != 0 && s.pid != pid)
    {
        ::duetos::arch::SerialWrite("[linux/signal] slot collision pid=");
        ::duetos::arch::SerialWriteHex(pid);
        ::duetos::arch::SerialWrite(" — overwriting\n");
    }
    s.pid = pid;
    s.user_frame_va = frame_va;
}

bool SlotTake(u64 pid, u64& out_frame_va)
{
    DeliverySlot& s = g_slots[pid % kSlots];
    if (s.pid != pid)
        return false;
    out_frame_va = s.user_frame_va;
    s.pid = 0;
    s.user_frame_va = 0;
    return true;
}

// Pick the lowest-numbered pending signal that's caught + unmasked.
// Returns 0 if none. Skips SIGKILL / SIGSTOP (the kernel handles
// those via LinuxSignalDeliver's default-action path; they never
// reach a user handler).
u32 PickEligible(::duetos::core::Process* p)
{
    const u64 pending = p->linux_pending_signals;
    const u64 deliverable = pending & ~p->linux_signal_mask;
    if (deliverable == 0)
        return 0;
    for (u32 sig = 1; sig < ::duetos::core::Process::kLinuxSignalCount; ++sig)
    {
        if ((deliverable & (1ULL << sig)) == 0)
            continue;
        if (sig == kSIGKILL || sig == kSIGSTOP)
            continue;
        const auto& slot = p->linux_sigactions[sig];
        if (slot.handler_va == kSigDfl || slot.handler_va == kSigIgn)
            continue;
        if ((slot.flags & kSaRestorer) == 0 || slot.restorer_va == 0)
        {
            // No SA_RESTORER from the sigaction call. Fall back
            // to the per-process vDSO __kernel_rt_sigreturn
            // trampoline — same path real Linux takes when
            // userland's libc hasn't supplied its own restorer.
            // If the vDSO somehow didn't map (rare; only on frame
            // OOM during spawn), drop the pending bit so a one-off
            // broken PE doesn't hang forever.
            if (p->linux_vdso_rt_sigreturn_va == 0)
            {
                p->linux_pending_signals &= ~(1ULL << sig);
                ::duetos::arch::SerialWrite("[linux/signal] no SA_RESTORER and no vDSO for sig=");
                ::duetos::arch::SerialWriteHex(sig);
                ::duetos::arch::SerialWrite(" — pending bit cleared\n");
                continue;
            }
            // Else fall through — Deliver() resolves the restorer
            // VA from sa.restorer_va OR proc->linux_vdso_*.
        }
        return sig;
    }
    return 0;
}

} // namespace

bool LinuxSignalCheckAndDeliver(::duetos::arch::TrapFrame* frame)
{
    using ::duetos::arch::Cli;
    using ::duetos::arch::Sti;
    using ::duetos::core::CurrentProcess;
    using ::duetos::core::Process;

    Process* p = CurrentProcess();
    if (p == nullptr)
        return false;
    // Only deliver on a return TO user-mode. cs == kernel selector
    // means a kernel-thread syscall (shouldn't happen for the Linux
    // dispatcher, but guard anyway).
    if ((frame->cs & 3) != 3)
        return false;

    Cli();
    const u32 sig = PickEligible(p);
    if (sig == 0)
    {
        Sti();
        return false;
    }
    const auto& sa = p->linux_sigactions[sig];
    const u64 handler_va = sa.handler_va;
    // Restorer VA: prefer the one supplied via sigaction's
    // SA_RESTORER pad; fall back to the per-process vDSO
    // trampoline when the caller's sigaction omitted it. The
    // PickEligible gate above guarantees the vDSO VA is non-zero
    // when we reach this fallback.
    const u64 restorer_va =
        ((sa.flags & kSaRestorer) != 0 && sa.restorer_va != 0) ? sa.restorer_va : p->linux_vdso_rt_sigreturn_va;
    const u64 sa_mask = sa.mask;
    const u64 prev_mask = p->linux_signal_mask;

    // Clear the pending bit + transiently mask the signal (Linux
    // semantics — handler doesn't re-enter itself). sa_mask
    // additions are honored; alt-stack is not.
    p->linux_pending_signals &= ~(1ULL << sig);
    p->linux_signal_mask = prev_mask | (1ULL << sig) | sa_mask;
    Sti();

    // Lay out user-stack: skip the 128-byte red zone, then make
    // room for retaddr + frame, 16-byte aligned for the handler
    // entry. Handler sees rsp+8 == LinuxSignalFrame address.
    const u64 caller_rsp = frame->rsp;
    constexpr u64 kRedZone = 128;
    u64 frame_va = AlignDown16(caller_rsp - kRedZone - sizeof(LinuxSignalFrame));
    u64 retaddr_va = frame_va - 8;

    LinuxSignalFrame stage{};
    stage.magic = kSignalFrameMagic;
    stage.saved_r15 = frame->r15;
    stage.saved_r14 = frame->r14;
    stage.saved_r13 = frame->r13;
    stage.saved_r12 = frame->r12;
    stage.saved_r11 = frame->r11;
    stage.saved_r10 = frame->r10;
    stage.saved_r9 = frame->r9;
    stage.saved_r8 = frame->r8;
    stage.saved_rbp = frame->rbp;
    stage.saved_rdi = frame->rdi;
    stage.saved_rsi = frame->rsi;
    stage.saved_rdx = frame->rdx;
    stage.saved_rcx = frame->rcx;
    stage.saved_rbx = frame->rbx;
    stage.saved_rax = frame->rax;
    stage.saved_rip = frame->rip;
    stage.saved_rflags = frame->rflags;
    stage.saved_rsp = frame->rsp;
    stage.saved_cs = frame->cs;
    stage.saved_ss = frame->ss;
    stage.saved_signal_mask = prev_mask;
    stage.signum = sig;

    if (!::duetos::mm::CopyToUser(reinterpret_cast<void*>(frame_va), &stage, sizeof(stage)))
    {
        // CopyToUser miss — the user RSP must be unmapped or
        // outside the user half. Re-set the pending bit so
        // signalfd can still drain it; restore the mask. Don't
        // crash — the caller will see whatever the original
        // syscall returned.
        Cli();
        p->linux_pending_signals |= (1ULL << sig);
        p->linux_signal_mask = prev_mask;
        Sti();
        ::duetos::arch::SerialWrite("[linux/signal] CopyToUser frame failed; deferring\n");
        return false;
    }

    if (!::duetos::mm::CopyToUser(reinterpret_cast<void*>(retaddr_va), &restorer_va, sizeof(restorer_va)))
    {
        Cli();
        p->linux_pending_signals |= (1ULL << sig);
        p->linux_signal_mask = prev_mask;
        Sti();
        ::duetos::arch::SerialWrite("[linux/signal] CopyToUser retaddr failed; deferring\n");
        return false;
    }

    SlotPut(p->pid, frame_va);

    // Mutate the trap frame so iretq lands in the handler.
    frame->rip = handler_va;
    frame->rsp = retaddr_va;
    frame->rdi = sig; // first arg: signum
    frame->rsi = 0;   // siginfo_t* (sub-GAP)
    frame->rdx = 0;   // ucontext_t* (sub-GAP)

    ::duetos::arch::SerialWrite("[linux/signal] deliver sig=");
    ::duetos::arch::SerialWriteHex(sig);
    ::duetos::arch::SerialWrite(" handler=");
    ::duetos::arch::SerialWriteHex(handler_va);
    ::duetos::arch::SerialWrite(" restorer=");
    ::duetos::arch::SerialWriteHex(restorer_va);
    ::duetos::arch::SerialWrite(" frame_va=");
    ::duetos::arch::SerialWriteHex(frame_va);
    ::duetos::arch::SerialWrite("\n");
    return true;
}

bool LinuxSignalRestoreFrame(::duetos::arch::TrapFrame* frame)
{
    using ::duetos::core::CurrentProcess;
    using ::duetos::core::Process;

    Process* p = CurrentProcess();
    if (p == nullptr)
        return false;

    // The user-mode trampoline (sa_restorer) issued `syscall
    // rt_sigreturn` with rsp pointing at the LinuxSignalFrame
    // we wrote above. Read it back from there. We trust the
    // recorded slot's user_frame_va over frame->rsp because a
    // misbehaving sa_restorer might have moved rsp; the recorded
    // value is what we wrote and what the magic guards.
    u64 frame_va = 0;
    if (!SlotTake(p->pid, frame_va))
    {
        // No saved frame — caller invented an rt_sigreturn.
        // Caller treats this as fatal (the existing DoRtSigreturn
        // already did that for the no-frame case).
        return false;
    }

    LinuxSignalFrame stage{};
    if (!::duetos::mm::CopyFromUser(&stage, reinterpret_cast<const void*>(frame_va), sizeof(stage)))
        return false;
    if (stage.magic != kSignalFrameMagic)
    {
        ::duetos::arch::SerialWrite("[linux/signal] sigreturn frame magic mismatch\n");
        return false;
    }

    frame->r15 = stage.saved_r15;
    frame->r14 = stage.saved_r14;
    frame->r13 = stage.saved_r13;
    frame->r12 = stage.saved_r12;
    frame->r11 = stage.saved_r11;
    frame->r10 = stage.saved_r10;
    frame->r9 = stage.saved_r9;
    frame->r8 = stage.saved_r8;
    frame->rbp = stage.saved_rbp;
    frame->rdi = stage.saved_rdi;
    frame->rsi = stage.saved_rsi;
    frame->rdx = stage.saved_rdx;
    frame->rcx = stage.saved_rcx;
    frame->rbx = stage.saved_rbx;
    frame->rax = stage.saved_rax;
    frame->rip = stage.saved_rip;
    frame->rflags = stage.saved_rflags;
    frame->rsp = stage.saved_rsp;
    // cs / ss intentionally not restored — they should already be
    // user selectors and re-loading user-controlled values into
    // them risks #GP if the user mutated the saved frame.
    p->linux_signal_mask = stage.saved_signal_mask;
    return true;
}

} // namespace duetos::subsystems::linux::internal
