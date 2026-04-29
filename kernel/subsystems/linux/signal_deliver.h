#pragma once

/*
 * Linux signal delivery — user-handler trampoline + sigreturn.
 *
 * Hook called at every Linux-ABI syscall return that examines the
 * caller's pending+unmasked+caught signal mask and, if a delivery
 * is due, mutates the TrapFrame so iretq lands at the user-space
 * handler instead of the original syscall caller.
 *
 * Concretely: a signal frame (LinuxSignalFrame, defined inside the
 * .cpp) is pushed onto the user stack capturing every value iretq
 * needs to restore (rip / rflags / cs / ss / rsp + the 15 GPRs
 * the dispatcher saved + the original signal_mask). Above the
 * frame goes a single retaddr slot containing sa_restorer — the
 * userland trampoline glibc / musl always supply when SA_RESTORER
 * is set. When the handler returns, control lands at sa_restorer
 * which issues `syscall rt_sigreturn` (Linux nr 15); the kernel's
 * DoRtSigreturn (kernel/subsystems/linux/syscall_sig.cpp) reads
 * the frame at rsp and restores the trap-frame for iretq.
 *
 * Sub-GAPs (intentional v0 corners):
 *   - Single signal per syscall return (no nested delivery).
 *   - Only handlers that set SA_RESTORER + a non-zero
 *     restorer_va are honored. Old-style "no SA_RESTORER" callers
 *     get the pending bit cleared with a serial warning — still
 *     better than blocking forever, but doesn't actually invoke
 *     their handler.
 *   - SA_SIGINFO (siginfo_t / ucontext_t pointers) — handler is
 *     called with rdi=signum, rsi=0, rdx=0; the ucontext field
 *     in the saved frame is internal only.
 *   - sa_mask (transient handler-time block) — the handler's mask
 *     is installed but not restored separately; rt_sigreturn
 *     restores the pre-delivery signal_mask wholesale.
 *   - Alt-stack delivery via sigaltstack — not honored (always
 *     uses the caller's normal stack).
 */

#include "arch/x86_64/traps.h"

namespace duetos::subsystems::linux::internal
{

// Examine the current process's pending-signal bitmap and, if a
// caught (handler != SIG_DFL/SIG_IGN with SA_RESTORER + restorer_va)
// signal is unmasked, mutate the frame to deliver it. Called at
// the tail of LinuxSyscallDispatch.
//
// Returns true if a delivery was injected (caller's rax has been
// preserved into the saved frame for sigreturn to restore later).
bool LinuxSignalCheckAndDeliver(arch::TrapFrame* frame);

// Restore a saved frame written by the helper above. Called from
// DoRtSigreturn. Returns true on a clean restore; false if the
// magic header is wrong (caller treats as fatal protocol miss).
bool LinuxSignalRestoreFrame(arch::TrapFrame* frame);

} // namespace duetos::subsystems::linux::internal
