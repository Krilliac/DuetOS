#pragma once

#include "../../core/types.h"

/*
 * CustomOS — Linux-ABI syscall subsystem (v0).
 *
 * Peer of subsystems/win32/. Lets statically-linked Linux ELF
 * binaries reach kernel services through the canonical x86_64
 * Linux ABI:
 *
 *   - Entry:  `syscall` instruction (MSR_LSTAR). User CS/SS
 *             swapped to kernel, RIP loaded from MSR_LSTAR,
 *             RFLAGS saved to R11, user RIP saved to RCX.
 *   - Args:   RAX = syscall #, then RDI, RSI, RDX, R10, R8, R9.
 *             Return value in RAX.
 *   - Exit:   `sysretq` — restores user CS/SS, RIP=RCX, RFLAGS=R11.
 *
 * The in-kernel dispatch table is separate from core::SyscallDispatch
 * (which is the native CustomOS table reached via int 0x80). A
 * process's `abi_flavor` field (core/process.h) is set by the
 * loader at spawn time and determines which entry path its ring-3
 * task will use — the Win32 PE subsystem stays on int 0x80
 * unchanged, Linux ELF binaries go through `syscall`.
 *
 * Context: kernel. Dispatcher runs with interrupts disabled (the
 * entry stub doesn't re-enable; short dispatches only) and on the
 * task's kernel stack (loaded via MSR_KERNEL_GS_BASE swapgs
 * during entry).
 */

namespace customos::arch
{
struct TrapFrame;
}

namespace customos::subsystems::linux
{

/// Program MSR_STAR / MSR_LSTAR / MSR_SFMASK / MSR_KERNEL_GS_BASE
/// so the `syscall` instruction from ring 3 lands on the entry
/// stub. Must run AFTER PerCpuInitBsp (we need CurrentCpu() to
/// give a stable pointer for MSR_KERNEL_GS_BASE) and AFTER the
/// GDT is final (we encode the kernel+user selectors in MSR_STAR).
void SyscallInit();

/// Main dispatch. Called from the assembly entry stub in
/// syscall_entry.S once registers have been stashed into a
/// TrapFrame on the kernel stack. Reads `frame->rax` as the
/// syscall number; writes the return value back into
/// `frame->rax` before the stub pops + sysretqs.
///
/// Unknown syscalls return -ENOSYS (-38) as Linux does so
/// musl's CRT sees a sensible error rather than a kernel oops.
extern "C" void LinuxSyscallDispatch(arch::TrapFrame* frame);

} // namespace customos::subsystems::linux
