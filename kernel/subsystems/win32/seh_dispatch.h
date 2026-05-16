#pragma once

#include "util/types.h"

/*
 * DuetOS — Win32 x64 kernel fault → user SEH dispatch (T6-02).
 *
 * When a ring-3 Win32 PE takes a CPU exception (#DE / #UD / #GP /
 * #PF), the kernel does NOT immediately kill the task. Instead it
 * builds a Microsoft `EXCEPTION_RECORD` + `CONTEXT` on the faulting
 * thread's own user stack and resumes the thread at
 * ntdll!KiUserExceptionDispatcher with rcx = EXCEPTION_RECORD,
 * rdx = CONTEXT — exactly the shape ntdll's structured-exception
 * machinery expects. The user-mode dispatcher then walks the
 * `.pdata`/`.xdata` frame chain and runs any `__try`/`__except`
 * (or `__finally`) handler. Only if delivery itself is impossible
 * (process has no ntdll, the user stack can't be written, or the
 * same instruction keeps re-faulting into the dispatcher) does the
 * caller fall back to the legacy task-kill path.
 *
 * Context: called from the trap dispatcher (arch::TrapDispatch),
 * IRQ-off, on the faulting task's kernel stack, with the faulting
 * process's address space still active in CR3.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

/// Attempt to deliver a ring-3 CPU fault to the faulting Win32 PE
/// as a structured exception. Returns true if the trap frame was
/// rewritten to resume at ntdll!KiUserExceptionDispatcher (the
/// caller must then just return so iretq lands in the dispatcher);
/// false if the fault is not deliverable and the caller should
/// proceed with the existing task-kill policy.
///
///   `frame`     — the live trap frame (rewritten in place on a
///                 successful delivery).
///   `ntstatus`  — the Windows exception code (e.g. 0xC0000005
///                 STATUS_ACCESS_VIOLATION, 0xC0000094
///                 STATUS_INTEGER_DIVIDE_BY_ZERO, 0xC000001D
///                 STATUS_ILLEGAL_INSTRUCTION).
///   `is_pf`     — true for a #PF: emits the standard 2-element
///                 ExceptionInformation (access type, fault VA).
///   `pf_write`  — for a #PF, true if the access was a write
///                 (ExceptionInformation[0] = 1), else a read (0).
///   `fault_va`  — for a #PF, the faulting linear address (cr2).
bool Win32DeliverException(arch::TrapFrame* frame, u32 ntstatus, bool is_pf, bool pf_write, u64 fault_va);

} // namespace duetos::subsystems::win32
