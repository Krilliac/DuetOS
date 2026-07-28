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

/// STATUS_STACK_BUFFER_OVERRUN — the code Windows raises for
/// `__fastfail`. The name is a historical misnomer: since Windows 8
/// every fail-fast reason (not just /GS) is reported under it, with
/// the actual reason in ExceptionInformation[0].
constexpr u32 kStatusStackBufferOverrun = 0xC0000409;

/// Decode a ring-3 #GP that was really an `int 0x29` — the x64
/// `__fastfail` intrinsic MSVC's CRT uses to abort unrecoverably.
///
/// There is no IDT gate for vector 0x29, so the instruction faults as
/// #GP(0x29*8+2) and, without this decode, is delivered as a generic
/// STATUS_ACCESS_VIOLATION at a RIP inside the CRT — which reads like
/// a loader bug when it is actually the CRT reporting, deliberately
/// and by contract, that one of its own invariants failed. The reason
/// code lives in ECX (`__fastfail`'s single argument); recovering it
/// is the difference between "the app crashed somewhere" and "the app
/// said FAST_FAIL_<reason>".
///
/// Returns true only when `frame` is a ring-3 #GP whose faulting
/// instruction bytes are literally `CD 29`, in which case `out_code`
/// receives the fail-fast reason from ECX. The instruction bytes are
/// read through CopyFromUser, so an unmapped or hostile RIP simply
/// yields false rather than faulting the kernel.
bool Win32DecodeFastFail(const arch::TrapFrame* frame, u32* out_code);

/// Human-readable name for a `__fastfail` reason code, or nullptr if
/// the code is not one of the documented set. Used for logging only.
const char* Win32FastFailName(u32 code);

} // namespace duetos::subsystems::win32
