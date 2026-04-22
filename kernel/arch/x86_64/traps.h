#pragma once

#include "../../core/types.h"

/*
 * Uniform trap frame presented to the C++ dispatcher by every CPU-exception
 * stub in exceptions.S. Field order mirrors the stack layout assembled by
 * isr_common — do NOT reorder without updating exceptions.S.
 *
 * Context: kernel. Instances live on the kernel stack for the duration of
 * one exception handler call; no heap allocation is ever involved.
 */

namespace customos::arch
{

struct TrapFrame
{
    // General-purpose registers saved by isr_common, in stack order.
    u64 r15;
    u64 r14;
    u64 r13;
    u64 r12;
    u64 r11;
    u64 r10;
    u64 r9;
    u64 r8;
    u64 rbp;
    u64 rdi;
    u64 rsi;
    u64 rdx;
    u64 rcx;
    u64 rbx;
    u64 rax;

    // Pushed by the per-vector stub.
    u64 vector;
    u64 error_code;

    // Pushed by the CPU on interrupt delivery.
    u64 rip;
    u64 cs;
    u64 rflags;
    u64 rsp;
    u64 ss;
};

static_assert(sizeof(TrapFrame) == 22 * sizeof(u64), "TrapFrame size must match exceptions.S push order");

/// Called from isr_common. For CPU exceptions (vector < 32), prints
/// diagnostic state to COM1 and halts — none are recoverable yet. For
/// IRQs (vector 32..47, plus the LAPIC spurious at 0xFF), routes through
/// the per-vector IRQ handler and returns so isr_common's iretq path
/// resumes the interrupted code.
extern "C" void TrapDispatch(TrapFrame* frame);

/// Current IRQ nesting depth for the running task. 0 = not in
/// interrupt context, 1 = one level deep (normal), >= 2 = a
/// handler itself was interrupted. The runtime checker watches
/// the lifetime max (IrqNestMax) to surface runaway re-entry.
u64 IrqNestDepth();

/// Highest IRQ nesting depth observed since boot. Monotonic;
/// never reset.
u64 IrqNestMax();

/// Direct accessor/mutator for the per-CPU depth counter. Used
/// by the scheduler's context-switch path to save the outgoing
/// task's nesting level and load the incoming task's. Mirrors
/// the FS_BASE save/restore pattern — same location, same
/// "stash-then-restore" shape. No public API beyond the
/// scheduler; other callers should use IrqNestDepth/Max.
u64 IrqNestDepthRaw();
void IrqNestDepthSet(u64 v);

/// Per-vector IRQ handler signature. The LAPIC EOI is sent by the IRQ
/// dispatcher (not by individual handlers), so handlers should NOT EOI
/// themselves — doing so twice loses an interrupt.
using IrqHandler = void (*)();

/// Install (or replace) a handler for IRQ vector `vector` (32..47) or the
/// LAPIC spurious vector (0xFF). Passing `nullptr` clears the handler;
/// the dispatcher then logs a one-line "unhandled IRQ" message.
void IrqInstall(u8 vector, IrqHandler handler);

/// Deliberately trigger int3 to verify the IDT path is wired up correctly.
/// Used only during early bring-up; remove from the boot sequence once
/// there's real work to do after IdtInit().
[[noreturn]] void RaiseSelfTestBreakpoint();

} // namespace customos::arch
