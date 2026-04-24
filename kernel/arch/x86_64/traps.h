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

namespace duetos::arch
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

/// Called from isr_common. For CPU exceptions (vector < 32), looks
/// up the per-vector response policy via `TrapResponseFor` and acts
/// on it (LogAndContinue / IsolateTask / Panic). For IRQs
/// (32..47, plus the LAPIC spurious at 0xFF), routes through the
/// per-vector handler and returns. For spurious vectors (48..127,
/// 129..254), logs the offending number and returns. The path that
/// halts is the explicit `Panic` policy outcome — every other path
/// is recoverable.
extern "C" void TrapDispatch(TrapFrame* frame);

/// Per-CPU-exception response policy. Mirrors `core::HealthResponse`
/// from the runtime invariant checker — explicit per-class outcome
/// instead of "everything panics" so a recoverable trap (#BP from
/// an in-kernel breakpoint, #DB single-step) doesn't bring the
/// kernel down. Ring-3 hits always become IsolateTask regardless
/// of vector — the existing task-kill path remains the user-mode
/// fault contract; this enum is the kernel-mode policy table.
enum class TrapResponse : u8
{
    LogAndContinue, // Log + iretq. Used for #BP / #DB from kernel mode.
    IsolateTask,    // Kill the offending task + reschedule. Ring-3 default.
    Panic,          // Halt the kernel. Last resort for kernel-mode bugs.
};

/// Resolve a vector + ring to its policy. `from_user` is true iff
/// the saved CS's RPL == 3.
///   - User-mode (any vector): IsolateTask.
///   - Kernel-mode #BP / #DB:  LogAndContinue.
///   - Kernel-mode anything else: Panic.
TrapResponse TrapResponseFor(u64 vector, bool from_user);

/// Stable name for a TrapResponse value, for log lines.
const char* TrapResponseName(TrapResponse r);

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

/// Install (or replace) a handler for IRQ vector `vector`. Valid range
/// is [32, 254] — the ISA range 32..47, the MSI-X pool 48..239, plus
/// the LAPIC spurious vector (0xFF). Passing `nullptr` clears the
/// handler; the dispatcher then logs a one-line "unhandled IRQ"
/// message.
void IrqInstall(u8 vector, IrqHandler handler);

/// Allocate the next unused MSI-X vector from the pool [48, 239].
/// Returns 0 when the pool is exhausted — caller must check. The
/// allocator is monotonic (no reclaim in v0); real hardware fans
/// out fewer than a hundred MSI-X lines so the pool is wide enough
/// for the lifetime of a boot.
u8 IrqAllocVector();

/// Deliberately trigger int3 to verify the IDT path is wired up correctly.
/// Used only during early bring-up; remove from the boot sequence once
/// there's real work to do after IdtInit().
[[noreturn]] void RaiseSelfTestBreakpoint();

/// Boot-time confidence check for the slice-80 trap surface:
///   1. Issue `int3` from kernel mode. Verifies the dispatcher routes
///      #BP through TrapResponse::LogAndContinue + iretq instead of
///      halting. If the policy regresses, the kernel hangs here and
///      the boot log shows the panic banner instead of the
///      "[trap] #BP (recoverable)" line.
///   2. Issue `int 0x42`. Verifies vector 66 has a real IDT gate
///      installed by the spurious-vector stub block in exceptions.S
///      and that TrapDispatch's spurious branch logs + returns
///      instead of #NP-cascading or panicking.
///
/// Cheap (two interrupts), prints two log lines, returns. Call once
/// from kernel_main after IdtInit. Kept in `arch::` so the runtime-
/// checker can also invoke it on demand from the shell `health`
/// command for live re-verification.
void TrapsSelfTest();

/// Register the fault-fixup ranges this TU owns (user-copy
/// helpers) with the kernel extable. Call once at boot after
/// the IDT is loaded and after KernelExtable is usable.
void TrapsRegisterExtable();

/// Per-vector IRQ counter snapshot. Returns the cumulative count
/// of handler invocations for vector `v` since boot. Used by the
/// runtime checker's IRQ-storm detector to compute per-scan
/// deltas and raise an alarm when a single vector fires at a
/// rate above its expected ceiling. Indexing outside 0..255 is
/// a no-op returning 0.
u64 IrqCountForVector(u8 v);

/// Cumulative CPU-exception fault counts by category. Bumped
/// each time a fault dump runs (either user task-kill or
/// kernel panic). Used by diagnostic commands and health
/// telemetry to show "the system has had N access violations
/// since boot" without grepping the serial log.
struct FaultCounts
{
    u64 access_violation; // non-present #PF (read / write / exec)
    u64 nx_violation;     // present #PF with instr-fetch bit
    u64 write_to_ro;      // present #PF with write bit
    u64 stack_overflow;   // #PF with cr2 just below rsp
    u64 reserved_bit;     // page-table entry with reserved bit set
    u64 gp;               // #GP count
    u64 ud;               // #UD count
};
FaultCounts FaultCountsSnapshot();

} // namespace duetos::arch
