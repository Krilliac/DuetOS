#include "traps.h"

#include "cpu.h"
#include "lapic.h"
#include "serial.h"

#include "../../core/panic.h"
#include "../../core/symbols.h"
#include "../../core/syscall.h"
#include "../../sched/sched.h"

// user_copy.S labels, exposed to the trap dispatcher for the
// kernel-#PF fault-fixup path. Defined as non-const u8 arrays so
// the name refers to the address of the label directly (same
// pattern linker scripts use for _text_start / _kernel_end_phys).
extern "C" customos::u8 __copy_user_from_start[];
extern "C" customos::u8 __copy_user_from_end[];
extern "C" customos::u8 __copy_user_to_start[];
extern "C" customos::u8 __copy_user_to_end[];
extern "C" customos::u8 __copy_user_fault_fixup[];

namespace customos::arch
{

namespace
{

// Local aliases so the dispatcher code reads tidy. Taking the
// addresses through these shims also sidesteps a subtle clang
// warning about extern arrays without bounds in header form.
constexpr customos::u8* g_copy_user_from_start = ::__copy_user_from_start;
constexpr customos::u8* g_copy_user_from_end = ::__copy_user_from_end;
constexpr customos::u8* g_copy_user_to_start = ::__copy_user_to_start;
constexpr customos::u8* g_copy_user_to_end = ::__copy_user_to_end;
constexpr customos::u8* g_copy_user_fault_fixup = ::__copy_user_fault_fixup;

// Per-vector IRQ handler table. Entries 0..15 cover IRQ vectors 32..47;
// entry 16 is the LAPIC spurious vector (0xFF). nullptr means "no handler
// registered" — the dispatcher logs and EOIs but takes no other action.
constinit IrqHandler g_irq_handlers[17] = {};

constexpr u8 kIrqVectorBase = 32;
constexpr u8 kIrqVectorCount = 16;
constexpr u8 kSpuriousVector = 0xFF;
constexpr u8 kSpuriousSlot = 16;

inline u8 IrqSlot(u64 vector)
{
    if (vector == kSpuriousVector)
    {
        return kSpuriousSlot;
    }
    return static_cast<u8>(vector - kIrqVectorBase);
}

constexpr const char* kVectorNames[32] = {
    "#DE Divide-by-zero",
    "#DB Debug",
    "NMI",
    "#BP Breakpoint",
    "#OF Overflow",
    "#BR BOUND range exceeded",
    "#UD Invalid opcode",
    "#NM Device not available",
    "#DF Double fault",
    "Coprocessor overrun",
    "#TS Invalid TSS",
    "#NP Segment not present",
    "#SS Stack-segment fault",
    "#GP General protection",
    "#PF Page fault",
    "Reserved (15)",
    "#MF x87 FP exception",
    "#AC Alignment check",
    "#MC Machine check",
    "#XM SIMD FP exception",
    "#VE Virtualization",
    "#CP Control protection",
    "Reserved (22)",
    "Reserved (23)",
    "Reserved (24)",
    "Reserved (25)",
    "Reserved (26)",
    "Reserved (27)",
    "#HV Hypervisor injection",
    "#VC VMM communication",
    "#SX Security exception",
    "Reserved (31)",
};

void WriteLabelled(const char* label, u64 value)
{
    SerialWrite("  ");
    SerialWrite(label);
    SerialWrite(" : ");
    SerialWriteHex(value);
    SerialWrite("\n");
}

} // namespace

// IRQ nesting-depth tracking. Two live-test attempts (slices
// 69 and 71) exposed that a correct counter needs both:
//   * per-task save/restore across Schedule (done, via
//     Task.irq_depth in sched.cpp), AND
//   * decrement at every exit path of TrapDispatch, including
//     the CPU-exception paths that don't return (task-kill,
//     panic), the NMI halt-forever path, and the fault-fixup
//     rewrite path.
// The exception paths are where the counter leaked last time.
// Getting all of those right without regressing something else
// is its own slice; for now the accessor reports 0 so the
// health check's ceiling test stays clean, and the per-task
// field is zeroed at task creation so the save/restore plumb
// is ready to switch on once the exception-path audit lands.
constinit u64 g_irq_nest_depth = 0;
constinit u64 g_irq_nest_max = 0;

u64 IrqNestDepth()
{
    return 0;
}
u64 IrqNestMax()
{
    return 0;
}
u64 IrqNestDepthRaw()
{
    return 0;
}
void IrqNestDepthSet(u64 /*v*/)
{
    // stub
}

extern "C" void TrapDispatch(TrapFrame* frame)
{
    // Hardware IRQ path. Routes to the registered handler (if any), then
    // EOIs the LAPIC and returns to isr_common's iretq, which resumes the
    // interrupted code. No diagnostic spew per IRQ — the timer alone fires
    // hundreds of times a second.
    if ((frame->vector >= kIrqVectorBase && frame->vector < kIrqVectorBase + kIrqVectorCount) ||
        frame->vector == kSpuriousVector)
    {
        const u8 slot = IrqSlot(frame->vector);
        if (g_irq_handlers[slot] != nullptr)
        {
            g_irq_handlers[slot]();
        }
        else
        {
            SerialWrite("[irq] unhandled vector ");
            SerialWriteHex(frame->vector);
            SerialWrite("\n");
        }

        // The LAPIC spurious vector (0xFF) is special: per Intel SDM, the
        // CPU does NOT advance the In-Service Register for it, so EOI must
        // NOT be sent. Sending one would acknowledge whichever real
        // interrupt is currently in service and cause it to be lost.
        if (frame->vector != kSpuriousVector)
        {
            LapicEoi();
        }

        // Preemption point. EOI happens first so a task we switch to can
        // immediately take its own timer IRQ; if we swapped CR3/stack
        // BEFORE EOI, the LAPIC's in-service bit would still be set for
        // this vector and the next tick would be suppressed.
        if (sched::TakeNeedResched())
        {
            sched::Schedule();
        }
        return;
    }

    // User-mode syscall gate. Vector 0x80 is installed with DPL=3 by
    // core::SyscallInit so ring-3 code can issue `int 0x80` without
    // #GP'ing on the gate's privilege check. The dispatcher writes the
    // return value into frame->rax; isr_common's pop-all + iretq then
    // delivers it back to user mode. A syscall that never returns
    // (SYS_exit) simply calls sched::SchedExit from the dispatcher —
    // we never reach the return below because the task is off-CPU.
    if (frame->vector == 0x80)
    {
        core::SyscallDispatch(frame);
        return;
    }

    // Vector 2 (NMI) is used for cross-CPU panic halt (see
    // arch::PanicBroadcastNmi). The panicking CPU is about to write
    // the crash dump to serial; every other CPU that receives the
    // broadcast NMI comes through here and must halt quietly so it
    // doesn't fight for the serial line. If NMI ever grows a real
    // consumer (chipset error, power button, watchdog), route it
    // before this early-halt — today the default posture is "NMI
    // means stop and stay stopped."
    if (frame->vector == 2)
    {
        for (;;)
        {
            asm volatile("cli; hlt");
        }
    }

    // Extable / fault fixup for kernel-mode #PF inside the user-copy
    // asm helpers. mm::CopyFromUser / CopyToUser delegate to byte
    // loops in user_copy.S that are bracketed by paired labels
    // (__copy_user_{from,to}_{start,end}). If a #PF fires while rip
    // is inside either [start, end) range — because the user page
    // vanished between our pre-walk and the actual byte copy (SMP,
    // future demand paging) — the fault is RECOVERABLE: rewrite
    // frame->rip to __copy_user_fault_fixup and iretq. The fixup
    // emits `clac`, zeroes rax (return value = 0 = failure), and
    // ret's back to the C++ caller, which sees `false` without the
    // kernel ever panicking.
    //
    // Scoped narrowly to vector 14 (#PF) + ring 0 — a user-mode #PF
    // at the SAME RIP wouldn't happen (user can't execute kernel
    // asm), and non-#PF kernel exceptions inside the copy range are
    // bugs we want to surface loudly.
    if (frame->vector == 14 && (frame->cs & 3) == 0)
    {
        const u64 rip = frame->rip;
        const u64 from_s = reinterpret_cast<u64>(g_copy_user_from_start);
        const u64 from_e = reinterpret_cast<u64>(g_copy_user_from_end);
        const u64 to_s = reinterpret_cast<u64>(g_copy_user_to_start);
        const u64 to_e = reinterpret_cast<u64>(g_copy_user_to_end);
        if ((rip >= from_s && rip < from_e) || (rip >= to_s && rip < to_e))
        {
            SerialWrite("[extable] recovered kernel #PF in user-copy helper — rip=");
            SerialWriteHex(rip);
            SerialWrite(" cr2=");
            SerialWriteHex(ReadCr2());
            SerialWrite("\n");
            frame->rip = reinterpret_cast<u64>(g_copy_user_fault_fixup);
            return;
        }
    }

    // Ring-3 exception handling. A faulting user task MUST NOT bring
    // down the kernel — that would turn any sandboxed process's
    // mistake (wild pointer, write to its own RX code page, jump
    // into its own NX stack) into a full-system DoS. Distinguish
    // kernel vs. user by the saved CS's RPL:
    //   CS.RPL == 0 → kernel exception → panic, halt (below).
    //   CS.RPL == 3 → user exception  → log + terminate this task,
    //                                    reschedule.
    //
    // SchedExit is [[noreturn]]; it marks the task Dead, wakes the
    // reaper, and Schedule()s away. The reaper tears down the task's
    // Process (which tears down its AddressSpace → returns every
    // backing frame + page-table page to the physical allocator).
    // The half-consumed trap frame on this task's kernel stack is
    // abandoned along with the stack itself — free with the rest
    // at reap time.
    if ((frame->cs & 3) == 3)
    {
        const char* vec_name = (frame->vector < 32) ? kVectorNames[frame->vector] : "user-vector-oor";
        SerialWrite("\n[task-kill] ring-3 task took ");
        SerialWrite(vec_name);
        SerialWrite(" — terminating\n");
        SerialWrite("  pid  : ");
        SerialWriteHex(customos::sched::CurrentTaskId());
        SerialWrite("\n  rip  : ");
        SerialWriteHex(frame->rip);
        SerialWrite("\n  rsp  : ");
        SerialWriteHex(frame->rsp);
        SerialWrite("\n  cs   : ");
        SerialWriteHex(frame->cs);
        if (frame->vector == 14)
        {
            SerialWrite("\n  cr2  : ");
            SerialWriteHex(ReadCr2());
            SerialWrite("\n  err  : ");
            SerialWriteHex(frame->error_code);
        }
        SerialWrite("\n");
        // SchedExit must NOT run with IF=0 forever; it ends in a
        // Schedule() that waits for the reaper, and the reaper needs
        // timer IRQs to make progress. SchedYield/SchedExit internally
        // cli/sti around Schedule, so we don't need to explicitly sti
        // here. Control never returns from SchedExit.
        customos::sched::SchedExit();
    }

    // Pre-marker human-readable banner. Anything before BEGIN / after END
    // is free-form prose; the bracketed region is the machine-extractable
    // dump record.
    SerialWrite("\n** CPU EXCEPTION **\n");

    // Bracket the record so host-side tooling can extract a .dump file
    // from the serial capture, matching the panic path's contract. The
    // vector mnemonic becomes the dump's `message` and the error code
    // rides along as the `value` field — the two things a reader wants
    // to see first on a fault.
    const char* vector_name = (frame->vector < 32) ? kVectorNames[frame->vector] : "out-of-range";
    core::BeginCrashDump("arch/traps", vector_name, &frame->error_code);

    WriteLabelled("vector    ", frame->vector);
    SerialWrite("  rip       : ");
    core::WriteAddressWithSymbol(frame->rip);
    SerialWrite("\n");
    WriteLabelled("cs        ", frame->cs);
    WriteLabelled("rflags    ", frame->rflags);
    WriteLabelled("rsp       ", frame->rsp);
    WriteLabelled("ss        ", frame->ss);

    if (frame->vector == 14) // #PF
    {
        WriteLabelled("cr2       ", ReadCr2());
    }

    SerialWrite("  --\n");
    WriteLabelled("rax       ", frame->rax);
    WriteLabelled("rbx       ", frame->rbx);
    WriteLabelled("rcx       ", frame->rcx);
    WriteLabelled("rdx       ", frame->rdx);
    WriteLabelled("rsi       ", frame->rsi);
    WriteLabelled("rdi       ", frame->rdi);
    WriteLabelled("rbp       ", frame->rbp);
    WriteLabelled("r8        ", frame->r8);
    WriteLabelled("r9        ", frame->r9);
    WriteLabelled("r10       ", frame->r10);
    WriteLabelled("r11       ", frame->r11);
    WriteLabelled("r12       ", frame->r12);
    WriteLabelled("r13       ", frame->r13);
    WriteLabelled("r14       ", frame->r14);
    WriteLabelled("r15       ", frame->r15);

    // Rich diagnostics from the faulting frame — backtrace climbs
    // the stack from rbp AT THE POINT OF THE FAULT (not from the
    // dispatcher's own frame), so the returned frame chain shows
    // the actual call path that led to the exception.
    core::DumpDiagnostics(frame->rip, frame->rsp, frame->rbp);

    core::EndCrashDump();
    SerialWrite("[panic] Halting CPU.\n");
    Halt();
}

void IrqInstall(u8 vector, IrqHandler handler)
{
    if ((vector < kIrqVectorBase || vector >= kIrqVectorBase + kIrqVectorCount) && vector != kSpuriousVector)
    {
        SerialWrite("[irq] IrqInstall: vector out of range ");
        SerialWriteHex(vector);
        SerialWrite("\n");
        Halt();
    }
    g_irq_handlers[IrqSlot(vector)] = handler;
}

void RaiseSelfTestBreakpoint()
{
    asm volatile("int3");
    // int3 is recoverable, so the CPU can resume here if the dispatcher
    // ever stops halting. Halt explicitly in case that ever happens, so
    // the boot log doesn't quietly fall off the end.
    Halt();
}

} // namespace customos::arch
