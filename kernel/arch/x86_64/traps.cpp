#include "traps.h"

#include "cpu.h"
#include "lapic.h"
#include "serial.h"

#include "../../core/panic.h"
#include "../../core/symbols.h"
#include "../../core/syscall.h"
#include "../../sched/sched.h"

namespace customos::arch
{

namespace
{

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
