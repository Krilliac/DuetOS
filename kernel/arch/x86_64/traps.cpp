#include "traps.h"

#include "cpu.h"
#include "serial.h"

namespace customos::arch
{

namespace
{

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
    SerialWrite("\n** CPU EXCEPTION **\n");

    WriteLabelled("vector    ", frame->vector);
    SerialWrite("             (");
    if (frame->vector < 32)
    {
        SerialWrite(kVectorNames[frame->vector]);
    }
    else
    {
        SerialWrite("out-of-range");
    }
    SerialWrite(")\n");

    WriteLabelled("error_code", frame->error_code);
    WriteLabelled("rip       ", frame->rip);
    WriteLabelled("cs        ", frame->cs);
    WriteLabelled("rflags    ", frame->rflags);
    WriteLabelled("rsp       ", frame->rsp);
    WriteLabelled("ss        ", frame->ss);

    if (frame->vector == 14)    // #PF
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

    SerialWrite("[panic] Halting CPU.\n");
    Halt();
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
