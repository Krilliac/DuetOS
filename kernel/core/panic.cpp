#include "panic.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "../cpu/percpu.h"

namespace customos::core
{

namespace
{

void WriteLabelled(const char* label, u64 value)
{
    arch::SerialWrite("  ");
    arch::SerialWrite(label);
    arch::SerialWrite(" : ");
    arch::SerialWriteHex(value);
    arch::SerialWrite("\n");
}

// A candidate stack address is "plausible" if it's non-zero,
// 8-byte aligned, and lives in a region where the current kernel
// could reasonably have a stack. Two such regions today:
//   1. Higher-half kernel VA (>= 0xFFFF_8000_0000_0000).
//      Every heap-allocated task stack is here.
//   2. Low identity-mapped kernel range (< 1 GiB).
//      The boot task's stack comes from boot.S's bootstrap .bss,
//      which lives below 1 MiB physical and is identity-mapped.
// Once userland lands the low-half check will be replaced with
// something more precise (per-process address-space range).
bool PlausibleStackPointer(u64 addr)
{
    if (addr == 0)
    {
        return false;
    }
    if ((addr & 0x7) != 0)
    {
        return false;
    }
    if (addr >= 0xFFFF800000000000ULL)
    {
        return true; // higher-half kernel
    }
    if (addr < 0x40000000ULL)
    {
        return true; // low 1 GiB identity map (boot stack)
    }
    return false;
}

// Walk the RBP chain and log up to 16 return addresses. Each stack
// frame (System V AMD64 ABI) lays out:
//     [rbp+0]  saved RBP of caller
//     [rbp+8]  return address
// So follow the chain via `[rbp]` and emit `[rbp+8]` each step.
//
// Each deref is guarded by PlausibleStackPointer — corrupted stacks
// routinely lead backtrace walkers into unmapped pages where a
// #PF-during-panic would triple-fault and lose the banner.
void DumpBacktrace(u64 rbp)
{
    arch::SerialWrite("  backtrace (up to 16 frames, innermost first):\n");
    for (int depth = 0; depth < 16; ++depth)
    {
        if (!PlausibleStackPointer(rbp))
        {
            arch::SerialWrite("    [end of chain]\n");
            return;
        }
        const u64 saved_rbp = *reinterpret_cast<const u64*>(rbp);
        const u64 ret_addr = *reinterpret_cast<const u64*>(rbp + 8);
        arch::SerialWrite("    #");
        arch::SerialWriteHex(static_cast<u64>(depth));
        arch::SerialWrite("  rip=");
        arch::SerialWriteHex(ret_addr);
        arch::SerialWrite(" rbp=");
        arch::SerialWriteHex(rbp);
        arch::SerialWrite("\n");
        if (saved_rbp <= rbp)
        {
            // RBP must strictly increase as we walk up; anything else
            // means the chain's been corrupted or we hit the bottom.
            arch::SerialWrite("    [chain stopped climbing]\n");
            return;
        }
        rbp = saved_rbp;
    }
    arch::SerialWrite("    [depth limit reached]\n");
}

// Dump the first N 8-byte quads starting at RSP. Useful for seeing
// the live state of the stack around a crash — local variables,
// spilled registers, return addresses that frame-pointer walking
// might have missed.
void DumpStack(u64 rsp, int count)
{
    arch::SerialWrite("  stack (");
    arch::SerialWriteHex(static_cast<u64>(count));
    arch::SerialWrite(" quads from rsp):\n");
    for (int i = 0; i < count; ++i)
    {
        const u64 addr = rsp + static_cast<u64>(i) * 8;
        if (!PlausibleStackPointer(addr))
        {
            break;
        }
        const u64 value = *reinterpret_cast<const u64*>(addr);
        arch::SerialWrite("    [");
        arch::SerialWriteHex(addr);
        arch::SerialWrite("] = ");
        arch::SerialWriteHex(value);
        arch::SerialWrite("\n");
    }
}

void DumpTask()
{
    // Only safe once PerCpu is installed; before that GSBASE is zero
    // and CurrentCpu() would deref null. The g_bsp_installed flag is
    // encapsulated by CurrentCpuIdOrBsp — if that returns 0 AND the
    // underlying struct isn't set, skip the per-task report.
    cpu::PerCpu* pcpu = cpu::CurrentCpu();
    if (pcpu == nullptr)
    {
        return;
    }
    WriteLabelled("cpu_id   ", static_cast<u64>(pcpu->cpu_id));
    WriteLabelled("lapic_id ", static_cast<u64>(pcpu->lapic_id));

    // current_task is nullable — can be null on a CPU that hasn't run
    // SchedInit yet (BSP before SchedInit, or an AP that hasn't joined
    // the scheduler).
    sched::Task* task = pcpu->current_task;
    if (task != nullptr)
    {
        // Task layout is file-local to sched.cpp; we only touch it via
        // forward-declared opaque pointer here. No field access until
        // sched exposes an accessor. Print the pointer; let the operator
        // cross-reference against the [sched] created-task log lines.
        WriteLabelled("task_ptr ", reinterpret_cast<u64>(task));
    }
}

} // namespace

void DumpDiagnostics(u64 rip, u64 rsp, u64 rbp)
{
    arch::SerialWrite("[panic] --- diagnostics ---\n");
    WriteLabelled("uptime   ", arch::TimerTicks());
    DumpTask();
    WriteLabelled("rip      ", rip);
    WriteLabelled("rsp      ", rsp);
    WriteLabelled("rbp      ", rbp);
    WriteLabelled("cr0      ", arch::ReadCr0());
    WriteLabelled("cr2      ", arch::ReadCr2());
    WriteLabelled("cr3      ", arch::ReadCr3());
    WriteLabelled("cr4      ", arch::ReadCr4());
    WriteLabelled("rflags   ", arch::ReadRflags());
    WriteLabelled("efer     ", arch::ReadEfer());
    DumpBacktrace(rbp);
    DumpStack(rsp, 16);
}

void Panic(const char* subsystem, const char* message)
{
    // Disable interrupts before writing the banner so a pending IRQ
    // can't preempt us mid-message and scramble the output. Halt
    // itself also CLI+HLT loops, but getting the clean banner out
    // first matters for diagnosis.
    arch::Cli();

    arch::SerialWrite("\n[panic] ");
    arch::SerialWrite(subsystem);
    arch::SerialWrite(": ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n");

    // Dump diagnostics using the panic call site's own frame. Reading
    // RBP/RSP here captures the state of Panic() itself; the backtrace
    // walker then climbs up through the caller.
    DumpDiagnostics(reinterpret_cast<u64>(__builtin_return_address(0)), arch::ReadRsp(), arch::ReadRbp());

    arch::SerialWrite("[panic] CPU halted — no recovery.\n");
    arch::Halt();
}

void PanicWithValue(const char* subsystem, const char* message, u64 value)
{
    arch::Cli();

    arch::SerialWrite("\n[panic] ");
    arch::SerialWrite(subsystem);
    arch::SerialWrite(": ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n  value    : ");
    arch::SerialWriteHex(value);
    arch::SerialWrite("\n");

    DumpDiagnostics(reinterpret_cast<u64>(__builtin_return_address(0)), arch::ReadRsp(), arch::ReadRbp());

    arch::SerialWrite("[panic] CPU halted — no recovery.\n");
    arch::Halt();
}

} // namespace customos::core
