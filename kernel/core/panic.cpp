#include "panic.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/nmi_watchdog.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smp.h"
#include "../arch/x86_64/timer.h"
#include "../cpu/percpu.h"
#include "../debug/probes.h"
#include "diag_decode.h"
#include "hexdump.h"
#include "klog.h"
#include "symbols.h"

/*
 * Panic / crash-dump output.
 *
 * Every halt path emits a self-contained crash dump bracketed by:
 *
 *     === DUETOS CRASH DUMP BEGIN ===
 *     ...
 *     === DUETOS CRASH DUMP END ===
 *
 * on COM1. Host-side tooling (`tools/test-panic.sh` today, a
 * post-mortem harness later) captures the bytes between the markers
 * into a file — that is the "dump file" the crash system produces,
 * given DuetOS has no persistent filesystem yet.
 *
 * Every address reachable through the embedded symbol table is
 * annotated inline with
 *
 *     0xADDRESS  [function+0xOFF (kernel/path/file.cpp:LINE)]
 *
 * so a dump is readable without re-running a symbolizer. Addresses
 * we cannot resolve (asm trampolines, early-boot stack data, user-
 * mode RIPs) fall back to bare hex — we never fabricate a symbol.
 */

namespace duetos::core
{

namespace
{

constexpr const char* kDumpBeginMarker = "=== DUETOS CRASH DUMP BEGIN ===\n";
constexpr const char* kDumpEndMarker = "=== DUETOS CRASH DUMP END ===\n";

// u16 schema version of the dump record. Bump whenever the layout of
// lines between BEGIN/END changes in a way a parser would care about.
// Host-side tools should read this first line and refuse dumps from a
// newer kernel than they know.
constexpr u64 kDumpSchemaVersion = 1;

void WriteLabelled(const char* label, u64 value)
{
    arch::SerialWrite("  ");
    arch::SerialWrite(label);
    arch::SerialWrite(" : ");
    arch::SerialWriteHex(value);
    arch::SerialWrite("\n");
}

// Like WriteLabelled, but also annotates the value with
// function+offset and source location if it resolves against the
// embedded symbol table. Used for RIP and other code-ish registers
// (the x86_64 return-address slots in the stack dump).
void WriteLabelledCode(const char* label, u64 value)
{
    arch::SerialWrite("  ");
    arch::SerialWrite(label);
    arch::SerialWrite(" : ");
    WriteAddressWithSymbol(value);
    WriteVaRegion(value);
    arch::SerialWrite("\n");
}

// Like WriteLabelled but appends the VA-region tag, e.g.
//     rsp      : 0xFFFFFFFFE0001FF8 [region=k.stack-arena]
// Used for raw VAs that aren't expected to be code (rsp / rbp) and
// for cr2 on a #PF — both cases benefit from "what region IS this?"
// annotation that the bare hex doesn't convey.
void WriteLabelledVa(const char* label, u64 value)
{
    arch::SerialWrite("  ");
    arch::SerialWrite(label);
    arch::SerialWrite(" : ");
    arch::SerialWriteHex(value);
    WriteVaRegion(value);
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
        WriteAddressWithSymbol(ret_addr);
        arch::SerialWrite("\n            rbp=");
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
// might have missed. Each quad is run through the symbol table so
// saved return addresses auto-label even when RBP-walking missed
// them.
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
        WriteAddressWithSymbol(value);
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
        WriteLabelled("task_ptr ", reinterpret_cast<u64>(task));
        // Resolve the task to its human-readable name and id so the
        // operator doesn't have to cross-reference the pointer
        // against earlier `[sched] created-task` lines.
        arch::SerialWrite("  task     : ");
        WriteCurrentTaskLabel();
        arch::SerialWrite("\n");
    }
}

} // namespace

void BeginCrashDump(const char* subsystem, const char* message, const u64* optional_value)
{
    arch::SerialWrite("\n");
    arch::SerialWrite(kDumpBeginMarker);
    WriteLabelled("version  ", kDumpSchemaVersion);
    arch::SerialWrite("  subsystem: ");
    arch::SerialWrite(subsystem);
    arch::SerialWrite("\n  message  : ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n");
    if (optional_value != nullptr)
    {
        WriteLabelled("value    ", *optional_value);
    }
    WriteLabelled("symtab_entries", SymbolTableSize());
}

void EndCrashDump()
{
    arch::SerialWrite(kDumpEndMarker);
}

void DumpDiagnostics(u64 rip, u64 rsp, u64 rbp)
{
    arch::SerialWrite("[panic] --- diagnostics ---\n");
    // Wall-clock time since boot, rendered as ms / s / m+s. The raw
    // tick count still goes out as the dump's `uptime` line so a
    // host-side parser sees a stable hex value, but the readable
    // form is what an operator scans first.
    WriteLabelled("uptime   ", arch::TimerTicks());
    arch::SerialWrite("  uptime   : ");
    WriteUptimeReadable();
    arch::SerialWrite(" since boot\n");
    DumpTask();
    WriteLabelledCode("rip      ", rip);
    WriteLabelledVa("rsp      ", rsp);
    WriteLabelledVa("rbp      ", rbp);

    // Control + flags registers. Each line carries the raw hex
    // (existing schema) plus a bracket-list naming the bits that
    // are set, so a reader doesn't have to decode `0x80050033` in
    // their head to see PE / WP / PG enabled.
    const u64 cr0 = arch::ReadCr0();
    const u64 cr2 = arch::ReadCr2();
    const u64 cr3 = arch::ReadCr3();
    const u64 cr4 = arch::ReadCr4();
    const u64 rflags = arch::ReadRflags();
    const u64 efer = arch::ReadEfer();
    arch::SerialWrite("  cr0      : ");
    arch::SerialWriteHex(cr0);
    WriteCr0Bits(cr0);
    arch::SerialWrite("\n");
    // CR2 outside a #PF is stale (it holds the last faulting VA the
    // CPU latched), but the region tag is still informative — a
    // panic in a code path that stalls on a guard-page touch will
    // show `k.stack-arena` here, for instance.
    WriteLabelledVa("cr2      ", cr2);
    arch::SerialWrite("  cr3      : ");
    arch::SerialWriteHex(cr3);
    WriteCr3Decoded(cr3);
    arch::SerialWrite("\n");
    arch::SerialWrite("  cr4      : ");
    arch::SerialWriteHex(cr4);
    WriteCr4Bits(cr4);
    arch::SerialWrite("\n");
    arch::SerialWrite("  rflags   : ");
    arch::SerialWriteHex(rflags);
    WriteRflagsBits(rflags);
    arch::SerialWrite("\n");
    arch::SerialWrite("  efer     : ");
    arch::SerialWriteHex(efer);
    WriteEferBits(efer);
    arch::SerialWrite("\n");
    // A blown IST stack is one of the quietest ways a kernel can
    // die — silently corrupts neighbouring BSS and shows up as
    // mystery data corruption later. Surface it explicitly here
    // so a canary violation is named, not debugged from entrails.
    arch::SerialWrite("  ist_canary : ");
    arch::SerialWrite(arch::IstStackCanariesIntact() ? "ok" : "CORRUPT");
    arch::SerialWrite("\n");
    // Instruction bytes at RIP. Guards against faulting-page reads
    // via PlausibleKernelAddress; a wild RIP simply emits a
    // skipped-line and diagnostics continue.
    DumpInstructionBytes("panic-rip", rip, 16);
    DumpBacktrace(rbp);
    DumpStack(rsp, 16);
    DumpLogRing();
    DumpInflightScopes();
}

void Panic(const char* subsystem, const char* message)
{
    // Probe before disabling interrupts so the log line hits the
    // ring buffer with a valid timestamp. Armed-log by default —
    // `[probe] panic.enter rip=...` tells you who called Panic.
    KBP_PROBE(::duetos::debug::ProbeId::kPanicEnter);

    // Disable interrupts before writing the banner so a pending IRQ
    // can't preempt us mid-message and scramble the output. Halt
    // itself also CLI+HLT loops, but getting the clean banner out
    // first matters for diagnosis.
    arch::Cli();
    // Silence the NMI watchdog. The crash-dump path can take
    // longer than one watchdog interval (serial write is slow,
    // symbol resolution walks the embedded table) and we don't
    // want a PMI overflow re-entering the trap dispatcher while
    // DumpDiagnostics is writing.
    arch::NmiWatchdogDisable();

    // Broadcast NMI to peer CPUs so they stop fighting for the
    // serial line / executing against potentially-corrupt shared
    // state. Peers halt quietly in the trap dispatcher's NMI
    // short-circuit. No-op pre-LapicInit.
    arch::PanicBroadcastNmi();

    arch::SerialWrite("\n[panic] ");
    arch::SerialWrite(subsystem);
    arch::SerialWrite(": ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n");

    BeginCrashDump(subsystem, message, nullptr);

    // Dump diagnostics using the panic call site's own frame. Reading
    // RBP/RSP here captures the state of Panic() itself; the backtrace
    // walker then climbs up through the caller.
    DumpDiagnostics(reinterpret_cast<u64>(__builtin_return_address(0)), arch::ReadRsp(), arch::ReadRbp());

    EndCrashDump();
    arch::SerialWrite("[panic] CPU halted — no recovery.\n");
    arch::Halt();
}

void PanicWithValue(const char* subsystem, const char* message, u64 value)
{
    arch::Cli();
    arch::NmiWatchdogDisable();
    arch::PanicBroadcastNmi();

    arch::SerialWrite("\n[panic] ");
    arch::SerialWrite(subsystem);
    arch::SerialWrite(": ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n  value    : ");
    arch::SerialWriteHex(value);
    arch::SerialWrite("\n");

    BeginCrashDump(subsystem, message, &value);

    DumpDiagnostics(reinterpret_cast<u64>(__builtin_return_address(0)), arch::ReadRsp(), arch::ReadRbp());

    EndCrashDump();
    arch::SerialWrite("[panic] CPU halted — no recovery.\n");
    arch::Halt();
}

} // namespace duetos::core
