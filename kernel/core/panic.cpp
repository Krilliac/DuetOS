#include "core/panic.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/lbr.h"
#include "arch/x86_64/nmi_watchdog.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/timer.h"
#include "time/tick.h"
#include "cpu/percpu.h"
#include "debug/probes.h"
#include "net/wireless/wifi_diag.h"
#include "diag/diag_decode.h"
#include "diag/soft_lockup.h"
#include "diag/hexdump.h"
#include "diag/minidump.h"
#include "loader/dll_loader.h"
#include "loader/pe_exports.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "util/build_config.h"
#include "util/symbols.h"

/*
 * Panic / crash-dump output.
 *
 * Every halt path emits a self-contained crash dump bracketed by:
 *
 *     === DUETOS CRASH DUMP BEGIN ===
 *     ...
 *     === DUETOS CRASH DUMP END ===
 *
 * on COM1. Host-side tooling (`tools/debug/test-panic.sh` today, a
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
//
// v2 (2026-05-03): added "return-address pointers" section between
// the raw stack-quad dump and the held-locks section. Each line is
// of shape `[slot] -> value [name+0xOFF (file:line)] [region=...]`
// and lists only stack slots whose value resolves to a kernel
// symbol — a focused pointer-to-return-address scan that
// complements the rbp-chain backtrace and the 16-quad raw dump.
//
// v3 (2026-05-03): page-walk block emitted for cr2 (when non-zero)
// and rip after the register dump and before the backtrace. Each
// emitted level reads as
//     PML4[0xIDX] = 0xENTRY [P|RW|...|NX]
// terminating in `-> phys=0x...` for a successful walk or
// `-> stop: <reason>` (NotPresent at level / non-canonical /
// out-of-direct-map). Answers "why did this fault?" without
// forcing the operator to walk by hand.
//
// v4 (2026-05-03): LBR (Architectural Last-Branch-Records)
// section emitted between the return-address-pointer scan and
// the held-locks block. On Intel CPUs that support
// CPUID.7.0.EDX[19] (Goldmont Plus / Ice Lake / etc.) it lists
// each captured `from -> to` branch with both addresses
// symbolized. On TCG QEMU / pre-Goldmont-Plus / AMD it emits
// a single "(unavailable)" line so the section's absence is
// explicit.
//
// v5 (2026-05-03): per-task syscall trail (last 8 syscalls)
// emitted after the LBR block, only when the current task has
// recorded entries (kernel-only tasks stay silent). Each line
// is `[idx] abi=<ABI> nr=0xN args=(0xN,0xN,0xN,0xN) -> ret=0xN tick=0xN`.
//
// v6 (2026-05-03): per-process VM info block emitted after the
// syscall trail, only when CurrentProcess is non-null. Lists
// pid + name, AddressSpace pml4_phys + region count + budget,
// vmap span (min/max mapped user VA), and the loaded-DLL
// table (name + base_va..base_va+size per entry). Lets a
// reader resolve a user-space rip against the right module
// without a separate symbolizer pass.
constexpr u64 kDumpSchemaVersion = 6;

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

// Scan a wider window of the kernel stack than DumpStack (which
// caps at 16 quads) and emit only the slots whose value resolves
// against the embedded symbol table. Each surviving line lists
// the stack address of the slot — the *pointer to the return
// address* — alongside the resolved target. Useful when:
//
//   - DumpBacktrace's rbp chain stops short (frame-pointer-omitted
//     leaf functions, corrupted saved-rbp link, hand-written asm
//     thunks that don't keep an rbp record),
//   - DumpStack's 16-quad window doesn't reach the real call sites
//     (locals + spilled registers consume the first frame),
//   - an investigator wants the slot pointer itself to correlate
//     against rsp+offset for tampering analysis.
//
// 0x80 quads = 1 KiB, comfortably within a 16 KiB kernel stack;
// PlausibleStackPointer halts the scan cleanly if rsp is wild
// instead of dereffing into an unmapped page.
void DumpReturnAddressPointers(u64 rsp)
{
    constexpr int kScanQuads = 0x80;
    arch::SerialWrite("  return-address pointers (scan of ");
    arch::SerialWriteHex(static_cast<u64>(kScanQuads));
    arch::SerialWrite(" quads from rsp):\n");
    int found = 0;
    for (int i = 0; i < kScanQuads; ++i)
    {
        const u64 slot = rsp + static_cast<u64>(i) * 8;
        if (!PlausibleStackPointer(slot))
        {
            break;
        }
        const u64 value = *reinterpret_cast<const u64*>(slot);
        SymbolResolution res{};
        if (!ResolveAddress(value, &res))
        {
            continue;
        }
        arch::SerialWrite("    [");
        arch::SerialWriteHex(slot);
        arch::SerialWrite("] -> ");
        arch::SerialWriteHex(value);
        WriteResolvedAddress(res);
        WriteVaRegion(value);
        arch::SerialWrite("\n");
        ++found;
    }
    if (found == 0)
    {
        arch::SerialWrite("    (none)\n");
    }
}

// Dump the per-CPU Architectural LBR ring. On hardware that
// supports the feature each entry is `from -> to` with both
// addresses symbolized when they fall inside known kernel
// functions. Entry 0 is the youngest branch — i.e. the most
// recent jump/call/ret/branch the CPU took before LbrFreeze
// silenced further captures. Sees through frame-pointer omission,
// asm thunks, and rbp-chain corruption because the records are
// the CPU's own ground truth.
//
// On TCG QEMU and pre-Goldmont-Plus Intel parts (and AMD), LBR
// is unavailable. The dump emits a single "(LBR unavailable...)"
// line so the section's absence isn't ambiguous.
void DumpLbr()
{
    if (!arch::LbrAvailable())
    {
        arch::SerialWrite("  LBR (last-branch records): (unavailable on this CPU)\n");
        return;
    }
    arch::LbrSnapshot snap;
    arch::LbrCapture(snap);
    arch::SerialWrite("  LBR (last-branch records, ");
    arch::SerialWriteHex(static_cast<u64>(snap.depth));
    arch::SerialWrite(" entries, newest first; ctl=");
    arch::SerialWriteHex(snap.ctl_at_capture);
    arch::SerialWrite("):\n");
    if (snap.depth == 0)
    {
        arch::SerialWrite("    (no entries)\n");
        return;
    }
    for (u32 i = 0; i < snap.depth; ++i)
    {
        // Skip empty slots — silicon may report depth N but only
        // N-k populated records (e.g. fewer than depth taken
        // branches since LBR was enabled).
        if (snap.from[i] == 0 && snap.to[i] == 0)
        {
            continue;
        }
        arch::SerialWrite("    #");
        arch::SerialWriteHex(static_cast<u64>(i));
        arch::SerialWrite("  from=");
        WriteAddressWithSymbol(snap.from[i]);
        arch::SerialWrite("\n         to  =");
        WriteAddressWithSymbol(snap.to[i]);
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

// Dump the current process's VM info: pid, name, AS pointer +
// region count, vmap min/max VA, and the loaded-DLL table.
// No-op for kernel-only tasks (CurrentProcess returns null) —
// the section's absence is itself a signal that the panic
// happened in a kernel thread, not a user process.
//
// Why this matters: bare hex `rip=0x...` plus `[region=
// user-canonical]` tells the operator "this fault is in user
// space" but not WHICH binary. With the DLL table, an rip in
// the range of `kernel32.dll` reads as exactly that — even
// before the operator runs an off-box symbolizer.
void DumpProcessVmInfo()
{
    Process* proc = CurrentProcess();
    if (proc == nullptr)
    {
        return;
    }
    arch::SerialWrite("  process VM info:\n    pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(proc->name != nullptr ? proc->name : "<noname>");
    arch::SerialWrite("\"\n");

    mm::AddressSpace* as = proc->as;
    if (as == nullptr)
    {
        arch::SerialWrite("    (no address space — kernel-AS task)\n");
        return;
    }
    arch::SerialWrite("    pml4_phys=");
    arch::SerialWriteHex(as->pml4_phys);
    arch::SerialWrite("  regions=");
    arch::SerialWriteHex(static_cast<u64>(as->region_count));
    arch::SerialWrite("  budget=");
    arch::SerialWriteHex(as->frame_budget);
    arch::SerialWrite("\n");

    // Region span — min / max user VA + total page count. We
    // deliberately don't print every single mapped page (up to
    // 1024 of them per process) because the resulting block
    // would dwarf the rest of the dump. The span + count tells
    // an operator whether rip / rsp fall inside the mapped
    // user range; per-page detail is available via shell at
    // post-mortem time.
    if (as->region_count > 0)
    {
        u64 vmin = ~static_cast<u64>(0);
        u64 vmax = 0;
        for (u16 i = 0; i < as->region_count; ++i)
        {
            const u64 v = as->regions[i].vaddr;
            if (v < vmin)
            {
                vmin = v;
            }
            if (v > vmax)
            {
                vmax = v;
            }
        }
        arch::SerialWrite("    vmap span: [");
        arch::SerialWriteHex(vmin);
        arch::SerialWrite(" .. ");
        arch::SerialWriteHex(vmax + 0x1000);
        arch::SerialWrite(")  pages=");
        arch::SerialWriteHex(static_cast<u64>(as->region_count));
        arch::SerialWrite("\n");
    }

    if (proc->dll_image_count > 0)
    {
        arch::SerialWrite("  loaded modules (");
        arch::SerialWriteHex(proc->dll_image_count);
        arch::SerialWrite(" DLLs):\n");
        for (u64 i = 0; i < proc->dll_image_count; ++i)
        {
            const DllImage& dll = proc->dll_images[i];
            const char* name = dll.has_exports ? PeExportsDllName(dll.exports) : nullptr;
            arch::SerialWrite("    [");
            arch::SerialWriteHex(dll.base_va);
            arch::SerialWrite(" .. ");
            arch::SerialWriteHex(dll.base_va + dll.size);
            arch::SerialWrite(")  size=");
            arch::SerialWriteHex(dll.size);
            arch::SerialWrite("  ");
            arch::SerialWrite(name != nullptr ? name : "<no export name>");
            arch::SerialWrite("\n");
        }
    }
}

} // namespace

void DumpPeerCpuSnapshots()
{
    const u32 self = cpu::BspInstalled() ? cpu::CurrentCpuIdOrBsp() : 0;
    const u32 limit = arch::SmpCpuIdLimit();
    if (limit <= 1)
    {
        // BSP-only configuration — nothing to dump. Emit a marker
        // anyway so the absence is explicit, not "did the dumper
        // even run?".
        arch::SerialWrite("[panic] --- peer CPU snapshots: (none — single CPU online) ---\n");
        return;
    }

    arch::SerialWrite("[panic] --- peer CPU snapshots ---\n");
    for (u32 id = 0; id < limit; ++id)
    {
        if (id == self)
        {
            continue;
        }
        cpu::PerCpu* peer = arch::SmpGetPercpu(id);
        if (peer == nullptr)
        {
            continue;
        }
        arch::SerialWrite("  cpu#");
        arch::SerialWriteHex(static_cast<u64>(id));
        arch::SerialWrite(" lapic=");
        arch::SerialWriteHex(static_cast<u64>(peer->lapic_id));
        if (peer->panic_snapshot_valid == 0)
        {
            arch::SerialWrite("  <no NMI snapshot — peer may be hung pre-NMI>\n");
            continue;
        }
        arch::SerialWrite("\n    rip=");
        WriteAddressWithSymbol(peer->panic_snapshot_rip);
        WriteVaRegion(peer->panic_snapshot_rip);
        arch::SerialWrite("\n    rsp=");
        arch::SerialWriteHex(peer->panic_snapshot_rsp);
        WriteVaRegion(peer->panic_snapshot_rsp);
        arch::SerialWrite("\n    task=");
        if (peer->panic_snapshot_task == nullptr)
        {
            arch::SerialWrite("<none>");
        }
        else
        {
            arch::SerialWriteHex(reinterpret_cast<u64>(peer->panic_snapshot_task));
        }
        arch::SerialWrite("\n");
        // Held locks captured at NMI time — if the peer was holding
        // anything when the panicking CPU broadcast NMI, that's the
        // first thing to look at for a deadlock-shaped panic.
        const u32 hl = peer->held_locks_count;
        if (hl != 0)
        {
            arch::SerialWrite("    held locks (");
            arch::SerialWriteHex(static_cast<u64>(hl));
            arch::SerialWrite("):\n");
            const u32 cap = (hl < cpu::kPerCpuMaxHeldLocks) ? hl : cpu::kPerCpuMaxHeldLocks;
            for (u32 i = 0; i < cap; ++i)
            {
                arch::SerialWrite("      [");
                arch::SerialWriteHex(static_cast<u64>(i));
                arch::SerialWrite("] lock=");
                arch::SerialWriteHex(reinterpret_cast<u64>(peer->held_locks[i]));
                arch::SerialWrite("  acquired-rip=");
                WriteAddressWithSymbol(peer->held_lock_rips[i]);
                arch::SerialWrite("\n");
            }
        }
    }
}

namespace
{

// Same as DumpPeerCpuSnapshots but for the panicking CPU's OWN held
// locks. Emitted from DumpDiagnostics so the local view comes out
// next to the rest of the panicker's state, not after the peer
// section. If we panicked while holding any lock, the entries here
// usually point straight at the bug.
void DumpHeldLocksLocal()
{
    if (!cpu::BspInstalled())
    {
        return;
    }
    cpu::PerCpu* p = cpu::CurrentCpu();
    if (p == nullptr || p->held_locks_count == 0)
    {
        return;
    }
    const u32 hl = p->held_locks_count;
    arch::SerialWrite("  held locks (");
    arch::SerialWriteHex(static_cast<u64>(hl));
    arch::SerialWrite(", innermost first):\n");
    const u32 cap = (hl < cpu::kPerCpuMaxHeldLocks) ? hl : cpu::kPerCpuMaxHeldLocks;
    // Stack discipline: index 0 is the bottom (acquired first).
    // Print top-down so the most recently acquired lock — usually
    // the one whose critical section we panicked inside — is the
    // first line a reader sees.
    for (u32 i = 0; i < cap; ++i)
    {
        const u32 idx = cap - 1 - i;
        arch::SerialWrite("    [");
        arch::SerialWriteHex(static_cast<u64>(idx));
        arch::SerialWrite("] lock=");
        arch::SerialWriteHex(reinterpret_cast<u64>(p->held_locks[idx]));
        arch::SerialWrite("  acquired-rip=");
        WriteAddressWithSymbol(p->held_lock_rips[idx]);
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
    WriteLabelled("uptime   ", ::duetos::time::TickCount());
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
    // 4-level page-table walk for the two addresses that most
    // often answer "why did this fault?". cr2 is the faulting
    // VA on a #PF (stale outside one, but the walk is still safe
    // to compute and the leaf entry is informative). rip's walk
    // surfaces NX / not-present / PS leaves around the failing
    // fetch — invaluable for #PF on instruction fetch and #UD on
    // a ripped-out code page. Both calls are allocation-free /
    // panic-free.
    if (cr2 != 0)
    {
        WritePageWalk("cr2", cr2);
    }
    WritePageWalk("rip", rip);
    DumpBacktrace(rbp);
    DumpStack(rsp, 16);
    DumpReturnAddressPointers(rsp);
    DumpLbr();
    sched::DumpCurrentTaskSyscallTrail();
    DumpProcessVmInfo();
    DumpHeldLocksLocal();
    DumpLogRing();
    DumpInflightScopes();
    // Wireless diag ring — only meaningful on hosts with active
    // Wi-Fi traffic, but the Dump call is safe (single irq-save
    // spinlock) and a no-op if the ring is empty.
    duetos::net::wireless::diag::Dump(0);
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
    duetos::diag::SoftLockupDisable();
    // Freeze the per-CPU LBR ring NOW so the dump-emission code
    // path itself doesn't push every SerialWrite call into the
    // most-recent slot. No-op when LBR isn't supported.
    arch::LbrFreeze();

    // Bypass the serial spinlock for the rest of this function.
    // A panic that fires while a peer CPU was already mid-
    // SerialWrite would otherwise deadlock here when we try to
    // print the banner — peer is suspended below by the broadcast
    // NMI but still owns the lock, and our SpinLockAcquire would
    // spin forever. PanicMode also handles the case where the
    // panic *itself* fires from inside SerialWrite (trap during a
    // print) — the inner SerialWrite would self-deadlock without
    // the bypass.
    arch::SerialEnterPanicMode();

    // Broadcast NMI to peer CPUs so they stop fighting for the
    // serial line / executing against potentially-corrupt shared
    // state. Peers halt quietly in the trap dispatcher's NMI
    // short-circuit AFTER capturing their own snapshot into
    // `panic_snapshot_*` — see DumpPeerCpuSnapshots later in this
    // routine. No-op pre-LapicInit.
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
    DumpPeerCpuSnapshots();

    EndCrashDump();

    // Binary minidump egress AFTER the human-readable text dump
    // has fully printed: the textual record is the highest-
    // priority artefact (it's all an operator on real hardware
    // gets), so it must finish first. The .dmp goes out via
    // debugcon (port 0xE9 → host file under QEMU); on real
    // hardware the OUTBs go nowhere and this is a no-op cost.
    duetos::diag::minidump::EmitMinidump(reinterpret_cast<u64>(__builtin_return_address(0)), arch::ReadRsp(),
                                         arch::ReadRbp(), /*exception_code=*/0);
    // EmitMinidump → PersistToDisk also writes the fix journal to
    // the second half of the NVMe crash-dump reservation. Both the
    // soft (this) and hard (EmitMinidumpFromTrapFrame) paths share
    // that PersistToDisk call site, so panicking here AND faulting
    // through a trap both land the journal on disk.

    arch::SerialWrite("[panic] CPU halted — no recovery.\n");
    arch::Halt();
}

void PanicWithValue(const char* subsystem, const char* message, u64 value)
{
    arch::Cli();
    arch::NmiWatchdogDisable();
    duetos::diag::SoftLockupDisable();
    // Freeze the per-CPU LBR ring NOW so the dump-emission code
    // path itself doesn't push every SerialWrite call into the
    // most-recent slot. No-op when LBR isn't supported.
    arch::LbrFreeze();
    // See Panic() above for why we bypass the serial spinlock from
    // here on.
    arch::SerialEnterPanicMode();
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
    DumpPeerCpuSnapshots();

    EndCrashDump();

    // Binary minidump egress AFTER the human-readable text dump
    // has fully printed: the textual record is the highest-
    // priority artefact (it's all an operator on real hardware
    // gets), so it must finish first. The .dmp goes out via
    // debugcon (port 0xE9 → host file under QEMU); on real
    // hardware the OUTBs go nowhere and this is a no-op cost.
    duetos::diag::minidump::EmitMinidump(reinterpret_cast<u64>(__builtin_return_address(0)), arch::ReadRsp(),
                                         arch::ReadRbp(), /*exception_code=*/0);
    // EmitMinidump → PersistToDisk also writes the fix journal to
    // the second half of the NVMe crash-dump reservation. Both the
    // soft (this) and hard (EmitMinidumpFromTrapFrame) paths share
    // that PersistToDisk call site, so panicking here AND faulting
    // through a trap both land the journal on disk.

    arch::SerialWrite("[panic] CPU halted — no recovery.\n");
    arch::Halt();
}

void DebugPanicOrWarn(const char* subsystem, const char* message)
{
    if constexpr (kIsDebugBuild)
    {
        Panic(subsystem, message);
    }
    else
    {
        Log(LogLevel::Error, subsystem, message);
    }
}

void DebugPanicOrWarnWithValue(const char* subsystem, const char* message, u64 value)
{
    if constexpr (kIsDebugBuild)
    {
        PanicWithValue(subsystem, message, value);
    }
    else
    {
        LogWithValue(LogLevel::Error, subsystem, message, value);
    }
}

} // namespace duetos::core
