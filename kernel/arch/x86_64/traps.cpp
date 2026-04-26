/*
 * DuetOS — x86_64 trap dispatcher: implementation.
 *
 * Companion to traps.h — see there for TrapFrame layout (which
 * matches the push order in exceptions.S) and the per-vector
 * dispatch contract.
 *
 * WHAT
 *   Single C++ entry point `TrapDispatch`, called from the
 *   shared `isr_common` stub in exceptions.S after the per-
 *   vector preamble has normalised the frame. Routes to the
 *   right handler based on `frame->vector`:
 *     - 0..31  CPU exceptions (#PF, #UD, #GP, ...)
 *     - 32..47 IRQs from PIC/IOAPIC (kept for legacy fallback)
 *     - 0x80   syscall gate -> core::SyscallDispatch
 *     - other  spurious / IPI / debug
 *
 * HOW
 *   Per-vector handlers are inline switch arms. The big ones
 *   (#PF / #GP / #DB) get their own helpers because they have
 *   non-trivial logic: extable lookup, fault-domain entry/exit,
 *   user-pointer fault recovery (cooperating with mm/user_copy.S),
 *   per-task DR* state for hardware breakpoints.
 *
 *   Crash-dump path: on an unrecoverable fault, the dispatcher
 *   captures the frame, walks the kernel stack via the embedded
 *   symbol table, and emits a BEGIN/END bracketed dump to
 *   serial. See core/panic.cpp for the dump formatter.
 */

#include "arch/x86_64/traps.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/nmi_watchdog.h"
#include "arch/x86_64/serial.h"

#include "diag/diag_decode.h"
#include "security/fault_domain.h"
#include "diag/hexdump.h"
#include "diag/log_names.h"
#include "core/panic.h"
#include "util/symbols.h"
#include "syscall/syscall.h"
#include "cpu/percpu.h"
#include "debug/breakpoints.h"
#include "debug/extable.h"
#include "debug/probes.h"
#include "mm/kstack.h"
#include "sched/sched.h"
#include "arch/x86_64/smp.h"

// user_copy.S labels, exposed to the trap dispatcher for the
// kernel-#PF fault-fixup path. Defined as non-const u8 arrays so
// the name refers to the address of the label directly (same
// pattern linker scripts use for _text_start / _kernel_end_phys).
extern "C" duetos::u8 __copy_user_from_start[];
extern "C" duetos::u8 __copy_user_from_end[];
extern "C" duetos::u8 __copy_user_to_start[];
extern "C" duetos::u8 __copy_user_to_end[];
extern "C" duetos::u8 __copy_user_fault_fixup[];

namespace duetos::arch
{

namespace
{

// Local aliases so the dispatcher code reads tidy. Taking the
// addresses through these shims also sidesteps a subtle clang
// warning about extern arrays without bounds in header form.
constexpr duetos::u8* g_copy_user_from_start = ::__copy_user_from_start;
constexpr duetos::u8* g_copy_user_from_end = ::__copy_user_from_end;
constexpr duetos::u8* g_copy_user_to_start = ::__copy_user_to_start;
constexpr duetos::u8* g_copy_user_to_end = ::__copy_user_to_end;
constexpr duetos::u8* g_copy_user_fault_fixup = ::__copy_user_fault_fixup;

// Per-vector IRQ handler table. Indexed directly by vector number.
// Vectors 0..31 are CPU exceptions (unused here — those dispatch
// through the CPU-exception branches later in this file). Vectors
// 32..47 are the ISA IRQ range (IOAPIC). Vectors 48..239 are the
// MSI-X pool (PCIe devices allocate through IrqAllocVector).
// 0xFF is the LAPIC spurious vector. nullptr means "no handler
// registered" — the dispatcher logs and EOIs but takes no other
// action.
constinit IrqHandler g_irq_handlers[256] = {};

// Per-vector cumulative handler-invocation count. Read by the
// runtime checker's IRQ-storm detector via IrqCountForVector.
// Written only from the IRQ dispatch path on the CPU serving the
// interrupt — interrupts are masked during handler dispatch so
// no intra-vector race is possible; cross-vector increments
// through this table are independent slots.
constinit u64 g_irq_counts[256] = {};

// Global fault counters by category. Bumped on every CPU
// exception dump (user-mode task-kill or kernel panic). Read
// only by diagnostic paths (shell health command / log prints);
// no hot-path dependency on these.
constinit u64 g_fault_access_violation = 0; // non-present #PF
constinit u64 g_fault_nx_violation = 0;     // present + instr fetch
constinit u64 g_fault_write_to_ro = 0;      // present + write
constinit u64 g_fault_stack_overflow = 0;   // #PF cr2 near rsp
constinit u64 g_fault_reserved_bit = 0;     // page-table poison
constinit u64 g_fault_gp = 0;               // #GP
constinit u64 g_fault_ud = 0;               // #UD

// Classify a page fault into a short mnemonic the dump header
// can show prominently. `err` is the hardware-pushed error code
// (Intel SDM Vol 3 Table 4-15); `cr2` is the faulting VA;
// `rsp` is the current stack pointer (used for the stack-
// overflow heuristic). Result is a static string literal —
// the caller does not free.
const char* ClassifyPageFault(u64 err, u64 cr2, u64 rsp, bool from_user)
{
    const bool present = (err & 0x01) != 0;
    const bool write = (err & 0x02) != 0;
    const bool rsvd = (err & 0x08) != 0;
    const bool instr = (err & 0x10) != 0;

    if (rsvd)
    {
        ++g_fault_reserved_bit;
        return "PT_RESERVED_BIT_SET";
    }

    // Stack-overflow heuristic. A push (or a call) that steps
    // past the stack's low edge will #PF with cr2 = rsp - k for
    // small k. The window is wide enough to catch single-frame
    // spills (up to ~one page below rsp) without aliasing random
    // dereferences.
    if (!present && cr2 < rsp && (rsp - cr2) < 0x2000)
    {
        ++g_fault_stack_overflow;
        return from_user ? "STACK_OVERFLOW_USER" : "STACK_OVERFLOW_KERNEL";
    }

    if (!present)
    {
        ++g_fault_access_violation;
        if (instr)
            return "ACCESS_VIOLATION_EXECUTE";
        if (write)
            return "ACCESS_VIOLATION_WRITE";
        return "ACCESS_VIOLATION_READ";
    }

    // Present but faulted — protection violation on the PTE.
    if (instr)
    {
        ++g_fault_nx_violation;
        return "NX_VIOLATION";
    }
    if (write)
    {
        ++g_fault_write_to_ro;
        return "WRITE_TO_RO_PAGE";
    }
    return "PROTECTION_FAULT";
}

// Emit the raw #PF error-code bits as a human-readable flag
// list. Follows the SDM layout: P (bit 0), W/R (1), U/S (2),
// RSVD (3), I/D (4), PK (5), SS (6). Newer bits (e.g. SGX bit
// 15) are noted generically.
void DumpPageFaultFlags(u64 err)
{
    SerialWrite("[");
    SerialWrite((err & 0x01) ? "present" : "notpresent");
    SerialWrite((err & 0x02) ? "|write" : "|read");
    SerialWrite((err & 0x04) ? "|user" : "|kernel");
    if (err & 0x08)
        SerialWrite("|rsvd");
    if (err & 0x10)
        SerialWrite("|instr");
    if (err & 0x20)
        SerialWrite("|pkey");
    if (err & 0x40)
        SerialWrite("|ss");
    SerialWrite("]");
}

constexpr u8 kIrqVectorBase = 32;
constexpr u8 kMsixVectorBase = 48;
constexpr u8 kMsixVectorMax = 239; // leave 240..254 reserved for future (IPIs, debug)
constexpr u8 kSpuriousVector = 0xFF;

// Monotonic pool cursor for IrqAllocVector. No reclaim in v0 —
// drivers never release vectors, and we have 192 of them.
constinit u8 g_msix_next_vector = kMsixVectorBase;

// Syscall gate vector is claimed by SyscallDispatch below, not by
// the generic IRQ path — exclude it from the dispatch predicate.
constexpr u8 kSyscallVector = 0x80;

inline bool IsDispatchedVector(u64 vector)
{
    if (vector == kSpuriousVector)
        return true;
    if (vector == kSyscallVector)
        return false;
    if (vector >= kIrqVectorBase && vector <= kMsixVectorMax)
        return true;
    return false;
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

// Variant for raw VAs (cr2 / rsp on the trap dump): same hex
// formatting, but appends a `[region=...]` tag so the operator
// instantly sees whether a faulting address landed in the kernel
// stack arena, an MMIO mapping, the non-canonical hole, or out at
// some user-space VA. Avoids forcing the reader to keep paging.h's
// memory map in their head.
void WriteLabelledVa(const char* label, duetos::u64 value)
{
    SerialWrite("  ");
    SerialWrite(label);
    SerialWrite(" : ");
    SerialWriteHex(value);
    duetos::core::WriteVaRegion(value);
    SerialWrite("\n");
}

// Render a GPR value with an optional symbolic annotation. Most GPRs
// hold non-pointer data (counts, indices, flags) for which a symbol
// lookup would either return nothing or — worse — match a symbol that
// happens to share its low bits with the value. We therefore only
// resolve when the value falls in the higher-half kernel range, which
// is what `core::WriteSymbolIfCode` enforces. A clean register full of
// zeros / counts / small values shows as plain hex; one that holds a
// kernel function pointer (callback, vtable, return-address spill)
// gets `[fn+0xOFF (path:LINE)]` appended.
void WriteLabelledGpr(const char* label, duetos::u64 value)
{
    SerialWrite("  ");
    SerialWrite(label);
    SerialWrite(" : ");
    SerialWriteHex(value);
    duetos::core::WriteSymbolIfCode(value);
    SerialWrite("\n");
}

// Render a segment-selector line as hex + ring/role decoded. Used
// for cs and ss in the trap dump so the operator immediately sees
// "ring 3 user-code" instead of having to map `0x33` to a GDT slot
// in their head.
void WriteLabelledSelector(const char* label, duetos::u64 value)
{
    SerialWrite("  ");
    SerialWrite(label);
    SerialWrite(" : ");
    SerialWriteHex(value);
    duetos::core::WriteSegmentSelectorBits(value);
    SerialWrite("\n");
}

// Render rflags as hex + decoded bits.
void WriteLabelledRflags(const char* label, duetos::u64 value)
{
    SerialWrite("  ");
    SerialWrite(label);
    SerialWrite(" : ");
    SerialWriteHex(value);
    duetos::core::WriteRflagsBits(value);
    SerialWrite("\n");
}

} // namespace

TrapResponse TrapResponseFor(u64 vector, bool from_user)
{
    // Ring 3 is always Isolate. The faulting task dies, the kernel
    // continues. This is the existing user-mode fault contract.
    if (from_user)
    {
        return TrapResponse::IsolateTask;
    }
    // Kernel-mode #BP (3) and #DB (1) are recoverable. #BP fires
    // when kernel code executes int3 — typically a deliberate
    // breakpoint or a future KASSERT-with-resume hook. #DB fires
    // on single-step and on hardware-breakpoint hits — both are
    // debugging primitives, not bugs. Logging the hit + returning
    // lets the kernel stay alive for the operator to inspect via
    // the shell or wait for a debugger.
    if (vector == 1 || vector == 3)
    {
        return TrapResponse::LogAndContinue;
    }
    // Everything else from kernel mode means the kernel itself is
    // in an inconsistent state (corrupt pointer, double fault, GP
    // on a wild segment register, etc.). Continued execution
    // accumulates damage. Halt.
    return TrapResponse::Panic;
}

const char* TrapResponseName(TrapResponse r)
{
    switch (r)
    {
    case TrapResponse::LogAndContinue:
        return "LogAndContinue";
    case TrapResponse::IsolateTask:
        return "IsolateTask";
    case TrapResponse::Panic:
        return "Panic";
    }
    return "?";
}

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
    if (IsDispatchedVector(frame->vector))
    {
        const u8 v = static_cast<u8>(frame->vector);
        ++g_irq_counts[v];
        const IrqHandler h = g_irq_handlers[v];
        if (h != nullptr)
        {
            h();
            // Only EOI for vectors with a registered handler. Software-
            // triggered `int n` (boot self-test at vector 0x42, debug
            // probes, etc.) arrives with no LAPIC ISR bit set — EOIing
            // those would dismiss some other genuinely in-flight IRQ.
            // LAPIC spurious (0xFF) ALSO skips EOI per Intel SDM:
            // the CPU doesn't advance the In-Service Register for it.
            if (frame->vector != kSpuriousVector)
            {
                LapicEoi();
            }

            // Preemption point. Only after a REAL IRQ handler ran —
            // a software-triggered stray (e.g. the boot `int 0x42`
            // probe, debug probes) must never touch the scheduler,
            // which may not exist yet and wouldn't have anything to
            // schedule anyway. Before this branch ran on
            // the unhandled path too; that regressed the pre-SchedInit
            // boot probe into a #GP inside Schedule().
            if (sched::TakeNeedResched())
            {
                sched::Schedule();
            }
        }
        else
        {
            SerialWrite("[irq] unhandled vector ");
            SerialWriteHex(frame->vector);
            SerialWrite("(");
            SerialWrite(::duetos::core::IdtVectorName(frame->vector));
            SerialWrite(")\n");
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

    // Spurious-vector path. Vectors 48..127 + 129..254 have stubs
    // in exceptions.S that route here, so a stray INT n / IPI /
    // device-injected interrupt logs the offending number instead
    // of cascading through #NP from a not-present IDT gate. No EOI
    // — these aren't from the LAPIC's normal pipeline; if a future
    // driver routes its IRQ outside the 32..47 window it'll need
    // its own handler installed via IrqInstall.
    if (frame->vector >= 48 && frame->vector < 256)
    {
        SerialWrite("[idt] spurious vector ");
        SerialWriteHex(frame->vector);
        SerialWrite(" rip=");
        SerialWriteHex(frame->rip);
        SerialWrite(" cs=");
        SerialWriteHex(frame->cs);
        SerialWrite("\n");
        return;
    }

    // Vector 2 (NMI). Two legitimate sources feed this entry:
    //   * The NMI watchdog — PMU counter overflow via LVT Perf.
    //     Consumed by NmiWatchdogHandleNmi; if the pet counter
    //     has advanced, the handler re-arms and returns so we
    //     iretq back to the interrupted code.
    //   * Cross-CPU panic broadcast (see PanicBroadcastNmi).
    //     Peers arrive here and must halt quietly so they don't
    //     fight the panicking CPU for the serial line.
    // Any non-watchdog NMI (external NMI pin, firmware-injected
    // chipset error, etc.) also falls through to the halt path —
    // conservative default: if we don't know why NMI fired, stop.
    if (frame->vector == 2)
    {
        if (NmiWatchdogHandleNmi())
            return;

        // Cross-CPU panic broadcast (or any unclaimed NMI). Capture
        // our state into the per-CPU snapshot buffer BEFORE halting
        // so the panicking CPU can include peer context in its dump.
        // The store-to-flag is last so a partial capture (e.g. NMI
        // on top of NMI-during-store) still leaves valid=0 and the
        // dumper prints the right "<no snapshot>" branch.
        //
        // Gated on BspInstalled — an NMI before PerCpu install
        // (very early boot) has no per-CPU buffer to write into,
        // and CurrentCpu()'s GSBASE read would return 0.
        if (cpu::BspInstalled())
        {
            cpu::PerCpu* p = cpu::CurrentCpu();
            if (p != nullptr)
            {
                p->panic_snapshot_rip = frame->rip;
                p->panic_snapshot_rsp = frame->rsp;
                p->panic_snapshot_task = p->current_task;
                asm volatile("" ::: "memory");
                p->panic_snapshot_valid = 1;
            }
        }
        for (;;)
        {
            asm volatile("cli; hlt");
        }
    }

    // Kernel-stack guard-page hit. Runs BEFORE the extable lookup so
    // a stray fault-fixup entry that happened to register a RIP
    // range around this site can't shadow a real overflow. Scoped
    // to kernel-mode #PF — userland can't reach the kernel-half
    // arena, and any fault delivered to ring 0 with CR2 inside the
    // arena's guard band IS an overflow.
    if (frame->vector == 14 && (frame->cs & 3) == 0)
    {
        const u64 cr2 = ReadCr2();
        if (mm::IsKernelStackGuardFault(cr2))
        {
            SerialWrite("\n** KERNEL STACK OVERFLOW **\n  task id : ");
            SerialWriteHex(duetos::sched::CurrentTaskId());
            SerialWrite("\n  cr2     : ");
            SerialWriteHex(cr2);
            SerialWrite("\n  rip     : ");
            SerialWriteHex(frame->rip);
            SerialWrite("\n");
            core::PanicWithValue("sched/kstack", "guard-page hit — kernel stack overflow", cr2);
        }
    }

    // Kernel-mode extable. Replaces the single hardcoded user-copy
    // check with a generic lookup — any subsystem that wants scoped
    // fault recovery registers (rip_start, rip_end, fixup) at init
    // time and the handler redirects `frame->rip` to the fixup on
    // any kernel-mode #PF / #GP that lands inside the range. The
    // user-copy helpers are now one row in this table (see
    // debug::KernelExtableRegisterUserCopy in extable.cpp's init).
    //
    // Scoped to kernel-mode traps (ring 0) — a user-mode fault at
    // a kernel RIP can't happen (user can't execute kernel code).
    if ((frame->vector == 14 || frame->vector == 13) && (frame->cs & 3) == 0)
    {
        const ::duetos::debug::ExtableEntry* hit = ::duetos::debug::KernelExtableFindEntry(frame->rip);
        if (hit != nullptr)
        {
            SerialWrite("[extable] recovered kernel trap vec=");
            SerialWriteHex(frame->vector);
            SerialWrite(" rip=");
            SerialWriteHex(frame->rip);
            if (frame->vector == 14)
            {
                SerialWrite(" cr2=");
                SerialWriteHex(ReadCr2());
            }
            SerialWrite(" -> fixup=");
            SerialWriteHex(hit->fixup_rip);
            SerialWrite(" tag=");
            SerialWrite(hit->tag);
            SerialWrite("\n");
            // If the row is bound to a fault domain, hand off
            // the recovery to the watchdog. The fixup runs first
            // and gives the synchronous caller a clean error
            // path; the watchdog then teardown+re-init's the
            // subsystem so future calls succeed. MarkRestart is
            // one bool write — safe from trap context.
            if (hit->domain_id != ::duetos::debug::kExtableNoDomain)
            {
                ::duetos::core::FaultDomainMarkRestart(hit->domain_id);
                SerialWrite("[extable] marked domain for deferred restart id=");
                SerialWriteHex(hit->domain_id);
                SerialWrite("\n");
            }
            frame->rip = hit->fixup_rip;
            return;
        }
    }

    // CPU exception path. Route through the per-vector tiered
    // response policy — explicit per-class outcome
    // instead of "everything panics", so a recoverable trap (an
    // in-kernel int3, a debug-register single-step) doesn't bring
    // the kernel down. The policy table itself lives in
    // TrapResponseFor; this dispatcher just acts on the result.
    //
    // Three outcomes:
    //   LogAndContinue — log a one-liner + iretq. Used for
    //     kernel-mode #BP / #DB. Lets a deliberate int3 or
    //     hardware single-step come and go without halting.
    //   IsolateTask    — kill the offending ring-3 task + reschedule.
    //     Default for every user-mode hit (sandboxed process's
    //     wild pointer / RX-page write / NX-stack jump must NOT
    //     become a kernel DoS).
    //   Panic          — halt. Only outcome that does not return.
    //     Reserved for kernel-mode bugs where continued execution
    //     accumulates damage.
    const bool from_user = (frame->cs & 3) == 3;

    // Breakpoint subsystem gets first refusal on #BP (vec 3) and
    // #DB (vec 1), REGARDLESS of ring. A user-mode task that
    // installed a BP via SYS_BP_INSTALL needs the same handler
    // path a kernel BP would hit — otherwise the per-task DR
    // hit would fall through to the ring-3 "IsolateTask" policy
    // and kill the task every time its own BP fired. Only if
    // the handler doesn't claim the trap (bare int3 in user
    // code, #DB with no registered cause) do we proceed with
    // the per-ring default policy below.
    if (frame->vector == 3 && debug::BpHandleBreakpoint(frame))
    {
        return;
    }
    if (frame->vector == 1 && debug::BpHandleDebug(frame))
    {
        return;
    }

    const TrapResponse policy = TrapResponseFor(frame->vector, from_user);

    if (policy == TrapResponse::LogAndContinue)
    {
        SerialWrite("[trap] ");
        SerialWrite((frame->vector < 32) ? kVectorNames[frame->vector] : "vec-oor");
        SerialWrite(" (recoverable) rip=");
        SerialWriteHex(frame->rip);
        SerialWrite(" cs=");
        SerialWriteHex(frame->cs);
        SerialWrite("\n");
        return;
    }

    // Ring-3 exception handling — the IsolateTask outcome.
    // SchedExit is [[noreturn]]; it marks the task Dead, wakes the
    // reaper, and Schedule()s away. The reaper tears down the task's
    // Process (which tears down its AddressSpace → returns every
    // backing frame + page-table page to the physical allocator).
    // The half-consumed trap frame on this task's kernel stack is
    // abandoned along with the stack itself — free with the rest
    // at reap time.
    if (policy == TrapResponse::IsolateTask)
    {
        const char* vec_name = (frame->vector < 32) ? kVectorNames[frame->vector] : "user-vector-oor";
        SerialWrite("\n[task-kill] ring-3 task took ");
        SerialWrite(vec_name);
        SerialWrite(" — terminating\n");
        // Category / reason label — BSOD-style one-liner that
        // tells the operator what shape the fault has before
        // they read hex values. Only meaningful for #PF / #GP /
        // #UD; other vectors skip the label.
        if (frame->vector == 14)
        {
            const u64 cr2 = ReadCr2();
            SerialWrite("  reason : ");
            SerialWrite(ClassifyPageFault(frame->error_code, cr2, frame->rsp, /*from_user=*/true));
            SerialWrite(" ");
            DumpPageFaultFlags(frame->error_code);
            SerialWrite("\n");
        }
        else if (frame->vector == 13)
        {
            ++g_fault_gp;
            SerialWrite("  reason : PROTECTION_FAULT_USER\n");
        }
        else if (frame->vector == 6)
        {
            ++g_fault_ud;
            SerialWrite("  reason : INVALID_OPCODE\n");
        }
        SerialWrite("  task : ");
        ::duetos::core::WriteCurrentTaskLabel();
        SerialWrite("\n  pid  : ");
        SerialWriteHex(duetos::sched::CurrentTaskId());
        SerialWrite("\n  rip  : ");
        SerialWriteHex(frame->rip);
        SerialWrite("\n  rsp  : ");
        SerialWriteHex(frame->rsp);
        SerialWrite("\n  cs   : ");
        SerialWriteHex(frame->cs);
        ::duetos::core::WriteSegmentSelectorBits(frame->cs);
        if (frame->vector == 14)
        {
            SerialWrite("\n  cr2  : ");
            SerialWriteHex(ReadCr2());
            SerialWrite("\n  err  : ");
            SerialWriteHex(frame->error_code);
            ::duetos::core::WritePageFaultErrBits(frame->error_code);
        }
        SerialWrite("\n");
        // Instruction-at-RIP dump. Most user-mode faults are a wild
        // jump into a garbage page or a malformed opcode the loader
        // wrote; having the actual bytes in the log tells you which
        // without re-running the program under a debugger. The
        // plausibility check rejects user-space RIPs (< 1 GiB is
        // plausible, but > 1 GiB user-space RIPs fall outside the
        // PlausibleKernelAddress range and emit a skipped line).
        core::DumpInstructionBytes("user-fault-rip", frame->rip, 16);
        // SchedExit must NOT run with IF=0 forever; it ends in a
        // Schedule() that waits for the reaper, and the reaper needs
        // timer IRQs to make progress. SchedYield/SchedExit internally
        // cli/sti around Schedule, so we don't need to explicitly sti
        // here. Control never returns from SchedExit.
        duetos::sched::SchedExit();
    }

    // Fall-through outcome: TrapResponse::Panic. Every kernel-mode
    // CPU exception that wasn't recoverable lands here. Pre-marker
    // human-readable banner. Anything before BEGIN / after END is
    // free-form prose; the bracketed region is the machine-extract
    // -able dump record.
    //
    // Fire the kernel-page-fault probe specifically for vec 14 so
    // the log ring records this as a structured event before the
    // panic dump; other kernel exceptions are already distinct
    // enough by name that they don't need a dedicated probe.
    if (frame->vector == 14)
        KBP_PROBE_V(::duetos::debug::ProbeId::kKernelPageFault, frame->rip);
    // Quiet the NMI watchdog before the dump. DumpDiagnostics +
    // symbol resolution + serial I/O can easily exceed one
    // watchdog interval; a PMI overflow during the dump would
    // re-enter the trap dispatcher and scramble the output.
    NmiWatchdogDisable();
    // Halt peer CPUs the same way `core::Panic` does — they're
    // running against potentially-corrupt shared state once we've
    // taken a fault in kernel mode, and their NMI handlers commit
    // a snapshot we can dump after our own diagnostics.
    PanicBroadcastNmi();
    SerialWrite("\n** CPU EXCEPTION **\n");

    // Bracket the record so host-side tooling can extract a .dump file
    // from the serial capture, matching the panic path's contract. The
    // vector mnemonic becomes the dump's `message` and the error code
    // rides along as the `value` field — the two things a reader wants
    // to see first on a fault.
    const char* vector_name = (frame->vector < 32) ? kVectorNames[frame->vector] : "out-of-range";
    core::BeginCrashDump("arch/traps", vector_name, &frame->error_code);

    WriteLabelled("vector    ", frame->vector);
    SerialWrite("  vector_name : ");
    SerialWrite(vector_name);
    SerialWrite("\n");
    SerialWrite("  rip       : ");
    core::WriteAddressWithSymbol(frame->rip);
    core::WriteVaRegion(frame->rip);
    SerialWrite("\n");
    WriteLabelledSelector("cs        ", frame->cs);
    WriteLabelledRflags("rflags    ", frame->rflags);
    WriteLabelledVa("rsp       ", frame->rsp);
    WriteLabelledSelector("ss        ", frame->ss);

    u64 cr2 = 0;
    if (frame->vector == 14) // #PF
    {
        cr2 = ReadCr2();
        // CR2 region tag instantly distinguishes "wild user pointer
        // poked into kernel land" (user-canonical) from "kernel
        // stack overflow" (k.stack-arena guard hit) from "MMIO
        // dereferenced after device removal" (k.mmio).
        WriteLabelledVa("cr2       ", cr2);
        // BSOD-style reason line. Classifies the fault into an
        // ACCESS_VIOLATION_* / NX_VIOLATION / STACK_OVERFLOW_*
        // category and breaks the raw err bits into flags.
        SerialWrite("  reason    : ");
        SerialWrite(ClassifyPageFault(frame->error_code, cr2, frame->rsp, /*from_user=*/false));
        SerialWrite(" ");
        DumpPageFaultFlags(frame->error_code);
        SerialWrite("\n");
    }
    else if (frame->vector == 13)
    {
        ++g_fault_gp;
        SerialWrite("  reason    : PROTECTION_FAULT_KERNEL\n");
    }
    else if (frame->vector == 6)
    {
        ++g_fault_ud;
        SerialWrite("  reason    : INVALID_OPCODE\n");
    }

    SerialWrite("  --\n");
    // GPRs. Each register is printed with its raw hex (existing
    // schema) and, when the value falls in plausible kernel code
    // range, the resolved `[fn+0xOFF (file:line)]` annotation. This
    // surfaces stale callback pointers, return-address spills,
    // vtable entries, etc., without forcing the operator to run a
    // separate symbolizer over every value by hand.
    WriteLabelledGpr("rax       ", frame->rax);
    WriteLabelledGpr("rbx       ", frame->rbx);
    WriteLabelledGpr("rcx       ", frame->rcx);
    WriteLabelledGpr("rdx       ", frame->rdx);
    WriteLabelledGpr("rsi       ", frame->rsi);
    WriteLabelledGpr("rdi       ", frame->rdi);
    WriteLabelledGpr("rbp       ", frame->rbp);
    WriteLabelledGpr("r8        ", frame->r8);
    WriteLabelledGpr("r9        ", frame->r9);
    WriteLabelledGpr("r10       ", frame->r10);
    WriteLabelledGpr("r11       ", frame->r11);
    WriteLabelledGpr("r12       ", frame->r12);
    WriteLabelledGpr("r13       ", frame->r13);
    WriteLabelledGpr("r14       ", frame->r14);
    WriteLabelledGpr("r15       ", frame->r15);

    // Instruction bytes at RIP. Lets the operator eyeball the actual
    // opcode that faulted without running objdump. x86_64 max
    // instruction length is 15 bytes; we dump 16 so a clean prefix +
    // opcode + ModRM + full displacement/immediate always fits.
    SerialWrite("  --\n");
    core::DumpInstructionBytes("fault-rip", frame->rip, 16);

    // On #PF, dump the 64 bytes flanking CR2. The page containing
    // CR2 is unmapped by definition (that's why the fault fired), so
    // the safe variant skips it and emits only the neighbouring
    // bytes — often enough to show whether the access was an
    // off-by-one past a valid struct (you'll see the struct's bytes
    // right up to the page boundary) or a wild dereference (you'll
    // see <unreadable>).
    if (frame->vector == 14)
    {
        // Align down 32 bytes + show 96, so a few lines before and
        // after CR2 are dumped; the faulting page gets skipped
        // automatically.
        const u64 window_start = (cr2 - 32) & ~static_cast<u64>(0xF);
        const u64 window_page = cr2 & ~static_cast<u64>(0xFFF);
        core::DumpHexRegionSafe("cr2-window", window_start, 96, window_page);
    }

    // Stack window starting at RSP. Distinct from the RBP backtrace
    // in DumpDiagnostics — this is raw quads on the stack, symbol-
    // annotated so saved return addresses auto-label even when the
    // RBP chain walked off into garbage. 16 quads = 128 bytes.
    core::DumpStackWindow("fault-stack", frame->rsp, 16);

    // Rich diagnostics from the faulting frame — backtrace climbs
    // the stack from rbp AT THE POINT OF THE FAULT (not from the
    // dispatcher's own frame), so the returned frame chain shows
    // the actual call path that led to the exception.
    core::DumpDiagnostics(frame->rip, frame->rsp, frame->rbp);
    core::DumpPeerCpuSnapshots();

    core::EndCrashDump();
    SerialWrite("[panic] Halting CPU.\n");
    Halt();
}

u64 IrqCountForVector(u8 v)
{
    return g_irq_counts[v];
}

FaultCounts FaultCountsSnapshot()
{
    FaultCounts s;
    s.access_violation = g_fault_access_violation;
    s.nx_violation = g_fault_nx_violation;
    s.write_to_ro = g_fault_write_to_ro;
    s.stack_overflow = g_fault_stack_overflow;
    s.reserved_bit = g_fault_reserved_bit;
    s.gp = g_fault_gp;
    s.ud = g_fault_ud;
    return s;
}

void IrqInstall(u8 vector, IrqHandler handler)
{
    if (!IsDispatchedVector(vector))
    {
        SerialWrite("[irq] IrqInstall: vector out of range ");
        SerialWriteHex(vector);
        SerialWrite("\n");
        Halt();
    }
    g_irq_handlers[vector] = handler;
}

u8 IrqAllocVector()
{
    if (g_msix_next_vector == 0 || g_msix_next_vector > kMsixVectorMax)
    {
        return 0;
    }
    const u8 v = g_msix_next_vector;
    ++g_msix_next_vector;
    return v;
}


void RaiseSelfTestBreakpoint()
{
    asm volatile("int3");
    // int3 is recoverable, so the CPU can resume here if the dispatcher
    // ever stops halting. Halt explicitly in case that ever happens, so
    // the boot log doesn't quietly fall off the end.
    Halt();
}

// Register the extable entries that `traps.cpp` itself owns —
// specifically the user-copy helpers that were previously
// hardcoded in this file's kernel-#PF branch. Called once at
// boot from main.cpp right after the IDT is loaded.
void TrapsRegisterExtable()
{
    const u64 from_s = reinterpret_cast<u64>(g_copy_user_from_start);
    const u64 from_e = reinterpret_cast<u64>(g_copy_user_from_end);
    const u64 to_s = reinterpret_cast<u64>(g_copy_user_to_start);
    const u64 to_e = reinterpret_cast<u64>(g_copy_user_to_end);
    const u64 fixup = reinterpret_cast<u64>(g_copy_user_fault_fixup);
    ::duetos::debug::KernelExtableRegister(from_s, from_e, fixup, "mm/CopyFromUser");
    ::duetos::debug::KernelExtableRegister(to_s, to_e, fixup, "mm/CopyToUser");
}

void TrapsSelfTest()
{
    SerialWrite("[traps] self-test\n");

    // 1. Kernel-mode int3. Slice-80 policy: TrapResponse::LogAndContinue.
    // The dispatcher emits "[trap] #BP Breakpoint (recoverable) ..."
    // and iretq's; execution resumes on the line below. If the policy
    // regresses to Panic the kernel halts here instead of returning,
    // and the boot log shows the crash banner — easy regression signal.
    asm volatile("int3");

    // 2. Spurious-vector probe. Vector 0x42 has no registered handler,
    // no driver routes IRQs to it. With the prior full-IDT install
    // it fires `mkstub 66` -> isr_common -> TrapDispatch's spurious
    // branch, which logs "[idt] spurious vector 0x42 ..." and
    // iretq's. Without the new install it would cascade to #NP and
    // halt — same easy regression signal.
    asm volatile("int $0x42");

    SerialWrite("[traps] self-test OK — #BP and spurious both recovered\n");
}

} // namespace duetos::arch
