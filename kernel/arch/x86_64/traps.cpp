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
#include "arch/x86_64/lbr.h"
#include "arch/x86_64/machine_check.h"
#include "arch/x86_64/nmi_watchdog.h"
#include "arch/x86_64/serial.h"

#include "diag/diag_decode.h"
#include "diag/event_trace.h"
#include "diag/fault_react.h"
#include "diag/fix_journal.h"
#include "diag/gdb_server.h"
#include "diag/kpath.h"
#include "security/fault_domain.h"
#include "diag/hexdump.h"
#include "diag/minidump.h"
#include "diag/log_names.h"
#include "core/panic.h"
#include "log/klog.h"
#include "util/saturating.h"
#include "util/symbols.h"
#include "syscall/syscall.h"
#include "acpi/acpi.h"
#include "cpu/critical.h"
#include "cpu/percpu.h"
#include "debug/breakpoints.h"
#include "debug/extable.h"
#include "debug/probes.h"
#include "mm/kstack.h"
#include "mm/paging.h"
#include "mm/poison_alloc.h"
#include "sched/sched.h"
#include "subsystems/win32/vmap_syscall.h"
#include "subsystems/win32/seh_dispatch.h"
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

// mm/safe_read.S — kernel-to-kernel safe read with fault fixup.
// Same shape as the user_copy bracket; registered alongside the
// CopyFromUser / CopyToUser rows in TrapsRegisterExtable.
extern "C" duetos::u8 __safe_read_kernel_start[];
extern "C" duetos::u8 __safe_read_kernel_end[];
extern "C" duetos::u8 __safe_read_kernel_fault_fixup[];

// Linker-emitted bounds of kernel `.text` (set by the linker script).
// Used by RetpolineWildCallback below + the in-TrapDispatch
// g_irq_handlers validator earlier.
extern "C" duetos::u8 _text_start[];
extern "C" duetos::u8 _text_end[];

// Called from isr_common (kernel/arch/x86_64/exceptions.S) when the
// kernel-mode iretq target — the trap-frame's saved RIP — fell
// outside [_text_start, _text_end). Catches the iretq-frame-RIP-
// corruption shape: a C handler scribbled the saved RIP slot in
// the trap frame, the unconditional iretq below would load that
// wild value, and the CPU faults at the wild target with no
// indirect-call site to attribute it to. The per-call validators
// (sched/trampoline, sync/rcu DrainQueue, arch/traps IrqHandler,
// __llvm_retpoline_r11) all stay silent for this shape because
// the wild value never went through them. Caller is in rdi (the
// wild RIP that iretq would have jumped to).
extern "C" [[noreturn]] void IretqFrameWildCallback(void* target)
{
    using namespace duetos;
    const u64 fn = reinterpret_cast<u64>(target);
    KBP_PROBE_V(::duetos::debug::ProbeId::kIretqFrameWild, fn);
    arch::SerialWrite("[arch/iretq] WILD iretq target — refusing return  cpu=");
    arch::SerialWriteHex(cpu::CurrentCpuIdOrBsp());
    arch::SerialWrite("  rip=");
    arch::SerialWriteHex(fn);
    arch::SerialWrite("  text=[");
    arch::SerialWriteHex(reinterpret_cast<u64>(_text_start));
    arch::SerialWrite("..");
    arch::SerialWriteHex(reinterpret_cast<u64>(_text_end));
    arch::SerialWrite(")\n");
    core::PanicWithValue("arch/iretq", "iretq frame RIP out of kernel text range", fn);
}

// Called from __llvm_retpoline_r11 (kernel/arch/x86_64/retpoline_thunks.S)
// when the retpoline detects r11 — the indirect-call target — fell
// outside [_text_start, _text_end). The retpoline thunk intercepts
// every `call *%r11` shape the compiler emits under -mretpoline, so
// this catches indirect dispatches that aren't covered by the three
// site-specific validators (sched/trampoline, sync/rcu DrainQueue,
// arch/traps IrqHandler). Caller is in rdi (the original r11 value).
extern "C" [[noreturn]] void RetpolineWildCallback(void* target)
{
    using namespace duetos;
    const u64 fn = reinterpret_cast<u64>(target);
    KBP_PROBE_V(::duetos::debug::ProbeId::kRetpolineWild, fn);
    arch::SerialWrite("[retpoline] WILD indirect call — refusing dispatch  cpu=");
    arch::SerialWriteHex(cpu::CurrentCpuIdOrBsp());
    arch::SerialWrite("  target=");
    arch::SerialWriteHex(fn);
    arch::SerialWrite("  text=[");
    arch::SerialWriteHex(reinterpret_cast<u64>(_text_start));
    arch::SerialWrite("..");
    arch::SerialWriteHex(reinterpret_cast<u64>(_text_end));
    arch::SerialWrite(")\n");
    core::PanicWithValue("arch/retpoline", "indirect call target out of kernel text range", fn);
}

// Called from ContextSwitch's pre-ret range-check (kernel/sched/
// context_switch.S) when the about-to-be-popped return target — the
// value at [rsp] immediately before the trailing `ret` — fell
// outside [_text_start, _text_end). Catches the planted-slot
// truncation shape: SchedCreate / a previous Schedule() ContextSwitch
// wrote a full-64-bit return address into that stack slot; something
// then scribbled it (32-bit store; off-CPU memory corruption;
// kstack slot-reuse race) to leave a low-canonical wild value.
// Without this gate, `ret` would silently dispatch the wild value
// and the CPU would fault with no indirect-call site to blame.
//
// Sibling of IretqFrameWildCallback (saved iretq RIP) and
// RetpolineWildCallback (indirect call target). Caller passes the
// wild ret target in rdi.
extern "C" [[noreturn]] void SchedContextSwitchWildRetCallback(void* target)
{
    using namespace duetos;
    const u64 fn = reinterpret_cast<u64>(target);
    KBP_PROBE_V(::duetos::debug::ProbeId::kSchedContextSwitchWildRet, fn);
    arch::SerialLineGuard guard;
    arch::SerialWrite("[sched/ctxsw] WILD ret target — refusing switch-in  cpu=");
    arch::SerialWriteHex(cpu::CurrentCpuIdOrBsp());
    arch::SerialWrite("  ret_target=");
    arch::SerialWriteHex(fn);
    arch::SerialWrite("  text=[");
    arch::SerialWriteHex(reinterpret_cast<u64>(_text_start));
    arch::SerialWrite("..");
    arch::SerialWriteHex(reinterpret_cast<u64>(_text_end));
    arch::SerialWrite(")  resuming_task_id=");
    arch::SerialWriteHex(sched::CurrentTaskId());
    arch::SerialWrite("\n");
    core::PanicWithValue("sched/ctxsw", "context-switch ret target out of kernel text range", fn);
}

// DIAG (boot-tail wild-frame chase, 2026-06-04): isr_common (exceptions.S)
// records each trap's entry shape into this fixed BSS ring on EVERY trap, so the
// wild-frame guard below can print the sequence of traps that led to a wild one.
// C linkage + global scope so the assembly can reach the symbols by name. The
// frame layout the asm reads is fixed by isr_common's 15-push prologue.
extern "C"
{
    struct TrapEntryRingSlot
    {
        // Full iretq-frame context per trap entry, captured by isr_common's asm
        // from fixed stack offsets after the 15 GPR pushes. The extra fields
        // (error/cs/rflags/ss) make the wild-frame capture self-discriminating:
        // on the wild-frame trap, a SANE cs/rflags means our own context-restore
        // corrupted rsp (the frame=rsp the dispatcher saw); a GARBAGE cs means the
        // hypervisor delivered a malformed frame. cpu_rsp vs frame_rsp reveals
        // whether a privilege/IST stack switch happened on this entry. 64-byte
        // slot (8 u64) so the asm index math stays a clean shl-by-6.
        duetos::u64 vector;       // [rsp+120]
        duetos::u64 error_code;   // [rsp+128]
        duetos::u64 saved_rip;    // [rsp+136] — where the CPU was when the trap fired
        duetos::u64 saved_cs;     // [rsp+144] — ring of the trapped context (RPL discriminator)
        duetos::u64 saved_rflags; // [rsp+152] — IF / sanity of the trapped context
        duetos::u64 cpu_rsp;      // [rsp+160] — the CPU's rsp BEFORE the trap (iretq frame)
        duetos::u64 saved_ss;     // [rsp+168] — stack segment of the trapped context
        duetos::u64 frame_rsp;    // rsp itself — the pointer handed to TrapDispatch as 'frame'
    };
    static_assert(sizeof(TrapEntryRingSlot) == 64, "asm in exceptions.S indexes slots by shl-6 (64B)");
    constexpr duetos::u64 kTrapRingSlots = 16; // power of two; asm masks with & 0xF
    alignas(64) TrapEntryRingSlot g_trap_ring[kTrapRingSlots] = {};
    duetos::u64 g_trap_ring_idx = 0; // next slot to write; (idx-1)&0xF is the newest
}

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

// Per-vector "have we already warned about this one?" bitmap.
// 256 bits = 4 u64. The unhandled-vector and spurious-vector
// branches of TrapDispatch each consult their own bitmap so the
// first occurrence of a stray IRQ lands in the klog ring buffer
// (and thus in the crash dump) while subsequent occurrences from
// the same vector are dropped silently — a chattering device that
// fires unhandled at 10 kHz used to flood raw serial at
// SerialWrite latency and bypass the ring entirely; now we capture
// it once per vector, per category, and move on.
constinit u64 g_unhandled_vector_warned[4] = {};
constinit u64 g_spurious_vector_warned[4] = {};

// Test-and-set a per-vector "already warned" bit. Returns true on
// FIRST observation (caller should log), false on every subsequent
// observation. Strictly per-CPU correctness is not required — at
// most one extra log per vector if two CPUs race the same vector's
// first miss, which is fine.
static inline bool ClaimVectorWarnSlot(u64 (&bitmap)[4], u8 vector)
{
    const u32 word = vector >> 6; // /64
    const u64 bit = 1ull << (vector & 63);
    if ((bitmap[word] & bit) != 0)
    {
        return false;
    }
    bitmap[word] |= bit;
    return true;
}

// Per-vector cumulative handler-invocation count. Stored per-CPU
// so the IRQ dispatch path (which fires hundreds of times per
// second per CPU on the timer alone) doesn't bounce a single
// cache line between cores. Each CPU writes only its own row;
// IrqCountForVector sums across CPUs for the read side.
//
// Plain u64 rather than SatU64 inside the per-CPU array: the
// write is a single-CPU operation under IF=0, so the saturating
// SatLogClamp warning at u64-max would fire on a wrap that takes
// thousands of years of continuous IRQ traffic to reach. The
// sum-walk on read still respects each row's monotonicity.
//
// Memory cost: kMaxCpus * 256 * 8 = 64 KiB of static. Acceptable
// for a kernel-static; no per-PerCpu growth (PerCpu cache-line
// footprint matters for the IPI/wake hot path).
constinit u64 g_irq_counts_per_cpu[acpi::kMaxCpus][256] = {};

// Per-CPU live IRQ/trap nesting depth. Incremented at TrapDispatch
// entry and decremented at every normal-return exit via the RAII
// IrqNestScope below; saved/restored PER TASK across context
// switches by sched::Schedule (prev->irq_depth = IrqNestDepthRaw();
// IrqNestDepthSet(next->irq_depth)). The invariant the two halves
// jointly maintain: slot[cpu] == the nesting depth of the task
// currently running on `cpu`. 0 = not in interrupt/trap context,
// 1 = one level deep (normal), >= 2 = a handler was itself
// interrupted. The combination is migration-safe: an increment on
// CPU X that is preempted mid-handler is carried to the task's
// saved irq_depth on switch-out and reloaded onto whatever CPU
// resumes the task, so the matching decrement always lands on the
// slot that holds this invocation's increment. Single-CPU writes
// under IF=0; no atomic needed on the slot itself.
constinit u64 g_irq_nest_depth_per_cpu[acpi::kMaxCpus] = {};

// Global fault counters by category. Bumped on every CPU
// exception dump (user-mode task-kill or kernel panic). Read
// only by diagnostic paths (shell health command / log prints);
// no hot-path dependency on these.
//
// Saturating: a malicious workload that floods one fault class
// (e.g. a ring-3 loop hammering NX violations) cannot wrap the
// per-class counter to zero and obscure attack-detection in
// later audits. wiki/security/Linux-CVE-Audit.md class BB
// (free-running counter wrap → defense gap).
constinit util::SatU64 g_fault_access_violation = 0; // non-present #PF
constinit util::SatU64 g_fault_nx_violation = 0;     // present + instr fetch
constinit util::SatU64 g_fault_write_to_ro = 0;      // present + write
constinit util::SatU64 g_fault_stack_overflow = 0;   // #PF cr2 near rsp
constinit util::SatU64 g_fault_reserved_bit = 0;     // page-table poison
constinit util::SatU64 g_fault_gp = 0;               // #GP
constinit util::SatU64 g_fault_ud = 0;               // #UD

// Recursive-fault sentinel. Set the moment a halt-bound path
// (this dispatcher's kernel-mode Panic outcome OR core::Panic /
// core::PanicWithValue) crosses into its diagnostic phase; read
// at every entry to those same paths. A second fault while the
// first one is still printing flips this off the dispatcher's
// happy path and into HaltOnRecursiveFault, which emits one raw-
// serial line and halts — no DumpDiagnostics, no symbol resolve,
// no stack walk. The dump-during-dump recursion is the single
// failure mode this guards against. Volatile because the read on
// the second CPU's recursive entry must not be hoisted, and a
// plain atomic isn't worth the overhead — once set, the value
// never goes back, and any ordering between two simultaneous
// panickers is acceptable.
volatile u32 g_panic_in_progress = 0;

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
    // Reschedule-IPI (0xF8): in the 240..254 reserved range. Goes
    // through the same dispatch + EOI path as a hardware IRQ so
    // the post-handler need_resched check fires Schedule() before
    // iretq, matching the timer-tick preemption shape.
    // TLB-shootdown IPI (0xF9) shares the same shape; both are
    // installed by SMP bring-up (kernel/arch/x86_64/smp.cpp).
    // Without the 0xF9 leg the IrqInstall registration path would
    // halt the kernel mid-boot the moment SMP wires up shootdowns.
    // IPI-call (0xFA): cross-CPU function-call primitive — same
    // shape, installed by kernel/cpu/ipi_call.cpp's IpiCallInstall.
    if (vector == 0xF8 || vector == 0xF9 || vector == 0xFA)
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
    // Sentinel/uninit hint: e.g. cr2/rsp/rbp = 0xFFFFFFFFFFFFFFFF
    // gets `[wild: all-ones — wild branch / corrupted return …]`
    // appended so the operator doesn't have to recognise the
    // magic number themselves.
    duetos::core::WriteWildAddressHint(value);
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
    // #MC (vector 18) is a system-level hardware fault, not a
    // per-task bug — a bad DIMM / cache parity / bus error taken
    // while ring 3 happened to be current does NOT mean only that
    // task is affected. It must never be IsolateTask'd or delivered
    // to user-mode SEH; decode-then-Panic regardless of ring. The
    // decode itself runs from the Panic dump path below.
    if (vector == 18)
    {
        return TrapResponse::Panic;
    }
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
    default:
        return "?";
    }
}

// IRQ nesting-depth tracking. Two earlier live-test attempts (slices
// 69 and 71) exposed that a correct counter needs BOTH halves:
//   * per-task save/restore across Schedule (sched.cpp does
//     prev->irq_depth = IrqNestDepthRaw(); IrqNestDepthSet(next->irq_depth)
//     at every context switch), AND
//   * increment-at-entry / decrement-at-exit of TrapDispatch.
// The decrement is the part the previous attempts leaked, because
// TrapDispatch has many non-returning exits (task-kill via SchedExit,
// the kernel-mode Panic outcome, the #DF / NMI halt-forever spins).
// The fix is to drive the decrement from a RAII guard (IrqNestScope,
// in TrapDispatch) whose dtor fires on EVERY normal return, paired
// with the per-task save/restore that fixes up the non-returning
// paths for free: SchedExit -> Schedule saves the (still-elevated)
// live depth into the dying task (reaped, value discarded) and loads
// the incoming task's depth, so the live slot is correct for whoever
// runs next; the Panic / Halt paths leave the slot elevated but the
// box is dead, so nothing reads it. The result: the runtime checker's
// IrqNesting ceiling and the panic-snapshot depth field, both wired
// up and waiting, finally see real values instead of a constant 0.
//
// The live depth is a per-CPU array (g_irq_nest_depth_per_cpu),
// indexed by the current CPU id; g_irq_nest_max is the global
// monotonic high-water mark read by the health check.
constinit u64 g_irq_nest_max = 0;

// Current CPU's live-depth slot. CurrentCpuIdOrBsp() falls back to
// the BSP id (0) before per-CPU state is installed, so this is safe
// to call from the very first boot trap. Out-of-range ids (should
// not happen) clamp to slot 0 rather than scribble past the array.
static inline u64& IrqNestSlot()
{
    const u32 id = ::duetos::cpu::CurrentCpuIdOrBsp();
    const u32 idx = (id < acpi::kMaxCpus) ? id : 0u;
    return g_irq_nest_depth_per_cpu[idx];
}

// Relaxed cross-CPU high-water update. The CAS loop only spins when
// `depth` actually exceeds the current max — once the system has
// reached its steady-state nesting (depth 1 for an un-nested trap)
// the common case is a single relaxed load + compare that skips the
// CAS entirely, so the per-trap hot path stays cheap.
static inline void IrqNestMaxObserve(u64 depth)
{
    u64 cur = __atomic_load_n(&g_irq_nest_max, __ATOMIC_RELAXED);
    while (depth > cur)
    {
        if (__atomic_compare_exchange_n(&g_irq_nest_max, &cur, depth, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            break;
    }
}

u64 IrqNestDepth()
{
    return IrqNestSlot();
}
u64 IrqNestMax()
{
    return __atomic_load_n(&g_irq_nest_max, __ATOMIC_RELAXED);
}
u64 IrqNestDepthRaw()
{
    return IrqNestSlot();
}
void IrqNestDepthSet(u64 v)
{
    IrqNestSlot() = v;
}

bool PanicInProgress()
{
    return g_panic_in_progress != 0;
}

void PanicInProgressMark()
{
    g_panic_in_progress = 1;
}

void HaltOnRecursiveFault(u64 vector, u64 rip)
{
    // Anything we touch here can re-fault (we're already on a
    // potentially-corrupt stack, possibly with broken page tables
    // or a wild GS base). Skip every heavy primitive (symbol
    // resolve, VA region tag, page walk). One line, then halt.
    //
    // Snapshot vec and rip into locals ONCE before any locking so a
    // concurrent fault on another CPU can't mutate the frame under us
    // while we're formatting or emitting. (The parameters are already
    // copies — this makes the intent explicit and guards against
    // future callers that pass frame fields by reference.)
    const u64 vec_snap = vector;
    const u64 rip_snap = rip;

    // SMP-correctness (CAS dedup): under multi-CPU saturation
    // (observed 2026-05-22 on x86_64-debug SMP=8), N peer CPUs
    // can hit their own kernel-mode fault concurrently and all
    // land here while the FIRST panicking CPU is still mid-dump.
    // The CAS below lets the FIRST peer here actually emit the
    // line; subsequent peers halt silently. Lossy by design —
    // one line of diagnostic per cluster of recursive faults is
    // what's useful; further lines just corrupt the first.
    //
    // SMP-correctness (byte interleave): even with one
    // recursive-fault writer, the BSP panic dumper may still be
    // emitting concurrently. Without serialization the BSP's hex
    // digits and our digits land byte-by-byte on the same UART,
    // producing the historical `vec=0x   __  rip=0x   __` symptom.
    // SerialWriteNRecursiveFault provides two-level serialization:
    //   1. try-acquire g_serial_lock (non-blocking) — succeeds when
    //      the BSP dump has finished; gives fully locked atomicity.
    //   2. PanicEmitTryClaim bounded-spin — used when the lock is
    //      still held (BSP mid-dump); serializes among concurrent
    //      panic-mode writers without blocking.
    static volatile u32 s_recursive_dump_owner = 0;
    u32 expected = 0;
    if (__atomic_compare_exchange_n(&s_recursive_dump_owner, &expected, 1u, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    {
        // Build "\n[recursive-fault] vec=0xVVVVVVVVVVVVVVVV
        //   rip=0xRRRRRRRRRRRRRRRR — short-circuiting panic dump\n"
        // into a stack buffer using the snapshotted values. No heap,
        // no symbol resolve, no klog. Fixed-width hex for both fields.
        constexpr char kHex[] = "0123456789abcdef";
        static constexpr const char kPrefix[] = "\n[recursive-fault] vec=0x";
        static constexpr const char kMid[] = " rip=0x";
        // "em dash" matches the original SerialWrite literal; the
        // UTF-8 bytes are e2 80 94. Tracked as raw bytes here so
        // the buffer math is explicit.
        static constexpr const char kSuffix[] = " \xe2\x80\x94 short-circuiting panic dump\n";
        constexpr u64 kPrefixLen = sizeof(kPrefix) - 1;
        constexpr u64 kMidLen = sizeof(kMid) - 1;
        constexpr u64 kSuffixLen = sizeof(kSuffix) - 1;
        // 16 hex digits per quad.
        constexpr u64 kHexQuad = 16;
        constexpr u64 kBufLen = kPrefixLen + kHexQuad + kMidLen + kHexQuad + kSuffixLen;
        char buf[kBufLen];
        u64 p = 0;
        for (u64 i = 0; i < kPrefixLen; ++i)
            buf[p++] = kPrefix[i];
        for (int shift = 60; shift >= 0; shift -= 4)
            buf[p++] = kHex[(vec_snap >> shift) & 0xF];
        for (u64 i = 0; i < kMidLen; ++i)
            buf[p++] = kMid[i];
        for (int shift = 60; shift >= 0; shift -= 4)
            buf[p++] = kHex[(rip_snap >> shift) & 0xF];
        for (u64 i = 0; i < kSuffixLen; ++i)
            buf[p++] = kSuffix[i];
        // Emit via the recursive-fault serializer: try-lock first,
        // fall back to bounded-spin panic-emit claim. One call = one
        // contiguous burst on the UART under either path.
        SerialWriteNRecursiveFault(buf, p);
    }
    Halt();
}

// Is `frame` safe to dereference as a trap frame — canonical AND its first quad
// present? Pure except for the fault-surviving SafeReadKernel probe (which returns
// false instead of faulting on an unmapped source). Catches both observed wild
// shapes: non-canonical (rejected by the arithmetic test, never dereferenced so it
// can't #GP) and canonical-but-unmapped (rejected by the present probe). Exposed to
// TrapsSelfTest so the reject path is verifiable without reproducing a wild trap.
static bool TrapFramePointerIsSane(const void* frame)
{
    const ::duetos::u64 fp = reinterpret_cast<::duetos::u64>(frame);
    const ::duetos::u64 hi17 = fp >> 47; // bits 63:47 — all-0 (low) or all-1 (high) => canonical
    if (hi17 != 0ULL && hi17 != 0x1FFFFULL)
        return false; // non-canonical — refuse without dereferencing (a deref would #GP)
    ::duetos::u64 probe = 0;
    return ::duetos::mm::SafeReadKernel(&probe, frame, sizeof(probe));
}

// DIAG (boot-tail wild-frame chase): runaway-fault-loop detector by TIGHT
// DESCENT. A fault-on-fault loop marches DOWN one stack, each TrapDispatch frame
// ~one frame-size (~0x1290) below the previous, with no work between. A plain
// global re-entry depth can't see this — legitimate nesting across tasks (a
// syscall here, a timer IRQ there) climbs it via context switches that suspend
// frames without returning. So instead: count CONSECUTIVE entries whose frame is
// just below the previous one on the same stack; ANY non-tight entry (context
// switch, fresh trap, upward/far frame) resets it. Crossing the threshold means a
// genuine same-stack recursion. Single-CPU diagnostic.
constexpr ::duetos::u64 kTightDescentBytes = 3u * 0x1290u; // up to ~3 frame-sizes below
constexpr ::duetos::u64 kMaxTightRecursion = 8;            // 8 tight descents in a row = runaway
::duetos::u64 g_last_trap_frame = 0;
::duetos::u64 g_tight_recursion = 0;

// DIAG (boot-tail wild-frame chase): print the trap-entry ring oldest->newest.
// In its OWN small frame (noinline) so the loop counter cannot alias
// TrapDispatch's huge UBSAN stack frame — inlined, that aliasing left the
// counter >= kTrapRingSlots and silently skipped the loop. Called only from the
// wild-frame bail. The newest entry whose frame=-1 is the wild trap; its
// vec/rip/cpu_rsp localise the origin.
[[gnu::noinline]] static void DumpTrapEntryRing()
{
    SerialWrite("[arch/traps] trap-entry ring (oldest->newest)  vec|err|rip|cs|rflags|cpu_rsp|ss|frame:\n");
    for (::duetos::u64 k = 0; k < kTrapRingSlots; ++k)
    {
        const ::duetos::u64 idx = (g_trap_ring_idx + k) & (kTrapRingSlots - 1);
        const TrapEntryRingSlot& e = g_trap_ring[idx];
        SerialWrite("  vec=");
        SerialWriteHex(e.vector);
        SerialWrite(" err=");
        SerialWriteHex(e.error_code);
        SerialWrite(" rip=");
        SerialWriteHex(e.saved_rip);
        SerialWrite(" cs=");
        SerialWriteHex(e.saved_cs);
        SerialWrite(" rflags=");
        SerialWriteHex(e.saved_rflags);
        SerialWrite(" cpu_rsp=");
        SerialWriteHex(e.cpu_rsp);
        SerialWrite(" ss=");
        SerialWriteHex(e.saved_ss);
        SerialWrite(" frame=");
        SerialWriteHex(e.frame_rsp);
        SerialWrite("\n");
    }
}

// Single source of truth mapping a CPU-exception vector to the
// NTSTATUS a Win32 process would observe for that fault. Shared by
// the ring-3 SEH delivery switch (which gates on a non-zero result
// to decide dispatchability + supplies the code to ntdll's
// KiUserExceptionDispatcher) and by the ring-3 minidump emit (which
// labels the .dmp's exception record). Keeping ONE table prevents
// the two sites drifting — the "sentinel divergence" class of bug
// where one path is taught a new vector and the other isn't.
//
// Returns 0 for vectors with no Windows structured-exception
// analogue (the caller substitutes its own fallback). #BP/#DB are
// deliberately 0 here: they never reach the IsolateTask path (the
// breakpoint / GDB subsystems claim them first under LogAndContinue
// policy), so a PE never sees them as a delivered exception.
static u32 VectorToUserNtStatus(u64 vector)
{
    switch (vector)
    {
    case 0:
        return 0xC0000094; // #DE STATUS_INTEGER_DIVIDE_BY_ZERO
    case 4:
        return 0xC0000095; // #OF STATUS_INTEGER_OVERFLOW
    case 5:
        return 0xC000008C; // #BR STATUS_ARRAY_BOUNDS_EXCEEDED
    case 6:
        return 0xC000001D; // #UD STATUS_ILLEGAL_INSTRUCTION
    case 13:
        return 0xC0000005; // #GP STATUS_ACCESS_VIOLATION
    case 14:
        return 0xC0000005; // #PF STATUS_ACCESS_VIOLATION
    case 16:
        // GAP: x87 #MF carries a status word distinguishing
        // divide-by-zero / overflow / underflow / inexact / denormal
        // / invalid; we deliver the generic
        // STATUS_FLOAT_INVALID_OPERATION rather than decoding the FSW.
        return 0xC0000090; // #MF STATUS_FLOAT_INVALID_OPERATION
    case 17:
        return 0x80000002; // #AC STATUS_DATATYPE_MISALIGNMENT
    case 19:
        // GAP: SSE #XM's specific exception lives in MXCSR; we deliver
        // the generic multiple-traps code rather than decoding it.
        return 0xC00002B4; // #XM STATUS_FLOAT_MULTIPLE_TRAPS
    default:
        return 0; // no structured-exception analogue
    }
}

extern "C" void TrapDispatch(TrapFrame* frame)
{
    // Diagnostic: snapshot the iretq-frame RIP at entry so the
    // RAII guard below can detect a mid-handler scribble. The five
    // dispatcher-site validators (sched/trampoline, sync/rcu,
    // arch/traps IrqHandler, __llvm_retpoline_r11, isr_common
    // iretq) all stay silent on the boot-tail #UD bug — meaning
    // the wild value somehow ends up in the trap-frame's saved
    // RIP slot without going through any indirect dispatch and
    // without triggering the iretq gate. This guard captures the
    // entry RIP, compares it at every exit path, and panics with
    // the diff if a handler scribbled it.
    struct RipIntegrityGuard
    {
        TrapFrame* frame;
        const ::duetos::u64 entry_rip;
        const ::duetos::u64 entry_r15;
        const ::duetos::u64 entry_cs;
        const bool kernel_mode_return;
        // Set by the dispatcher when it legitimately redirects RIP via a
        // registered extable fixup (kernel-mode #PF/#GP recovery, e.g.
        // mm/SafeReadKernel reading a faulting user RIP during task-kill).
        // That is a sanctioned rewrite, not a scribble — without this the
        // guard false-positives on every extable-recovered kernel fault.
        bool sanctioned_rewrite = false;
        RipIntegrityGuard(TrapFrame* f)
            : frame(f), entry_rip(f->rip), entry_r15(f->r15), entry_cs(f->cs), kernel_mode_return((f->cs & 0x3) == 0)
        {
        }
        ~RipIntegrityGuard()
        {
            // Skip the check for handlers that legitimately rewrite
            // the iretq target: syscall (vector 0x80), execve, signal
            // delivery, breakpoint-redirect, extable fixup. The
            // exempt set is the vectors where TrapDispatch's call
            // tree is allowed to mutate frame->rip.
            const ::duetos::u64 v = frame->vector;
            const bool exempt = (v == 0x80) || (v == 3) || (v == 1);
            if (exempt || sanctioned_rewrite)
                return;
            // Only kernel-mode returns are checked — user-mode RIPs
            // can be anywhere in the process VA range.
            if (!kernel_mode_return)
                return;
            if (frame->rip == entry_rip)
                return;
            // RIP changed mid-handler on a kernel-mode return path
            // outside the legitimate-rewrite vectors. Whether the
            // new value is in kernel text or not, this is a bug:
            // the IRQ / fault handler tree scribbled the saved RIP
            // slot. The canary12 capture (2026-05-22) showed
            // entry_rip = IdleMain+0x57 (post-MWAIT in the idle
            // loop) and exit_rip = SchedTaskTrampoline+0x17 (post
            // `call *rbx`) — both in kernel `.text`, so the
            // text-range gate alone misses it. Fire on any
            // mismatch and let the panic banner name the
            // entry/exit pair.
            KBP_PROBE_V(::duetos::debug::ProbeId::kTrapDispatchRipScribble, frame->rip);
            SerialWrite("[arch/traps] TRAP-FRAME RIP scribbled mid-handler  cpu=");
            SerialWriteHex(::duetos::cpu::CurrentCpuIdOrBsp());
            SerialWrite("  vector=");
            SerialWriteHex(v);
            SerialWrite("  entry_rip=");
            SerialWriteHex(entry_rip);
            SerialWrite("  exit_rip=");
            SerialWriteHex(frame->rip);
            SerialWrite("  entry_r15=");
            SerialWriteHex(entry_r15);
            SerialWrite("  exit_r15=");
            SerialWriteHex(frame->r15);
            SerialWrite("  cs=");
            SerialWriteHex(entry_cs);
            SerialWrite("\n");
            ::duetos::core::PanicWithValue("arch/traps", "trap frame RIP scribbled mid-handler", frame->rip);
        }
    };
    // Defense-in-depth: the entry stub can hand us a WILD trap-frame pointer — the
    // tracked boot-tail wild-frame bug (observed under VBox as frame=-1, canonical
    // but unmapped, and a non-canonical 0x001d2025… shape). RipIntegrityGuard's ctor
    // below dereferences frame->rip/cs immediately; on a wild pointer that #PFs, so
    // the guard meant to DIAGNOSE corruption instead becomes a SECOND fault that
    // buries the original context (cr2=-1, fault-site mislabeled as the guard ctor).
    // Validate canonical-AND-present BEFORE any field access; on a wild pointer name
    // the offender and halt cleanly so the NEXT occurrence is diagnosable, not a
    // nested #PF. Does NOT fix the wild-frame root cause (tracked separately) — it
    // stops that bug from masking itself. Sixth dispatcher-site validator.
    if (!TrapFramePointerIsSane(frame))
    {
        const ::duetos::u64 fp = reinterpret_cast<::duetos::u64>(frame);
        const ::duetos::u64 hi17 = fp >> 47;
        const bool canonical = (hi17 == 0ULL) || (hi17 == 0x1FFFFULL);
        KBP_PROBE_V(::duetos::debug::ProbeId::kTrapDispatchRipScribble, fp);
        SerialWrite("[arch/traps] WILD trap-frame pointer — refusing to dereference  cpu=");
        SerialWriteHex(::duetos::cpu::CurrentCpuIdOrBsp());
        SerialWrite("  frame=");
        SerialWriteHex(fp);
        SerialWrite(canonical ? "  [canonical, not-present]\n" : "  [non-canonical]\n");
        // DIAG: dump the trap-entry ring (oldest -> newest). The newest entry
        // whose frame=-1 IS this wild trap; its vector/rip/cpu_rsp reveal where
        // the wild frame came from (the SafeReadKernel #PF the present-probe just
        // took is also in the ring — identify the wild one by frame=0xff..ff).
        // Done in a dedicated noinline fn: TrapDispatch's huge UBSAN frame was
        // aliasing the loop counter's stack slot, skipping the loop entirely.
        DumpTrapEntryRing();
        ::duetos::core::PanicWithValue("arch/traps", "wild trap-frame pointer at dispatch entry", fp);
    }

    // DIAG: runaway fault-loop catcher by tight descent (see kMaxTightRecursion).
    // A fault-on-fault loop hands us frames marching DOWN one stack, each ~one
    // TrapDispatch frame below the last. Count consecutive tight descents; ANY
    // other shape (context switch to another stack, a fresh/higher frame) resets
    // the run, so legitimate cross-task nesting never trips it. On a genuine run
    // halt EARLY while the ring still holds the TRIGGER (the first traps, with a
    // VALID vec/rip — before the loop corrupts the slots to -1) and dump it.
    {
        const ::duetos::u64 thisFrame = reinterpret_cast<::duetos::u64>(frame);
        if (g_last_trap_frame != 0 && thisFrame < g_last_trap_frame &&
            (g_last_trap_frame - thisFrame) < kTightDescentBytes)
            ++g_tight_recursion;
        else
            g_tight_recursion = 0;
        g_last_trap_frame = thisFrame;
        if (g_tight_recursion > kMaxTightRecursion)
        {
            asm volatile("cli");
            SerialWrite("[arch/traps] RUNAWAY trap recursion (tight descent) — halting + dumping trigger  run=");
            SerialWriteHex(g_tight_recursion);
            SerialWrite("\n");
            DumpTrapEntryRing();
            ::duetos::core::PanicWithValue("arch/traps", "runaway trap recursion (fault loop)", g_tight_recursion);
        }
    }

    RipIntegrityGuard guard(frame);

    // IRQ/trap nesting-depth accounting. Increment the current CPU's
    // live depth on entry (updating the global high-water mark) and
    // decrement on EVERY normal return via the dtor — including the
    // recoverable IRQ / syscall / extable / LogAndContinue paths.
    // The non-returning exits (SchedExit task-kill, the Panic / Halt
    // outcomes, the #DF / NMI halt-spins) skip the dtor by design: a
    // killed task's elevated slot is corrected by the very next
    // context switch's IrqNestDepthSet, and a halted kernel never
    // reads the slot again. Declared AFTER `guard` so it destructs
    // first — the depth unwinds before the RIP-scribble check runs.
    // This is what makes the runtime checker's IrqNesting ceiling
    // (kIrqNestingCeiling) and the panic-snapshot depth field live
    // signals instead of constants.
    struct IrqNestScope
    {
        IrqNestScope()
        {
            const u64 depth = ++IrqNestSlot();
            IrqNestMaxObserve(depth);
        }
        ~IrqNestScope()
        {
            // Defensive floor: never wrap a slot that is somehow
            // already 0 (a stray decrement on a non-returning path
            // that later re-entered) to u64-max — that would trip
            // the ceiling alarm forever. Underflow-safe by design.
            u64& slot = IrqNestSlot();
            if (slot != 0)
            {
                --slot;
            }
        }
    } nest_scope;

    // KPath: record that this vector fired before any handler-
    // specific dispatch. Single bounds check + relaxed atomic add;
    // safe in trap / IRQ context (no allocation, no klog, no locks).
    ::duetos::diag::KPathHitVector(static_cast<::duetos::u32>(frame->vector));
    // Hardware IRQ path. Routes to the registered handler (if any), then
    // EOIs the LAPIC and returns to isr_common's iretq, which resumes the
    // interrupted code. No diagnostic spew per IRQ — the timer alone fires
    // hundreds of times a second.
    if (IsDispatchedVector(frame->vector))
    {
        const u8 v = static_cast<u8>(frame->vector);
        cpu::PerCpu* pc = cpu::CurrentCpu();
        const u32 cpu_id = (pc != nullptr) ? pc->cpu_id : 0u;
        if (cpu_id < acpi::kMaxCpus)
        {
            ++g_irq_counts_per_cpu[cpu_id][v];
        }
        const IrqHandler h = g_irq_handlers[v];
        // Sanity-check `h` is in kernel .text before the indirect call.
        // A corrupted entry (concurrent IrqInstall scribble, table-
        // adjacent overflow, slab class collision) lands here. The
        // pre-fix path indirect-called blindly and faulted at the wild
        // address (#PF NX_VIOLATION on a higher-half .bss page) — the
        // trap RIP was the wild address, not TrapDispatch, so the
        // banner never named the IRQ subsystem. Catching here names
        // the offender (vector, fn, table base) and halts with a real
        // banner. Observed 2026-05-22: ~1/10 SMP=8 boots faulted at
        // a wild rip in lockdep g_per_cpu range during an idle AP's
        // first timer IRQ dispatch.
        if (h != nullptr)
        {
            extern duetos::u8 _text_start[];
            extern duetos::u8 _text_end[];
            const duetos::u64 fn = reinterpret_cast<duetos::u64>(h);
            const duetos::u64 lo = reinterpret_cast<duetos::u64>(_text_start);
            const duetos::u64 hi = reinterpret_cast<duetos::u64>(_text_end);
            if (fn < lo || fn >= hi)
            {
                KBP_PROBE_V(::duetos::debug::ProbeId::kIrqHandlerWild, fn);
                SerialWrite("[arch/traps] WILD irq handler — refusing dispatch  cpu=");
                SerialWriteHex(cpu_id);
                SerialWrite("  vector=");
                SerialWriteHex(static_cast<duetos::u64>(v));
                SerialWrite("  fn=");
                SerialWriteHex(fn);
                SerialWrite("  text=[");
                SerialWriteHex(lo);
                SerialWrite("..");
                SerialWriteHex(hi);
                SerialWrite(")\n");
                ::duetos::core::PanicWithValue("arch/traps", "irq handler out of kernel text range", fn);
            }
        }
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

            // Async-stop hook. After EOI (so the LAPIC is clean
            // for the duration of any pause) and before the
            // resched check (so the GDB user sees the kernel at
            // the IRQ's interruption point, not after a context
            // switch). On most IRQs this is a single INB on the
            // COM2 LSR — when GDB sends 0x03, this routes the
            // current trap frame into the stop loop and returns
            // once the debugger resumes.
            (void)::duetos::diag::gdb::PollAsyncStop(frame);

            // Preemption point. Only after a REAL IRQ handler ran —
            // a software-triggered stray (e.g. the boot `int 0x42`
            // probe, debug probes) must never touch the scheduler,
            // which may not exist yet and wouldn't have anything to
            // schedule anyway. Before this branch ran on
            // the unhandled path too; that regressed the pre-SchedInit
            // boot probe into a #GP inside Schedule().
            //
            // critnest gate (FreeBSD critical_enter semantics): if
            // we're inside a preempt-off critical section, defer the
            // reschedule until CriticalExit drains it. DeferPreemptIfCritical
            // returns true and atomically records the deferral when
            // critnest > 0; otherwise it returns false and we
            // proceed to call Schedule() normally. We still consume
            // need_resched via TakeNeedResched so a future tick
            // doesn't see a stale flag.
            if (sched::TakeNeedResched())
            {
                if (!cpu::DeferPreemptIfCritical())
                {
                    sched::Schedule();
                }
            }
        }
        else
        {
            // Defense-in-depth: an unhandled but HARDWARE-DELIVERED IRQ
            // still latched this CPU's LAPIC In-Service bit. Leaving it
            // un-EOI'd silently blocks every lower-priority vector on
            // this CPU for the rest of the boot — a device that fires
            // on a vector whose handler was cleared (MSI-X bind
            // fallback, hot-unplug, a driver that unmasked before
            // installing) would wedge the timer tick and freeze the
            // box with no diagnostic. We must NOT blindly EOI here,
            // though: a software-triggered `int n` to a vector in the
            // dispatched range (the boot `int $0x42` self-test lands in
            // the MSI-X pool) never set an ISR bit, and EOIing it would
            // dismiss some OTHER genuinely in-flight interrupt. Reading
            // the LAPIC ISR for exactly this vector distinguishes the
            // two: set => hardware delivery, needs EOI; clear =>
            // software int n / spurious, leave the LAPIC alone.
            if (LapicInServiceBitSet(static_cast<u8>(frame->vector)))
            {
                LapicEoi();
            }
            // First time we see this unhandled vector: route through
            // klog so it shows up in the ring buffer + any future
            // crash dump. Subsequent fires from the same vector are
            // dropped — a chattering device used to flood raw serial
            // here at handler-dispatch latency.
            if (ClaimVectorWarnSlot(g_unhandled_vector_warned, static_cast<u8>(frame->vector)))
            {
                KLOG_WARN_V("arch/traps", "unhandled IRQ vector", frame->vector);
            }
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
        // First time we see this spurious vector: emit the rich
        // serial diagnostic (with RIP symbol + CS) AND drop a
        // dedup-ed klog WARN so the ring buffer carries the event.
        // A stray-IRQ storm from a chattering device used to write
        // ~80 bytes per fire to raw serial; the per-vector once
        // bitmap caps the cost at one trace per (vector, category).
        if (ClaimVectorWarnSlot(g_spurious_vector_warned, static_cast<u8>(frame->vector)))
        {
            SerialWrite("[idt] spurious vector ");
            SerialWriteHex(frame->vector);
            SerialWrite(" rip=");
            duetos::core::WriteAddressWithSymbol(frame->rip);
            SerialWrite(" cs=");
            SerialWriteHex(frame->cs);
            SerialWrite("\n");
            KLOG_WARN_V("arch/traps", "spurious IDT vector", frame->vector);
        }
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
    // chipset error, etc.) is decoded from port 0x61 (SERR#/IOCHK#)
    // and reported, then falls through to the halt path —
    // conservative default: if NMI fired, decode the source, stop.
    if (frame->vector == 2)
    {
        if (NmiWatchdogHandleNmi(frame->rip))
            return;

        // GDB stop-rendezvous broadcast (recoverable). Distinct from
        // the panic-broadcast halt path below: the calling CPU will
        // clear arch::SmpGdbStopActive() once its stop loop exits,
        // and we want to RESUME from the NMI at that point — not
        // halt. Capture our state into the per-CPU gdb snapshot,
        // flip the gdb_frozen flag, then spin until the flag clears.
        if (cpu::BspInstalled() && arch::SmpGdbStopActive())
        {
            cpu::PerCpu* p = cpu::CurrentCpu();
            if (p != nullptr)
            {
                p->gdb_snapshot_rip = frame->rip;
                p->gdb_snapshot_rsp = frame->rsp;
                p->gdb_snapshot_rflags = frame->rflags;
                // Publish the live trap frame so the BSP's GDB stop
                // loop can populate a register snapshot for this
                // peer on demand (Hg <tid> + g). The frame lives on
                // this CPU's kernel stack and stays valid for the
                // entire freeze spin below.
                p->gdb_frozen_frame = frame;
                asm volatile("" ::: "memory");
                p->gdb_frozen = 1;
            }
            // Bounded by the BSP's release: it clears the global
            // flag the moment its stop loop exits (continue / detach
            // / kill / step). We re-read with a `pause` to be polite
            // to the SMT sibling. No timeout — the BSP is the only
            // path that can release us, and if it never does, the
            // kernel is wedged anyway and the operator will reset.
            while (arch::SmpGdbStopActive())
            {
                asm volatile("pause" ::: "memory");
            }
            if (p != nullptr)
            {
                asm volatile("" ::: "memory");
                p->gdb_frozen = 0;
                p->gdb_frozen_frame = nullptr;
            }
            return; // resume the interrupted code on this peer
        }

        // Chipset / external NMI decode. A non-watchdog, non-GDB,
        // non-panic-broadcast NMI on real hardware is almost always
        // a hardware error reported through the NMI Status & Control
        // register (port 0x61): bit 7 = PCI SERR# (system / bus
        // parity error), bit 6 = IOCHK# (I/O-channel-check from an
        // add-in card). Just halting left the operator blind to
        // WHICH hardware source fired — the same gap the #MC bank
        // decode closed for vector 18. Gate on !PanicInProgress() so
        // panic-broadcast peers (which arrive here because a panic
        // is already underway) stay quiet and don't fight the
        // panicking CPU for the serial line. Raw serial only — NMI
        // context, possibly-corrupt state, panic-mode serial bypass.
        if (!PanicInProgress())
        {
            const u8 nmi_sc = Inb(0x61);
            SerialWrite("\n** NMI (non-watchdog) **\n  port-0x61 : ");
            SerialWriteHex(nmi_sc);
            const bool serr = (nmi_sc & 0x80) != 0;
            const bool iochk = (nmi_sc & 0x40) != 0;
            if (serr)
                SerialWrite(" SERR#(PCI-system/parity)");
            if (iochk)
                SerialWrite(" IOCHK#(I/O-channel-check)");
            if (!serr && !iochk)
                SerialWrite(" no-SERR/IOCHK — external NMI pin or unknown source");
            SerialWrite("\n  verdict   : hardware error — halting (no NMI-recovery path)\n");
            KLOG_ERROR_V("arch/nmi", "non-watchdog NMI — see ** NMI (non-watchdog) ** dump (port 0x61)",
                         static_cast<u64>(nmi_sc));
            if (serr || iochk)
            {
                KBP_PROBE_V(::duetos::debug::ProbeId::kChipsetNmi, static_cast<u64>(nmi_sc));
            }
        }

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
                // Extended state — captured at the SAME instant as
                // rip/rsp/task so a cross-CPU view shows a
                // consistent snapshot. None of these reads can
                // fault (all are kernel-owned per-CPU memory).
                p->panic_snapshot_cr2 = arch::ReadCr2();
                p->panic_snapshot_rflags = frame->rflags;
                p->panic_snapshot_irq_depth = static_cast<u32>(IrqNestDepthRaw());
                p->panic_snapshot_held_lock_count = p->held_locks_count;
                if (p->held_locks_count > 0)
                {
                    const u32 top = p->held_locks_count - 1;
                    p->panic_snapshot_topmost_lock_acq_rip = p->held_lock_rips[top];
                    p->panic_snapshot_topmost_lock_addr = p->held_locks[top];
                }
                else
                {
                    p->panic_snapshot_topmost_lock_acq_rip = 0;
                    p->panic_snapshot_topmost_lock_addr = nullptr;
                }
                asm volatile("" ::: "memory");
                p->panic_snapshot_valid = 1;
            }
        }
        for (;;)
        {
            asm volatile("cli; hlt");
        }
    }

    // #DF (Double Fault, vector 8). Runs on the dedicated IST1
    // stack (configured by IdtSetIst(8, kIstDoubleFault) at boot),
    // so even if the regular kernel stack is corrupt or
    // exhausted we land here with a known-good RSP. A #DF means
    // ANOTHER trap fired while we were trying to deliver an
    // earlier trap — typically a #PF whose IRET frame couldn't
    // be pushed because the kernel stack itself was unmapped /
    // overflowed.
    //
    // We can't trust the normal Panic path here — even the
    // serial spinlock might be held by the CPU that #DFed. Use
    // panic-mode serial directly + halt. The error_code on #DF
    // is always 0 (Intel SDM 6.15.1) so it's not worth printing.
    if (frame->vector == 8)
    {
        arch::SerialEnterPanicMode();
        arch::SerialWrite("\n[!!! DOUBLE FAULT (vec 8) — ist1 stack ]\n");
        arch::SerialWrite("  rip=");
        arch::SerialWriteHex(frame->rip);
        arch::SerialWrite("\n  rsp=");
        arch::SerialWriteHex(frame->rsp);
        arch::SerialWrite("\n  rflags=");
        arch::SerialWriteHex(frame->rflags);
        arch::SerialWrite("\n  cr2=");
        arch::SerialWriteHex(ReadCr2());
        arch::SerialWrite("\n  cr3=");
        arch::SerialWriteHex(ReadCr3());
        arch::SerialWrite("\n[df] original trap stack likely overflowed or unmapped; halting.\n");
        // Mark panic-in-progress so any recursive halt path
        // short-circuits cleanly instead of trying to dump.
        PanicInProgressMark();
        for (;;)
            asm volatile("cli; hlt");
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
        // mm/poison-alloc guard-page hit. A CR2 inside the poison
        // VA region is, by construction, a buffer overrun OR a use-
        // after-free on a poison-allocated buffer — the data page
        // is the only mapped page in the slot, the two flanking
        // pages are reserved-unmapped guards, and freed slots have
        // their data page unmapped (VA leak by design). Either way,
        // catching this fault at the write site IS the whole point
        // of the allocator, so the reaction is Halt — continuing
        // would only mask the bug. Routed through FaultReactDispatch
        // so the kernel-owned floor + policy machinery get to log
        // and tally the event uniformly with every other fault kind.
        if (mm::IsPoisonRegionAddress(cr2))
        {
            SerialWrite("[poison] guard-page hit at CR2=");
            SerialWriteHex(cr2);
            SerialWrite(" RIP=");
            SerialWriteHex(frame->rip);
            SerialWrite(" — buffer overrun or use-after-free detected\n");
            ::duetos::diag::FaultEvidence ev{};
            ev.source = "kernel/mm/poison-alloc";
            ev.kind = ::duetos::diag::FaultKind::PoisonGuardHit;
            ev.severity = ::duetos::diag::FaultSeverity::Critical;
            ev.attempt_count = 0;
            ev.faulting_rip = frame->rip;
            ev.aux = cr2;
            (void)::duetos::diag::FaultReactDispatch(::duetos::core::kFaultDomainInvalid, ev);
            // Dispatch should Halt (default policy is Halt for this
            // kind, floor pins it to Halt anyway). Belt-and-braces
            // panic on the off chance dispatch returned — the panic
            // value lets the operator recover CR2 even if the
            // dispatch logged the wrong field.
            core::PanicWithValue("kernel/mm/poison-alloc", "guard-page hit (overrun / UAF)", cr2);
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
            // the recovery to the watchdog via the FaultReact
            // deferred-report path. That path:
            //   - records (kind, faulting RIP) in a per-domain
            //     pending slot — picked up by the heartbeat's
            //     FaultReactDrainPending so the per-subsystem
            //     policy + kernel-owned floor get to react;
            //   - calls FaultDomainMarkRestart as the lossless
            //     backbone, so even if the dispatch path lost
            //     the slot, the bool-driven restart still fires
            //     on the next FaultDomainTick.
            // Both writes are plain stores — safe from trap
            // context (no locks, no klog, no allocation).
            if (hit->domain_id != ::duetos::debug::kExtableNoDomain)
            {
                // An extable hit means recovery WAS planned for
                // this fault — it's not the kernel-page-fault
                // floor case. Use InternalInvariant so the
                // dispatcher's default policy returns
                // RestartDomain and the kernel-owned floor
                // (which escalates KernelPageFault to Halt) does
                // not fire. The trap vector + cr2 are still
                // logged on the [extable] line above for
                // post-mortem.
                ::duetos::diag::FaultReactReportFromTrap(hit->domain_id, ::duetos::diag::FaultKind::InternalInvariant,
                                                         frame->rip);
                SerialWrite("[extable] queued fault-react report for domain id=");
                SerialWriteHex(hit->domain_id);
                SerialWrite("\n");
            }
            // Journal the soft-fault recovery so the off-line fix
            // pipeline (gen-fix-report.py / gen-fix-patches.py) sees
            // "this kernel touch is flaky enough that the extable
            // catches it." A single such record per (faulting RIP)
            // dedups: the entry stays at repeat_count=1 for the rare
            // SMAP-violation case we already understand, but if a
            // production touch starts firing here the count rises and
            // the report flags the new pin for human attention. Trap
            // context: deferred path; the heartbeat drain promotes the
            // single-slot pending into a full FixRecord with detector-
            // aware pin "trap.recov" + hint "extable / canary / fixup
            // recovered in trap" (see fix_journal.cpp:357-363).
            ::duetos::diag::FixJournalRecordFromTrap(::duetos::diag::FixDetector::SoftFaultRecov, frame->rip,
                                                     hit->fixup_rip);
            // Sanctioned RIP redirect — tell the integrity guard so it
            // doesn't mistake this extable recovery for a mid-handler
            // scribble (false-positive found by mem/smp stress fuzzing).
            guard.sanctioned_rewrite = true;
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

    // Ring-3 #PF: give the Win32 PAGE_GUARD recovery the first
    // bite. If cr2 lies inside a vmap region's currently-guard-
    // armed page, the helper clears the guard bit, re-applies the
    // base protection, and we return so the faulting instruction
    // is retried. Otherwise the fault flows through the normal
    // IsolateTask policy below. Full STATUS_GUARD_PAGE_VIOLATION
    // delivery is gated on T6-02 (x64 SEH); v0 silently re-arms,
    // which still services the common stack-grow probe pattern.
    if (frame->vector == 14 && from_user)
    {
        const u64 cr2 = ReadCr2();
        if (::duetos::subsystems::win32::Win32VmapPageGuardClear(cr2))
        {
            return;
        }
    }

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
    // After the in-kernel breakpoints subsystem said "not mine",
    // route to the GDB stub IF an external debugger has been
    // wired up via DUETOS_GDB_SERVER. The stub's RouteToStopLoop
    // returns false when no sink is published, in which case the
    // existing recoverable-trap path below picks the int3 / #DB
    // up the same way it always did.
    if (frame->vector == 3 && ::duetos::diag::gdb::HandleSoftwareBreakpoint(frame))
    {
        return;
    }
    if (frame->vector == 1 && ::duetos::diag::gdb::HandleDebugException(frame))
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
        // T6-02: before tearing the task down, try to deliver the
        // fault to the faulting Win32 PE as a structured exception.
        // A PE with a covering __try/__except (or a vectored
        // handler) catches it and continues, and only when the
        // process has our ntdll mapped. On success the trap frame now
        // resumes at ntdll!KiUserExceptionDispatcher — just return so
        // iretq lands there. Any failure (no ntdll, unwritable user
        // stack, re-fault loop) falls through to the legacy task-kill
        // path unchanged.
        //
        // The dispatchable set is every CPU exception Windows itself
        // surfaces as a structured exception (see VectorToUserNtStatus,
        // the shared vector->NTSTATUS table), each mapped to the
        // matching code so a __try/__except filtering on a specific
        // EXCEPTION_* value sees the right one. #BP/#DB are absent —
        // they are claimed earlier by the breakpoint / GDB subsystems
        // under LogAndContinue policy and never reach this block.
        {
            const u32 seh_status = VectorToUserNtStatus(frame->vector);
            const bool seh_dispatchable = (seh_status != 0);
            const bool seh_is_pf = (frame->vector == 14);
            const bool seh_pf_write = seh_is_pf && ((frame->error_code & 0x2) != 0);
            const u64 seh_fault_va = seh_is_pf ? ReadCr2() : 0;
            if (seh_dispatchable && ::duetos::subsystems::win32::Win32DeliverException(frame, seh_status, seh_is_pf,
                                                                                       seh_pf_write, seh_fault_va))
            {
                return;
            }
        }

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
        // User-mode RIPs don't resolve against the kernel symbol
        // table, but the wild-address hint still applies — a
        // ring-3 call through a corrupted vtable lands at -1 / NULL
        // exactly the same shape the kernel's wild classifier
        // already names.
        ::duetos::core::WriteAddressWithSymbol(frame->rip);
        SerialWrite("\n  rsp  : ");
        SerialWriteHex(frame->rsp);
        ::duetos::core::WriteWildAddressHint(frame->rsp);
        SerialWrite("\n  cs   : ");
        SerialWriteHex(frame->cs);
        ::duetos::core::WriteSegmentSelectorBits(frame->cs);
        if (frame->vector == 14)
        {
            const u64 user_cr2 = ReadCr2();
            SerialWrite("\n  cr2  : ");
            SerialWriteHex(user_cr2);
            // Sentinel hint on cr2 so a `[wild: u32 -1 zero-extended …]`
            // fires when ring-3 dereferences a sentinel-shaped value
            // it didn't recognise as "no result".
            ::duetos::core::WriteWildAddressHint(user_cr2);
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
        // Emit a Windows-format minidump for the faulting PE before
        // we reap the task. Kernel-mode panics already do this at the
        // hard-panic site below; ring-3 faults previously left no
        // post-mortem behind, so a PE that crashed on a STUB
        // import / wild pointer / bad opcode forced an operator to
        // rebuild + replay just to see register state. With the dump
        // egressed via debugcon the host gets a real `.dmp` per ring-3
        // crash — loadable in WinDbg / VS / VSCode — and the NVMe
        // reserved slot picks up the same bytes for offline triage.
        // Same vector->NTSTATUS table the SEH delivery used, so the
        // .dmp's exception code matches what a covering __try/__except
        // would have seen. Vectors with no structured-exception
        // analogue fall back to STATUS_BREAKPOINT (0x80000003).
        u32 user_ntstatus = VectorToUserNtStatus(frame->vector);
        if (user_ntstatus == 0)
        {
            user_ntstatus = 0x80000003;
        }
        duetos::diag::minidump::EmitMinidumpFromTrapFrame(frame, user_ntstatus);
        // UserFault: journal the ring-3 crash so a chronically-failing
        // PE binary becomes visible in dfix list and the offline
        // report. Dedups per (task_id, vector) — a single EXE
        // wild-jumping on every spawn produces ONE record with
        // repeat_count = crash count, not one per launch. Recording
        // happens after the minidump emit so the .dmp is on disk
        // even if the journal flush gets interrupted; the trap-
        // pending slot is drained by the next heartbeat from the
        // reaper. ctx_a same shape as TrapCapture
        // ((vector << 32) | error_code); ctx_b = CR2 for #PF / 0
        // otherwise.
        {
            const u64 uf_ctx_a =
                (static_cast<u64>(frame->vector) << 32) | (static_cast<u64>(frame->error_code) & 0xffffffffULL);
            const u64 uf_ctx_b = (frame->vector == 14) ? ReadCr2() : 0ULL;
            ::duetos::diag::FixJournalRecordFromTrap2(::duetos::diag::FixDetector::UserFault, uf_ctx_a, uf_ctx_b,
                                                      frame->rip);
        }
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

    // Recursive-fault short-circuit. If we're already inside a
    // halt-bound dump (this dispatcher entered its Panic branch on
    // a previous trap, or core::Panic was running its
    // DumpDiagnostics when something faulted), every diagnostic we
    // could run from here is itself running on a potentially-
    // corrupt frame and risks re-faulting. Emit one raw-serial
    // marker so the operator sees the recursion and halt — losing
    // the second dump beats triple-faulting.
    if (PanicInProgress())
    {
        HaltOnRecursiveFault(frame->vector, frame->rip);
    }
    PanicInProgressMark();

    // TrapCapture: deferred-slot record so the FAT32 / NVMe panic-
    // write tier picks up a structured (faulting-RIP, vector, CR2)
    // tuple for the offline patch generator. The drain in
    // FixJournalDrainTrapPending promotes it into a full FixRecord
    // with an auto-pinned `func+0xOFF` source pin keyed off the
    // faulting RIP — the patch generator resolves that via
    // addr2line to get file:line for a per-fault brief.
    //
    // ctx_a packs (vector << 32) | (error_code & 0xffffffff). ctx_b
    // is CR2 for #PF (vector 14) and 0 for all other vectors.
    // Recording here is BEFORE the dump emit so even if the dump
    // path re-faults, the panic-tier persistence (which runs from
    // EmitMinidumpFromTrapFrame and includes a fix-journal flush)
    // already has the record.
    {
        const u64 cap_ctx_a =
            (static_cast<u64>(frame->vector) << 32) | (static_cast<u64>(frame->error_code) & 0xffffffffULL);
        const u64 cap_ctx_b = (frame->vector == 14) ? ReadCr2() : 0ULL;
        ::duetos::diag::FixJournalRecordFromTrap2(::duetos::diag::FixDetector::TrapCapture, cap_ctx_a, cap_ctx_b,
                                                  frame->rip);
    }

    // Publish the trap-frame state to the GDB stub so a future
    // attach (or a stop-at-fault GDB session) sees the real
    // register values from the moment of fault. Single struct
    // copy + pointer publish; cheap. (D7-followup, 2026-04-28.)
    static ::duetos::diag::gdb::GdbServerRegSnapshot s_gdb_snap;
    s_gdb_snap.rax = frame->rax;
    s_gdb_snap.rbx = frame->rbx;
    s_gdb_snap.rcx = frame->rcx;
    s_gdb_snap.rdx = frame->rdx;
    s_gdb_snap.rsi = frame->rsi;
    s_gdb_snap.rdi = frame->rdi;
    s_gdb_snap.rbp = frame->rbp;
    s_gdb_snap.rsp = frame->rsp;
    s_gdb_snap.r8 = frame->r8;
    s_gdb_snap.r9 = frame->r9;
    s_gdb_snap.r10 = frame->r10;
    s_gdb_snap.r11 = frame->r11;
    s_gdb_snap.r12 = frame->r12;
    s_gdb_snap.r13 = frame->r13;
    s_gdb_snap.r14 = frame->r14;
    s_gdb_snap.r15 = frame->r15;
    s_gdb_snap.rip = frame->rip;
    s_gdb_snap.rflags = frame->rflags;
    s_gdb_snap.cs = static_cast<u32>(frame->cs);
    s_gdb_snap.ss = static_cast<u32>(frame->ss);
    s_gdb_snap.ds = 0;
    s_gdb_snap.es = 0;
    s_gdb_snap.fs = 0;
    s_gdb_snap.gs = 0;
    ::duetos::diag::gdb::GdbServerPublishRegisters(&s_gdb_snap);
    // Also publish as writable so a connected GDB session's `G`
    // packet can apply edits before the operator continues. The
    // edits land in s_gdb_snap; copying them back into the trap
    // frame on resume is the next D7-followup once a stop-at-
    // fault flow exists.
    ::duetos::diag::gdb::GdbServerPublishWritableRegisters(&s_gdb_snap);
    //
    // Fire the per-vector probe so the log ring records this as a
    // structured event before the panic dump. Each kernel-mode CPU
    // exception that has a distinct shape gets its own probe; the
    // operator can disarm noisy ones in isolation. #PF additionally
    // emits a D2 EventTrace so a subsequent `tracer dump` shows the
    // fault in its chronological place.
    if (frame->vector == 14)
    {
        KBP_PROBE_V(::duetos::debug::ProbeId::kKernelPageFault, frame->rip);
        u64 cr2;
        asm volatile("mov %%cr2, %0" : "=r"(cr2));
        ::duetos::diag::EventTrace(::duetos::diag::kEventPageFault, cr2, frame->error_code);
    }
    else if (frame->vector == 13)
    {
        KBP_PROBE_V(::duetos::debug::ProbeId::kKernelGpf, frame->rip);
    }
    else if (frame->vector == 6)
    {
        KBP_PROBE_V(::duetos::debug::ProbeId::kKernelUd, frame->rip);
    }
    // Quiet the NMI watchdog before the dump. DumpDiagnostics +
    // symbol resolution + serial I/O can easily exceed one
    // watchdog interval; a PMI overflow during the dump would
    // re-enter the trap dispatcher and scramble the output.
    NmiWatchdogDisable();
    // Freeze the LBR ring before any further branches in this
    // dispatcher push real call sites out of the most-recent
    // entries. No-op when LBR isn't available.
    LbrFreeze();
    // Halt peer CPUs the same way `core::Panic` does — they're
    // running against potentially-corrupt shared state once we've
    // taken a fault in kernel mode, and their NMI handlers commit
    // a snapshot we can dump after our own diagnostics. Wait for
    // peers to actually reach the NMI halt-spin (snapshot flag
    // flipped) before starting the serial dump — see
    // PanicWaitPeersHalt for why an immediate dump corrupts
    // output on SMP. Budget: ~50k pause-iters is a few-ms on TCG
    // (LAPIC IPI delivery + handler entry latency), bounded so a
    // dropped IPI / wedged peer never traps the dumper forever.
    PanicBroadcastNmi();
    arch::PanicWaitPeersHalt(50'000);
    SerialWrite("\n** CPU EXCEPTION **\n");

    // #MC: decode the Machine Check Architecture banks before the
    // generic register dump so the operator sees *which hardware*
    // failed (bank, MCA error class, faulting physical address,
    // PCC/RIPV recoverability) up-front. Pure MSR read-back + raw
    // serial; safe on the IST2 machine-check stack. The standard
    // crash-dump record (registers, stack walk) still follows.
    if (frame->vector == 18)
    {
        (void)arch::MachineCheckReport(frame);
    }

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
    // If RIP is recognisably wild (-1, NULL, u32 sentinel, etc.)
    // emit a multi-line `[!] crash analysis:` banner ABOVE the rip
    // line so the operator sees the diagnosis up-front instead of
    // having to spot the magic number further down. No-op for a
    // valid RIP — the standard line below carries the symbol.
    core::WriteCrashAnalysisBanner(frame->rip);
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
    // RBP chain walked off into garbage. 32 quads = 256 bytes —
    // bumped from 16 (2026-05-22) so a deeper call chain remains
    // visible when the RBP chain itself was clobbered (the typical
    // shape of the SMP-saturation UAF: rbp = 0xdedede..., rip in
    // freed-poison; the stack quads above rsp still carry the real
    // return addresses).
    core::DumpStackWindow("fault-stack", frame->rsp, 32);

    // Rich diagnostics from the faulting frame — backtrace climbs
    // the stack from rbp AT THE POINT OF THE FAULT (not from the
    // dispatcher's own frame), so the returned frame chain shows
    // the actual call path that led to the exception.
    core::DumpDiagnostics(frame->rip, frame->rsp, frame->rbp);
    core::DumpPeerCpuSnapshots();

    core::EndCrashDump();

    // Binary minidump egress — see core::Panic for rationale. Map the
    // exception vector to a recognisable NTSTATUS via the shared table
    // (the same one the ring-3 path uses) so a debugger that opens the
    // .dmp shows the right exception kind for #DE/#UD/#GP/#PF/#MF/etc.
    // Vectors with no analogue fall back to STATUS_BREAKPOINT. Use the
    // TrapFrame-aware overload so all 16 GPRs + segment selectors +
    // rflags land in the dump's CONTEXT_X64 — not just rip/rsp/rbp
    // like the soft-panic path.
    u32 ntstatus = VectorToUserNtStatus(frame->vector);
    if (ntstatus == 0)
    {
        ntstatus = 0x80000003;
    }
    duetos::diag::minidump::EmitMinidumpFromTrapFrame(frame, ntstatus);

    SerialWrite("[panic] Halting CPU.\n");
    Halt();
}

u64 IrqCountForVector(u8 v)
{
    // Sum per-CPU rows for this vector. Each CPU's row is written
    // only by itself with IF=0, so the per-row read is consistent.
    // The total may transiently miss an in-flight increment on
    // another CPU; the runtime checker's storm detector tolerates
    // that (it samples deltas across two reads).
    u64 sum = 0;
    for (u32 cpu = 0; cpu < acpi::kMaxCpus; ++cpu)
    {
        sum += g_irq_counts_per_cpu[cpu][v];
    }
    return sum;
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
        // A caller passing an OOB vector is a kernel bug — there is
        // no recovery path that produces a working device. The old
        // shape here raw-serialled the vector then bare-Halt()ed,
        // bypassing klog and the panic dump entirely so a
        // post-mortem only ever saw the four-line trailer. Route
        // through the full panic path so the crash dump captures
        // the offending vector, the call site (via backtrace), and
        // the per-CPU state.
        ::duetos::core::PanicWithValue("arch/traps", "IrqInstall: vector out of range", vector);
    }
    // A null handler CLEARS the slot — the documented contract (see
    // traps.h) and what the dispatcher already expects: g_irq_handlers
    // defaults to nullptr meaning "no handler", and TrapDispatch
    // sanity-checks the slot is in kernel .text before the indirect
    // call (so a null slot logs+EOIs, never derefs). Callers rely on
    // this to UNDO an install — e.g. PciMsixBindSimple's cleanup when
    // MSI-X routing fails on a device that has no MSI-X (an e1000 /
    // 82540EM under QEMU/VirtualBox). The previous PanicWithValue here
    // violated that contract and crashed the boot the instant a NIC's
    // MSI-X bind tried to fall back to polling — i.e. on every wired
    // NIC the VM exposes.
    g_irq_handlers[vector] = handler; // handler may be nullptr (clear)
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
    // mm/SafeReadKernel — kernel-to-kernel read with fault fixup.
    // Used by the panic dump's DumpInstructionBytes to read bytes
    // at addresses outside the kernel range (user VA in active
    // AS, guard pages) without taking the box down on a stale
    // pointer.
    const u64 sr_s = reinterpret_cast<u64>(__safe_read_kernel_start);
    const u64 sr_e = reinterpret_cast<u64>(__safe_read_kernel_end);
    const u64 sr_fixup = reinterpret_cast<u64>(__safe_read_kernel_fault_fixup);
    ::duetos::debug::KernelExtableRegister(sr_s, sr_e, sr_fixup, "mm/SafeReadKernel");
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

    // 2. Stray-vector probe. Vector 0x42 (66) has no registered
    // handler. It lands in the dispatched MSI-X range [48,239], so it
    // takes the IRQ path's no-handler leg (logging "unhandled IRQ
    // vector 0x42"), NOT the 48..255 "[idt] spurious" leg — which only
    // covers vectors outside the dispatched range. That no-handler leg
    // now also exercises the LAPIC-ISR EOI gate: because this is a
    // software `int n`, the ISR bit for 0x42 is clear, so the gate
    // must NOT EOI (an EOI here would dismiss a real in-flight IRQ).
    // Either way the stub `mkstub 66` -> isr_common -> TrapDispatch
    // must recover and iretq; without the full-IDT install it would
    // cascade to #NP and halt — easy regression signal.
    asm volatile("int $0x42");

    // 3. Wild trap-frame-pointer guard (the TrapDispatch entry validator). The
    //    non-canonical wild shape must be REFUSED and a live present address
    //    ACCEPTED. Only fault-free cases run here: TrapsSelfTest precedes
    //    TrapsRegisterExtable in boot, so probing an UNMAPPED address (the -1 shape)
    //    would fault with no extable armed and triple-fault — that present-reject
    //    path rides on SafeReadKernel's own contract. Non-canonical short-circuits
    //    before any probe; the accept case reads a valid mapped stack address.
    bool guard_ok = true;
    guard_ok &= !TrapFramePointerIsSane(reinterpret_cast<void*>(0x001d2025001d2025ULL)); // non-canonical -> reject
    guard_ok &= TrapFramePointerIsSane(&guard_ok);                                       // live frame -> accept
    if (guard_ok)
    {
        SerialWrite("[traps] wild-frame-pointer guard OK (non-canonical refused, live frame accepted)\n");
    }
    else
    {
        SerialWrite("[traps] wild-frame-pointer guard FAIL\n");
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x6u);
    }

    // 4. IRQ/trap nesting-depth counter. Steps 1+2 each drove a trap
    //    through TrapDispatch, so IrqNestScope incremented then
    //    decremented the live depth twice and bumped the high-water
    //    mark to at least 1. We are back in straight-line kernel code
    //    now (no handler on the stack), so the live depth MUST read 0
    //    and the max MUST be >= 1. A regression where the accessors
    //    revert to the old constant-0 stubs (silently disarming the
    //    runtime checker's IrqNesting ceiling + the panic-snapshot
    //    depth field) trips this: max stays 0. A regression where the
    //    dtor stops firing leaves the live depth elevated: depth != 0.
    const u64 nest_now = IrqNestDepth();
    const u64 nest_max = IrqNestMax();
    if (nest_now == 0 && nest_max >= 1)
    {
        SerialWrite("[traps] irq-nest-depth counter OK (live=0 after self-test, max>=1)\n");
    }
    else
    {
        SerialWrite("[traps] irq-nest-depth counter FAIL live=");
        SerialWriteHex(nest_now);
        SerialWrite(" max=");
        SerialWriteHex(nest_max);
        SerialWrite("\n");
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x7u);
    }

    // 5. Vector -> NTSTATUS table (VectorToUserNtStatus). Pure-function
    //    spot-check of the single source of truth shared by the ring-3
    //    SEH delivery switch and both minidump emits. A typo or an
    //    accidental edit that desyncs a mapping (the "sentinel
    //    divergence" class of bug) would silently hand a PE the wrong
    //    EXCEPTION_* code or mislabel a .dmp; this catches it at boot.
    //    Checks a representative spread plus the must-be-zero entries
    //    (#BP and a reserved vector have no structured-exception
    //    analogue and must return 0 so the caller's fallback fires).
    bool ntmap_ok = true;
    ntmap_ok &= (VectorToUserNtStatus(0) == 0xC0000094);  // #DE
    ntmap_ok &= (VectorToUserNtStatus(6) == 0xC000001D);  // #UD
    ntmap_ok &= (VectorToUserNtStatus(14) == 0xC0000005); // #PF
    ntmap_ok &= (VectorToUserNtStatus(17) == 0x80000002); // #AC
    ntmap_ok &= (VectorToUserNtStatus(19) == 0xC00002B4); // #XM
    ntmap_ok &= (VectorToUserNtStatus(3) == 0);           // #BP — no analogue
    ntmap_ok &= (VectorToUserNtStatus(15) == 0);          // reserved — no analogue
    if (ntmap_ok)
    {
        SerialWrite("[traps] vector->NTSTATUS table OK (SEH delivery + minidump share one map)\n");
    }
    else
    {
        SerialWrite("[traps] vector->NTSTATUS table FAIL\n");
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x8u);
    }

    SerialWrite("[traps] self-test OK — #BP and spurious both recovered\n");
}

} // namespace duetos::arch
