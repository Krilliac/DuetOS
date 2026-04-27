#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — formal kernel init ordering, v0 (plan A1).
 *
 * WHAT
 *   A registry of named init callbacks bucketed by `Phase`. Callers
 *   register a function pointer at runtime via `InitcallRegister`;
 *   the boot driver calls `RunPhase(Phase::X)` to invoke every
 *   callback registered against that phase, in registration order.
 *   See the trailing-comment block for why `KERNEL_INITCALL`
 *   (the macro form mentioned in plan A1) is intentionally absent.
 *
 * WHY
 *   The legacy boot path is one long imperative sequence inside
 *   `kernel_main`. That stays — see the file-level comment in
 *   `core/main.cpp` for the rationale ("getting boot order wrong is a
 *   triple-fault, not a unit-test failure"). What's added here is an
 *   *adjacent* mechanism: subsystems that want a clean,
 *   self-describing init contract can register callbacks against a
 *   phase, and a future commit can migrate them from the imperative
 *   call list to the registry without re-engineering the whole file.
 *
 *   The infrastructure also gives the runtime checker / health
 *   reporter a single table to walk when answering "what came up at
 *   boot, in what order, and how long did each take?".
 *
 * NO BOOT-TIME ALLOCATOR
 *   The registry is a fixed-size table sized at compile time. No
 *   heap allocation; safe to call before `KernelHeapInit`.
 *
 * CONTEXT
 *   Kernel, BSP only, single-threaded boot. Registration is not
 *   thread-safe by design (it must run before SMP comes up). After
 *   AP bringup, the table is read-only.
 */

namespace duetos::core
{

/// Init phases, ordered as the boot sequence runs them. The numeric
/// values are stable so a future health/diag report can sort by
/// phase without consulting this header. Keep contiguous; the
/// dispatch loop iterates `0..kPhaseCount`.
enum class Phase : u32
{
    Earlycon = 0,  ///< Serial / early klog / KLogSelfTest.
    PhysMem = 1,   ///< Multiboot2 parse, frame allocator.
    Paging = 2,    ///< Page tables, higher-half move, NX/SMEP/SMAP.
    Heap = 3,      ///< Kernel heap online.
    Idt = 4,       ///< GDT/IDT/TSS/IST, syscall gate, extable.
    Apic = 5,      ///< LAPIC, IO-APIC, PIC mask-off, IRQ routing.
    Time = 6,      ///< HPET/TSC/RTC, periodic tick, NMI watchdog.
    PerCpuBsp = 7, ///< BSP per-CPU area + scheduler runqueue.
    Sched = 8,     ///< Scheduler online (kernel threads OK from here).
    Smp = 9,       ///< AP bringup.
    Drivers = 10,  ///< PCI enum, NVMe, GPU, USB, NIC, audio.
    Vfs = 11,      ///< VFS root, ramfs, GPT scan, FS mount.
    Userland = 12, ///< First user task / init.

    kPhaseCount = 13
};

/// Init callback. Returns Ok on success; Err halts the phase and
/// the dispatch loop reports the failing record. Whether a failure
/// panics or marks a fault domain is the dispatcher's policy
/// decision (see `RunPhase` doc).
using InitcallFn = Result<void> (*)();

/// One row of the registry.
struct InitcallRecord
{
    Phase phase;
    const char* name; ///< Stable string literal, used in logs.
    InitcallFn fn;
    u64 invoke_count;   ///< Times `fn` returned (typically 1).
    u64 last_run_ticks; ///< Scheduler-tick of the most recent invocation.
    bool ran_ok;        ///< True iff the most recent run returned Ok.
};

/// Registry capacity. Sized for the planned subsystems plus
/// headroom; bump if a real registration is rejected.
inline constexpr u32 kMaxInitcalls = 64;

/// Register `fn` against `phase`. Returns Ok on success, Err when:
///   - `name` or `fn` is null
///   - the registry is full
///   - `phase` is out of range
/// Idempotency: not enforced. Two calls with the same (phase, name,
/// fn) produce two rows; the dispatcher invokes both. Callers
/// should not rely on this for "register once" semantics.
Result<void> InitcallRegister(Phase phase, const char* name, InitcallFn fn);

/// Number of currently-registered callbacks across all phases.
u32 InitcallCount();

/// Number of callbacks registered against `phase`.
u32 InitcallCountForPhase(Phase phase);

/// Invoke every callback registered against `phase`, in registration
/// order. Returns the first Err produced; subsequent records in the
/// phase are not run. Logs each invocation (name + result) at Info
/// level. Caller policy decides whether to panic on Err — the
/// dispatcher itself does not.
Result<void> RunPhase(Phase phase);

/// Read-only accessor for diagnostics / shell `init list` command
/// (future). Returns nullptr for out-of-range index.
const InitcallRecord* InitcallGet(u32 index);

/// Human-readable phase name. Returns "?" for out-of-range. Used by
/// the dispatch loop's log lines and any future shell printer.
const char* PhaseName(Phase phase);

/// Boot-time self-test. Registers three throwaway callbacks against
/// three different phases, runs each phase, asserts each callback
/// fired exactly once and that registration order is preserved.
/// Panics on mismatch — the init registry is load-bearing for any
/// future caller, so a regression here is a hard stop.
void InitSelfTest();

} // namespace duetos::core

/*
 * NOTE on `KERNEL_INITCALL`: the plan A1 entry calls for a
 * registration macro that lands callbacks in a fixed-size table
 * "at link time". This kernel does not currently invoke
 * `_init_array` at boot, so a static-constructor-driven macro
 * would compile but never run — exactly the dead-code class
 * CLAUDE.md forbids. Until a `_init_array` invocation is added
 * (a separate slice; see the plan's Status table), subsystems
 * call `InitcallRegister(...)` directly from their existing init
 * hook. The macro itself is intentionally absent rather than
 * stubbed.
 */
