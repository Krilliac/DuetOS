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

/// Walk `[__init_array_start, __init_array_end)` (defined by the
/// linker script) and invoke each function pointer in order.
/// Standard hosted-runtime behaviour for C++ static constructors
/// — kernel TUs almost always use `constinit` globals to avoid
/// runtime initialisers, so the table is typically empty / very
/// short. Call once at boot AFTER the kernel heap is online (so
/// any constructor that allocates won't trip the early frame
/// allocator). Subsequent calls are safe but redundant.
void RunInitArray();

/// Lightweight registration helper for the `KERNEL_INITCALL`
/// macro. Stamped into a `.init_array.<phase>` slot via the
/// macro below; runs from `RunInitArray()` and forwards into
/// `InitcallRegister` so the entry shows up in the registry
/// alongside hand-registered callbacks. Returns void; failures
/// inside `InitcallRegister` are non-fatal (logged + dropped)
/// because at constructor-time there's no panic context yet.
void InitcallAutoRegister(Phase phase, const char* name, InitcallFn fn);

} // namespace duetos::core

/*
 * KERNEL_INITCALL — compile-time registration. Place at file
 * scope in the TU that owns the callback:
 *
 *     static ::duetos::core::Result<void> MySubsystemInit() { ... }
 *     KERNEL_INITCALL(Drivers, "my-subsystem", MySubsystemInit);
 *
 * The macro emits a `__attribute__((constructor))` thunk that
 * `core::RunInitArray()` invokes once at boot; the thunk calls
 * `InitcallAutoRegister(phase, name, fn)`. The actual
 * `RunPhase(phase)` call still has to be made by `kernel_main`
 * (or whoever owns the dispatcher) — registration alone doesn't
 * imply ordering.
 *
 * Concatenation gymnastics (DUETOS_INITCALL_CONCAT) make each
 * use produce a unique symbol name without forcing the caller
 * to invent one.
 */
#define DUETOS_INITCALL_CONCAT2(a, b) a##b
#define DUETOS_INITCALL_CONCAT(a, b) DUETOS_INITCALL_CONCAT2(a, b)

#define KERNEL_INITCALL(phase_name, label, fn)                                                                         \
    namespace                                                                                                          \
    {                                                                                                                  \
    __attribute__((constructor)) void DUETOS_INITCALL_CONCAT(_kernel_initcall_ctor_, __LINE__)()                       \
    {                                                                                                                  \
        ::duetos::core::InitcallAutoRegister(::duetos::core::Phase::phase_name, label, fn);                            \
    }                                                                                                                  \
    } // namespace

/*
 * The original NOTE on KERNEL_INITCALL (deferred until
 * `_init_array` was invoked) has been resolved. `_init_array`
 * is now walked by `core::RunInitArray()` immediately after
 * `KernelHeapInit`, and the macro above forwards into
 * `InitcallAutoRegister`. Subsystems can use either form —
 * direct `InitcallRegister(...)` from a hand-written init hook
 * or `KERNEL_INITCALL(phase, name, fn)` at file scope. The two
 * coexist (the macro just calls the same registry).
 */
