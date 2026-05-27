#pragma once

#include "util/types.h"

/*
 * DuetOS — cross-CPU function call primitive (v0).
 *
 * Pattern: Linux `smp_call_function*` + Windows `KeIpiGenericCall`.
 * Lets any CPU invoke an arbitrary function on a single peer or on
 * every online CPU, with optional spin-wait for completion.
 *
 * Unblocks correct TLB shootdown (per-CPU sequencing instead of a
 * single global request slot), runtime-checker rebaseline-on-all-
 * CPUs, and future stop-machine / live-patching primitives.
 *
 * Mailbox shape (see ipi_call.cpp for the implementation):
 *   Each CPU owns a 16-slot MPSC ring. Producers (any CPU) bump the
 *   head atomically, fill the slot's {fn, arg, completion_word},
 *   then publish via a release-store of the "armed" tag. The owning
 *   CPU is the only consumer of its own ring (the IPI handler runs
 *   on the target CPU). The single-consumer invariant lets the
 *   consumer side skip read fences beyond the armed-tag gate.
 *
 * Context for callee `fn`:
 *   Runs in IRQ context on the target CPU with IF=0 (the IPI vector
 *   delivered through the kernel's IDT inherits IF=0 from the gate).
 *   `fn` MUST NOT sleep, allocate from a sleeping allocator, take a
 *   sleeping mutex, or do anything else that requires PASSIVE-level
 *   context. `arch::SerialWrite`, `KLOG_*`, atomic ops, spinlocks
 *   that are themselves IRQ-safe are all fine.
 *
 * Reentrancy:
 *   The handler is reentrant against itself only if a higher-vector
 *   interrupt with IF=0 disabled were to fire — which can't happen
 *   on a vanilla fixed-delivery IPI. We still drain to the head as
 *   observed at handler entry so a nested invocation (NMI-routed,
 *   future debug pokes) cannot loop forever.
 *
 * Deadlock contract:
 *   `IpiCallOne(self, fn, arg, wait=true)` is short-circuited to a
 *   direct local invocation — no IPI fired, no risk of self-wait.
 *   Calling `IpiCallOne(peer, fn, arg, wait=true)` from inside an
 *   IPI handler while peer is also waiting on us would deadlock;
 *   don't do that. (No supported caller does today; documented for
 *   future authors.)
 */

namespace duetos::cpu
{

/// Function-pointer signature for an IPI-callable. Sees the
/// caller-provided opaque arg; returns void. See `arg` lifetime
/// rules on the API functions below.
using IpiCallFn = void (*)(void* arg);

/// Call `fn(arg)` on a single target CPU.
///
/// If `cpu_id` is the calling CPU's own id, runs `fn(arg)`
/// synchronously on the caller and returns true — no IPI is sent.
///
/// If `cpu_id` is a peer CPU and `wait == true`, pushes the call
/// onto the target's mailbox, sends the IPI, and spins until the
/// target's handler has executed `fn(arg)` and posted completion.
/// `arg` must outlive the call — one stack frame is sufficient.
///
/// If `wait == false`, returns once the IPI has been queued and
/// the LAPIC ICR write has been issued. Completion is fire-and-
/// forget; `arg` must outlive the target's handler invocation,
/// which usually means caller-side static / heap allocation with
/// target-side ownership transfer.
///
/// Returns false when `cpu_id` is out of range or that CPU's
/// PerCpu has never been allocated (i.e. AP slot that never
/// brought up).
bool IpiCallOne(u32 cpu_id, IpiCallFn fn, void* arg, bool wait);

/// Call `fn(arg)` on EVERY online CPU including the caller.
///
/// The caller's `fn(arg)` runs synchronously on entry (before
/// any peer IPI is sent), so a `wait == false` broadcast still
/// has the local effect committed by return.
///
/// If `wait == true`, returns only after every peer CPU has
/// executed `fn(arg)` and posted completion. The same `arg`
/// pointer is delivered to every CPU; the function must therefore
/// either be stateless or use thread-local-equivalent state (e.g.
/// per-CPU counters via `cpu::CurrentCpu()`).
///
/// Returns the number of CPUs the call was dispatched to (so
/// callers can sanity-check against `acpi::CpuCount()`).
u32 IpiCallEach(IpiCallFn fn, void* arg, bool wait);

/// Diagnostic counters since boot. Read-mostly snapshot; non-
/// atomic against in-flight calls (a concurrent post may or may
/// not be visible). Used by the self-test and by debug shell
/// dumps; not on any hot path.
struct IpiCallStats
{
    u64 calls_one_total;      ///< IpiCallOne invocations (every call counts, including self)
    u64 calls_each_total;     ///< IpiCallEach invocations
    u64 invocations_received; ///< fn() executions across all CPUs (local + remote)
    u64 wait_spin_max_loops;  ///< longest observed wait spin (saturating; pause iterations)
    u64 wait_timeout_count;   ///< times the spin exceeded the soft cap; logged WARN but not fatal
};
IpiCallStats IpiCallStatsRead();

/// Reserve the IPI vector + install the IDT handler. Called once
/// after `IdtInit` and BEFORE `SmpStartAps` so every AP's IDT
/// (which is a clone of the BSP IDT taken during AP bring-up)
/// inherits the wired handler.
///
/// Idempotent — re-install reuses the same vector and overwrites
/// the dispatcher slot with the same handler.
void IpiCallInstall();

/// Boot-time self-test. Drives:
///   1. `IpiCallOne` to self, both wait modes — local fn runs.
///   2. `IpiCallOne` to a peer CPU, wait=true — fn runs there.
///   3. `IpiCallEach` wait=true — fn runs on every CPU, the
///      final invocation count matches `acpi::CpuCount()`.
///
/// On a single-CPU boot (BSP only) the peer-cpu leg is skipped;
/// the self-cpu legs still run. Stats counters are verified to
/// have advanced as expected.
///
/// Emits `[ipi-call] self-test OK (cpus=N, invocations=M)` on
/// success via raw SerialWrite (structural sentinel grepped by
/// CI / boot-log-analyze).
void IpiCallSelfTest();

} // namespace duetos::cpu
