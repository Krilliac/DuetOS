#pragma once

#include "util/types.h"

/*
 * DuetOS — preemption-off (IRQs-on) critical section.
 *
 * Modelled on FreeBSD's `critical_enter(9)` / `critical_exit(9)`: a
 * per-CPU nesting counter that BLOCKS THE SCHEDULER from migrating /
 * preempting the current thread but DOES NOT disable interrupts. This
 * is the middle ground between two existing primitives:
 *
 *   - spinlock-IRQ-off    (`SpinLockAcquire`): heavy. Masks every IRQ
 *                          on this CPU. Used when the protected state
 *                          can be touched by an interrupt handler.
 *   - unguarded code     : free to migrate at the next tick. Used
 *                          everywhere it doesn't matter.
 *
 * Critical sections sit between them. While critnest > 0:
 *
 *   - the timer-tick handler still fires, ISRs still run, the IRQ
 *     scaffolding (LAPIC EOI, IST switches, NMIs) is unaffected;
 *   - but a tick that wants to PREEMPT this CPU will defer — it sets
 *     `deferred_preempt = 1` and returns instead of calling Schedule;
 *   - on CriticalExit, if the deferred flag is set, Schedule() is
 *     invoked synchronously.
 *
 * Cost vs spinlock-IRQ-off: two single-instruction `gs:`-relative
 * memory ops (inc / dec via `arch::ThisCpuInc64` / `ThisCpuAdd64`) on
 * the hot path, vs `pushfq + cli + ... + popfq + sti` (~10x cost on
 * modern Intel). The deferred-preempt check on Exit costs one extra
 * load + branch; it's predictable (deferred==0 in the common case).
 *
 * When to use:
 *   - Reading per-CPU data and you must not migrate to another CPU
 *     mid-read (walking the current CPU's runqueue, sampling per-CPU
 *     stats consistently with whose-CPU-is-running them).
 *   - Updating per-CPU stats that must agree with the executing CPU.
 *   - Short critical sections where the IRQ-off cost of a spinlock
 *     would crush interrupt latency for what is essentially a
 *     per-CPU-only critical section.
 *
 * When NOT to use:
 *   - From IRQ context (IRQ handlers run with implicit "critnest =
 *     infinity"; adding to it is meaningless, the Exit path would
 *     also be IRQ-context).
 *   - When you need to block IRQs (use SpinLockAcquire / arch::Cli).
 *   - Around any sleeping primitive (SchedYield, SchedSleepTicks,
 *     WaitQueueBlock, sleeping-Mutex acquire). Sleeping inside a
 *     critical section is a contract violation — those primitives
 *     KASSERT critnest == 0.
 *
 * Nesting: every `CriticalEnter` MUST pair with exactly one
 * `CriticalExit` on the same CPU. The RAII `CriticalGuard` below
 * makes this hard to get wrong — prefer it over the bare calls.
 *
 * Per-CPU state owned: `PerCpu::critnest`, `PerCpu::deferred_preempt`
 * (see kernel/cpu/percpu.h).
 *
 * Scheduler integration:
 *   - Timer-tick reschedule (`OnTimerTick` → `TakeNeedResched` →
 *     `Schedule`): the `TakeNeedResched` site in arch/x86_64/traps.cpp
 *     gates on critnest. If critnest > 0, the reschedule is deferred.
 *   - Wake-up reschedule, IPI-driven reschedule, kill-requested: all
 *     route through `NeedResched()` + the same gated `TakeNeedResched`
 *     drain at the IRET path, so they inherit the deferral.
 *   - Voluntary yields (SchedYield, SchedSleepTicks, WaitQueueBlock,
 *     Mutex park-path) KASSERT critnest == 0.
 *
 * Context: kernel only. The IRET path from userland always has
 * critnest == 0 (entering a critical section requires kernel code,
 * and CriticalExit is required before returning to userland).
 */

namespace duetos::cpu
{

/// Enter a critical section. Increments the current CPU's `critnest`
/// counter; subsequent preemption attempts (timer-tick reschedule,
/// wake-up reschedule, voluntary yield) are DEFERRED until `critnest`
/// returns to zero. IRQs remain ON — timer ticks still fire, ISRs
/// still run; they just can't cause a context switch on this CPU.
///
/// Two memory writes per Enter/Exit pair (the counter + a possible
/// "deferred preempt" flag check at Exit). Cheaper than cli/sti by
/// roughly 5x on modern Intel.
///
/// Nestable. Pair with `CriticalExit()` exactly — every Enter MUST
/// have a matching Exit on the same CPU. Prefer `CriticalGuard`.
///
/// Context: kernel. Must NOT be called from IRQ context (IRQ
/// handlers run with implicit critnest=infinity; adding to it is
/// meaningless and the matching Exit path would also be IRQ-context).
void CriticalEnter();

/// Exit a critical section. Decrements `critnest`. If it returns to
/// zero AND a reschedule was deferred while critnest > 0, invokes
/// `sched::Schedule()` immediately.
void CriticalExit();

/// Read the current CPU's critnest. Diagnostic; not for control flow.
u32 CriticalNesting();

/// RAII wrapper. Construct = Enter; destruct = Exit. Strongly
/// preferred over the bare Enter/Exit pair — the matching Exit
/// becomes compiler-enforced for every code path leaving the scope
/// (returns, exceptions if they ever land, early gotos, etc.).
class CriticalGuard
{
  public:
    CriticalGuard() { CriticalEnter(); }
    ~CriticalGuard() { CriticalExit(); }

    CriticalGuard(const CriticalGuard&) = delete;
    CriticalGuard& operator=(const CriticalGuard&) = delete;
    CriticalGuard(CriticalGuard&&) = delete;
    CriticalGuard& operator=(CriticalGuard&&) = delete;
};

/// Diagnostic counters since boot. Summed across all CPUs.
struct CriticalStats
{
    u64 enter_total;             // total CriticalEnter calls (all CPUs)
    u64 exit_total;              // total CriticalExit calls (all CPUs)
    u64 deferred_preempts_total; // count of timer-tick preempts deferred
    u32 max_nesting_observed;    // deepest critnest observed across boot
};

/// Read the diagnostic counters. Cross-CPU sum — cheap enough for an
/// occasional shell / observability call; do NOT call on the hot path.
CriticalStats CriticalStatsRead();

/// Record that a reschedule was deferred while inside a critical
/// section. Called by the scheduler tick path when it wants to
/// preempt but observes critnest > 0. Bumps the per-CPU
/// `deferred_preempt` flag and the global deferred counter.
///
/// Returns true if the deferral was recorded (was inside a critical
/// section); false if critnest was zero and the caller should proceed
/// to call Schedule() normally.
bool DeferPreemptIfCritical();

/// Boot self-test. Drives:
///   - Plain enter/exit round-trip.
///   - Nested enter/exit (depth 3); critnest tracks correctly.
///   - During a critical section, simulate a "preempt me" request
///     (set the per-CPU deferred_preempt bit via the public path),
///     exit, verify Schedule() was called (counter advanced).
///
/// Prints `[critical] self-test OK` on success. Panics on any
/// invariant violation — there's no recoverable critical-section
/// failure mode that should let the boot continue.
void CriticalSelfTest();

} // namespace duetos::cpu
