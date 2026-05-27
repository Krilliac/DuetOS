#pragma once

#include "util/types.h"

/*
 * DuetOS — cyclic subsystem.
 *
 * Pattern from Solaris/illumos `cyclic`: a unified timer-callback
 * abstraction with an explicit level-rule taxonomy. Consolidates
 * the ad-hoc timer-callback paths that currently grow inline
 * inside `OnTimerTick` (sched-tick bookkeeping, soft-lockup tick,
 * future tracer / heartbeat).
 *
 * Three execution levels, each with a documented context contract:
 *
 *   - High: runs FROM THE TIMER IRQ ITSELF (inside `OnTimerTick`'s
 *     IRQ handler, AFTER the existing sched-tick + soft-lockup +
 *     RcuTick calls). No klog, no allocation, no locks (raw
 *     `arch::SerialWrite` is the only "log" available). Reserved
 *     for hardirq-tail work that MUST run on every tick before any
 *     other CPU touch.
 *
 *   - Lock: same dispatch site as High (deferred-from-IRQ slot at
 *     the tail of `OnTimerTick`) but with IRQs already disabled
 *     and lockdep arranged so callbacks may take spinlocks and
 *     emit KLOG_DEBUG_* lines. NO sleeping mutexes, NO allocation
 *     paths that might block, NO schedule(). Reserved for the
 *     fault-react drain / runtime-checker scan pattern.
 *
 *   - Low: full task context. Fires from a dedicated kthread the
 *     cyclic subsystem owns. May allocate from KMalloc, take
 *     sleeping mutexes, KLOG_INFO at full level, etc. The
 *     "every 5 s dump stats" / "every 30 s GC walk" pattern.
 *
 * IRQ-safety taxonomy:
 *   High and Lock callbacks share a single heap protected by a
 *   spinlock (`g_cyclic_lock`, IRQ-off acquire). The IRQ-tail
 *   dispatcher walks the heap under that lock, POPS one due
 *   entry, RELEASES the lock, runs the callback, and re-acquires
 *   for the next pop. This bounds the worst-case lock hold to
 *   ONE callback's runtime; a slow High callback does NOT block
 *   subsequent ones on the SAME tick.
 *
 *   Low has its own heap, protected by the same `g_cyclic_lock`
 *   (since `CyclicRegister` from any context must be able to
 *   add to either heap), but its dispatcher kthread re-acquires
 *   the lock between callbacks — same pattern, task context.
 *
 * Drift-free advancement:
 *   When a cyclic fires, its next deadline is
 *   `previous_deadline + interval_ticks`, NOT `now + interval_ticks`.
 *   Matches the absolute-deadline pattern the heartbeat already
 *   uses to avoid 0.2%/beat drift from per-callback latency.
 *
 * Overrun semantics:
 *   If `previous_deadline + interval_ticks <= now` (i.e. the
 *   dispatcher missed at least one interval — long IRQ
 *   disable region, monster slow callback, etc.) the
 *   `overruns` counter is bumped and the next deadline is
 *   snapped forward to `now + interval_ticks`. We do NOT
 *   try to "catch up" by firing rapidly back-to-back; the
 *   semantics match Solaris's behaviour for the same case.
 *
 * Context: kernel. The public API is thread-safe; callbacks
 * themselves carry the per-level restrictions above.
 */

namespace duetos::time
{

/// Execution context for a cyclic callback. The wrong-level
/// callback at the wrong context is a bug — the lockdep-lite
/// IRQ-safety classes catch the violation if the callback
/// reaches for a primitive that doesn't fit.
enum class CyclicLevel : u8
{
    /// IRQ context. No klog, no allocation, no locks. Raw
    /// `arch::SerialWrite` is permitted but discouraged
    /// (bypasses log levels — see CLAUDE.md "Diagnostic
    /// Logging — Keep It, Gate It, Probe It"). Fires inside
    /// the timer IRQ handler. KASSERT is permitted but
    /// `core::Panic` is NOT — the IRQ context is too
    /// constrained for the panic path's serial flush /
    /// stack-walk machinery.
    High = 0,

    /// IRQ-disabled but pre-IRQ-tail. Spinlocks OK,
    /// `KLOG_DEBUG_*` lines OK. NO sleeping mutexes, NO
    /// allocation that might block, NO `Schedule()`. Same
    /// panic restriction as High.
    Lock,

    /// Full task context. Sleeping mutexes OK, allocation
    /// OK, `KLOG_INFO` OK. Standard kernel-task contract;
    /// `core::Panic` is allowed (same as any kthread).
    Low,
};

/// Cyclic callback. Re-entrant ONLY across distinct cyclic ids
/// — the dispatcher serialises every fire of any single id.
using CyclicFn = void (*)(void* arg);

/// Opaque handle returned by `CyclicRegister`. Zero is reserved
/// as the "invalid / never returned" sentinel so callers can
/// initialise their slot to 0 and treat that as "unregistered".
using CyclicId = u32;
inline constexpr CyclicId kInvalidCyclicId = 0;

/// Maximum number of live registrations across the system. Each
/// level pulls from this single pool — sizing is per-system, not
/// per-level. 64 covers every legitimate v0 caller (sched-tick,
/// soft-lockup, heartbeat, runtime-checker, fault-react drain,
/// future tracer hooks) with generous headroom. Going past this
/// likely signals a registration leak — the calling subsystem
/// should pin one cyclic at init, not register a fresh one per
/// event.
inline constexpr u32 kMaxCyclics = 64;

/// Register a cyclic callback. Thread-safe; callable from any
/// context that already holds nothing the dispatcher needs.
///
///   `level`           — execution context (see above).
///   `interval_ticks`  — period in 10 ms ticks (TickHz units).
///                       Minimum 1; values < 1 are clamped UP
///                       and a one-shot warning fires.
///   `fn`              — callback (must be non-null).
///   `arg`             — opaque pointer passed to fn verbatim.
///   `name`            — short stable string for diagnostics
///                       (must outlive the registration —
///                       string literal is the canonical case).
///
/// On full table (or invalid `fn`) returns `kInvalidCyclicId`
/// with a one-shot warning. First fire happens at
/// `now + interval_ticks`; subsequent fires advance drift-free
/// from the previous deadline.
CyclicId CyclicRegister(CyclicLevel level, u64 interval_ticks, CyclicFn fn, void* arg, const char* name);

/// Remove a registration. Idempotent. If the callback is currently
/// executing, this function returns AFTER it completes (so a
/// caller can safely tear down `arg` after the call returns).
/// Pending-but-not-fired callbacks for this id are dropped.
void CyclicRemove(CyclicId id);

/// IRQ-tail entry point. Called from the timer IRQ handler at the
/// tail (after the existing sched-tick + soft-lockup + RcuTick
/// calls). Walks the High and Lock heaps and fires every callback
/// whose deadline has arrived. Cheap on the common "nothing due"
/// path — one heap-top compare per level.
void CyclicTimerTick();

/// Diagnostic counters since boot.
struct CyclicStats
{
    u32 registrations_total; ///< lifetime call count to CyclicRegister
    u32 registrations_live;  ///< current live registrations
    u64 fires_high;          ///< High-level callbacks fired
    u64 fires_lock;          ///< Lock-level callbacks fired
    u64 fires_low;           ///< Low-level callbacks fired
    u64 overruns;            ///< fires that ran past their next deadline
};

/// Snapshot of the counters. Cheap (no locking — counters are
/// read with relaxed loads; the snapshot is approximate but
/// monotonic per-counter).
CyclicStats CyclicStatsRead();

/// Boot-time install. Spawns the Low-level dispatcher kthread.
/// MUST be called AFTER `sched::SchedInit` (needs the scheduler
/// to spawn the kthread) and BEFORE any `CyclicRegister` call.
/// Idempotent if called twice (second call is a no-op + warn).
void CyclicInstall();

/// Boot-time self-test. Registers one cyclic at each level with
/// a short interval, waits long enough for each to fire 3+
/// times, removes them, asserts the counters advanced. Emits
/// `[cyclic] self-test OK (...)` on success via the canonical
/// arch::SerialWrite sentinel pattern (so CI greps can confirm
/// the test ran). Panics on failure.
void CyclicSelfTest();

} // namespace duetos::time
