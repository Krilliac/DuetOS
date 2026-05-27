#pragma once

#include "sched/sched.h"
#include "sync/lockdep.h"
#include "util/types.h"

/*
 * DuetOS — adaptive mutex primitive.
 *
 * Pattern from illumos: contention on a held mutex spins as long as
 * the holder is currently running on SOME CPU (release is imminent —
 * cheaper to busy-wait than to pay two context-switch costs to park
 * and unpark), and parks the caller on a wait queue if the holder is
 * off-CPU (Blocked / Sleeping / Ready in someone's runqueue / Dead).
 * Strict Pareto improvement over the existing `sched::Mutex` (which
 * always parks): uncontested fast path is the same CAS, the slow
 * path is at worst what `sched::Mutex` already pays.
 *
 * Design:
 *   - One owner pointer (Task*) doubles as the held flag. nullptr =
 *     unheld; non-null = held by that task. CAS from nullptr to
 *     `CurrentTask()` is the fast path. Race-free because owner is
 *     the only mutable field on the hot path and the CAS pins both
 *     "decide" and "claim" into one atomic step.
 *   - The wait queue (`sched::WaitQueue`) is the parking lot for
 *     the slow path. `MutexLock`'s slow path uses the same primitive
 *     — adaptive mutex is interface-compatible with the parking
 *     pattern, just gated on a spin first.
 *   - Spin loop reads `holder->on_cpu` with __ATOMIC_ACQUIRE on every
 *     iteration. The flag is set/cleared by the scheduler around
 *     ContextSwitch with __ATOMIC_RELEASE (see
 *     `kernel/sched/sched.cpp::Schedule`). The cap
 *     `kAdaptiveSpinLimit` is the safety net: a runaway holder
 *     stuck in a tight loop on its own CPU should not pin a peer
 *     forever. Hitting the cap falls through to the park path —
 *     correct, just slower than a successful spin.
 *   - Lockdep integration mirrors `sched::Mutex`. The class_id field
 *     is a u16 (`sync::LockClass`). Default-initialised to
 *     `kLockClassUnclassified`, which short-circuits the hooks for
 *     untagged mutexes. Tagged mutexes participate in the lockdep
 *     edge graph the rest of the kernel uses.
 *
 * Scope limits:
 *   - Not recursive. A task that re-locks a mutex it already owns
 *     deadlocks on its own on_cpu flag (slow path will spin until
 *     `on_cpu` clears, which it won't, until the spin cap fires
 *     and the task parks — at which point it waits forever for
 *     itself). The self-deadlock guard in `Lock` panics on this
 *     contract violation just like `MutexLock` does.
 *   - No priority inheritance. Priority class is currently flat
 *     (`TaskPriority::Normal` / `Idle`); when real-time class lands,
 *     a holder-promotion path can be added without changing the
 *     ABI here.
 *   - No timed acquire. `MutexLockTimed` covers that surface for
 *     callers that need it; the adaptive primitive is the
 *     "block-eventually" case the timed variant degenerates into
 *     when ticks is large.
 *
 * Context: kernel. Safe to call from task context. NOT safe from
 * IRQ context — both the spin path and the park path can block
 * (parking yields the CPU). Spinning under IRQs off is also
 * dangerous: the holder's release would itself need to fire its
 * IRQs to context-switch off-CPU, so we'd never see the on_cpu
 * flip. Callers that need an IRQ-context mutex use a SpinLock.
 */

namespace duetos::sync
{

/// Spin budget for the adaptive slow path. Beyond this iteration
/// count the slow path falls through to park-on-wait-queue even if
/// the holder is technically still on-CPU. The cap matters when the
/// holder is stuck in a long critical section (priority-inversion
/// shape, or a holder running on an SMT sibling whose CPU we are
/// fighting for cache) — better to pay the park cost than to burn
/// the whole timeslice spinning.
///
/// 10000 iterations × (~5 ns / pause-spaced load) ≈ 50 µs on a
/// modern x86_64 host. That is on the same order as a context-switch
/// + reschedule + cache reload, so spinning longer than the cap is
/// strictly worse than parking.
inline constexpr u32 kAdaptiveSpinLimit = 10000;

/// Adaptive mutex. Default-initialise (zero-init) to "unheld,
/// untagged, empty wait queue" — no explicit Init function.
struct AdaptiveMutex
{
    /// Current owner. nullptr means unheld. The CAS in Lock /
    /// TryLock pins both the "decide" and the "claim" steps.
    sched::Task* m_owner;

    /// FIFO wait queue. Parked tasks live here when the spin-budget
    /// falls through. Released on Unlock by `WaitQueueWakeOne` —
    /// the woken waiter does NOT inherit the lock automatically; it
    /// retries the fast-path CAS, the same shape illumos uses.
    /// Hand-off-on-wake (the sched::Mutex shape) is a separate
    /// optimisation we can layer on later without changing this ABI.
    sched::WaitQueue m_waiters;

    /// Lockdep class. Default 0 = `kLockClassUnclassified` —
    /// untagged mutexes pay one compare-and-skip per call. Tag at
    /// declaration site to opt into locking-order validation.
    LockClass m_class_id;
};

/// Blocking acquire. Fast path: CAS-claim if free. Slow path: spin
/// while the holder is on-CPU (capped at `kAdaptiveSpinLimit`),
/// otherwise park on the wait queue. Spurious wakes are handled by
/// re-checking the owner field after every wake. Panics on a
/// self-deadlock (caller already owns the mutex).
void AdaptiveMutexLock(AdaptiveMutex& m);

/// Release. Caller must own the mutex; panics otherwise. Clears
/// `m_owner` and wakes one waiter (FIFO). The woken waiter races
/// the fast path with any other CPU's pending Lock attempt — a
/// brief steal window is tolerated as the cost of keeping Unlock
/// out of the wait-queue's per-task book-keeping.
void AdaptiveMutexUnlock(AdaptiveMutex& m);

/// Non-blocking acquire. Returns true if it claimed the mutex,
/// false if held by anyone (including the calling task — TryLock
/// does NOT distinguish "self-held" from "other-held" because the
/// safe answer for both is "no, you don't have it via this call").
[[nodiscard]] bool AdaptiveMutexTryLock(AdaptiveMutex& m);

/// Diagnostic: true iff the mutex has a non-null owner. Read with
/// __ATOMIC_ACQUIRE so the answer is stable enough for asserts and
/// `ps` / `top`-style snapshots; not a sufficient predicate to
/// gate a real critical section on (use Lock / TryLock for that).
[[nodiscard]] bool AdaptiveMutexIsHeld(const AdaptiveMutex& m);

/// Boot-time self-test. Exercises:
///   - Uncontested Lock/Unlock (fast path).
///   - TryLock on held vs unheld.
///   - Lockdep registration round-trip (the mutex's class_id
///     appears on the held stack after Lock, falls off on Unlock).
///   - Two-task contention via `sched::SchedCreate` — owner sleeps
///     while holding the mutex, contender parks, owner unlocks,
///     contender resumes.
///
/// Panics on any failure; emits `[adaptive-mutex] self-test OK
/// (...)` on success. Called from `boot_bringup.cpp` after the
/// SpinLock self-test and after the scheduler is online.
void AdaptiveMutexSelfTest();

} // namespace duetos::sync
