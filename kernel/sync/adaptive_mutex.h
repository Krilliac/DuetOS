#pragma once

#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/types.h"

/*
 * DuetOS - AdaptiveMutex compatibility surface.
 *
 * The original implementation kept a raw Task* owner and implemented its own
 * spin-then-park protocol. That duplicated scheduler mutex ownership without
 * participating in Task lifetime accounting, so a killed owner could be
 * reaped while a contender still dereferenced it. Its owner recheck was also
 * separate from wait-queue enrollment: disabling local interrupts could not
 * stop a peer CPU from performing the last unlock between those operations.
 *
 * Keep the established AdaptiveMutex API for the TPM transport and existing
 * callers, but delegate its state and synchronization to sched::Mutex. The
 * scheduler primitive serializes owner tests, FIFO enrollment, direct
 * hand-off, and owner lifetime accounting under the scheduler lock. This is a
 * correctness-first implementation; adaptive spinning can return only behind
 * that same lifetime-safe ownership protocol.
 *
 * Context: task context after SchedInit. The single-threaded BSP boot path may
 * also use a Lock/Unlock pair wholly before SchedInit; with no runnable peer,
 * those calls are explicit no-ops and expose no held-state snapshot. A pair
 * must never straddle SchedInit. Lock may sleep and therefore must not be
 * called from IRQ context or while preemption is disabled. Zero-initialization
 * is a complete initialization; no explicit init function is required.
 */

namespace duetos::sync
{

/// Retained for source compatibility with code that used the old tuning
/// constant. The compatibility implementation does not spin.
inline constexpr u32 kAdaptiveSpinLimit = 10000;

/// Mutex facade backed by the scheduler's lifetime-safe sleeping mutex. The
/// scheduler mutex remains the sole ownership/wait-queue authority. The small
/// publication lock mirrors only whether a public Lock call has returned; it
/// makes AdaptiveMutexIsHeld race-free without reading scheduler-owned state.
struct AdaptiveMutex
{
    sched::Mutex m_mutex;
    SpinLock m_publication_lock;
    u64 m_published_owner_id;
    bool m_published_held;
};

/// Blocking acquire with sched::Mutex FIFO hand-off semantics.
void AdaptiveMutexLock(AdaptiveMutex& m);

/// Release. The calling task must own the mutex.
void AdaptiveMutexUnlock(AdaptiveMutex& m);

/// Non-blocking acquire. Returns true only when this call acquires the mutex.
[[nodiscard]] bool AdaptiveMutexTryLock(AdaptiveMutex& m);

/// Diagnostic snapshot for live task context. Do not use it to guard protected
/// data; only Lock/TryLock establishes lasting ownership.
[[nodiscard]] bool AdaptiveMutexIsHeld(const AdaptiveMutex& m);

/// Boot-time coverage for uncontended acquire, try-lock, lockdep integration,
/// and FIFO contention through the scheduler mutex.
void AdaptiveMutexSelfTest();

} // namespace duetos::sync
