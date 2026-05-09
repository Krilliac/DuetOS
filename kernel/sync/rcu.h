#pragma once

#include "util/types.h"

/*
 * DuetOS — quiescent-state RCU, v0 (plan B1.4).
 *
 * WHAT
 *   Read-Copy-Update for read-mostly hot data. Readers run
 *   inside `RcuReadLock()` / `RcuReadUnlock()` brackets — both
 *   are no-ops on the read fast path (just a compiler barrier
 *   in v0). Writers update by publishing a new version; old
 *   versions are retired through `RcuCallback` once all CPUs
 *   have passed through a quiescent state.
 *
 *   QS detection in v0: each scheduler tick increments a
 *   per-CPU counter; reclamation walks pending callbacks and
 *   invokes any whose enqueue-grace was observed by every CPU
 *   at least once.
 *
 * WHY
 *   `sync::RwLock` works for read-mostly data with non-trivial
 *   read-side critical sections, but its mutex still serialises
 *   readers against writers. RCU's read fast path is literally
 *   zero overhead on x86 — readers walk the data structure
 *   without any atomic / fence / store. The cost is on the
 *   writer side: producing a fresh copy + grace-period waiting.
 *
 * SCOPE FOR v0
 *   - Readers: `RcuReadLock` / `RcuReadUnlock` (compiler
 *     barriers).
 *   - Writers: `RcuCall(callback, arg)` defers tear-down until
 *     a grace period elapses.
 *   - Quiescent-state polling tied to `OnTimerTick`.
 *   - Per-CPU callback queues — every CPU drains its own pending
 *     list without contending against peers; `RcuReclaim()` walks
 *     every queue, `RcuReclaimLocal()` walks just the caller's.
 *
 * NOT IN SCOPE
 *   - Synchronous wait (`synchronize_rcu`) — every consumer
 *     today uses async callbacks.
 *   - Sleepable RCU.
 *   - Tree-RCU / multi-level batching.
 */

namespace duetos::sync
{

using RcuCallback = void (*)(void* arg);

/// Read-side delimiter. v0: compiler barrier so reads of the
/// protected data don't get hoisted past the bracket. On x86
/// with `volatile`-loaded pointers the barrier is sufficient.
inline void RcuReadLock()
{
    asm volatile("" ::: "memory");
}

inline void RcuReadUnlock()
{
    asm volatile("" ::: "memory");
}

/// Defer `cb(arg)` until a grace period after this call. The
/// callback runs from a future `RcuTick` invocation; do NOT
/// rely on any specific timing beyond "at least one full
/// scheduler tick has elapsed". Returns false if the queue is
/// full (caller must retry or panic — losing a callback is a
/// memory leak).
bool RcuCall(RcuCallback cb, void* arg);

/// Signal a quiescent state on the calling CPU. Called from
/// `OnTimerTick` once per scheduler tick. Cheap (single
/// counter bump). Eventually drives callback reclamation when
/// every CPU has signalled at least one QS since a callback
/// was queued.
void RcuTick();

/// Reclaim path. Walks every CPU's pending-callbacks queue and
/// invokes any whose grace period has elapsed. Called from the
/// boot task / a future RCU kthread; safe to call from any task
/// context but NOT from IRQ (callbacks may free memory).
u32 RcuReclaim();

/// Reclaim only the calling CPU's pending callbacks. Cheap, no
/// cross-CPU traffic — designed for the idle-thread drain hook
/// where each AP picks up its own queue between HALTs. Returns
/// the number of callbacks actually invoked.
u32 RcuReclaimLocal();

/// Diagnostic: total callbacks ever queued.
u64 RcuCallsQueued();

/// Diagnostic: total callbacks ever invoked.
u64 RcuCallsCompleted();

/// Boot-time self-test. Queues a callback that bumps a flag,
/// drives N ticks + a reclaim cycle, asserts the flag fired
/// exactly once. Panics on mismatch.
void RcuSelfTest();

} // namespace duetos::sync
