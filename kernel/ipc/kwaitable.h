#pragma once

#include "ipc/kobject.h"
#include "sched/sched.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — concrete `KWaitable` kernel object, v0 (plan A3-followup).
 *
 * WHAT
 *   Fifth and final concrete `KObject` subclass (after KMutex /
 *   KEvent / KSemaphore / KMailbox). Coordinates a "wait until any
 *   of N independently-signaled conditions becomes true" pattern.
 *
 * MAPS TO
 *   - Win32 `WaitForMultipleObjects` (the multi-object superset
 *     that ABI front-ends will eventually surface)
 *   - POSIX `select` / `poll` (multiple fds + a wakeup condition
 *     per fd)
 *   - Linux `epoll` (registered set of waitable conditions)
 *
 * WHY
 *   KMutex / KEvent / KSemaphore / KMailbox each cover a single
 *   wait-on-one-condition primitive. KWaitable is the abstraction
 *   for "block until any of these N become ready" — the building
 *   block any non-trivial event loop needs.
 *
 * v0 DESIGN: PREDICATE LIST + SHARED CONDVAR
 *   Caller code constructs a KWaitable, then attaches predicate
 *   functions that examine some external state. WaitForAny holds
 *   the inner mutex, polls every predicate; if any return true,
 *   returns its index. Otherwise blocks on the shared condvar.
 *   Whoever changes the state behind one of the predicates calls
 *   `KWaitableSignal(w)` to wake any waiters; they re-poll.
 *
 *   The kernel-internal contract: producers (the code that
 *   changes the underlying state, e.g. KEventSet, KMailboxPost)
 *   are NOT modified to call KWaitableSignal automatically — that
 *   would couple every primitive to every wait abstraction.
 *   Instead, callers that want multi-object wait semantics layer
 *   their own KWaitable over the primitives and call Signal
 *   themselves. Crude but additive — full Linux-style wait_queue
 *   subscription chains land later if a workload demands it.
 *
 * WHAT THIS COMMIT IS NOT
 *   - It does NOT modify any existing primitive's signal path to
 *     auto-notify subscribed KWaitables (deferred — see above).
 *   - It does NOT expose a syscall surface (the SYS_WAIT_*
 *     migration is its own slice and must compose with the
 *     existing Win32 / Linux wait syscalls' semantics).
 *
 * THREADING
 *   `WaitForAny` / `Signal` serialise through the embedded
 *   `sched::Mutex`. The condvar's broadcast wakes every waiter so
 *   they each re-poll. No spinning on the wait side.
 */

namespace duetos::ipc
{

/// Capacity for predicates per waitable. Matches Win32's
/// MAXIMUM_WAIT_OBJECTS == 64 — the "any" path doesn't justify
/// more than that without paging the predicate table.
inline constexpr u32 kWaitableMaxPredicates = 64;

/// Predicate function. Returns true iff the underlying condition
/// is ready. Called under the waitable's inner mutex; must NOT
/// acquire any lock that could be held while another caller is
/// in `KWaitableSignal` (lock-order inversion).
using KWaitablePredicate = bool (*)(void* arg);

struct KWaitablePredicateEntry
{
    KWaitablePredicate fn;
    void* arg;
};

struct KWaitable
{
    /// MUST be first — `KObject*` ↔ `KWaitable*` cast shape.
    KObject base;

    sched::Mutex inner;
    sched::Condvar cv;

    KWaitablePredicateEntry preds[kWaitableMaxPredicates];
    u32 pred_count;
};

/// Allocate + zero-init + KObjectInit a fresh KWaitable. Returns
/// `Err{ErrorCode::OutOfMemory}` on heap exhaustion.
::duetos::core::Result<KWaitable*> KWaitableCreate();

/// Register a predicate. Returns the assigned index (0-based) on
/// success, `Err{ErrorCode::InvalidArgument}` for null fn,
/// `Err{ErrorCode::OutOfMemory}` if the table is full. Predicates
/// are NOT removable in v0 — the typical lifecycle is "register
/// at construction, wait, destroy". A removal API lands when a
/// workload demands it.
::duetos::core::Result<u32> KWaitableAddPredicate(KWaitable* w, KWaitablePredicate fn, void* arg);

/// Block until any registered predicate returns true. Returns the
/// index of the first predicate observed true. If multiple are
/// ready simultaneously, returns the lowest-indexed one.
u32 KWaitableWaitForAny(KWaitable* w);

/// Wake every waiter so they re-poll. Caller invokes this AFTER
/// changing any state a registered predicate might check.
/// Cheap — the broadcast costs O(waiter count), and waiters that
/// re-poll-and-find-nothing-ready will block again.
void KWaitableSignal(KWaitable* w);

/// Read-only accessor for diagnostics.
u32 KWaitablePredicateCount(const KWaitable* w);

/// Boot-time self-test. Allocates a KWaitable, registers two
/// predicates wrapping shared atomic flags, exercises:
///   - Add-predicate beyond capacity returns OutOfMemory.
///   - Add-predicate with null fn returns InvalidArgument.
///   - WaitForAny returns the right index when one flag is true.
///   - Multi-flag race: both true → returns lowest-index.
///   - HandleTable round-trip with right + wrong type-tag.
/// Real concurrent waiter contention (multiple tasks WaitForAny
/// while a third Signals) lands as a follow-up alongside the
/// SMP-stress contention tests.
void KWaitableSelfTest();

} // namespace duetos::ipc
