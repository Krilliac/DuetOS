#pragma once

#include "ipc/kobject.h"
#include "sched/sched.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — concrete `KEvent` kernel object, v0 (plan A3-followup).
 *
 * WHAT
 *   Second concrete `KObject` subclass (after `KMutex`). A binary
 *   signaling primitive: tasks block on it until it's signaled,
 *   then either one waiter (auto-reset) or all waiters
 *   (manual-reset) wake up.
 *
 * MAPS TO
 *   - Win32 `CreateEvent` / `SetEvent` / `ResetEvent` / `WaitForSingleObject`
 *   - POSIX condition-variable + bool flag idiom (the canonical
 *     "wait until something happens" primitive).
 *
 * WHY
 *   The existing `Process::win32_events` array is Win32-shaped
 *   (kWaitObject0 / kWaitTimeout, eight slots, reachable only
 *   from SYS_EVENT_*). A native (non-Win32) workload that wants
 *   "wake-me-on-condition" has nowhere to go. KEvent is that
 *   home — every ABI front-end converges on the same refcounted,
 *   handle-tabled, type-tagged primitive.
 *
 * WHAT THIS COMMIT IS NOT
 *   v0 lands the type + Set/Reset/Wait + a self-test that round-
 *   trips through HandleTable. The `SYS_EVENT_*` syscalls keep
 *   using the legacy Win32 array — migrating them is a separate
 *   slice (Win32 ABI semantics need careful preservation).
 *
 * RESET SEMANTICS
 *   - `manual_reset == true`: `Set` wakes EVERY waiter and the
 *     event STAYS signaled until `Reset` clears it. New waiters
 *     arriving after `Set` see the signaled state and return
 *     immediately.
 *   - `manual_reset == false`: `Set` wakes ONE waiter and
 *     atomically clears `signaled` for that wakeup (the woken
 *     task observes the event as cleared). If no waiter is
 *     queued, the event stays signaled until exactly one waiter
 *     consumes it.
 *
 * THREADING
 *   `Set` / `Reset` / `Wait` all serialise through the embedded
 *   `sched::Mutex`. The condvar's broadcast (manual) or signal
 *   (auto) handles the wakeup. No spinning on the wait side.
 */

namespace duetos::ipc
{

struct KEvent
{
    /// MUST be first — `KObject*` ↔ `KEvent*` cast shape.
    KObject base;

    sched::Mutex inner;
    sched::Condvar cv;
    bool manual_reset;
    bool signaled;
};

/// Allocate + zero-init + KObjectInit a fresh KEvent. Caller
/// hands the returned reference to a HandleTable. Returns
/// `Err{ErrorCode::OutOfMemory}` on heap exhaustion.
::duetos::core::Result<KEvent*> KEventCreate(bool manual_reset, bool initially_signaled);

/// Signal the event. Manual-reset wakes every waiter; auto-reset
/// wakes exactly one waiter (or signals "stays-signaled" until a
/// future waiter consumes it). Idempotent — calling `Set` on an
/// already-signaled manual-reset event is a no-op.
void KEventSet(KEvent* e);

/// Clear the signal on a manual-reset event. No-op on auto-reset
/// (auto-reset clears itself on wake).
void KEventReset(KEvent* e);

/// Block until the event is signaled. On auto-reset, atomically
/// clears the signal before returning so only one waiter
/// consumes a single `Set`. Wakes immediately if the event is
/// already signaled at the time of the call.
void KEventWait(KEvent* e);

/// Timed variant. Blocks at most `ticks` timer ticks for the
/// event to signal. Returns true if the wait consumed a signal
/// (auto-reset cleared, manual-reset stayed signaled), false on
/// timeout. The deadline is computed once at entry and respected
/// across spurious wakeups + race-losses against other waiters.
/// `ticks == 0` is "test only" — returns true iff the event is
/// already signaled at call time (and consumes it on auto-reset).
///
/// Backs the timed-wait variant of WaitForSingleObject on an
/// event handle; the SYS_EVENT_WAIT migration in the roadmap
/// routes through here.
bool KEventWaitTimed(KEvent* e, u64 ticks);

/// Non-blocking peek at the signaled state. Locks the inner
/// mutex briefly. Returns the current value of `signaled` —
/// race-prone by design (caller is expected to be a poll loop
/// such as WaitForMultipleObjects that re-tests). Does not
/// consume the signal even on auto-reset events.
bool KEventIsSignaled(KEvent* e);

/// If `e` is auto-reset, atomically clear `signaled`; if
/// manual-reset, no-op. Locks the inner mutex briefly. Used by
/// WaitForMultipleObjects after the wait set is satisfied to
/// claim the wakeup on auto-reset slots while leaving manual-
/// reset slots latched (Win32 contract).
void KEventClearAutoReset(KEvent* e);

/// Boot-time self-test. Allocates one auto-reset and one
/// manual-reset KEvent on the heap, inserts both into a synthetic
/// HandleTable, exercises the Set / Reset / consume semantics
/// without spawning waiter tasks (the v0 test verifies the state
/// machine on the fast path — Wait-with-blocking is exercised
/// once a future contention test spawns a waiter), removes both,
/// asserts destroy fires twice. Panics on any mismatch.
void KEventSelfTest();

} // namespace duetos::ipc
