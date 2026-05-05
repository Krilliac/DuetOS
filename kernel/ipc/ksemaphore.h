#pragma once

#include "ipc/kobject.h"
#include "sched/sched.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — concrete `KSemaphore` kernel object, v0 (plan A3-followup).
 *
 * WHAT
 *   Third concrete `KObject` subclass (after `KMutex` and `KEvent`).
 *   A counted signaling primitive: a non-negative count gates how
 *   many concurrent acquirers can pass through. Acquire decrements;
 *   blocks when count is zero. Release increments by N; wakes up to
 *   N waiters.
 *
 * MAPS TO
 *   - Win32 `CreateSemaphore` / `ReleaseSemaphore` / `WaitForSingleObject`
 *   - POSIX `sem_init` / `sem_wait` / `sem_post`
 *   - The classic Dijkstra P/V primitive — a building block for
 *     bounded resource pools, producer/consumer queues, and
 *     N-element rate-limiting.
 *
 * WHY
 *   Same rationale as KMutex / KEvent: the existing
 *   `Process::win32_semaphores` array is Win32-shaped and reachable
 *   only from SYS_SEM_*. KSemaphore gives every ABI front-end the
 *   same refcounted, handle-tabled, type-tagged primitive.
 *
 * WHAT THIS COMMIT IS NOT
 *   v0 lands the type + Acquire/Release + a self-test. The
 *   `SYS_SEM_*` syscalls keep using the legacy Win32 array.
 *
 * COUNT SEMANTICS
 *   - `count` starts at `initial_count` (caller chooses).
 *   - `Acquire` blocks until count > 0, then decrements by 1.
 *   - `Release(n)` increments count by n, wakes up to n waiters.
 *     Posting more than `max_count - count` is a hard panic in v0
 *     — overflowing the count silently is the kind of bug we want
 *     to fail loud at the moment of violation.
 *
 * THREADING
 *   `Acquire` / `Release` serialise through the embedded
 *   `sched::Mutex`. The condvar's signal handles the wakeup.
 */

namespace duetos::ipc
{

struct KSemaphore
{
    /// MUST be first — `KObject*` ↔ `KSemaphore*` cast shape.
    KObject base;

    sched::Mutex inner;
    sched::Condvar cv;
    u32 count;     ///< Current available permits.
    u32 max_count; ///< Hard cap; Release that would exceed this panics.
};

/// Allocate + zero-init + KObjectInit a fresh KSemaphore. Caller
/// hands the returned reference to a HandleTable. Validates
/// `initial_count <= max_count`; returns
/// `Err{ErrorCode::InvalidArgument}` if not, or
/// `Err{ErrorCode::OutOfMemory}` on heap exhaustion.
::duetos::core::Result<KSemaphore*> KSemaphoreCreate(u32 initial_count, u32 max_count);

/// Block until count > 0, then decrement by 1.
void KSemaphoreAcquire(KSemaphore* s);

/// Timed acquire. Identical to `KSemaphoreAcquire` on the fast
/// path (count > 0 — decrement and return true immediately).
/// Otherwise blocks at most `ticks` timer ticks for a permit;
/// returns true if a permit was consumed, false on timeout. The
/// deadline is computed once at entry; spurious wakeups and
/// races against other acquirers don't re-arm the budget.
/// `ticks == 0` is "test only" — returns true iff a permit was
/// available at call time.
///
/// Backs the timed-wait variant of WaitForSingleObject on a
/// semaphore handle; the SYS_SEM_WAIT migration in the roadmap
/// routes through here.
bool KSemaphoreAcquireTimed(KSemaphore* s, u64 ticks);

/// Release `n` permits. Increments count by n and wakes up to n
/// waiters (each will resume their `Acquire` and consume one
/// permit). Panics if `count + n > max_count` — count overflow
/// is a kernel bug.
void KSemaphoreRelease(KSemaphore* s, u32 n);

/// Best-effort release: increments count by n only if count+n
/// would not exceed max_count. On success, writes the pre-release
/// count to `*prev_out` (caller may pass nullptr) and wakes up to
/// n waiters. On overflow, leaves count unchanged and returns
/// false — `*prev_out` is not written. Used by ABI surfaces that
/// must surface ERROR_TOO_MANY_POSTS to userland rather than
/// panic the kernel.
bool KSemaphoreTryRelease(KSemaphore* s, u32 n, u32* prev_out);

/// Read-only accessor for diagnostics. Racy under SMP; the
/// returned value reflects a single sample.
u32 KSemaphoreCount(const KSemaphore* s);

/// Boot-time self-test. Allocates a KSemaphore on the heap,
/// inserts into a HandleTable, exercises Acquire to drain the
/// initial count + Release to refill + count clamping, removes
/// from table. Panics on any mismatch. Real waiter contention is
/// out of scope (no spawned tasks); the v0 test verifies the
/// state machine on the fast path.
void KSemaphoreSelfTest();

} // namespace duetos::ipc
