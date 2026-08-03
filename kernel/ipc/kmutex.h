#pragma once

#include "ipc/kobject.h"
#include "sched/sched.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — concrete `KMutex` kernel object, v0 (plan A3-followup).
 *
 * WHAT
 *   The first concrete `KObject` subclass. Embeds a `KObject` as
 *   its first member so a `HandleTable`-resolved `KObject*` can be
 *   reinterpret_cast'd back to `KMutex*` after a
 *   `KObjectType::Mutex` check.
 *
 *   Wraps a `sched::Mutex` plus the bookkeeping any "real" mutex
 *   ABI front-end will want: owning task, recursion depth, and a
 *   stable creation tick (for diagnostic ranking — "oldest live
 *   mutex" / "longest hold"). Front-ends translate their ABI's
 *   acquire/release calls into `KMutexAcquire` / `KMutexRelease`;
 *   the kernel-internal lock state lives here, not duplicated per-
 *   ABI.
 *
 * RELATION TO Win32 SYS_MUTEX_*
 *   Every `SYS_MUTEX_CREATE` / `SYS_MUTEX_WAIT` / `SYS_MUTEX_RELEASE`
 *   syscall routes through this type — the per-process
 *   `Process::kobj_handles` table holds the `KMutex*`. A native
 *   (non-Win32) workload that wants a kernel-mediated mutex
 *   reaches the same primitive through the same handle table; the
 *   Win32 surface translates the explicit acquired / abandoned /
 *   timeout result at the syscall boundary.
 *
 * REFCOUNT SEMANTICS
 *   `KMutexCreate` allocates one through the kheap, calls
 *   `KObjectInit` (refcount = 1), and returns the new KMutex.
 *   The caller is expected to hand it off to a `HandleTable` —
 *   that table takes the initial reference (no extra acquire).
 *
 *   The first successful acquire on an unowned mutex takes an
 *   additional reference (the "holder ref"); the outermost
 *   release drops it. While a task is blocked in `KMutexAcquire`
 *   / `KMutexAcquireTimed`, an extra "wait ref" is held — that
 *   ref upgrades to the holder ref on hand-off success, or is
 *   dropped on timeout. The wait/holder refs together guarantee
 *   that closing every handle while the mutex is still held or
 *   contended cannot free the storage out from under a current
 *   holder or a still-blocked waiter — the standard Win32
 *   "abandoned mutex" / "mutex outlives its handle" scenarios
 *   stay safe even though the kernel never owns its own implicit
 *   reference.
 *
 *   The destructor `KMutexDestroy` is registered as the type's
 *   `destroy` callback; it runs on last release, frees the
 *   storage, and panics if the lock is still held (a leak that
 *   reaches refcount=0 with the lock held is a bug in the
 *   refcount accounting itself, not in the caller's release
 *   ordering — caller mistakes are absorbed by the holder/wait
 *   refs above).
 *
 * THREADING
 *   `KMutexAcquire` / `KMutexRelease` go through the embedded
 *   `sched::Mutex`. Public ownership uses an atomic immutable TID,
 *   while the scheduler alone retains the Task pointer in its
 *   intrusive abandonment ledger. Each acquire by that TID bumps
 *   recursion; only the outermost release unlinks the ledger node
 *   and unlocks the inner mutex.
 */

namespace duetos::ipc
{

enum class KMutexWaitResult : u8
{
    Acquired,
    Abandoned,
    TimedOut,
    Cancelled,
    Failed,
};

struct KMutex
{
    /// MUST be the first member — `KObject*` ↔ `KMutex*` cast
    /// shape. Compile-time assertion in `kmutex.cpp` enforces
    /// `offsetof(KMutex, base) == 0`.
    KObject base;

    /// Underlying scheduler mutex. Owns the wait-queue + the
    /// FIFO hand-off behaviour.
    sched::Mutex inner;

    /// Atomic public ownership snapshot. Task ID zero is valid, so `held`
    /// disambiguates the boot task from an unowned mutex.
    bool held;
    u64 owner_tid;

    /// Recursion count. Zero when not held; >= 1 when held.
    u32 recursion;

    /// Release-published before an abandoned owner's FIFO hand-off and
    /// consumed exactly once by the successful successor.
    bool abandoned_pending;

    /// Scheduler-owned intrusive receipt for dead-task abandonment. KMutex
    /// itself never retains or exposes a raw Task pointer.
    sched::AbandonableOwnershipNode ownership_node;

    /// Scheduler tick at creation. Pure diagnostic; helps a
    /// future `inspect ipc mutexes` rank the oldest live mutex.
    u64 created_tick;
};

/// Allocate + zero-init + KObjectInit a fresh KMutex on the
/// kernel heap. Returns the new object with refcount = 1; caller
/// hands the reference to a `HandleTable` (which takes ownership)
/// or calls `KObjectRelease` directly. Returns
/// `Err{ErrorCode::OutOfMemory}` on heap exhaustion.
::duetos::core::Result<KMutex*> KMutexCreate();

/// Recursive acquire. Same task may acquire repeatedly; each call
/// must be paired with a matching `KMutexRelease`. Blocks (via
/// the result-bearing scheduler mutex path) when another task holds
/// the lock. Requires an installed current Task.
KMutexWaitResult KMutexAcquire(KMutex* m);

/// Timed recursive acquire. Identical to `KMutexAcquire` for the
/// re-entrant fast path (recursion bumps regardless of the
/// timeout — re-entry never blocks). Otherwise blocks at most
/// `ticks` timer ticks via the result-bearing cancellable scheduler wait.
/// `ticks == 0` is the non-blocking variant. The result distinguishes
/// timeout, cooperative cancellation, failure, and one-shot abandonment.
///
/// Backs the timed-wait variant of Win32-style WaitForSingleObject
/// on a mutex handle; the SYS_MUTEX_WAIT migration ahead in the
/// roadmap routes through here once the surface is moved onto
/// `Process::kobj_handles`.
KMutexWaitResult KMutexAcquireTimed(KMutex* m, u64 ticks);

/// Drop one recursion level. The outermost release transfers
/// ownership to the next FIFO waiter (or unlocks if the queue is
/// empty). Calling release on a mutex this task does not own is
/// rejected without mutation and reported as false to the ABI front-end.
bool KMutexRelease(KMutex* m);

/// Atomic read-only snapshots for diagnostics. `KMutexOwnerTid` is meaningful
/// only when `KMutexHeld` is true.
bool KMutexHeld(const KMutex* m);
u64 KMutexOwnerTid(const KMutex* m);

/// Boot-time self-test. Allocates a KMutex on the heap, inserts
/// it into a synthetic `HandleTable`, looks it up by handle (with
/// type check), drives recursion/timed acquire, proves public cancellation
/// rejects a live process-null owner, then verifies the reaper's one-shot
/// abandoned hand-off before removing it from the table, draining the lookup
/// and table references, and proving the stale slot no longer resolves.
/// Demonstrates the full HandleTable round-trip on a concrete subclass without
/// touching Process or any live syscall surface. Panics on any mismatch.
void KMutexSelfTest();

} // namespace duetos::ipc
