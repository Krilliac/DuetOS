#pragma once

#include "sched/sched.h"
#include "sync/lockdep.h"
#include "util/types.h"

/*
 * DuetOS — reader / writer lock (plan B1.2).
 *
 * WHAT
 *   Multiple-reader, single-writer mutual exclusion built on top of
 *   the existing `sched::Mutex` + `sched::Condvar` primitives. Use
 *   when a data structure has many more readers than writers and
 *   the read-side critical section is non-trivial (long enough that
 *   blocking out concurrent readers under a plain mutex shows up).
 *
 * WHY
 *   The address-space tables, the IPC handle table (plan A3 once
 *   it lands), the driver registry, the routing tables in `fs::` —
 *   all classic read-mostly hot data. A plain mutex serialises
 *   readers needlessly; a spinlock burns IF-disabled cycles when
 *   the read might cross a page-table walk. RwLock gives readers
 *   parallelism, writers exclusion, and never spins.
 *
 * FAIRNESS
 *   Writer preference: once `waiting_writers > 0`, new readers
 *   block until the queued writer(s) drain. Without writer
 *   preference, a steady stream of readers starves writers
 *   indefinitely. Writers themselves form a FIFO via the
 *   underlying Condvar's wait-queue ordering.
 *
 * RECURSION
 *   Not supported. A task that holds the lock shared and tries to
 *   acquire it exclusive (or vice-versa) deadlocks. Same contract
 *   as `sched::Mutex`.
 *
 * CONTEXT
 *   Task context only. Like `sched::Mutex`, this lock CAN block;
 *   never call Acquire from IRQ context. The underlying mutex
 *   uses `arch::Cli` / `arch::Sti` for the short critical section
 *   over its own state but does not hold IRQs disabled across the
 *   read or write the caller is protecting.
 *
 * INITIALISATION
 *   Zero-initialise — `RwLock x{};` or `static RwLock g_x;` is the
 *   correct, safe default. No explicit Init function.
 */

namespace duetos::sync
{

struct RwLock
{
    sched::Mutex inner;        ///< Serialises mutations of the counters.
    sched::Condvar readers_cv; ///< Readers wait here while a writer holds / queued.
    sched::Condvar writers_cv; ///< Writers wait here while readers / another writer hold.
    u32 active_readers;        ///< Live shared holders.
    u32 waiting_writers;       ///< Writers blocked on writers_cv.
    bool writer_active;        ///< True iff one writer holds exclusive.
    /// Lockdep class (plan D1-followup). Default 0 = unclassified
    /// (no overhead). Tag with a canonical `kLockClass*` ID from
    /// `sync/lockdep.h` to opt into locking-order validation.
    /// Hooked from both the read and write acquire/release paths
    /// so reader/writer order vs other tagged primitives is
    /// recorded consistently. The inner `sched::Mutex` is NOT
    /// independently classified — it would double-count every
    /// RwLock acquire as a Mutex acquire too.
    LockClass class_id;
};

/// Block until shared access is granted. Multiple callers may hold
/// the lock shared concurrently. Reads of the protected data are
/// safe between Acquire and Release. Returns nothing — the lock is
/// always granted (eventually) unless the caller hits a deadlock,
/// which is a kernel bug.
void RwLockAcquireShared(RwLock& lock);

/// Release a previously-acquired shared lock. Must pair with
/// `RwLockAcquireShared` (or a successful `RwLockTryAcquireShared`).
/// Wakes a queued writer if this is the last reader leaving.
void RwLockReleaseShared(RwLock& lock);

/// Block until exclusive access is granted. No other holders —
/// reader or writer — exist for the duration. Use for any mutation
/// of the protected data.
void RwLockAcquireExclusive(RwLock& lock);

/// Release a previously-acquired exclusive lock. Must pair with
/// `RwLockAcquireExclusive` (or a successful `RwLockTryAcquireExclusive`).
/// Wakes a queued writer (preferred) or all queued readers.
void RwLockReleaseExclusive(RwLock& lock);

/// Non-blocking shared acquire. Returns true on success, false if
/// a writer is active or queued. Useful for "try the read; if it
/// would block, return cached data instead" patterns.
bool RwLockTryAcquireShared(RwLock& lock);

/// Non-blocking exclusive acquire. Returns true on success, false
/// if any reader or writer holds the lock.
bool RwLockTryAcquireExclusive(RwLock& lock);

/// RAII guard for the shared path. Acquires on construction,
/// releases on destruction. Non-copyable / non-movable so the
/// release always happens at the same scope level.
class RwLockSharedGuard
{
  public:
    explicit RwLockSharedGuard(RwLock& lock) : m_lock(lock) { RwLockAcquireShared(lock); }
    ~RwLockSharedGuard() { RwLockReleaseShared(m_lock); }

    RwLockSharedGuard(const RwLockSharedGuard&) = delete;
    RwLockSharedGuard& operator=(const RwLockSharedGuard&) = delete;
    RwLockSharedGuard(RwLockSharedGuard&&) = delete;
    RwLockSharedGuard& operator=(RwLockSharedGuard&&) = delete;

  private:
    RwLock& m_lock;
};

/// RAII guard for the exclusive path. Same single-scope contract.
class RwLockExclusiveGuard
{
  public:
    explicit RwLockExclusiveGuard(RwLock& lock) : m_lock(lock) { RwLockAcquireExclusive(lock); }
    ~RwLockExclusiveGuard() { RwLockReleaseExclusive(m_lock); }

    RwLockExclusiveGuard(const RwLockExclusiveGuard&) = delete;
    RwLockExclusiveGuard& operator=(const RwLockExclusiveGuard&) = delete;
    RwLockExclusiveGuard(RwLockExclusiveGuard&&) = delete;
    RwLockExclusiveGuard& operator=(RwLockExclusiveGuard&&) = delete;

  private:
    RwLock& m_lock;
};

/// Boot-time self-test. Exercises uncontended state transitions:
/// try-shared (1, 2 readers), try-exclusive blocked by readers,
/// release-shared back to free, try-exclusive succeeds, try-shared
/// blocked by writer, release-exclusive back to free. Cannot
/// exercise contention paths (single-task boot context); the
/// blocking paths are validated once SMP arrives. Panics on any
/// state-machine violation.
void RwLockSelfTest();

} // namespace duetos::sync
