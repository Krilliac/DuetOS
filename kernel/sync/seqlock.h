#pragma once

#include "sync/spinlock.h"
#include "util/types.h"

/*
 * DuetOS — sequence lock (plan B1.3).
 *
 * WHAT
 *   A reader/writer primitive for read-mostly hot data. Writers
 *   serialise against each other via an internal `SpinLock` and bump
 *   a sequence counter on entry/exit; readers do an "optimistic"
 *   read that captures the counter, performs the read, then re-checks
 *   the counter. If the counter changed mid-read (or was odd at
 *   start, signalling a write in progress), the reader retries.
 *
 * WHY
 *   Timekeeper, per-CPU stat counters, and other read-mostly hot
 *   paths want cheaper readers than `RwLock`/`Mutex` can offer:
 *     - Readers take no lock, do no atomic RMW, and don't disable
 *       interrupts.
 *     - Writers serialise but never block readers.
 *   The trade-off is that readers must be able to retry safely —
 *   they read potentially-torn data on a conflict and only commit
 *   to the snapshot if EndRead reports success. This makes seqlock
 *   the wrong tool when "read failed" is unrecoverable; the right
 *   tool when the protected payload can be sampled twice cheaply
 *   (a u64 timestamp, a small struct, …).
 *
 * READER PATTERN (canonical)
 *
 *     Snapshot snap;
 *     u32 seq;
 *     do
 *     {
 *         seq = SeqLockBeginRead(lock);
 *         snap = g_payload;          // plain reads, no atomics needed.
 *     } while (!SeqLockEndRead(lock, seq));
 *     // `snap` is now a coherent picture of g_payload at some point
 *     // between BeginRead and EndRead.
 *
 *   The loop body must be idempotent — it can run any number of
 *   times. Don't dereference pointers loaded inside the loop until
 *   AFTER EndRead returns true.
 *
 * WRITER PATTERN
 *
 *     {
 *         SeqLockWriteGuard g(lock);
 *         // Mutate the protected data here. Other writers are
 *         // excluded; readers see "in progress" and will retry.
 *     }
 *
 *   Or the manual form when a guard's scope doesn't fit:
 *
 *     IrqFlags f = SeqLockBeginWrite(lock);
 *     // ... mutate ...
 *     SeqLockEndWrite(lock, f);
 *
 * CONTEXT
 *   Both reader and writer paths are safe in IRQ and task context.
 *   The writer side acquires the inner SpinLock (which disables
 *   interrupts on the calling CPU), so a writer must not block. The
 *   reader side never disables interrupts and never spins beyond a
 *   bounded retry on writer-collision.
 *
 * INITIALISATION
 *   Zero-initialise — `SeqLock x{};` is correct. The sequence
 *   starts at 0 (even = stable); the inner SpinLock is unlocked.
 */

namespace duetos::sync
{

struct SeqLock
{
    /// Even = stable (no writer in flight), odd = writer is updating.
    /// Wraps cleanly at u32 max; readers see the wrap as a sequence
    /// change just like any other update.
    volatile u32 sequence;

    /// Serialises writers against each other. Held only across the
    /// odd-sequence window. Readers never touch this field.
    SpinLock writer;
};

/// Acquire the writer side of the seqlock. Bumps `sequence` from
/// even → odd so any concurrent reader sees a write in progress
/// (its EndRead will fail and force a retry). Returns the IrqFlags
/// captured by the inner SpinLock — pass them back to EndWrite
/// unchanged. Callers must not block while holding the writer side.
[[nodiscard]] IrqFlags SeqLockBeginWrite(SeqLock& lock);

/// Release the writer side. Bumps `sequence` from odd → even and
/// releases the inner SpinLock (restoring IRQs to their pre-Begin
/// state).
void SeqLockEndWrite(SeqLock& lock, IrqFlags flags);

/// Sample the sequence counter for an optimistic read. If the
/// returned value is odd, a writer was mid-update at sample time —
/// the caller's first EndRead is guaranteed to fail and force a
/// retry, which is correct (we deliberately don't spin here so
/// readers never burn cycles waiting on a writer; the retry-on-fail
/// loop in the canonical pattern handles it cleanly).
[[nodiscard]] u32 SeqLockBeginRead(const SeqLock& lock);

/// Validate a previously-sampled sequence. Returns true iff the
/// sequence is still equal to `snapshot` AND `snapshot` was even at
/// sample time. A false return means the read raced with a writer
/// and must be retried; the protected data the reader copied is
/// potentially torn and must NOT be acted on.
[[nodiscard]] bool SeqLockEndRead(const SeqLock& lock, u32 snapshot);

/// RAII guard for the writer side. Acquires on construction,
/// releases on destruction. Non-copyable / non-movable so the
/// EndWrite always pairs at the same scope level.
class SeqLockWriteGuard
{
  public:
    explicit SeqLockWriteGuard(SeqLock& lock) : m_lock(lock), m_flags(SeqLockBeginWrite(lock)) {}
    ~SeqLockWriteGuard() { SeqLockEndWrite(m_lock, m_flags); }

    SeqLockWriteGuard(const SeqLockWriteGuard&) = delete;
    SeqLockWriteGuard& operator=(const SeqLockWriteGuard&) = delete;
    SeqLockWriteGuard(SeqLockWriteGuard&&) = delete;
    SeqLockWriteGuard& operator=(SeqLockWriteGuard&&) = delete;

  private:
    SeqLock& m_lock;
    IrqFlags m_flags;
};

/// Boot-time self-test. Walks every state-machine transition that
/// can be exercised without contention:
///   - sequence parity (even → odd → even across one Begin/EndWrite)
///   - reader sees stable sequence on quiet lock
///   - reader detects "writer in progress" (odd snapshot)
///   - reader detects "writer completed mid-read" (sequence bumped)
///   - canonical retry-loop pattern converges on a clean read
/// Contention paths (writer serialisation under multi-CPU) only
/// exercise once SMP AP bringup lands — covered by a follow-up
/// self-test then. Panics on any state-machine violation.
void SeqLockSelfTest();

} // namespace duetos::sync
