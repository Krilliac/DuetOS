/*
 * DuetOS — reader/writer lock implementation, v0 (plan B1.2).
 *
 * See `rwlock.h` for the public contract. This TU owns the state
 * machine + Mutex/Condvar wiring + boot self-test.
 *
 * State invariants (verified by every Acquire / Release):
 *   - writer_active && active_readers == 0     when a writer holds.
 *   - !writer_active && active_readers >= 0    when readers hold (or none).
 *   - writer_active and active_readers > 0     is NEVER valid.
 *
 * Writer preference avoids reader starvation of writers: any reader
 * arriving while `waiting_writers > 0` blocks. The trade-off is
 * that a steady stream of writers can starve readers — acceptable
 * because the protected workloads are read-mostly (writes are
 * rare; readers are not the contended side of "reader-vs-writer
 * race").
 */

#include "sync/rwlock.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "util/types.h"

namespace duetos::sync
{

void RwLockAcquireShared(RwLock& lock)
{
    LockdepBeforeAcquire(lock.class_id);
    sched::MutexLock(&lock.inner);
    while (lock.writer_active || lock.waiting_writers > 0)
    {
        sched::CondvarWait(&lock.readers_cv, &lock.inner);
    }
    ++lock.active_readers;
    sched::MutexUnlock(&lock.inner);
    LockdepAfterAcquire(lock.class_id);
}

void RwLockReleaseShared(RwLock& lock)
{
    LockdepBeforeRelease(lock.class_id);
    sched::MutexLock(&lock.inner);
    if (lock.active_readers == 0)
    {
        core::Panic("sync/rwlock", "RwLockReleaseShared on lock with no readers");
    }
    --lock.active_readers;
    if (lock.active_readers == 0 && lock.waiting_writers > 0)
    {
        sched::CondvarSignal(&lock.writers_cv);
    }
    sched::MutexUnlock(&lock.inner);
}

void RwLockAcquireExclusive(RwLock& lock)
{
    LockdepBeforeAcquire(lock.class_id);
    sched::MutexLock(&lock.inner);
    ++lock.waiting_writers;
    while (lock.writer_active || lock.active_readers > 0)
    {
        sched::CondvarWait(&lock.writers_cv, &lock.inner);
    }
    --lock.waiting_writers;
    lock.writer_active = true;
    sched::MutexUnlock(&lock.inner);
    LockdepAfterAcquire(lock.class_id);
}

void RwLockReleaseExclusive(RwLock& lock)
{
    LockdepBeforeRelease(lock.class_id);
    sched::MutexLock(&lock.inner);
    if (!lock.writer_active)
    {
        core::Panic("sync/rwlock", "RwLockReleaseExclusive on lock with no writer");
    }
    lock.writer_active = false;
    if (lock.waiting_writers > 0)
    {
        // Writer-preference: hand off to the next queued writer
        // before any readers get a turn.
        sched::CondvarSignal(&lock.writers_cv);
    }
    else
    {
        // No queued writers; let every queued reader proceed.
        sched::CondvarBroadcast(&lock.readers_cv);
    }
    sched::MutexUnlock(&lock.inner);
}

bool RwLockTryAcquireShared(RwLock& lock)
{
    sched::MutexLock(&lock.inner);
    bool ok = false;
    if (!lock.writer_active && lock.waiting_writers == 0)
    {
        ++lock.active_readers;
        ok = true;
    }
    sched::MutexUnlock(&lock.inner);
    if (ok)
    {
        // Match the BlockingAcquire shape — record the held edge
        // only on the success path so a failed try doesn't add a
        // never-acquired entry to the graph.
        LockdepBeforeAcquire(lock.class_id);
        LockdepAfterAcquire(lock.class_id);
    }
    return ok;
}

bool RwLockTryAcquireExclusive(RwLock& lock)
{
    sched::MutexLock(&lock.inner);
    bool ok = false;
    if (!lock.writer_active && lock.active_readers == 0)
    {
        lock.writer_active = true;
        ok = true;
    }
    sched::MutexUnlock(&lock.inner);
    if (ok)
    {
        LockdepBeforeAcquire(lock.class_id);
        LockdepAfterAcquire(lock.class_id);
    }
    return ok;
}

namespace
{

[[noreturn]] void PanicRw(const char* what)
{
    core::Panic("sync/rwlock self-test", what);
}

} // namespace

void RwLockSelfTest()
{
    arch::SerialWrite("[sync] rwlock self-test: state-machine paths\n");

    RwLock lock{};

    // (1) Free → shared → multi-shared: try-shared succeeds twice.
    if (!RwLockTryAcquireShared(lock))
    {
        PanicRw("free lock rejected first reader");
    }
    if (!RwLockTryAcquireShared(lock))
    {
        PanicRw("free lock rejected second concurrent reader");
    }
    if (lock.active_readers != 2 || lock.writer_active)
    {
        PanicRw("counters wrong after two readers");
    }

    // (2) Readers active: try-exclusive must fail.
    if (RwLockTryAcquireExclusive(lock))
    {
        PanicRw("try-exclusive succeeded with active readers");
    }

    // (3) Release both readers; counters back to zero.
    RwLockReleaseShared(lock);
    RwLockReleaseShared(lock);
    if (lock.active_readers != 0 || lock.writer_active || lock.waiting_writers != 0)
    {
        PanicRw("counters not zero after release-all");
    }

    // (4) Free → exclusive: try-exclusive succeeds.
    if (!RwLockTryAcquireExclusive(lock))
    {
        PanicRw("free lock rejected exclusive acquirer");
    }
    if (!lock.writer_active || lock.active_readers != 0)
    {
        PanicRw("counters wrong after exclusive acquire");
    }

    // (5) Writer active: try-shared and try-exclusive must both fail.
    if (RwLockTryAcquireShared(lock))
    {
        PanicRw("try-shared succeeded with writer active");
    }
    if (RwLockTryAcquireExclusive(lock))
    {
        PanicRw("try-exclusive succeeded with writer active");
    }

    // (6) Release exclusive; back to free.
    RwLockReleaseExclusive(lock);
    if (lock.active_readers != 0 || lock.writer_active || lock.waiting_writers != 0)
    {
        PanicRw("counters not zero after release-exclusive");
    }

    // (7) Acquire / release via the blocking entry points (uncontended
    // path only — single-task boot context can't exercise contention
    // without deadlocking). Asserts the non-Try variants don't drop
    // bytes on the floor when the lock is free.
    RwLockAcquireShared(lock);
    if (lock.active_readers != 1)
    {
        PanicRw("AcquireShared (uncontended) did not bump counter");
    }
    RwLockReleaseShared(lock);

    RwLockAcquireExclusive(lock);
    if (!lock.writer_active)
    {
        PanicRw("AcquireExclusive (uncontended) did not flip flag");
    }
    RwLockReleaseExclusive(lock);

    if (lock.active_readers != 0 || lock.writer_active || lock.waiting_writers != 0)
    {
        PanicRw("counters not zero at end of self-test");
    }

    arch::SerialWrite("[sync] rwlock self-test OK (free/shared/exclusive transitions verified).\n");
}

} // namespace duetos::sync
