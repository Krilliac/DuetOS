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

#include "core/panic.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "util/types.h"

namespace duetos::sync
{

// Mutual-exclusion invariant. The file header documents that
// `writer_active && active_readers > 0` is NEVER valid; this is
// the runtime enforcement. Called under `lock.inner` so the read
// is a coherent snapshot. KASSERT, not DEBUG_ASSERT — the cost
// is one cmp+branch and a violation means a reader is about to
// observe a writer's mid-update payload, the exact bug rwlock
// exists to prevent.
[[gnu::always_inline]] inline void RwLockAssertExclusivity(const RwLock& lock)
{
    KASSERT(!(lock.writer_active && lock.active_readers > 0), "sync/rwlock",
            "exclusivity invariant: writer_active && active_readers > 0");
}

void RwLockAcquireShared(RwLock& lock)
{
    LockdepBeforeAcquire(lock.class_id);
    sched::MutexLock(&lock.inner);
    while (lock.writer_active || lock.waiting_writers > 0)
    {
        sched::CondvarWait(&lock.readers_cv, &lock.inner);
    }
    ++lock.active_readers;
    RwLockAssertExclusivity(lock);
    sched::MutexUnlock(&lock.inner);
    LockdepAfterAcquire(lock.class_id);
}

void RwLockReleaseShared(RwLock& lock)
{
    LockdepBeforeRelease(lock.class_id);
    sched::MutexLock(&lock.inner);
    if (lock.active_readers == 0)
    {
        // Debug: hard panic so the offending caller is found.
        // Release: log, drop the inner mutex, and refuse the
        // release — an unmatched release is a caller bug, but
        // pretending to honour it would underflow `active_readers`
        // and cement the bug into the lock's state.
        sched::MutexUnlock(&lock.inner);
        KLOG_ERROR_V("sync/rwlock", "ReleaseShared on lock with 0 readers; lock=", reinterpret_cast<u64>(&lock));
        core::DebugPanicOrWarn("sync/rwlock", "RwLockReleaseShared on lock with no readers");
        return;
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
    RwLockAssertExclusivity(lock);
    sched::MutexUnlock(&lock.inner);
    LockdepAfterAcquire(lock.class_id);
}

void RwLockReleaseExclusive(RwLock& lock)
{
    LockdepBeforeRelease(lock.class_id);
    sched::MutexLock(&lock.inner);
    if (!lock.writer_active)
    {
        // Same recovery shape as RwLockReleaseShared above: drop
        // the inner mutex and refuse the release in a release
        // build rather than corrupt the writer-flag.
        sched::MutexUnlock(&lock.inner);
        KLOG_ERROR_V("sync/rwlock", "ReleaseExclusive on lock with no writer; lock=", reinterpret_cast<u64>(&lock));
        core::DebugPanicOrWarn("sync/rwlock", "RwLockReleaseExclusive on lock with no writer");
        return;
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
    RwLockAssertExclusivity(lock);
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
    RwLockAssertExclusivity(lock);
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
    KLOG_TRACE_SCOPE("sync/rwlock", "RwLockSelfTest");
    KLOG_INFO("sync/rwlock", "self-test: state-machine paths");

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

    KLOG_INFO("sync/rwlock", "self-test OK (free/shared/exclusive transitions verified)");
}

namespace
{

// Shared state for the contention test. File-scope statics so
// the spawned tasks can reach them through their void* arg
// without per-test allocation gymnastics. `volatile` to keep the
// compiler from hoisting reads out of the wait-for-progress
// loops; the actual counter mutations go through GCC atomic
// builtins so a real SMP path stays correct.
struct ContentionShared
{
    RwLock lock;
    u32 acquired_count;
    u32 released_count;
    u32 attempts_started;
};

ContentionShared g_rwl_shared{};

void ReaderTask(void* arg)
{
    auto* s = static_cast<ContentionShared*>(arg);
    __atomic_add_fetch(&s->attempts_started, 1, __ATOMIC_SEQ_CST);
    RwLockAcquireShared(s->lock);
    __atomic_add_fetch(&s->acquired_count, 1, __ATOMIC_SEQ_CST);
    // Hold long enough that the OTHER reader can also race in
    // before this one releases. One scheduler tick is plenty —
    // the runqueue rotation will let the second reader land.
    sched::SchedSleepTicks(1);
    RwLockReleaseShared(s->lock);
    __atomic_add_fetch(&s->released_count, 1, __ATOMIC_SEQ_CST);
}

void WriterTask(void* arg)
{
    auto* s = static_cast<ContentionShared*>(arg);
    __atomic_add_fetch(&s->attempts_started, 1, __ATOMIC_SEQ_CST);
    RwLockAcquireExclusive(s->lock);
    __atomic_add_fetch(&s->acquired_count, 1, __ATOMIC_SEQ_CST);
    RwLockReleaseExclusive(s->lock);
    __atomic_add_fetch(&s->released_count, 1, __ATOMIC_SEQ_CST);
}

// Wait until `*counter == target` or 100 scheduler ticks (~1 s)
// elapse. Yields between checks so the spawned tasks actually
// run. Returns true on success, false on timeout — the caller
// panics with a context-specific message.
bool WaitForCount(volatile u32& counter, u32 target)
{
    constexpr u32 kMaxTicks = 100;
    for (u32 i = 0; i < kMaxTicks; ++i)
    {
        if (__atomic_load_n(&counter, __ATOMIC_SEQ_CST) >= target)
        {
            return true;
        }
        sched::SchedSleepTicks(1);
    }
    return __atomic_load_n(&counter, __ATOMIC_SEQ_CST) >= target;
}

} // namespace

void RwLockContentionSelfTest()
{
    KLOG_TRACE_SCOPE("sync/rwlock", "RwLockContentionSelfTest");
    KLOG_INFO("sync/rwlock", "contention self-test: blocking + wakeup paths");

    // Reset shared state — the static is reused across the two
    // sub-tests below so resetting between scenarios keeps the
    // expected-counter math simple.
    g_rwl_shared = ContentionShared{};

    // Scenario 1: writer-blocks-readers, then release wakes them.
    // Main acquires exclusive; spawn 2 reader tasks; verify they
    // block (counters stay 0); release and verify they BOTH wake
    // and complete.
    RwLockAcquireExclusive(g_rwl_shared.lock);
    sched::SchedCreate(ReaderTask, &g_rwl_shared, "rwl-r1");
    sched::SchedCreate(ReaderTask, &g_rwl_shared, "rwl-r2");
    // Wait for both reader tasks to have STARTED (i.e. reached
    // RwLockAcquireShared and blocked in CondvarWait). Without
    // this we'd race the spawn ordering; the readers might not
    // have run yet when we release, and we'd see them complete
    // through the fast path instead of the wakeup path.
    if (!WaitForCount(g_rwl_shared.attempts_started, 2))
    {
        core::Panic("sync/rwlock", "contention test: readers never started");
    }
    sched::SchedSleepTicks(2); // ensure both blocked in CondvarWait

    // While exclusive is held, no reader should have acquired.
    if (__atomic_load_n(&g_rwl_shared.acquired_count, __ATOMIC_SEQ_CST) != 0)
    {
        core::Panic("sync/rwlock", "contention test: reader acquired while writer held");
    }
    RwLockReleaseExclusive(g_rwl_shared.lock);

    // After release, both readers must wake. With writer-preference
    // and no queued writer, the broadcast path fires and both
    // readers proceed.
    if (!WaitForCount(g_rwl_shared.released_count, 2))
    {
        core::Panic("sync/rwlock", "contention test: readers never woke");
    }

    // Scenario 2: reader-blocks-writer. Main acquires shared,
    // spawn 1 writer; writer must block; main releases; writer
    // proceeds.
    g_rwl_shared = ContentionShared{};
    RwLockAcquireShared(g_rwl_shared.lock);
    sched::SchedCreate(WriterTask, &g_rwl_shared, "rwl-w1");
    if (!WaitForCount(g_rwl_shared.attempts_started, 1))
    {
        core::Panic("sync/rwlock", "contention test: writer never started");
    }
    sched::SchedSleepTicks(2);

    if (__atomic_load_n(&g_rwl_shared.acquired_count, __ATOMIC_SEQ_CST) != 0)
    {
        core::Panic("sync/rwlock", "contention test: writer acquired while reader held");
    }
    RwLockReleaseShared(g_rwl_shared.lock);

    if (!WaitForCount(g_rwl_shared.released_count, 1))
    {
        core::Panic("sync/rwlock", "contention test: writer never woke");
    }

    // Lock should be free at the end.
    if (g_rwl_shared.lock.active_readers != 0 || g_rwl_shared.lock.writer_active ||
        g_rwl_shared.lock.waiting_writers != 0)
    {
        core::Panic("sync/rwlock", "contention test: lock not free at end");
    }

    KLOG_INFO("sync/rwlock", "contention self-test OK (blocking + wakeup paths verified)");
}

} // namespace duetos::sync
