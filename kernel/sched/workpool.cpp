/*
 * DuetOS — kernel work pool: implementation.
 *
 * See `workpool.h` for the public contract. This TU owns the
 * pool struct, the slot ring, the worker entry function, the
 * lifecycle of every spawned worker, and the boot self-test.
 *
 * State invariants (held under `inner`):
 *   - count <= capacity
 *   - active <= worker_count
 *   - workers_alive <= worker_count
 *   - shutdown == true => no further Submit calls (KASSERT'd)
 *
 * The worker loop pattern is the textbook bounded-buffer
 * consumer with a separate "drained" condvar so Drain doesn't
 * race against `not_empty` wakes meant for workers — see the
 * banner above WorkerMain.
 */

#include "sched/workpool.h"

#include "core/panic.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "util/types.h"

namespace duetos::sched
{

namespace
{

struct WorkItem
{
    WorkFn fn;
    void* arg;
};

} // namespace

struct WorkPool
{
    sched::Mutex inner;
    sched::Condvar not_empty; ///< Workers wait here when the queue is empty.
    sched::Condvar not_full;  ///< Submitters wait here when the queue is full.
    sched::Condvar drained;   ///< Drain waiters wake when count == 0 && active == 0.
    sched::Condvar exited;    ///< Shutdown waits here for workers_alive to hit 0.

    WorkItem* slots;
    u32 capacity;
    u32 count;
    u32 head; ///< Next slot a Submit will write to.
    u32 tail; ///< Next slot a worker will read from.

    u32 worker_count;  ///< Worker threads spawned at Create.
    u32 workers_alive; ///< Worker threads still running (drops on shutdown exit).
    u32 active;        ///< Workers currently inside a work-item callback.
    bool shutdown;     ///< Set by Shutdown; tells workers to exit when queue empties.

    const char* name_prefix; ///< Caller-owned; must outlive the pool.
};

namespace
{

// Worker main loop. Pulls items from the queue and runs them
// until Shutdown is requested AND the queue is empty. The
// "drain" condvar is signalled whenever the worker observes a
// fully-quiescent pool (queue empty + no other worker active)
// after completing an item — that's the exact condition Drain
// is waiting on, and the worker is in the perfect position to
// notice it.
void WorkerMain(void* arg)
{
    auto* p = static_cast<WorkPool*>(arg);

    for (;;)
    {
        sched::MutexLock(&p->inner);

        // Wait for either work to arrive or for shutdown to be
        // requested. Shutdown alone is not enough — a worker
        // must drain queued items before exiting so a Submit
        // followed immediately by Shutdown still completes
        // every submitted item.
        while (p->count == 0 && !p->shutdown)
        {
            sched::CondvarWait(&p->not_empty, &p->inner);
        }

        if (p->count == 0 && p->shutdown)
        {
            --p->workers_alive;
            // Signal Shutdown's join-equivalent waiter. The
            // last worker to leave wakes Shutdown so it can
            // free the pool.
            if (p->workers_alive == 0)
            {
                sched::CondvarBroadcast(&p->exited);
            }
            sched::MutexUnlock(&p->inner);
            sched::SchedExit();
            // SchedExit is [[noreturn]]; the loop never reaches
            // here.
        }

        WorkItem item = p->slots[p->tail];
        p->tail = (p->tail + 1) % p->capacity;
        --p->count;
        ++p->active;

        // A producer waiting on a full queue is now welcome.
        sched::CondvarSignal(&p->not_full);

        sched::MutexUnlock(&p->inner);

        // Run the user callback OUTSIDE the pool mutex. This
        // is the whole point of the pool — concurrent execution
        // of independent items.
        item.fn(item.arg);

        sched::MutexLock(&p->inner);
        --p->active;
        // Quiescence check: if this worker just finished the
        // last in-flight item AND no further items are queued,
        // wake every Drain caller.
        if (p->count == 0 && p->active == 0)
        {
            sched::CondvarBroadcast(&p->drained);
        }
        sched::MutexUnlock(&p->inner);
    }
}

} // namespace

WorkPool* WorkPoolCreate(u32 worker_count, u32 queue_capacity, const char* name_prefix)
{
    if (worker_count == 0 || queue_capacity == 0 || name_prefix == nullptr)
    {
        return nullptr;
    }

    auto* p = static_cast<WorkPool*>(duetos::mm::KMalloc(sizeof(WorkPool)));
    if (p == nullptr)
    {
        return nullptr;
    }
    *p = WorkPool{};
    p->slots = static_cast<WorkItem*>(duetos::mm::KMalloc(sizeof(WorkItem) * queue_capacity));
    if (p->slots == nullptr)
    {
        duetos::mm::KFree(p);
        return nullptr;
    }
    p->capacity = queue_capacity;
    p->worker_count = worker_count;
    p->name_prefix = name_prefix;

    // Spawn workers under the pool mutex so a worker that wakes
    // before WorkPoolCreate returns sees workers_alive consistent
    // with the actual spawn count.
    sched::MutexLock(&p->inner);
    for (u32 i = 0; i < worker_count; ++i)
    {
        // Per-worker name buffer is owned by the pool and lives
        // alongside the WorkPool struct — workers stay alive for
        // the pool's lifetime, so a single shared prefix is
        // sufficient. The scheduler keeps its own copy of the
        // pointer, not the bytes; we pass the prefix unchanged
        // and accept that all workers in a pool share a label.
        sched::Task* t = sched::SchedCreate(&WorkerMain, p, p->name_prefix);
        if (t == nullptr)
        {
            // Roll back the half-built pool. Mark shutdown +
            // wake any worker that already started; they'll
            // exit through the normal shutdown path.
            p->shutdown = true;
            sched::CondvarBroadcast(&p->not_empty);
            // Wait for the workers we DID spawn to exit before
            // freeing the storage their stacks never read.
            while (p->workers_alive > 0)
            {
                sched::CondvarWait(&p->exited, &p->inner);
            }
            sched::MutexUnlock(&p->inner);
            duetos::mm::KFree(p->slots);
            duetos::mm::KFree(p);
            KLOG_WARN_S("workpool", "WorkPoolCreate: SchedCreate failed", "name", name_prefix);
            return nullptr;
        }
        ++p->workers_alive;
    }
    sched::MutexUnlock(&p->inner);

    KLOG_INFO_S("workpool", "WorkPoolCreate: pool ready", "name", name_prefix);
    return p;
}

void WorkPoolSubmit(WorkPool* p, WorkFn fn, void* arg)
{
    KASSERT(p != nullptr, "workpool", "WorkPoolSubmit null pool");
    KASSERT(fn != nullptr, "workpool", "WorkPoolSubmit null fn");
    sched::MutexLock(&p->inner);
    KASSERT(!p->shutdown, "workpool", "WorkPoolSubmit on shutdown pool");
    while (p->count == p->capacity)
    {
        sched::CondvarWait(&p->not_full, &p->inner);
    }
    p->slots[p->head] = WorkItem{fn, arg};
    p->head = (p->head + 1) % p->capacity;
    ++p->count;
    sched::CondvarSignal(&p->not_empty);
    sched::MutexUnlock(&p->inner);
}

bool WorkPoolTrySubmit(WorkPool* p, WorkFn fn, void* arg)
{
    KASSERT(p != nullptr, "workpool", "WorkPoolTrySubmit null pool");
    KASSERT(fn != nullptr, "workpool", "WorkPoolTrySubmit null fn");
    sched::MutexLock(&p->inner);
    KASSERT(!p->shutdown, "workpool", "WorkPoolTrySubmit on shutdown pool");
    if (p->count == p->capacity)
    {
        sched::MutexUnlock(&p->inner);
        return false;
    }
    p->slots[p->head] = WorkItem{fn, arg};
    p->head = (p->head + 1) % p->capacity;
    ++p->count;
    sched::CondvarSignal(&p->not_empty);
    sched::MutexUnlock(&p->inner);
    return true;
}

void WorkPoolDrain(WorkPool* p)
{
    KASSERT(p != nullptr, "workpool", "WorkPoolDrain null pool");
    sched::MutexLock(&p->inner);
    while (p->count != 0 || p->active != 0)
    {
        sched::CondvarWait(&p->drained, &p->inner);
    }
    sched::MutexUnlock(&p->inner);
}

void WorkPoolShutdown(WorkPool* p)
{
    KASSERT(p != nullptr, "workpool", "WorkPoolShutdown null pool");
    sched::MutexLock(&p->inner);
    // Wait for any in-flight items first — Shutdown's contract
    // is "drain, then exit", same as glibc's pthread_pool_destroy.
    while (p->count != 0 || p->active != 0)
    {
        sched::CondvarWait(&p->drained, &p->inner);
    }
    p->shutdown = true;
    // Every worker is currently in the not_empty wait; broadcast
    // wakes every one of them, each observes shutdown + empty
    // queue and exits.
    sched::CondvarBroadcast(&p->not_empty);
    while (p->workers_alive > 0)
    {
        sched::CondvarWait(&p->exited, &p->inner);
    }
    sched::MutexUnlock(&p->inner);

    duetos::mm::KFree(p->slots);
    duetos::mm::KFree(p);
}

u32 WorkPoolPending(const WorkPool* p)
{
    return p == nullptr ? 0u : p->count;
}

u32 WorkPoolActive(const WorkPool* p)
{
    return p == nullptr ? 0u : p->active;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace
{

// The self-test exercises the entire lifecycle. Counter is
// incremented by every worker without explicit synchronisation
// — the pool's own queue serialises Submit/Receive, but
// callbacks run concurrently. We use a sched::Mutex inside the
// callback to serialise the increment so the final value is
// deterministic regardless of how many CPUs the workers land on.
struct SelfTestState
{
    sched::Mutex lock;
    u64 counter;
};

void SelfTestItem(void* arg)
{
    auto* st = static_cast<SelfTestState*>(arg);
    sched::MutexLock(&st->lock);
    ++st->counter;
    sched::MutexUnlock(&st->lock);
}

} // namespace

void WorkPoolSelfTest()
{
    constexpr u32 kWorkers = 4;
    constexpr u32 kCapacity = 8; // intentionally smaller than kItems so Submit blocks
    constexpr u64 kItems = 256;

    WorkPool* p = WorkPoolCreate(kWorkers, kCapacity, "wpool-st");
    KASSERT(p != nullptr, "workpool", "self-test: Create failed");

    SelfTestState st{};
    for (u64 i = 0; i < kItems; ++i)
    {
        WorkPoolSubmit(p, &SelfTestItem, &st);
    }

    WorkPoolDrain(p);

    KASSERT(WorkPoolPending(p) == 0, "workpool", "self-test: pending != 0 after drain");
    KASSERT(WorkPoolActive(p) == 0, "workpool", "self-test: active != 0 after drain");
    KASSERT(st.counter == kItems, "workpool", "self-test: counter mismatch after drain");

    WorkPoolShutdown(p);

    KLOG_INFO_V("workpool", "self-test: passed", st.counter);
}

} // namespace duetos::sched
