/*
 * DuetOS — kernel work pool: implementation.
 *
 * See `workpool.h` for the public contract. This TU owns the
 * pool struct, the per-lane slot rings, the worker entry function,
 * the lifecycle of every spawned worker, and the boot self-test.
 *
 * SHAPE
 *   The queue is split into N "lanes" (one per worker). Each lane
 *   has its own slots, lock, and not_full condvar. Submitters
 *   round-robin across lanes; workers prefer their own lane and
 *   steal from peers when their own is empty. The shared shutdown /
 *   drain / wake state is carried by a single `inner` mutex +
 *   condvars on the pool.
 *
 * STATE INVARIANTS
 *   (under `p->inner`)
 *     - count_total == sum of every lane's count
 *     - active <= worker_count
 *     - workers_alive <= worker_count
 *     - shutdown == true => no further Submit calls (KASSERT'd)
 *
 *   (under `lane.lock`)
 *     - lane.count <= lane.capacity
 *     - lane.head + count == lane.tail (mod capacity)
 *
 * LOCK ORDER
 *   `lane.lock` → `inner`. Submit and Worker both take a lane lock
 *   first (briefly) and then the inner lock for shared bookkeeping.
 *   Worker waits on `not_empty` under `inner` ONLY (no lane lock
 *   held while sleeping).
 */

#include "sched/workpool.h"

#include "acpi/acpi.h"
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

struct WorkPoolLane
{
    sched::Mutex lock;
    sched::Condvar not_full; ///< Submitters wait here when THIS lane is full.
    WorkItem* slots;
    u32 capacity;
    u32 count;
    u32 head; ///< Next slot a Submit will write to.
    u32 tail; ///< Next slot a worker will read from.
};

} // namespace

struct WorkPool
{
    sched::Mutex inner;
    sched::Condvar not_empty;   ///< Workers wait here when count_total == 0.
    sched::Condvar space_avail; ///< Submitters wait here when every lane was full at scan time.
    sched::Condvar drained;     ///< Drain waiters wake when count_total == 0 && active == 0.
    sched::Condvar exited;      ///< Shutdown waits here for workers_alive to hit 0.

    u32 worker_count;  ///< Worker threads spawned at Create.
    u32 workers_alive; ///< Worker threads still running.
    u32 active;        ///< Workers currently inside a work-item callback.
    u64 count_total;   ///< Sum across every lane; updated under `inner`.
    bool shutdown;     ///< Set by Shutdown; tells workers to exit when queues empty.

    u32 lane_count;
    WorkPoolLane* lanes;

    u32 next_submit_lane; ///< Round-robin counter for Submit, atomic.

    const char* name_prefix;
};

namespace
{

// Per-worker context handed to WorkerMain so each thread knows which
// lane is its "preferred" starting point for the steal scan.
struct WorkerCtx
{
    WorkPool* pool;
    u32 idx; ///< 0..worker_count-1; doubles as preferred lane index.
};

// Try to claim one item from `l`. Returns true on success and writes
// the item into `*out`. Caller must NOT hold `inner` (we take the
// lane lock briefly + signal not_full). Used by both the local-lane
// path and the steal scan.
bool TryPopFromLane(WorkPoolLane& l, WorkItem* out)
{
    sched::MutexLock(&l.lock);
    if (l.count == 0)
    {
        sched::MutexUnlock(&l.lock);
        return false;
    }
    *out = l.slots[l.tail];
    l.tail = (l.tail + 1) % l.capacity;
    --l.count;
    sched::CondvarSignal(&l.not_full);
    sched::MutexUnlock(&l.lock);
    return true;
}

// Worker main loop. Pulls items from its preferred lane first,
// then steals from peers when the local lane is empty. Blocks on
// the pool-wide `not_empty` condvar when every lane is dry.
void WorkerMain(void* arg)
{
    auto* ctx = static_cast<WorkerCtx*>(arg);
    WorkPool* p = ctx->pool;
    const u32 my_idx = ctx->idx;

    for (;;)
    {
        // ---- Sleep until there's work or shutdown ---------------
        sched::MutexLock(&p->inner);
        while (p->count_total == 0 && !p->shutdown)
        {
            sched::CondvarWait(&p->not_empty, &p->inner);
        }
        if (p->count_total == 0 && p->shutdown)
        {
            --p->workers_alive;
            if (p->workers_alive == 0)
            {
                sched::CondvarBroadcast(&p->exited);
            }
            sched::MutexUnlock(&p->inner);
            duetos::mm::KFree(ctx);
            sched::SchedExit();
            // [[noreturn]] above; flow does not reach here.
        }
        sched::MutexUnlock(&p->inner);

        // ---- Scan lanes starting at the preferred slot ----------
        // The wake above only proves count_total WAS > 0 at some
        // point; a peer may have grabbed the only item. Pop is
        // best-effort across every lane.
        WorkItem item{};
        bool got = false;
        for (u32 i = 0; i < p->lane_count; ++i)
        {
            const u32 lane_idx = (my_idx + i) % p->lane_count;
            if (TryPopFromLane(p->lanes[lane_idx], &item))
            {
                got = true;
                break;
            }
        }
        if (!got)
        {
            // Spurious wake / lost race — go back to wait.
            continue;
        }

        // ---- Account the pop, run the callback -----------------
        sched::MutexLock(&p->inner);
        --p->count_total;
        ++p->active;
        // A pop opens space in some lane — wake any submitter
        // that was waiting because every lane was full.
        sched::CondvarSignal(&p->space_avail);
        sched::MutexUnlock(&p->inner);

        // Run the user callback OUTSIDE every pool lock. This is
        // the whole point of the pool — concurrent execution of
        // independent items.
        item.fn(item.arg);

        sched::MutexLock(&p->inner);
        --p->active;
        if (p->count_total == 0 && p->active == 0)
        {
            sched::CondvarBroadcast(&p->drained);
        }
        sched::MutexUnlock(&p->inner);
    }
}

void DestroyLanes(WorkPool* p)
{
    if (p == nullptr || p->lanes == nullptr)
    {
        return;
    }
    for (u32 i = 0; i < p->lane_count; ++i)
    {
        if (p->lanes[i].slots != nullptr)
        {
            duetos::mm::KFree(p->lanes[i].slots);
            p->lanes[i].slots = nullptr;
        }
    }
    duetos::mm::KFree(p->lanes);
    p->lanes = nullptr;
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
    p->worker_count = worker_count;
    p->name_prefix = name_prefix;

    // One lane per worker — bounded by acpi::kMaxCpus so a caller
    // that requests more workers than the architecture supports
    // is silently capped. Each lane gets queue_capacity / lane_count
    // slots (rounded up to at least 1) so the TOTAL pool capacity
    // matches the caller's request.
    p->lane_count = worker_count <= acpi::kMaxCpus ? worker_count : static_cast<u32>(acpi::kMaxCpus);
    const u32 per_lane = (queue_capacity + p->lane_count - 1) / p->lane_count;

    p->lanes = static_cast<WorkPoolLane*>(duetos::mm::KMalloc(sizeof(WorkPoolLane) * p->lane_count));
    if (p->lanes == nullptr)
    {
        duetos::mm::KFree(p);
        return nullptr;
    }
    for (u32 i = 0; i < p->lane_count; ++i)
    {
        p->lanes[i] = WorkPoolLane{};
    }
    for (u32 i = 0; i < p->lane_count; ++i)
    {
        p->lanes[i].capacity = per_lane;
        p->lanes[i].slots = static_cast<WorkItem*>(duetos::mm::KMalloc(sizeof(WorkItem) * per_lane));
        if (p->lanes[i].slots == nullptr)
        {
            DestroyLanes(p);
            duetos::mm::KFree(p);
            return nullptr;
        }
    }

    // Spawn workers under the inner mutex so a worker that wakes
    // before WorkPoolCreate returns sees workers_alive consistent
    // with the actual spawn count.
    sched::MutexLock(&p->inner);
    for (u32 i = 0; i < worker_count; ++i)
    {
        auto* ctx = static_cast<WorkerCtx*>(duetos::mm::KMalloc(sizeof(WorkerCtx)));
        if (ctx == nullptr)
        {
            p->shutdown = true;
            sched::CondvarBroadcast(&p->not_empty);
            while (p->workers_alive > 0)
            {
                sched::CondvarWait(&p->exited, &p->inner);
            }
            sched::MutexUnlock(&p->inner);
            DestroyLanes(p);
            duetos::mm::KFree(p);
            return nullptr;
        }
        ctx->pool = p;
        ctx->idx = i;
        sched::Task* t = sched::SchedCreate(&WorkerMain, ctx, p->name_prefix);
        if (t == nullptr)
        {
            duetos::mm::KFree(ctx);
            p->shutdown = true;
            sched::CondvarBroadcast(&p->not_empty);
            while (p->workers_alive > 0)
            {
                sched::CondvarWait(&p->exited, &p->inner);
            }
            sched::MutexUnlock(&p->inner);
            DestroyLanes(p);
            duetos::mm::KFree(p);
            KLOG_WARN_S("workpool", "WorkPoolCreate: SchedCreate failed", "name", name_prefix);
            return nullptr;
        }
        // Bias each worker toward its preferred CPU so the work-
        // item callback's CPU-local data has a chance to stay
        // warm. SchedSetAffinity is a soft hint today — the
        // scheduler may still migrate — but the bias is what we
        // need to pair with round-robin Submit for spread.
        sched::SchedSetAffinity(t, i % static_cast<u32>(acpi::kMaxCpus));
        ++p->workers_alive;
    }
    sched::MutexUnlock(&p->inner);

    KLOG_INFO_S("workpool", "WorkPoolCreate: pool ready", "name", name_prefix);
    return p;
}

namespace
{

// Try to push (fn, arg) onto the lane indexed by `lane_idx`.
// Returns true on success. On failure, the lane was full at the
// moment of the test; caller decides whether to wait or move on.
bool TryPushToLane(WorkPool* p, u32 lane_idx, WorkFn fn, void* arg)
{
    WorkPoolLane& l = p->lanes[lane_idx];
    sched::MutexLock(&l.lock);
    if (l.count >= l.capacity)
    {
        sched::MutexUnlock(&l.lock);
        return false;
    }
    l.slots[l.head] = WorkItem{fn, arg};
    l.head = (l.head + 1) % l.capacity;
    ++l.count;
    sched::MutexUnlock(&l.lock);

    sched::MutexLock(&p->inner);
    ++p->count_total;
    sched::CondvarSignal(&p->not_empty);
    sched::MutexUnlock(&p->inner);
    return true;
}

} // namespace

void WorkPoolSubmit(WorkPool* p, WorkFn fn, void* arg)
{
    KASSERT(p != nullptr, "workpool", "WorkPoolSubmit null pool");
    KASSERT(fn != nullptr, "workpool", "WorkPoolSubmit null fn");
    KASSERT(!p->shutdown, "workpool", "WorkPoolSubmit on shutdown pool");

    while (true)
    {
        // Round-robin over lanes. The fast path is one trylock that
        // either succeeds or sees a full lane; on full we move on
        // to the next index instead of blocking the caller.
        const u32 start = __atomic_fetch_add(&p->next_submit_lane, 1, __ATOMIC_RELAXED);
        bool any_full = false;
        for (u32 i = 0; i < p->lane_count; ++i)
        {
            const u32 lane_idx = (start + i) % p->lane_count;
            if (TryPushToLane(p, lane_idx, fn, arg))
            {
                return;
            }
            any_full = true;
        }
        // Every lane was full at the moment we scanned. Wait on
        // the pool-wide space_avail condvar; workers signal it on
        // every successful pop, so we wake as soon as ANY lane has
        // room. Re-check the predicate under `inner` before waiting
        // so a signal sent between our lane scan and the wait isn't
        // lost — that lost-wakeup is the classic intermittent
        // workpool-selftest hang (Submit blocks forever after the
        // last worker drained the last lane between scan and wait).
        if (any_full)
        {
            const u64 total_capacity = static_cast<u64>(p->lane_count) * static_cast<u64>(p->lanes[0].capacity);
            sched::MutexLock(&p->inner);
            while (p->count_total >= total_capacity && !p->shutdown)
            {
                sched::CondvarWait(&p->space_avail, &p->inner);
            }
            sched::MutexUnlock(&p->inner);
        }
    }
}

bool WorkPoolTrySubmit(WorkPool* p, WorkFn fn, void* arg)
{
    KASSERT(p != nullptr, "workpool", "WorkPoolTrySubmit null pool");
    KASSERT(fn != nullptr, "workpool", "WorkPoolTrySubmit null fn");
    KASSERT(!p->shutdown, "workpool", "WorkPoolTrySubmit on shutdown pool");

    const u32 start = __atomic_fetch_add(&p->next_submit_lane, 1, __ATOMIC_RELAXED);
    for (u32 i = 0; i < p->lane_count; ++i)
    {
        const u32 lane_idx = (start + i) % p->lane_count;
        if (TryPushToLane(p, lane_idx, fn, arg))
        {
            return true;
        }
    }
    return false;
}

void WorkPoolDrain(WorkPool* p)
{
    KASSERT(p != nullptr, "workpool", "WorkPoolDrain null pool");
    sched::MutexLock(&p->inner);
    while (p->count_total != 0 || p->active != 0)
    {
        sched::CondvarWait(&p->drained, &p->inner);
    }
    sched::MutexUnlock(&p->inner);
}

void WorkPoolShutdown(WorkPool* p)
{
    KASSERT(p != nullptr, "workpool", "WorkPoolShutdown null pool");
    sched::MutexLock(&p->inner);
    while (p->count_total != 0 || p->active != 0)
    {
        sched::CondvarWait(&p->drained, &p->inner);
    }
    p->shutdown = true;
    sched::CondvarBroadcast(&p->not_empty);
    while (p->workers_alive > 0)
    {
        sched::CondvarWait(&p->exited, &p->inner);
    }
    sched::MutexUnlock(&p->inner);

    DestroyLanes(p);
    duetos::mm::KFree(p);
}

u32 WorkPoolPending(const WorkPool* p)
{
    return p == nullptr ? 0u : static_cast<u32>(p->count_total);
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
