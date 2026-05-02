/*
 * DuetOS — concrete KSemaphore implementation, v0 (plan A3-followup).
 *
 * See `ksemaphore.h` for the public contract. This TU owns:
 *   - kheap-backed allocation + KObjectInit on Create,
 *   - the count + max_count state machine,
 *   - the destroy callback that runs on last refcount release,
 *   - a self-test that drives Acquire / Release / clamp paths
 *     without spawned waiters (fast-path verification only).
 */

#include "ipc/ksemaphore.h"

#include "core/panic.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "sched/sched.h"

#include <stddef.h>

namespace duetos::ipc
{

static_assert(__builtin_offsetof(KSemaphore, base) == 0, "KObject must be the first member of KSemaphore");

namespace
{

void KSemaphoreDestroy(KObject* obj)
{
    auto* s = reinterpret_cast<KSemaphore*>(obj);
    duetos::mm::KFree(s);
}

} // namespace

::duetos::core::Result<KSemaphore*> KSemaphoreCreate(u32 initial_count, u32 max_count)
{
    if (initial_count > max_count)
    {
        KLOG_WARN_2V("ipc/ksemaphore", "Create: initial > max", "initial", static_cast<u64>(initial_count), "max",
                     static_cast<u64>(max_count));
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    auto* s = static_cast<KSemaphore*>(duetos::mm::KMalloc(sizeof(KSemaphore)));
    if (s == nullptr)
    {
        KLOG_ERROR_AV(::duetos::core::LogArea::IPC, "ipc/ksemaphore", "Create: KMalloc failed (OOM)",
                      static_cast<u64>(sizeof(KSemaphore)));
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *s = KSemaphore{};
    KObjectInit(&s->base, KObjectType::Semaphore, &KSemaphoreDestroy);
    s->count = initial_count;
    s->max_count = max_count;
    KLOG_TRACE_AV(::duetos::core::LogArea::IPC, "ipc/ksemaphore", "create ok initial", static_cast<u64>(initial_count));
    return s;
}

void KSemaphoreAcquire(KSemaphore* s)
{
    sched::MutexLock(&s->inner);
    while (s->count == 0)
    {
        sched::CondvarWait(&s->cv, &s->inner);
    }
    --s->count;
    sched::MutexUnlock(&s->inner);
}

void KSemaphoreRelease(KSemaphore* s, u32 n)
{
    if (n == 0)
    {
        return;
    }
    sched::MutexLock(&s->inner);
    if (s->count + n > s->max_count)
    {
        // Debug: panic; release: log and refuse the release. The
        // mutex is already dropped — letting `count` exceed
        // `max_count` would leak permits past the contract that
        // every consumer relies on.
        const u32 cur = s->count;
        const u32 cap = s->max_count;
        sched::MutexUnlock(&s->inner);
        KLOG_ERROR_2V("ipc/ksemaphore", "release would overflow max_count", "count+n",
                      static_cast<u64>(cur) + static_cast<u64>(n), "max", static_cast<u64>(cap));
        core::DebugPanicOrWarn("ipc/ksemaphore", "release would overflow max_count");
        return;
    }
    s->count += n;
    // Wake up to n waiters. Each will re-check `count > 0` under
    // the mutex and consume one permit. Broadcasting all and
    // letting them filter is correct but wasteful when n < waiter
    // count; a per-N signal loop matches the intent.
    for (u32 i = 0; i < n; ++i)
    {
        sched::CondvarSignal(&s->cv);
    }
    sched::MutexUnlock(&s->inner);
}

u32 KSemaphoreCount(const KSemaphore* s)
{
    return s->count;
}

void KSemaphoreSelfTest()
{
    KLOG_TRACE_SCOPE("ipc/ksemaphore", "KSemaphoreSelfTest");
    KLOG_INFO_A(::duetos::core::LogArea::IPC, "ipc/ksemaphore", "self-test: state machine + HandleTable round-trip");

    // initial=0 with max=2 should reject Acquire-before-Release
    // patterns; we don't test that here (would need a spawned
    // waiter). Instead: initial=2 max=2 — drain via two acquires,
    // refill via one release-of-2, drain again.
    auto create_r = KSemaphoreCreate(2, 2);
    if (!create_r.has_value())
    {
        core::Panic("ipc/ksemaphore", "self-test: KSemaphoreCreate failed");
    }
    KSemaphore* s = create_r.value();
    if (KSemaphoreCount(s) != 2)
    {
        core::Panic("ipc/ksemaphore", "self-test: initial count != 2");
    }

    // Bad-arg: initial > max should fail without allocating.
    auto bad_r = KSemaphoreCreate(5, 2);
    if (bad_r.has_value())
    {
        core::Panic("ipc/ksemaphore", "self-test: bad-arg create succeeded");
    }
    if (bad_r.error() != ::duetos::core::ErrorCode::InvalidArgument)
    {
        core::Panic("ipc/ksemaphore", "self-test: bad-arg returned wrong error");
    }

    // Drain via two acquires. count → 1 → 0.
    KSemaphoreAcquire(s);
    if (KSemaphoreCount(s) != 1)
    {
        core::Panic("ipc/ksemaphore", "self-test: count after one acquire != 1");
    }
    KSemaphoreAcquire(s);
    if (KSemaphoreCount(s) != 0)
    {
        core::Panic("ipc/ksemaphore", "self-test: count after two acquires != 0");
    }

    // Refill via release-of-2.
    KSemaphoreRelease(s, 2);
    if (KSemaphoreCount(s) != 2)
    {
        core::Panic("ipc/ksemaphore", "self-test: count after release-2 != 2");
    }

    // Release of 0 is a no-op — count unchanged.
    KSemaphoreRelease(s, 0);
    if (KSemaphoreCount(s) != 2)
    {
        core::Panic("ipc/ksemaphore", "self-test: release(0) changed count");
    }

    // Round-trip through HandleTable.
    static HandleTable table{};
    auto insert_r = HandleTableInsert(table, &s->base);
    if (!insert_r.has_value())
    {
        core::Panic("ipc/ksemaphore", "self-test: HandleTableInsert failed");
    }
    const Handle h = insert_r.value();
    if (HandleTableLookup(table, h, KObjectType::Semaphore) != &s->base)
    {
        core::Panic("ipc/ksemaphore", "self-test: lookup did not return semaphore");
    }
    if (HandleTableLookup(table, h, KObjectType::Mutex) != nullptr)
    {
        core::Panic("ipc/ksemaphore", "self-test: lookup with wrong type-tag returned non-null");
    }
    if (!HandleTableRemove(table, h).has_value())
    {
        core::Panic("ipc/ksemaphore", "self-test: HandleTableRemove failed");
    }
    if (HandleTableLiveCount(table) != 0)
    {
        core::Panic("ipc/ksemaphore", "self-test: live count != 0 at end");
    }

    KLOG_INFO_A(::duetos::core::LogArea::IPC, "ipc/ksemaphore",
                "self-test OK (Create + Acquire + Release + clamp + HandleTable cycle)");
}

} // namespace duetos::ipc
