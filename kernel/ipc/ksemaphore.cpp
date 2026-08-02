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

constexpr u64 kMaxRelativeWaitTicks = (~u64{0}) >> 1;

u64 ClampRelativeWaitTicks(u64 ticks)
{
    return ticks > kMaxRelativeWaitTicks ? kMaxRelativeWaitTicks : ticks;
}

u64 RelativeDeadlineFromNow(u64 now, u64 ticks)
{
    const u64 bounded_ticks = ClampRelativeWaitTicks(ticks);
    return bounded_ticks > (~u64{0} - now) ? ~u64{0} : now + bounded_ticks;
}

bool TickDeadlineReached(u64 now, u64 deadline)
{
    return static_cast<i64>(now - deadline) >= 0;
}

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

KSemaphoreWaitResult KSemaphoreAcquire(KSemaphore* s)
{
    // Pin during the operation. The caller supplies a live reference
    // at entry; this extra pin extends it across blocking so a parallel
    // close cannot destroy the semaphore beneath the waiter.
    if (s == nullptr || !KObjectAcquire(&s->base))
    {
        return KSemaphoreWaitResult::Failed;
    }
    sched::MutexLock(&s->inner);
    while (s->count == 0)
    {
        if (sched::CondvarWaitCancellable(&s->cv, &s->inner) == sched::WaitQueueBlockResult::Cancelled)
        {
            sched::MutexUnlock(&s->inner);
            KObjectRelease(&s->base);
            return KSemaphoreWaitResult::Cancelled;
        }
    }
    // Loop-exit precondition: `count > 0` here. If a concurrent
    // path corrupted `count` we'd underflow into UINT32_MAX and
    // every subsequent caller would race past the wait forever.
    KASSERT(s->count > 0, "ipc/ksemaphore", "acquire: count underflow precondition");
    --s->count;
    sched::MutexUnlock(&s->inner);
    KObjectRelease(&s->base);
    return KSemaphoreWaitResult::Acquired;
}

KSemaphoreWaitResult KSemaphoreAcquireTimed(KSemaphore* s, u64 ticks)
{
    if (s == nullptr || !KObjectAcquire(&s->base))
    {
        return KSemaphoreWaitResult::Failed;
    }
    sched::MutexLock(&s->inner);
    if (s->count > 0)
    {
        --s->count;
        sched::MutexUnlock(&s->inner);
        KObjectRelease(&s->base);
        return KSemaphoreWaitResult::Acquired;
    }
    if (ticks == 0)
    {
        sched::MutexUnlock(&s->inner);
        KObjectRelease(&s->base);
        return KSemaphoreWaitResult::TimedOut;
    }
    const u64 deadline = RelativeDeadlineFromNow(sched::SchedNowTicks(), ticks);
    while (s->count == 0)
    {
        const u64 now = sched::SchedNowTicks();
        if (TickDeadlineReached(now, deadline))
        {
            sched::MutexUnlock(&s->inner);
            KObjectRelease(&s->base);
            return KSemaphoreWaitResult::TimedOut;
        }
        const sched::WaitQueueBlockResult wait_result =
            sched::CondvarWaitTimeoutCancellable(&s->cv, &s->inner, deadline - now);
        if (wait_result == sched::WaitQueueBlockResult::Cancelled)
        {
            sched::MutexUnlock(&s->inner);
            KObjectRelease(&s->base);
            return KSemaphoreWaitResult::Cancelled;
        }
        if (wait_result == sched::WaitQueueBlockResult::TimedOut && s->count == 0)
        {
            sched::MutexUnlock(&s->inner);
            KObjectRelease(&s->base);
            return KSemaphoreWaitResult::TimedOut;
        }
    }
    --s->count;
    sched::MutexUnlock(&s->inner);
    KObjectRelease(&s->base);
    return KSemaphoreWaitResult::Acquired;
}

void KSemaphoreRelease(KSemaphore* s, u32 n)
{
    if (n == 0)
    {
        return;
    }
    sched::MutexLock(&s->inner);
    KASSERT_WITH_VALUE(s->count <= s->max_count, "ipc/ksemaphore", "release: count > max_count precondition",
                       static_cast<u64>(s->count));
    if (n > s->max_count - s->count)
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
    // Cap-invariant postcondition. The `count + n > max_count`
    // guard above already proved `count <= max_count` here; the
    // KASSERT pins the postcondition so a future refactor that
    // drops the guard (e.g. an "atomic add then check" rewrite)
    // can't silently let the count drift past the contract every
    // consumer relies on. KASSERT, not DEBUG_ASSERT — a leaked
    // permit is the silent-corruption shape this whole TU defends
    // against, and we don't want it stripped in release.
    KASSERT_WITH_VALUE(s->count <= s->max_count, "ipc/ksemaphore", "release: count > max_count postcondition",
                       static_cast<u64>(s->count));
    // One bounded wake operation even when n == UINT32_MAX. Every
    // waiter rechecks count under this mutex; at most n can consume
    // permits, and any excess waiter reparks without changing state.
    (void)sched::CondvarBroadcast(&s->cv);
    sched::MutexUnlock(&s->inner);
}

bool KSemaphoreTryRelease(KSemaphore* s, u32 n, u32* prev_out)
{
    if (n == 0)
    {
        if (prev_out != nullptr)
        {
            sched::MutexLock(&s->inner);
            *prev_out = s->count;
            sched::MutexUnlock(&s->inner);
        }
        return true;
    }
    sched::MutexLock(&s->inner);
    const u64 new_count = static_cast<u64>(s->count) + static_cast<u64>(n);
    if (new_count > static_cast<u64>(s->max_count))
    {
        sched::MutexUnlock(&s->inner);
        return false;
    }
    const u32 prev = s->count;
    s->count = static_cast<u32>(new_count);
    KASSERT_WITH_VALUE(s->count <= s->max_count, "ipc/ksemaphore", "try-release: count > max_count postcondition",
                       static_cast<u64>(s->count));
    // Keep wake cost independent of the user-controlled release count.
    // The count predicate, not the number of wake calls, grants permits.
    (void)sched::CondvarBroadcast(&s->cv);
    sched::MutexUnlock(&s->inner);
    if (prev_out != nullptr)
    {
        *prev_out = prev;
    }
    return true;
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
    if (KSemaphoreAcquire(s) != KSemaphoreWaitResult::Acquired)
    {
        core::Panic("ipc/ksemaphore", "self-test: first acquire failed");
    }
    if (KSemaphoreCount(s) != 1)
    {
        core::Panic("ipc/ksemaphore", "self-test: count after one acquire != 1");
    }
    if (KSemaphoreAcquire(s) != KSemaphoreWaitResult::Acquired)
    {
        core::Panic("ipc/ksemaphore", "self-test: second acquire failed");
    }
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

    // A full-width release request must be rejected before u32 addition.
    // Use the non-panicking ABI-facing variant so the boot self-test can
    // exercise this hostile input in debug builds as well as release builds.
    u32 overflow_prev = 0xA5A5A5A5u;
    if (KSemaphoreTryRelease(s, ~u32{0}, &overflow_prev))
    {
        core::Panic("ipc/ksemaphore", "self-test: UINT32_MAX release unexpectedly succeeded");
    }
    if (KSemaphoreCount(s) != 2 || overflow_prev != 0xA5A5A5A5u)
    {
        core::Panic("ipc/ksemaphore", "self-test: rejected UINT32_MAX release mutated state");
    }

    // Timed-acquire fast paths: count > 0 consumes a permit
    // immediately; count == 0 with a zero budget returns TimedOut
    // without blocking. Real waiter contention is out of scope
    // until SMP AP bringup unlocks spawned-waiter tests.
    if (KSemaphoreAcquireTimed(s, 5) != KSemaphoreWaitResult::Acquired)
    {
        core::Panic("ipc/ksemaphore", "self-test: AcquireTimed(5) on count=2 failed");
    }
    if (KSemaphoreCount(s) != 1)
    {
        core::Panic("ipc/ksemaphore", "self-test: AcquireTimed did not decrement count");
    }
    if (KSemaphoreAcquireTimed(s, 0) != KSemaphoreWaitResult::Acquired)
    {
        core::Panic("ipc/ksemaphore", "self-test: AcquireTimed(0) on count=1 failed");
    }
    if (KSemaphoreCount(s) != 0)
    {
        core::Panic("ipc/ksemaphore", "self-test: AcquireTimed(0) did not decrement count");
    }
    if (KSemaphoreAcquireTimed(s, 0) != KSemaphoreWaitResult::TimedOut)
    {
        core::Panic("ipc/ksemaphore", "self-test: AcquireTimed(0) on count=0 did not time out");
    }
    if (KSemaphoreCount(s) != 0)
    {
        core::Panic("ipc/ksemaphore", "self-test: failing AcquireTimed touched count");
    }
    // Refill so the rest of the test runs against count=2.
    KSemaphoreRelease(s, 2);

    // Round-trip through HandleTable.
    static HandleTable table{};
    auto insert_r = HandleTableInsert(table, &s->base, TypeAllowedRights(KObjectType::Semaphore));
    if (!insert_r.has_value())
    {
        core::Panic("ipc/ksemaphore", "self-test: HandleTableInsert failed");
    }
    const Handle h = insert_r.value();
    KObject* looked_up = HandleTableLookupRef(table, h, KObjectType::Semaphore);
    if (looked_up != &s->base)
    {
        core::Panic("ipc/ksemaphore", "self-test: lookup did not return semaphore");
    }
    KObjectRelease(looked_up);
    if (HandleTableLookupRef(table, h, KObjectType::Mutex) != nullptr)
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
