/*
 * DuetOS — concrete KEvent implementation, v0 (plan A3-followup).
 *
 * See `kevent.h` for the public contract. This TU owns:
 *   - kheap-backed allocation + KObjectInit on Create,
 *   - the manual-vs-auto-reset state machine,
 *   - the destroy callback that runs on last refcount release,
 *   - a self-test that drives the full HandleTable round-trip
 *     plus the Set/Reset/Wait fast-path (no waiter contention).
 */

#include "ipc/kevent.h"

#include "core/panic.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "sched/sched.h"

#include <stddef.h>

namespace duetos::ipc
{

static_assert(__builtin_offsetof(KEvent, base) == 0, "KObject must be the first member of KEvent");

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

void KEventDestroy(KObject* obj)
{
    auto* e = reinterpret_cast<KEvent*>(obj);
    // No "still held" panic equivalent — the event has no owner;
    // any task still blocked on the condvar holds an explicit wait
    // pin. Closing the last handle therefore cannot reach this path
    // until every waiter has unwound and dropped that pin.
    duetos::mm::KFree(e);
}

} // namespace

::duetos::core::Result<KEvent*> KEventCreate(bool manual_reset, bool initially_signaled)
{
    auto* e = static_cast<KEvent*>(duetos::mm::KMalloc(sizeof(KEvent)));
    if (e == nullptr)
    {
        KLOG_ERROR_AV(::duetos::core::LogArea::IPC, "ipc/kevent", "Create: KMalloc failed (OOM)",
                      static_cast<u64>(sizeof(KEvent)));
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *e = KEvent{};
    KObjectInit(&e->base, KObjectType::Event, &KEventDestroy);
    e->manual_reset = manual_reset;
    e->signaled = initially_signaled;
    KLOG_TRACE_A(::duetos::core::LogArea::IPC, "ipc/kevent",
                 manual_reset ? "create ok manual-reset" : "create ok auto-reset");
    return e;
}

void KEventSet(KEvent* e)
{
    sched::MutexLock(&e->inner);
    e->signaled = true;
    if (e->manual_reset)
    {
        // Wake every waiter; they each re-check `signaled` under
        // the mutex and return.
        sched::CondvarBroadcast(&e->cv);
    }
    else
    {
        // Auto-reset: wake exactly one. The woken waiter clears
        // the flag itself before returning, so a subsequent Set
        // sees `signaled == false` again. If no waiter is queued,
        // signaled stays true until one arrives.
        sched::CondvarSignal(&e->cv);
    }
    sched::MutexUnlock(&e->inner);
}

void KEventReset(KEvent* e)
{
    sched::MutexLock(&e->inner);
    if (e->manual_reset)
    {
        e->signaled = false;
    }
    // No-op on auto-reset — Set/Wait pair handles the clearing.
    sched::MutexUnlock(&e->inner);
}

KEventWaitResult KEventWait(KEvent* e)
{
    // Pin during the wait so closing every handle while a waiter
    // is blocked cannot free the storage. The caller supplies a live
    // reference at entry; this extra pin extends it across blocking.
    if (e == nullptr || !KObjectAcquire(&e->base))
    {
        return KEventWaitResult::Failed;
    }
    sched::MutexLock(&e->inner);
    while (!e->signaled)
    {
        if (sched::CondvarWaitCancellable(&e->cv, &e->inner) == sched::WaitQueueBlockResult::Cancelled)
        {
            sched::MutexUnlock(&e->inner);
            KObjectRelease(&e->base);
            return KEventWaitResult::Cancelled;
        }
    }
    if (!e->manual_reset)
    {
        // Auto-reset: this waiter consumes the signal. Subsequent
        // waiters block until the next Set.
        e->signaled = false;
    }
    sched::MutexUnlock(&e->inner);
    KObjectRelease(&e->base);
    return KEventWaitResult::Signaled;
}

KEventWaitResult KEventWaitTimed(KEvent* e, u64 ticks)
{
    if (e == nullptr || !KObjectAcquire(&e->base))
    {
        return KEventWaitResult::Failed;
    }
    sched::MutexLock(&e->inner);
    if (e->signaled)
    {
        if (!e->manual_reset)
        {
            e->signaled = false;
        }
        sched::MutexUnlock(&e->inner);
        KObjectRelease(&e->base);
        return KEventWaitResult::Signaled;
    }
    if (ticks == 0)
    {
        sched::MutexUnlock(&e->inner);
        KObjectRelease(&e->base);
        return KEventWaitResult::TimedOut;
    }
    // Compute the deadline once so spurious wakeups and "another
    // waiter consumed the auto-reset signal first" races don't
    // re-arm the full budget on every iteration.
    const u64 deadline = RelativeDeadlineFromNow(sched::SchedNowTicks(), ticks);
    while (!e->signaled)
    {
        const u64 now = sched::SchedNowTicks();
        if (TickDeadlineReached(now, deadline))
        {
            sched::MutexUnlock(&e->inner);
            KObjectRelease(&e->base);
            return KEventWaitResult::TimedOut;
        }
        const sched::WaitQueueBlockResult wait_result =
            sched::CondvarWaitTimeoutCancellable(&e->cv, &e->inner, deadline - now);
        if (wait_result == sched::WaitQueueBlockResult::Cancelled)
        {
            sched::MutexUnlock(&e->inner);
            KObjectRelease(&e->base);
            return KEventWaitResult::Cancelled;
        }
        if (wait_result == sched::WaitQueueBlockResult::TimedOut && !e->signaled)
        {
            sched::MutexUnlock(&e->inner);
            KObjectRelease(&e->base);
            return KEventWaitResult::TimedOut;
        }
    }
    if (!e->manual_reset)
    {
        e->signaled = false;
    }
    sched::MutexUnlock(&e->inner);
    KObjectRelease(&e->base);
    return KEventWaitResult::Signaled;
}

bool KEventIsSignaled(KEvent* e)
{
    sched::MutexLock(&e->inner);
    const bool s = e->signaled;
    sched::MutexUnlock(&e->inner);
    return s;
}

void KEventClearAutoReset(KEvent* e)
{
    sched::MutexLock(&e->inner);
    if (!e->manual_reset)
    {
        e->signaled = false;
    }
    sched::MutexUnlock(&e->inner);
}

void KEventSelfTest()
{
    KLOG_TRACE_SCOPE("ipc/kevent", "KEventSelfTest");
    KLOG_INFO_A(::duetos::core::LogArea::IPC, "ipc/kevent", "self-test: state machine + HandleTable round-trip");

    // Manual-reset event, initially signaled. Wait should return
    // immediately (no blocking needed).
    auto manual_r = KEventCreate(true, true);
    if (!manual_r.has_value())
    {
        core::Panic("ipc/kevent", "self-test: manual KEventCreate failed");
    }
    KEvent* manual = manual_r.value();
    if (!manual->signaled || !manual->manual_reset)
    {
        core::Panic("ipc/kevent", "self-test: manual event init flags wrong");
    }

    // Wait on signaled manual event — must return without blocking.
    if (KEventWait(manual) != KEventWaitResult::Signaled)
    {
        core::Panic("ipc/kevent", "self-test: Wait on signaled manual event failed");
    }
    // Manual-reset should STILL be signaled after a wait.
    if (!manual->signaled)
    {
        core::Panic("ipc/kevent", "self-test: manual event cleared after wait");
    }
    KEventReset(manual);
    if (manual->signaled)
    {
        core::Panic("ipc/kevent", "self-test: manual event reset did not clear");
    }
    KEventSet(manual);
    if (!manual->signaled)
    {
        core::Panic("ipc/kevent", "self-test: manual event set did not signal");
    }

    // Auto-reset event, initially signaled. Wait must clear it.
    auto auto_r = KEventCreate(false, true);
    if (!auto_r.has_value())
    {
        core::Panic("ipc/kevent", "self-test: auto KEventCreate failed");
    }
    KEvent* auto_ev = auto_r.value();
    if (KEventWait(auto_ev) != KEventWaitResult::Signaled)
    {
        core::Panic("ipc/kevent", "self-test: Wait on signaled auto event failed");
    }
    if (auto_ev->signaled)
    {
        core::Panic("ipc/kevent", "self-test: auto-reset did not clear after wait");
    }
    KEventSet(auto_ev);
    if (!auto_ev->signaled)
    {
        core::Panic("ipc/kevent", "self-test: auto event set did not signal");
    }

    // Timed-wait fast paths. Already-signaled event consumes the
    // signal regardless of the budget. Cleared event with a zero
    // budget returns TimedOut without blocking. Real "Set during
    // wait wins the race" + "timer fires before Set" verification
    // needs spawned waiter tasks (deferred to an SMP/contention
    // test); v0 covers the un-contended branches.
    if (KEventWaitTimed(auto_ev, 5) != KEventWaitResult::Signaled)
    {
        core::Panic("ipc/kevent", "self-test: WaitTimed on signaled auto event did not signal");
    }
    if (auto_ev->signaled)
    {
        core::Panic("ipc/kevent", "self-test: WaitTimed did not consume auto-reset signal");
    }
    if (KEventWaitTimed(auto_ev, 0) != KEventWaitResult::TimedOut)
    {
        core::Panic("ipc/kevent", "self-test: WaitTimed(0) on cleared event did not time out");
    }
    KEventSet(manual);
    if (KEventWaitTimed(manual, 0) != KEventWaitResult::Signaled)
    {
        core::Panic("ipc/kevent", "self-test: WaitTimed(0) on signaled manual event did not signal");
    }
    if (!manual->signaled)
    {
        core::Panic("ipc/kevent", "self-test: manual event cleared after WaitTimed");
    }

    // Round-trip through a HandleTable on the manual-reset event
    // (the auto-reset path has equivalent insert/lookup/remove
    // shape; one round-trip suffices to exercise the IPC layer).
    static HandleTable table{};
    auto insert_r = HandleTableInsert(table, &manual->base, TypeAllowedRights(KObjectType::Event));
    if (!insert_r.has_value())
    {
        core::Panic("ipc/kevent", "self-test: HandleTableInsert failed");
    }
    const Handle h = insert_r.value();
    KObject* looked_up = HandleTableLookupRef(table, h, KObjectType::Event);
    if (looked_up != &manual->base)
    {
        core::Panic("ipc/kevent", "self-test: lookup did not return manual event");
    }
    KObjectRelease(looked_up);
    // Wrong type-tag rejects.
    if (HandleTableLookupRef(table, h, KObjectType::Mutex) != nullptr)
    {
        core::Panic("ipc/kevent", "self-test: lookup with wrong type-tag returned non-null");
    }
    if (!HandleTableRemove(table, h).has_value())
    {
        core::Panic("ipc/kevent", "self-test: HandleTableRemove failed");
    }
    // Auto-reset event isn't in the table; drop its reference
    // explicitly so the destroy fires for symmetry.
    KObjectRelease(&auto_ev->base);

    if (HandleTableLiveCount(table) != 0)
    {
        core::Panic("ipc/kevent", "self-test: live count != 0 at end");
    }

    KLOG_INFO_A(::duetos::core::LogArea::IPC, "ipc/kevent",
                "self-test OK (manual + auto reset, Set/Wait/Reset, HandleTable cycle)");
}

} // namespace duetos::ipc
