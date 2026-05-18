/*
 * DuetOS — concrete KWaitable implementation, v0 (plan A3-followup).
 *
 * See `kwaitable.h` for the public contract. This TU owns:
 *   - kheap-backed allocation + KObjectInit on Create,
 *   - the predicate table (fixed-capacity, no resizing),
 *   - the wait/signal state machine (mutex + condvar),
 *   - the destroy callback,
 *   - a self-test that drives the predicate-table + wait-for-any
 *     fast paths without spawning waiter contention.
 */

#include "ipc/kwaitable.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "mm/kheap.h"
#include "sched/sched.h"

#include <stddef.h>

namespace duetos::ipc
{

static_assert(__builtin_offsetof(KWaitable, base) == 0, "KObject must be the first member of KWaitable");

namespace
{

void KWaitableDestroy(KObject* obj)
{
    auto* w = reinterpret_cast<KWaitable*>(obj);
    duetos::mm::KFree(w);
}

} // namespace

::duetos::core::Result<KWaitable*> KWaitableCreate()
{
    auto* w = static_cast<KWaitable*>(duetos::mm::KMalloc(sizeof(KWaitable)));
    if (w == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *w = KWaitable{};
    KObjectInit(&w->base, KObjectType::Waitable, &KWaitableDestroy);
    return w;
}

::duetos::core::Result<u32> KWaitableAddPredicate(KWaitable* w, KWaitablePredicate fn, void* arg)
{
    if (fn == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    sched::MutexLock(&w->inner);
    if (w->pred_count >= kWaitableMaxPredicates)
    {
        sched::MutexUnlock(&w->inner);
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    const u32 idx = w->pred_count;
    w->preds[idx] = {fn, arg};
    ++w->pred_count;
    sched::MutexUnlock(&w->inner);
    return idx;
}

u32 KWaitableWaitForAny(KWaitable* w)
{
    // Pin during the blocking wait so closing every handle while a
    // waiter is parked on the condvar cannot run KWaitableDestroy
    // and free w out from under us. Same pattern as
    // KEventWait/KMailboxReceive.
    KObjectAcquire(&w->base);
    sched::MutexLock(&w->inner);
    while (true)
    {
        // Lowest-index-wins iteration so a deterministic order is
        // observable to callers (matches Win32 WaitForMultiple's
        // documented "wait_object_0 + first ready" semantics).
        for (u32 i = 0; i < w->pred_count; ++i)
        {
            // Predicate runs UNDER the inner mutex. The contract
            // is documented in the header — the predicate must
            // not acquire any lock held by a Signal caller.
            if (w->preds[i].fn(w->preds[i].arg))
            {
                sched::MutexUnlock(&w->inner);
                KObjectRelease(&w->base);
                return i;
            }
        }
        sched::CondvarWait(&w->cv, &w->inner);
    }
}

void KWaitableSignal(KWaitable* w)
{
    sched::MutexLock(&w->inner);
    sched::CondvarBroadcast(&w->cv);
    sched::MutexUnlock(&w->inner);
}

u32 KWaitablePredicateCount(const KWaitable* w)
{
    return w->pred_count;
}

namespace
{

// Self-test fixtures — file-scope so the predicate functions can
// reach them. Each "predicate" is just "is this flag non-zero".
constinit u64 g_test_flag_a = 0;
constinit u64 g_test_flag_b = 0;

bool TestPredicateA(void*)
{
    return g_test_flag_a != 0;
}
bool TestPredicateB(void*)
{
    return g_test_flag_b != 0;
}

bool TestPredicateAlwaysFalse(void*)
{
    return false;
}

} // namespace

void KWaitableSelfTest()
{
    arch::SerialWrite("[ipc] kwaitable self-test: predicate table + wait-for-any state machine\n");

    auto create_r = KWaitableCreate();
    if (!create_r.has_value())
    {
        core::Panic("ipc/kwaitable", "self-test: KWaitableCreate failed");
    }
    KWaitable* w = create_r.value();
    if (KWaitablePredicateCount(w) != 0)
    {
        core::Panic("ipc/kwaitable", "self-test: fresh waitable predicate count != 0");
    }

    // Bad-arg: null fn returns InvalidArgument without inserting.
    if (KWaitableAddPredicate(w, nullptr, nullptr).has_value())
    {
        core::Panic("ipc/kwaitable", "self-test: null-fn predicate accepted");
    }
    if (KWaitablePredicateCount(w) != 0)
    {
        core::Panic("ipc/kwaitable", "self-test: predicate count changed after rejected add");
    }

    // Reset the test flags before registering predicates against
    // them.
    g_test_flag_a = 0;
    g_test_flag_b = 0;

    auto idx_a = KWaitableAddPredicate(w, &TestPredicateA, nullptr);
    auto idx_b = KWaitableAddPredicate(w, &TestPredicateB, nullptr);
    if (!idx_a.has_value() || idx_a.value() != 0)
    {
        core::Panic("ipc/kwaitable", "self-test: predicate A index != 0");
    }
    if (!idx_b.has_value() || idx_b.value() != 1)
    {
        core::Panic("ipc/kwaitable", "self-test: predicate B index != 1");
    }
    if (KWaitablePredicateCount(w) != 2)
    {
        core::Panic("ipc/kwaitable", "self-test: predicate count != 2 after two adds");
    }

    // Set flag B only — wait should return 1 immediately (no
    // condvar wait needed, predicate is already true).
    g_test_flag_b = 1;
    const u32 got1 = KWaitableWaitForAny(w);
    if (got1 != 1)
    {
        core::Panic("ipc/kwaitable", "self-test: wait did not return predicate-B index");
    }

    // Set both flags — wait returns lowest index (0 for A).
    g_test_flag_a = 1;
    g_test_flag_b = 1;
    const u32 got2 = KWaitableWaitForAny(w);
    if (got2 != 0)
    {
        core::Panic("ipc/kwaitable", "self-test: wait did not pick lowest-index when both ready");
    }

    // Reset and re-check predicate B alone.
    g_test_flag_a = 0;
    g_test_flag_b = 1;
    const u32 got3 = KWaitableWaitForAny(w);
    if (got3 != 1)
    {
        core::Panic("ipc/kwaitable", "self-test: wait did not re-pick B after A cleared");
    }

    // Reset state for the table-full path. We can't fill the
    // existing waitable past kWaitableMaxPredicates (two slots
    // already used), but we CAN test the bound with a fresh one.
    auto create2_r = KWaitableCreate();
    if (!create2_r.has_value())
    {
        core::Panic("ipc/kwaitable", "self-test: second KWaitableCreate failed");
    }
    KWaitable* w2 = create2_r.value();
    for (u32 i = 0; i < kWaitableMaxPredicates; ++i)
    {
        if (!KWaitableAddPredicate(w2, &TestPredicateAlwaysFalse, nullptr).has_value())
        {
            core::Panic("ipc/kwaitable", "self-test: capacity-fill rejected before max");
        }
    }
    auto over_r = KWaitableAddPredicate(w2, &TestPredicateAlwaysFalse, nullptr);
    if (over_r.has_value())
    {
        core::Panic("ipc/kwaitable", "self-test: over-capacity add accepted");
    }
    if (over_r.error() != ::duetos::core::ErrorCode::OutOfMemory)
    {
        core::Panic("ipc/kwaitable", "self-test: over-capacity add wrong error");
    }
    KObjectRelease(&w2->base);

    // HandleTable round-trip on the original waitable.
    static HandleTable table{};
    auto insert_r = HandleTableInsert(table, &w->base);
    if (!insert_r.has_value())
    {
        core::Panic("ipc/kwaitable", "self-test: HandleTableInsert failed");
    }
    const Handle h = insert_r.value();
    if (HandleTableLookup(table, h, KObjectType::Waitable) != &w->base)
    {
        core::Panic("ipc/kwaitable", "self-test: lookup did not return waitable");
    }
    if (HandleTableLookup(table, h, KObjectType::Mutex) != nullptr)
    {
        core::Panic("ipc/kwaitable", "self-test: lookup with wrong type-tag returned non-null");
    }
    if (!HandleTableRemove(table, h).has_value())
    {
        core::Panic("ipc/kwaitable", "self-test: HandleTableRemove failed");
    }
    if (HandleTableLiveCount(table) != 0)
    {
        core::Panic("ipc/kwaitable", "self-test: live count != 0 at end");
    }

    // Reset test flags so a future caller starts clean.
    g_test_flag_a = 0;
    g_test_flag_b = 0;

    arch::SerialWrite(
        "[ipc] kwaitable self-test OK (predicate table + wait-for-any + lowest-index + HandleTable cycle).\n");
}

} // namespace duetos::ipc
