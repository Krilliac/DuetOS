/*
 * DuetOS — concrete, recursive KMutex kernel object.
 *
 * The scheduler owns task lifetime and the FIFO sleeping-mutex state. KMutex
 * adds the user-visible recursive/abandoned contract, object references that
 * span waits and ownership, and an intrusive dead-task ownership receipt.
 */

#include "ipc/kmutex.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "mm/kheap.h"
#include "sched/sched.h"

#include <stddef.h>

namespace duetos::ipc
{

static_assert(__builtin_offsetof(KMutex, base) == 0, "KObject must be the first member of KMutex");

namespace
{

KMutex* KMutexFromOwnershipNode(sched::AbandonableOwnershipNode* node)
{
    return reinterpret_cast<KMutex*>(reinterpret_cast<u8*>(node) - __builtin_offsetof(KMutex, ownership_node));
}

void KMutexAbandonOwnership(sched::AbandonableOwnershipNode* node)
{
    KASSERT(node != nullptr, "ipc/kmutex", "abandon callback received null ownership node");
    KMutex* m = KMutexFromOwnershipNode(node);

    // Publish abandoned state before FIFO hand-off. A successor cannot return
    // from its scheduler wait until MutexAbandon completes the hand-off, so
    // its exchange below necessarily observes this release or a newer one.
    __atomic_store_n(&m->recursion, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&m->owner_tid, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&m->held, false, __ATOMIC_RELEASE);
    __atomic_store_n(&m->abandoned_pending, true, __ATOMIC_RELEASE);

    if (!sched::MutexAbandon(&m->inner))
    {
        // Keep the holder reference on structural inconsistency. A bounded
        // leak is safer than freeing storage an unknown owner may reference.
        core::DebugPanicOrWarn("ipc/kmutex", "dead-owner ledger did not match scheduler mutex owner");
        return;
    }
    KObjectRelease(&m->base);
}

void KMutexDestroy(KObject* obj)
{
    auto* m = reinterpret_cast<KMutex*>(obj);
    if (__atomic_load_n(&m->recursion, __ATOMIC_ACQUIRE) != 0 || __atomic_load_n(&m->held, __ATOMIC_ACQUIRE) ||
        m->ownership_node.owner != nullptr)
    {
        // Never free storage from under a holder or a scheduler ledger node.
        // Debug builds stop at the accounting bug; release builds retain the
        // object as a bounded leak rather than creating a use-after-free.
        core::DebugPanicOrWarn("ipc/kmutex", "destroy on still-held mutex");
        return;
    }
    duetos::mm::KFree(m);
}

struct KMutexAbandonSelfTestContext
{
    KMutex* mutex;
    sched::WaitQueue release_waiters;
    u64 release_sequence;
    bool release_owner;
    u32 owner_state;
};

[[noreturn]] void KMutexAbandonSelfTestOwner(void* opaque)
{
    auto* context = static_cast<KMutexAbandonSelfTestContext*>(opaque);
    KASSERT(context != nullptr && context->mutex != nullptr, "ipc/kmutex", "self-test owner context invalid");

    const KMutexWaitResult result = KMutexAcquire(context->mutex);
    __atomic_store_n(&context->owner_state, result == KMutexWaitResult::Acquired ? 1u : 2u, __ATOMIC_RELEASE);
    if (result != KMutexWaitResult::Acquired)
    {
        sched::SchedExit();
    }

    // Keep a live kernel Task owning the KMutex long enough for the
    // coordinator to prove process-null public cancellation is rejected.
    // Exit deliberately omits KMutexRelease: the reaper must publish exactly
    // one abandoned result and hand the inner FIFO mutex to the waiter.
    while (!__atomic_load_n(&context->release_owner, __ATOMIC_ACQUIRE))
    {
        const u64 observed = __atomic_load_n(&context->release_sequence, __ATOMIC_ACQUIRE);
        if (__atomic_load_n(&context->release_owner, __ATOMIC_ACQUIRE))
            break;
        (void)sched::WaitQueueBlockIfSequenceUnchanged(&context->release_waiters, &context->release_sequence, observed);
    }
    sched::SchedExit();
}

KMutexWaitResult KMutexAcquireImpl(KMutex* m, bool timed, u64 ticks)
{
    if (m == nullptr)
    {
        return KMutexWaitResult::Failed;
    }

    const u64 current_tid = sched::CurrentTaskId();
    if (current_tid == ~u64{0})
    {
        return KMutexWaitResult::Failed;
    }
    if (__atomic_load_n(&m->held, __ATOMIC_ACQUIRE) && __atomic_load_n(&m->owner_tid, __ATOMIC_RELAXED) == current_tid)
    {
        const u32 recursion = __atomic_load_n(&m->recursion, __ATOMIC_RELAXED);
        if (recursion == ~u32{0})
        {
            core::DebugPanicOrWarn("ipc/kmutex", "recursion counter saturated");
            return KMutexWaitResult::Failed;
        }
        __atomic_store_n(&m->recursion, recursion + 1, __ATOMIC_RELAXED);
        return KMutexWaitResult::Acquired;
    }

    // This reference spans the complete cancellable block. Only success
    // retains it as the holder reference; every other explicit result drops
    // it before returning to the ABI dispatcher.
    if (!KObjectAcquire(&m->base))
    {
        return KMutexWaitResult::Failed;
    }

    const sched::MutexAcquireResult acquire_result =
        timed ? sched::MutexLockTimedCancellable(&m->inner, ticks) : sched::MutexLockCancellable(&m->inner);
    if (acquire_result == sched::MutexAcquireResult::TimedOut)
    {
        KObjectRelease(&m->base);
        return KMutexWaitResult::TimedOut;
    }
    if (acquire_result == sched::MutexAcquireResult::Cancelled)
    {
        KObjectRelease(&m->base);
        return KMutexWaitResult::Cancelled;
    }
    if (acquire_result != sched::MutexAcquireResult::Acquired)
    {
        KObjectRelease(&m->base);
        return KMutexWaitResult::Failed;
    }

    __atomic_store_n(&m->recursion, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&m->owner_tid, current_tid, __ATOMIC_RELAXED);
    __atomic_store_n(&m->held, true, __ATOMIC_RELEASE);
    if (!sched::SchedTrackCurrentAbandonableOwnership(&m->ownership_node))
    {
        __atomic_store_n(&m->recursion, 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&m->owner_tid, 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&m->held, false, __ATOMIC_RELEASE);
        sched::MutexUnlock(&m->inner);
        KObjectRelease(&m->base);
        return KMutexWaitResult::Failed;
    }

    if (__atomic_exchange_n(&m->abandoned_pending, false, __ATOMIC_ACQ_REL))
    {
        return KMutexWaitResult::Abandoned;
    }
    return KMutexWaitResult::Acquired;
}

} // namespace

::duetos::core::Result<KMutex*> KMutexCreate()
{
    auto* m = static_cast<KMutex*>(duetos::mm::KMalloc(sizeof(KMutex)));
    if (m == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *m = KMutex{};
    KObjectInit(&m->base, KObjectType::Mutex, &KMutexDestroy);
    m->inner.ownership_class = sched::Mutex::OwnershipClass::AbandonableUserWaitable;
    m->ownership_node.abandon = &KMutexAbandonOwnership;
    m->created_tick = sched::SchedNowTicks();
    return m;
}

KMutexWaitResult KMutexAcquire(KMutex* m)
{
    return KMutexAcquireImpl(m, false, 0);
}

KMutexWaitResult KMutexAcquireTimed(KMutex* m, u64 ticks)
{
    return KMutexAcquireImpl(m, true, ticks);
}

bool KMutexRelease(KMutex* m)
{
    if (m == nullptr || !__atomic_load_n(&m->held, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&m->owner_tid, __ATOMIC_RELAXED) != sched::CurrentTaskId())
    {
        return false;
    }

    const u32 recursion = __atomic_load_n(&m->recursion, __ATOMIC_RELAXED);
    if (recursion == 0)
    {
        return false;
    }
    if (recursion > 1)
    {
        __atomic_store_n(&m->recursion, recursion - 1, __ATOMIC_RELAXED);
        return true;
    }

    // The scheduler verifies and unlinks the exact current Task identity in
    // one lock transaction. Only then may public state clear and FIFO hand-
    // off make the next waiter runnable.
    if (!sched::SchedUntrackCurrentAbandonableOwnership(&m->ownership_node))
    {
        return false;
    }
    __atomic_store_n(&m->recursion, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&m->owner_tid, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&m->held, false, __ATOMIC_RELEASE);
    sched::MutexUnlock(&m->inner);
    KObjectRelease(&m->base);
    return true;
}

bool KMutexHeld(const KMutex* m)
{
    return m != nullptr && __atomic_load_n(&m->held, __ATOMIC_ACQUIRE);
}

u64 KMutexOwnerTid(const KMutex* m)
{
    return m != nullptr ? __atomic_load_n(&m->owner_tid, __ATOMIC_ACQUIRE) : 0;
}

void KMutexSelfTest()
{
    arch::SerialWrite("[ipc] kmutex self-test: HandleTable + recursion + cancellation + abandonment\n");

    auto create_r = KMutexCreate();
    if (!create_r.has_value())
    {
        core::Panic("ipc/kmutex", "self-test: KMutexCreate failed");
    }
    KMutex* m = create_r.value();
    if (KObjectRefcount(&m->base) != 1)
    {
        core::Panic("ipc/kmutex", "self-test: post-create refcount != 1");
    }

    static HandleTable table{};
    auto insert_r = HandleTableInsert(table, &m->base, TypeAllowedRights(KObjectType::Mutex));
    if (!insert_r.has_value() || insert_r.value() == kHandleInvalid)
    {
        core::Panic("ipc/kmutex", "self-test: HandleTableInsert failed");
    }
    const Handle h = insert_r.value();
    KObject* obj_back = HandleTableLookupRef(table, h, KObjectType::Mutex);
    if (obj_back != &m->base)
    {
        core::Panic("ipc/kmutex", "self-test: lookup returned wrong KObject");
    }
    if (HandleTableLookupRef(table, h, KObjectType::Event) != nullptr)
    {
        core::Panic("ipc/kmutex", "self-test: wrong-type lookup succeeded");
    }

    auto* km = reinterpret_cast<KMutex*>(obj_back);
    if (KMutexAcquire(km) != KMutexWaitResult::Acquired || !KMutexHeld(km) ||
        __atomic_load_n(&km->recursion, __ATOMIC_RELAXED) != 1)
    {
        core::Panic("ipc/kmutex", "self-test: first acquire failed");
    }
    if (KMutexAcquire(km) != KMutexWaitResult::Acquired || __atomic_load_n(&km->recursion, __ATOMIC_RELAXED) != 2)
    {
        core::Panic("ipc/kmutex", "self-test: recursive acquire failed");
    }
    if (!KMutexRelease(km) || __atomic_load_n(&km->recursion, __ATOMIC_RELAXED) != 1 || !KMutexRelease(km) ||
        KMutexHeld(km))
    {
        core::Panic("ipc/kmutex", "self-test: recursive release failed");
    }

    if (KMutexAcquireTimed(km, 1) != KMutexWaitResult::Acquired ||
        KMutexAcquireTimed(km, 0) != KMutexWaitResult::Acquired ||
        __atomic_load_n(&km->recursion, __ATOMIC_RELAXED) != 2)
    {
        core::Panic("ipc/kmutex", "self-test: timed/re-entrant acquire failed");
    }
    if (!KMutexRelease(km) || !KMutexRelease(km) || KMutexHeld(km))
    {
        core::Panic("ipc/kmutex", "self-test: timed acquire release failed");
    }

    KMutexAbandonSelfTestContext abandon_context{};
    abandon_context.mutex = km;
    const sched::TaskCreateResult owner =
        sched::SchedCreate(&KMutexAbandonSelfTestOwner, &abandon_context, "kmutex-abandon-owner");
    if (!owner.created)
    {
        core::Panic("ipc/kmutex", "self-test: failed to create abandonment owner");
    }

    u32 owner_wait_budget = 10000;
    while (__atomic_load_n(&abandon_context.owner_state, __ATOMIC_ACQUIRE) == 0 && owner_wait_budget-- != 0)
    {
        sched::SchedYield();
    }
    if (__atomic_load_n(&abandon_context.owner_state, __ATOMIC_ACQUIRE) != 1)
    {
        core::Panic("ipc/kmutex", "self-test: abandonment owner did not acquire");
    }
    if (sched::SchedKillByPid(owner.tid) != sched::KillResult::Protected)
    {
        core::Panic("ipc/kmutex", "self-test: public kill accepted a kernel Task");
    }

    __atomic_store_n(&abandon_context.release_owner, true, __ATOMIC_RELEASE);
    __atomic_fetch_add(&abandon_context.release_sequence, 1u, __ATOMIC_RELEASE);
    sched::WaitQueueWakeAll(&abandon_context.release_waiters);

    if (KMutexAcquireTimed(km, 100) != KMutexWaitResult::Abandoned)
    {
        core::Panic("ipc/kmutex", "self-test: dead owner did not publish abandonment");
    }
    if (!KMutexRelease(km) || KMutexHeld(km))
    {
        core::Panic("ipc/kmutex", "self-test: abandoned successor release failed");
    }
    if (KMutexAcquireTimed(km, 0) != KMutexWaitResult::Acquired || !KMutexRelease(km))
    {
        core::Panic("ipc/kmutex", "self-test: abandoned state was not consumed exactly once");
    }

    KObjectRelease(obj_back);
    auto remove_r = HandleTableRemove(table, h);
    if (!remove_r.has_value() || HandleTableLookupRef(table, h, KObjectType::Mutex) != nullptr ||
        HandleTableLiveCount(table) != 0)
    {
        core::Panic("ipc/kmutex", "self-test: table drain failed");
    }

    arch::SerialWrite("[ipc] kmutex self-test OK (kernel kill protected + WAIT_ABANDONED hand-off)\n");
}

} // namespace duetos::ipc
