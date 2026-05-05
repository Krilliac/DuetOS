/*
 * DuetOS — concrete KMutex implementation, v0 (plan A3-followup).
 *
 * See `kmutex.h` for the public contract. This TU owns:
 *   - kheap-backed allocation + KObjectInit on Create,
 *   - the recursion + ownership state machine,
 *   - the destroy callback that runs on last refcount release,
 *   - a self-test that drives the full HandleTable round-trip.
 *
 * `KObject` MUST be the first member of `KMutex` so a HandleTable
 * lookup that returns `KObject*` can be `reinterpret_cast`'d back
 * to `KMutex*` (and a static_cast through KObject* would break the
 * type system; we deliberately stay in the C-style cast lane that
 * the surrounding KObject ecosystem already uses).
 */

#include "ipc/kmutex.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "sched/sched.h"

#include <stddef.h> // for offsetof

namespace duetos::ipc
{

static_assert(__builtin_offsetof(KMutex, base) == 0, "KObject must be the first member of KMutex");

namespace
{

void KMutexDestroy(KObject* obj)
{
    auto* m = reinterpret_cast<KMutex*>(obj);
    if (m->recursion != 0 || m->owner != nullptr)
    {
        // Reaching refcount=0 with the lock still held means an
        // ABI front-end leaked a release. Debug builds panic so
        // the leak surfaces at the moment of the bug. Release
        // builds log and leak the mutex memory rather than free
        // it from under a thread that still believes it owns the
        // lock — a one-time leak is recoverable; a use-after-free
        // is not.
        core::DebugPanicOrWarn("ipc/kmutex", "destroy on still-held mutex");
        return;
    }
    duetos::mm::KFree(m);
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
    m->created_tick = sched::SchedNowTicks();
    return m;
}

void KMutexAcquire(KMutex* m)
{
    sched::Task* me = sched::CurrentTask();
    // Fast path for re-entrant acquire — same owner, just bump
    // recursion. Read of `owner` is safe outside the inner lock
    // ONLY when `me == owner`, because no other task can mutate
    // the owner field while we hold it. Recursion does NOT take
    // a fresh ref — the holder-ref already counts.
    if (m->owner == me)
    {
        ++m->recursion;
        return;
    }
    // Pin the storage during the wait. If every handle closes
    // while we're blocked, the wait-ref keeps the KMutex alive
    // until we wake; on success the same ref upgrades to the
    // holder-ref so the storage stays alive while we own it.
    KObjectAcquire(&m->base);
    sched::MutexLock(&m->inner);
    m->owner = me;
    m->recursion = 1;
    // Wait-ref retained as holder-ref; no count change.
}

bool KMutexAcquireTimed(KMutex* m, u64 ticks)
{
    sched::Task* me = sched::CurrentTask();
    // Re-entrant acquire bypasses the timeout — a task that
    // already owns the lock cannot block on itself, so the
    // timeout never applies and no fresh ref is taken.
    if (m->owner == me)
    {
        ++m->recursion;
        return true;
    }
    KObjectAcquire(&m->base);
    if (!sched::MutexLockTimed(&m->inner, ticks))
    {
        // Timed out — drop the wait-ref. May trigger destroy if
        // every handle closed while we were blocked AND we were
        // the last waiter; that's the correct outcome.
        KObjectRelease(&m->base);
        return false;
    }
    m->owner = me;
    m->recursion = 1;
    // Wait-ref retained as holder-ref.
    return true;
}

void KMutexRelease(KMutex* m)
{
    sched::Task* me = sched::CurrentTask();
    if (m->owner != me)
    {
        // Debug: panic; release: log and refuse. Decrementing
        // recursion or clearing owner here would corrupt the
        // lock state visible to the real owner.
        core::DebugPanicOrWarn("ipc/kmutex", "release by non-owner");
        return;
    }
    if (m->recursion == 0)
    {
        // Same shape — a double-release in a release build is
        // ignored rather than allowed to wrap the recursion
        // counter into a wedged state.
        core::DebugPanicOrWarn("ipc/kmutex", "release on already-released mutex");
        return;
    }
    --m->recursion;
    if (m->recursion > 0)
    {
        return; // outer holder still owns it
    }
    // Outermost release — clear owner before unlocking so the
    // next acquirer sees a fresh state.
    m->owner = nullptr;
    sched::MutexUnlock(&m->inner);
    // Drop the holder-ref unconditionally. In the no-hand-off
    // case, this may push refcount to zero and fire `KMutexDestroy`
    // (correct: nobody holds and no waiters held a wait-ref).
    // In the hand-off case, the new holder's wait-ref upgraded
    // to their holder-ref inside their `KMutexAcquire` /
    // `KMutexAcquireTimed` success continuation — net refcount
    // unchanged across the transition (we dropped one, they
    // implicitly retained one).
    KObjectRelease(&m->base);
}

sched::Task* KMutexOwner(const KMutex* m)
{
    return m->owner;
}

void KMutexSelfTest()
{
    arch::SerialWrite("[ipc] kmutex self-test: full HandleTable round-trip\n");

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

    // Build a synthetic per-test HandleTable on the boot stack.
    // Static so the SpinLock embedded in HandleTable doesn't sit
    // on a transient stack frame across an internal yield (the
    // table itself never yields, but defensive against future
    // changes).
    static HandleTable table{};
    auto insert_r = HandleTableInsert(table, &m->base);
    if (!insert_r.has_value())
    {
        core::Panic("ipc/kmutex", "self-test: HandleTableInsert failed");
    }
    const Handle h = insert_r.value();
    if (h == kHandleInvalid)
    {
        core::Panic("ipc/kmutex", "self-test: insert returned kHandleInvalid");
    }

    // Refcount unchanged — the table took ownership of the
    // initial reference, no extra acquire performed.
    if (KObjectRefcount(&m->base) != 1)
    {
        core::Panic("ipc/kmutex", "self-test: refcount changed after insert");
    }

    // Lookup with right type-tag should resolve.
    KObject* obj_back = HandleTableLookup(table, h, KObjectType::Mutex);
    if (obj_back != &m->base)
    {
        core::Panic("ipc/kmutex", "self-test: lookup returned wrong KObject");
    }

    // Lookup with wrong type-tag must return nullptr (KObject's
    // type-check, not the table's).
    if (HandleTableLookup(table, h, KObjectType::Event) != nullptr)
    {
        core::Panic("ipc/kmutex", "self-test: lookup with wrong type-tag returned non-null");
    }

    // Cast back through the KObject* and exercise the lock state
    // machine. Acquire then re-acquire then release-twice — the
    // recursion counter should walk 0 → 1 → 2 → 1 → 0 cleanly.
    auto* km = reinterpret_cast<KMutex*>(obj_back);
    KMutexAcquire(km);
    if (km->recursion != 1 || km->owner == nullptr)
    {
        core::Panic("ipc/kmutex", "self-test: state wrong after first acquire");
    }
    KMutexAcquire(km);
    if (km->recursion != 2)
    {
        core::Panic("ipc/kmutex", "self-test: recursion counter did not bump on re-acquire");
    }
    KMutexRelease(km);
    if (km->recursion != 1 || km->owner == nullptr)
    {
        core::Panic("ipc/kmutex", "self-test: outer release dropped owner too early");
    }
    KMutexRelease(km);
    if (km->recursion != 0 || km->owner != nullptr)
    {
        core::Panic("ipc/kmutex", "self-test: final release did not reset state");
    }

    // Timed-acquire fast paths. Re-entrant timed acquire must
    // succeed regardless of the timeout (no self-block). A
    // timed-acquire on an unowned mutex with a non-zero budget
    // must succeed via the fast path. Real contention (waiter
    // taking the timeout vs. an unlock-handoff) is verified by
    // a future SMP/contention test once AP bringup lands; v0
    // exercises the un-contended branches here.
    if (!KMutexAcquireTimed(km, 1))
    {
        core::Panic("ipc/kmutex", "self-test: AcquireTimed(1) on free mutex failed");
    }
    if (km->recursion != 1 || km->owner == nullptr)
    {
        core::Panic("ipc/kmutex", "self-test: AcquireTimed did not stamp owner+recursion");
    }
    if (!KMutexAcquireTimed(km, 0))
    {
        core::Panic("ipc/kmutex", "self-test: re-entrant AcquireTimed(0) failed");
    }
    if (km->recursion != 2)
    {
        core::Panic("ipc/kmutex", "self-test: re-entrant timed acquire did not bump recursion");
    }
    KMutexRelease(km);
    KMutexRelease(km);
    if (km->recursion != 0 || km->owner != nullptr)
    {
        core::Panic("ipc/kmutex", "self-test: timed-acquire release pairs did not reset state");
    }

    // Remove from table — refcount falls to zero, destroy fires,
    // storage is freed. After this point `m` / `km` are dangling.
    auto remove_r = HandleTableRemove(table, h);
    if (!remove_r.has_value())
    {
        core::Panic("ipc/kmutex", "self-test: HandleTableRemove failed");
    }

    // Looking up the now-removed handle returns nullptr.
    if (HandleTableLookup(table, h, KObjectType::Mutex) != nullptr)
    {
        core::Panic("ipc/kmutex", "self-test: lookup after remove returned non-null");
    }

    if (HandleTableLiveCount(table) != 0)
    {
        core::Panic("ipc/kmutex", "self-test: live count != 0 after drain");
    }

    arch::SerialWrite("[ipc] kmutex self-test OK (Create + Insert + Lookup + recursion + Remove + destroy).\n");
}

} // namespace duetos::ipc
