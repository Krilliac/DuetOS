#include "sync/adaptive_mutex.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "sched/sched.h"
#include "sync/lockdep.h"

namespace duetos::sync
{

namespace
{

[[noreturn]] void PanicAdaptive(const char* message)
{
    core::Panic("sync/adaptive-mutex", message);
}

void PublishOwner(AdaptiveMutex& m, u64 owner_id)
{
    bool inconsistent = false;
    const IrqFlags flags = SpinLockAcquire(m.m_publication_lock);
    if (m.m_published_held)
    {
        inconsistent = true;
    }
    else
    {
        m.m_published_owner_id = owner_id;
        m.m_published_held = true;
    }
    SpinLockRelease(m.m_publication_lock, flags);

    if (inconsistent)
    {
        PanicAdaptive("published owner already set after scheduler acquire");
    }
}

} // namespace

void AdaptiveMutexLock(AdaptiveMutex& m)
{
    // TPM initialization runs before SchedInit while the BSP is the only
    // possible caller. Do not ask sched::Mutex to install a null Task owner;
    // make that single-threaded bootstrap exception explicit instead.
    if (sched::CurrentTask() == nullptr)
    {
        return;
    }
    sched::MutexLock(&m.m_mutex);
    PublishOwner(m, sched::CurrentTaskId());
}

void AdaptiveMutexUnlock(AdaptiveMutex& m)
{
    if (sched::CurrentTask() == nullptr)
    {
        return;
    }

    const u64 current_id = sched::CurrentTaskId();
    const IrqFlags flags = SpinLockAcquire(m.m_publication_lock);
    if (!m.m_published_held || m.m_published_owner_id != current_id)
    {
        SpinLockRelease(m.m_publication_lock, flags);
        // Preserve sched::Mutex's non-owner diagnostic without corrupting the
        // published state that belongs to the real holder.
        sched::MutexUnlock(&m.m_mutex);
        return;
    }

    // Keep the publication lock across direct hand-off. A woken successor can
    // own the scheduler mutex on another CPU, but its AdaptiveMutexLock cannot
    // publish until this releaser clears the previous public owner.
    sched::MutexUnlock(&m.m_mutex);
    m.m_published_owner_id = 0;
    m.m_published_held = false;
    SpinLockRelease(m.m_publication_lock, flags);
}

bool AdaptiveMutexTryLock(AdaptiveMutex& m)
{
    if (sched::CurrentTask() == nullptr)
    {
        // The pre-scheduler BSP has no contender; model the explicit
        // bootstrap no-op Lock contract as a successful try-acquire.
        return true;
    }
    if (!sched::MutexTryLock(&m.m_mutex))
    {
        return false;
    }
    PublishOwner(m, sched::CurrentTaskId());
    return true;
}

bool AdaptiveMutexIsHeld(const AdaptiveMutex& m)
{
    if (sched::CurrentTask() == nullptr)
    {
        // Bootstrap Lock/Unlock are explicit no-ops, so there is no published
        // owner to observe before SchedInit.
        return false;
    }

    AdaptiveMutex& mutable_mutex = const_cast<AdaptiveMutex&>(m);
    const IrqFlags flags = SpinLockAcquire(mutable_mutex.m_publication_lock);
    const bool held = mutable_mutex.m_published_held;
    SpinLockRelease(mutable_mutex.m_publication_lock, flags);
    return held;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace
{

AdaptiveMutex g_st_mutex;
volatile u32 g_st_owner_acquired = 0;
volatile u32 g_st_allow_owner_release = 0;
volatile u32 g_st_owner_releasing = 0;
volatile u32 g_st_contender_acquired = 0;
volatile u32 g_st_contender_completed = 0;

void ContentionOwnerWorker(void*)
{
    AdaptiveMutexLock(g_st_mutex);
    __atomic_store_n(&g_st_owner_acquired, 1u, __ATOMIC_RELEASE);

    // Keep ownership until the coordinator has observed the contender in
    // TaskState::Blocked. This makes the hand-off test deterministic even on
    // an SMP boot with unrelated Normal tasks competing for run slots.
    while (__atomic_load_n(&g_st_allow_owner_release, __ATOMIC_ACQUIRE) == 0)
    {
        sched::SchedSleepTicks(1);
    }

    __atomic_store_n(&g_st_owner_releasing, 1u, __ATOMIC_RELEASE);
    AdaptiveMutexUnlock(g_st_mutex);
}

void ContentionContenderWorker(void*)
{
    AdaptiveMutexLock(g_st_mutex);
    __atomic_store_n(&g_st_contender_acquired, 1u, __ATOMIC_RELEASE);
    AdaptiveMutexUnlock(g_st_mutex);
    // Publish completion only after releasing. Publishing the acquired flag
    // first is intentional coverage that the critical section ran, but it is
    // not a safe oracle for the coordinator's final unheld assertion on SMP.
    __atomic_store_n(&g_st_contender_completed, 1u, __ATOMIC_RELEASE);
}

} // namespace

void AdaptiveMutexSelfTest()
{
    arch::SerialWrite("[adaptive-mutex] self-test: scheduler delegation + trylock + lockdep + contention\n");

    // (1) Uncontended Lock + Unlock.
    {
        AdaptiveMutex m{};
        if (AdaptiveMutexIsHeld(m))
        {
            PanicAdaptive("self-test: fresh mutex not zero-initialized");
        }
        AdaptiveMutexLock(m);
        if (!AdaptiveMutexIsHeld(m))
        {
            PanicAdaptive("self-test: Lock did not mark mutex held");
        }
        AdaptiveMutexUnlock(m);
        if (AdaptiveMutexIsHeld(m))
        {
            PanicAdaptive("self-test: Unlock did not clear owner");
        }
    }

    // (2) TryLock succeeds only while free.
    {
        AdaptiveMutex m{};
        if (!AdaptiveMutexTryLock(m))
        {
            PanicAdaptive("self-test: TryLock failed on unheld mutex");
        }
        if (!AdaptiveMutexIsHeld(m))
        {
            PanicAdaptive("self-test: TryLock did not mark mutex held");
        }
        if (AdaptiveMutexTryLock(m))
        {
            PanicAdaptive("self-test: TryLock succeeded on self-held mutex");
        }
        AdaptiveMutexUnlock(m);
        if (!AdaptiveMutexTryLock(m))
        {
            PanicAdaptive("self-test: TryLock failed after release");
        }
        AdaptiveMutexUnlock(m);
    }

    // (3) Lockdep class is carried by the single scheduler mutex state.
    {
        AdaptiveMutex untagged{};
        untagged.m_mutex.class_id = kLockClassUnclassified;
        AdaptiveMutexLock(untagged);
        AdaptiveMutexUnlock(untagged);

        AdaptiveMutex tagged{};
        tagged.m_mutex.class_id = kLockClassKObject;
        LockClass scratch[kLockdepHeldMax];
        const u32 before = LockdepHeldSnapshot(scratch, kLockdepHeldMax);
        AdaptiveMutexLock(tagged);
        const u32 during = LockdepHeldSnapshot(scratch, kLockdepHeldMax);
        if (during != before + 1)
        {
            PanicAdaptive("self-test: lockdep held depth did not climb on Lock");
        }
        AdaptiveMutexUnlock(tagged);
        const u32 after = LockdepHeldSnapshot(scratch, kLockdepHeldMax);
        if (after != before)
        {
            PanicAdaptive("self-test: lockdep held depth did not fall on Unlock");
        }
    }

    // (4) Owner sleeps while holding the lock; the contender must block,
    // receive FIFO ownership hand-off, and release it.
    if (AdaptiveMutexIsHeld(g_st_mutex))
    {
        PanicAdaptive("self-test: global contention mutex not fresh");
    }
    g_st_owner_acquired = 0;
    g_st_allow_owner_release = 0;
    g_st_owner_releasing = 0;
    g_st_contender_acquired = 0;
    g_st_contender_completed = 0;

    const sched::TaskCreateResult owner = sched::SchedCreate(ContentionOwnerWorker, nullptr, "amx-st-owner");
    if (!owner.created)
    {
        PanicAdaptive("self-test: failed to create contention owner");
    }

    // A fixed number of yields is not a join: on SMP, another Normal task may
    // win each slot. Poll with the same bounded tick budget used below.
    for (u32 i = 0; i < 200; ++i)
    {
        if (__atomic_load_n(&g_st_owner_acquired, __ATOMIC_ACQUIRE) != 0)
        {
            break;
        }
        sched::SchedSleepTicks(1);
    }

    if (__atomic_load_n(&g_st_owner_acquired, __ATOMIC_ACQUIRE) == 0)
    {
        PanicAdaptive("self-test: contention owner never acquired the mutex");
    }

    // SchedSnapshotBlockedTasks reserves block_start_tick==0 for non-wait
    // suspension. Ensure the real mutex wait below starts on a non-zero tick.
    if (sched::SchedNowTicks() == 0)
    {
        sched::SchedSleepTicks(1);
    }

    const sched::TaskCreateResult contender =
        sched::SchedCreate(ContentionContenderWorker, nullptr, "amx-st-contender");
    if (!contender.created)
    {
        PanicAdaptive("self-test: failed to create contention contender");
    }

    // Wait for an exact scheduler snapshot showing that the contender reached
    // the mutex wait queue. Releasing merely after its entry function starts
    // would retain a store-before-enqueue race and sometimes exercise only the
    // uncontended path.
    const u64 contender_id = contender.tid;
    bool contender_blocked = false;
    for (u32 i = 0; i < 200 && !contender_blocked; ++i)
    {
        sched::SchedBlockedTaskInfo blocked[64];
        const u64 count = sched::SchedSnapshotBlockedTasks(blocked, 64);
        for (u64 j = 0; j < count; ++j)
        {
            if (blocked[j].id == contender_id)
            {
                contender_blocked = true;
                break;
            }
        }
        if (!contender_blocked)
        {
            sched::SchedSleepTicks(1);
        }
    }
    if (!contender_blocked)
    {
        PanicAdaptive("self-test: contender never blocked on scheduler mutex");
    }

    __atomic_store_n(&g_st_allow_owner_release, 1u, __ATOMIC_RELEASE);
    for (u32 i = 0; i < 200; ++i)
    {
        if (__atomic_load_n(&g_st_contender_completed, __ATOMIC_ACQUIRE) != 0)
        {
            break;
        }
        sched::SchedSleepTicks(1);
    }

    if (__atomic_load_n(&g_st_contender_acquired, __ATOMIC_ACQUIRE) == 0)
    {
        PanicAdaptive("self-test: contender never resumed through direct hand-off");
    }
    if (__atomic_load_n(&g_st_contender_completed, __ATOMIC_ACQUIRE) == 0)
    {
        PanicAdaptive("self-test: contender did not release the mutex");
    }
    if (__atomic_load_n(&g_st_owner_releasing, __ATOMIC_ACQUIRE) == 0)
    {
        PanicAdaptive("self-test: owner never reached release");
    }
    if (AdaptiveMutexIsHeld(g_st_mutex))
    {
        PanicAdaptive("self-test: contention mutex left held");
    }

    arch::SerialWrite("[adaptive-mutex] self-test OK (scheduler mutex ownership + FIFO hand-off)\n");
}

} // namespace duetos::sync
