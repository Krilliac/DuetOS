#include "sync/adaptive_mutex.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "sched/sched.h"
#include "sync/lockdep.h"

/*
 * Adaptive-mutex implementation. See `sync/adaptive_mutex.h` for the
 * full design contract; this TU is the spin-then-park slow path and
 * its lockdep + diagnostic plumbing.
 *
 * Concurrency invariants:
 *   - `m_owner` is the only field on the hot fast path. CAS from
 *     nullptr to `CurrentTask()` claims the lock atomically.
 *   - The wait queue is mediated by `sched::WaitQueueBlock` /
 *     `sched::WaitQueueWakeOne`, which themselves take
 *     `g_sched_lock`. Adaptive mutex does not own a private lock
 *     — the sched lock is what serialises the park/wake transition.
 *   - The spin loop never holds `g_sched_lock`. Spinning under that
 *     lock would deadlock the holder's own Unlock (which must take
 *     the same lock to wake us).
 *   - Self-deadlock guard mirrors `sched::MutexLock`: a non-null
 *     owner equal to the running task means the caller already
 *     holds it — recursion is unsupported.
 */

namespace duetos::sync
{

namespace
{

[[noreturn]] void PanicAdaptive(const char* message)
{
    core::Panic("sync/adaptive-mutex", message);
}

// Read the owner with __ATOMIC_ACQUIRE so the spin loop sees a
// consistent value with the rest of the holder's state. The holder
// installs itself with the same CAS that performs the acquire; a
// later read here pairs with that CAS.
inline sched::Task* LoadOwner(const AdaptiveMutex& m)
{
    return __atomic_load_n(&const_cast<AdaptiveMutex&>(m).m_owner, __ATOMIC_ACQUIRE);
}

// CAS from nullptr → me. Returns true on win. ACQUIRE on success so
// the caller's read of the critical-section state happens-after the
// previous holder's RELEASE-store on Unlock. RELAXED on failure —
// the caller's next move is either to retry or to enter the slow
// path, both of which will re-load owner anyway.
inline bool TryClaim(AdaptiveMutex& m, sched::Task* me)
{
    sched::Task* expected = nullptr;
    return __atomic_compare_exchange_n(&m.m_owner, &expected, me,
                                       /*weak=*/false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

} // namespace

void AdaptiveMutexLock(AdaptiveMutex& m)
{
    sched::Task* me = sched::CurrentTask();

    // Lockdep edge-walk BEFORE the CAS. Mirrors `sched::MutexLock`
    // — the "held → this" edge is recorded against any tagged lock
    // this task already holds. Untagged adaptive mutexes
    // (class_id == kLockClassUnclassified) short-circuit inside
    // the hook for a single compare-and-skip.
    LockdepBeforeAcquire(m.m_class_id);

    // Self-deadlock guard. Predicate: non-null owner equal to me.
    // Mirrors sched::Mutex; the nullptr disjunct in the predicate
    // is load-bearing because early-boot Current() can be nullptr
    // and an unheld mutex's owner is also nullptr — we must not
    // panic on `nullptr == nullptr`.
    sched::Task* observed = LoadOwner(m);
    if (me != nullptr && observed == me)
    {
        PanicAdaptive("self-deadlock: AdaptiveMutexLock of a mutex this task already owns");
    }

    // Fast path. If the owner is null, CAS-claim. On a single
    // attempt the typical uncontested case takes this branch and
    // returns without touching the wait queue.
    if (observed == nullptr && TryClaim(m, me))
    {
        LockdepAfterAcquire(m.m_class_id);
        return;
    }

    // Slow path. Loop: spin while the holder is on-CPU (release
    // imminent), park if the holder is off-CPU (no point in burning
    // cycles waiting for a reschedule). Re-CAS on every iteration
    // so a release we observe by the holder's `on_cpu` flip
    // immediately becomes our win.
    for (;;)
    {
        // Re-read the owner. The fast-path CAS may have lost to a
        // peer between our initial load and here, so always
        // re-derive the holder before deciding spin vs park.
        sched::Task* holder = LoadOwner(m);
        if (holder == nullptr)
        {
            // Owner cleared between us and here. Race for it.
            if (TryClaim(m, me))
            {
                LockdepAfterAcquire(m.m_class_id);
                return;
            }
            // Lost the CAS to another contender. Loop and re-read.
            continue;
        }

        // Adaptive spin. Pause-spaced, capped at kAdaptiveSpinLimit.
        // The cap is the safety net against a holder stuck in a
        // long critical section: better to park than to burn the
        // whole timeslice on a peer CPU. `TaskIsDead` handles the
        // pathological "owner died while holding" case — we never
        // want to spin forever on a corpse.
        u32 spins = 0;
        while (spins < kAdaptiveSpinLimit && sched::TaskIsOnCpu(holder) && !sched::TaskIsDead(holder))
        {
            asm volatile("pause" ::: "memory");

            // Cheap mid-spin claim attempt: if the holder released
            // while we were spinning, the next iteration's CAS
            // wins immediately instead of waiting for the on_cpu
            // flip we are watching. The compiler hoists the load
            // either way; the explicit CAS lets us short-circuit.
            if (LoadOwner(m) == nullptr && TryClaim(m, me))
            {
                LockdepAfterAcquire(m.m_class_id);
                return;
            }
            ++spins;
        }

        // Either the holder went off-CPU, or we exhausted the spin
        // cap. Park on the wait queue. WaitQueueBlock takes
        // g_sched_lock + flips this task's state to Blocked +
        // hands the lock off across ContextSwitch. We come back
        // here when AdaptiveMutexUnlock's WaitQueueWakeOne picks
        // us off the queue.
        //
        // Race window: between our decision to park and
        // WaitQueueBlock acquiring g_sched_lock, the holder may
        // already have called Unlock — which wakes ONE waiter, and
        // it could be a task that parked earlier. That's fine: the
        // owner is now nullptr (or briefly held by the woken
        // waiter), the next loop iteration's CAS will either win
        // (free) or re-spin (newly held by someone running). The
        // only thing we cannot allow is "park forever after the
        // last unlock" — which would happen if Unlock observed an
        // empty queue between our park decision and our actual
        // enqueue. WaitQueueBlock + WaitQueueWakeOne share
        // g_sched_lock, so by the time we are on the queue, any
        // subsequent Unlock will see us.
        //
        // What if Unlock fired BEFORE we entered the queue? Then
        // owner == nullptr right now; the recheck below catches
        // it without parking, identical to the standard
        // condition-variable "check, then block" race-close
        // pattern.
        arch::Cli();
        if (LoadOwner(m) == nullptr)
        {
            // Owner released between the spin and the would-be
            // park. Re-enable IRQs, retry the CAS. Avoids parking
            // on a queue nobody is going to wake.
            arch::Sti();
            continue;
        }
        sched::WaitQueueBlock(&m.m_waiters);
        // WaitQueueBlock returns with IRQs still disabled — the
        // sched-lock RELEASE inside SchedFinishTaskSwitch restores
        // the rflags it captured at the matching SpinLockAcquire,
        // which was the state right after our Cli() above. Re-enable
        // them so the loop's next iteration (CAS attempt / spin) can
        // observe ticks and IPIs. The wake may have been a spurious
        // one (or another contender beat us to the CAS), so the only
        // correct response is to re-test the owner.
        arch::Sti();
    }
}

void AdaptiveMutexUnlock(AdaptiveMutex& m)
{
    sched::Task* me = sched::CurrentTask();
    sched::Task* observed = LoadOwner(m);

    // Caller-side contract: only the owner may unlock. Debug:
    // panic; release: the kernel's DebugPanicOrWarn path logs and
    // returns without mutating m so the rightful holder isn't
    // robbed of the lock.
    if (observed != me)
    {
        arch::SerialWrite("[adaptive-mutex] UNLOCK-NONOWNER m=");
        arch::SerialWriteHex(reinterpret_cast<u64>(&m));
        arch::SerialWrite(" actual_owner=");
        arch::SerialWriteHex(reinterpret_cast<u64>(observed));
        arch::SerialWrite(" caller=");
        arch::SerialWriteHex(reinterpret_cast<u64>(me));
        arch::SerialWrite("\n");
        core::DebugPanicOrWarn("sync/adaptive-mutex", "AdaptiveMutexUnlock by non-owner");
        return;
    }

    // Pop from lockdep held stack BEFORE the owner pointer changes
    // — mirrors SpinLockRelease / MutexUnlock ordering. A LockdepView
    // read between the pop and the owner clear sees a consistent
    // "we're letting it go" state.
    LockdepBeforeRelease(m.m_class_id);

    // Release-store the owner. ACQUIRE on the next contender's
    // claim pairs with this. After this store, any peer CPU's
    // fast-path CAS can win — no need to wake a waiter first.
    __atomic_store_n(&m.m_owner, static_cast<sched::Task*>(nullptr), __ATOMIC_RELEASE);

    // Wake one waiter (FIFO). The woken task does NOT inherit the
    // lock; it returns from WaitQueueBlock and retries the CAS
    // path. A brief "stolen by a CPU that wasn't parked" window is
    // tolerated as the trade-off for keeping Unlock simple — the
    // illumos design accepts this; throughput is still bounded by
    // the same WaitQueue's FIFO ordering for the parked set.
    sched::WaitQueueWakeOne(&m.m_waiters);
}

bool AdaptiveMutexTryLock(AdaptiveMutex& m)
{
    sched::Task* me = sched::CurrentTask();

    // Fast-path CAS only. No spin, no park. A loser (lock held by
    // anyone — including ourselves) returns false. Lockdep edge
    // walk fires only on success: a declined attempt never
    // actually acquired the lock, so the held stack must not
    // record an edge through it.
    if (TryClaim(m, me))
    {
        LockdepBeforeAcquire(m.m_class_id);
        LockdepAfterAcquire(m.m_class_id);
        return true;
    }
    return false;
}

bool AdaptiveMutexIsHeld(const AdaptiveMutex& m)
{
    return LoadOwner(m) != nullptr;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace
{

// Test fixtures live in an anonymous namespace so the wait/wake
// contention test's worker can reach the mutex + flag without
// passing them through `void*`. Anonymous-namespace globals are
// confined to this TU; on a clean boot the values never escape the
// self-test window.
AdaptiveMutex g_st_mutex;
volatile u32 g_st_owner_acquired = 0;
volatile u32 g_st_owner_releasing = 0;
volatile u32 g_st_contender_acquired = 0;

// Owner worker: takes the mutex, sleeps a few ticks (giving the
// contender room to park), then releases. The sleep is what
// generates the off-CPU half of the adaptive-mutex pattern: while
// we are sleeping, our `on_cpu` flag is 0, so the contender's spin
// loop falls through to the park path immediately.
void ContentionOwnerWorker(void*)
{
    AdaptiveMutexLock(g_st_mutex);
    __atomic_store_n(&g_st_owner_acquired, 1u, __ATOMIC_RELEASE);

    // Sleep so we're provably off-CPU when the contender runs.
    // 10 ticks @ 100 Hz = 100 ms — plenty of room for the
    // contender to be scheduled, fail its spin, and park.
    sched::SchedSleepTicks(10);

    __atomic_store_n(&g_st_owner_releasing, 1u, __ATOMIC_RELEASE);
    AdaptiveMutexUnlock(g_st_mutex);
}

// Contender worker: try to acquire. If the owner is asleep
// holding the mutex, the slow path falls through to park
// immediately (owner is off-CPU). When the owner unlocks, the
// wake wakes us, the CAS wins, and we mark ourselves acquired.
void ContentionContenderWorker(void*)
{
    AdaptiveMutexLock(g_st_mutex);
    __atomic_store_n(&g_st_contender_acquired, 1u, __ATOMIC_RELEASE);
    AdaptiveMutexUnlock(g_st_mutex);
}

} // namespace

void AdaptiveMutexSelfTest()
{
    arch::SerialWrite("[adaptive-mutex] self-test: fast path + trylock + lockdep + contention\n");

    // ---- (1) Uncontested Lock + Unlock (fast path). -----------------
    {
        AdaptiveMutex m{};
        if (AdaptiveMutexIsHeld(m))
        {
            PanicAdaptive("self-test: fresh mutex not zero-initialised");
        }
        AdaptiveMutexLock(m);
        if (!AdaptiveMutexIsHeld(m))
        {
            PanicAdaptive("self-test: Lock did not mark mutex held");
        }
        if (LoadOwner(m) != sched::CurrentTask())
        {
            PanicAdaptive("self-test: owner pointer not set to current task");
        }
        AdaptiveMutexUnlock(m);
        if (AdaptiveMutexIsHeld(m))
        {
            PanicAdaptive("self-test: Unlock did not clear owner");
        }
    }

    // ---- (2) TryLock on unheld returns true; held returns false. ----
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
        if (AdaptiveMutexIsHeld(m))
        {
            PanicAdaptive("self-test: Unlock after TryLock did not clear owner");
        }
        // Free mutex now succeeds again.
        if (!AdaptiveMutexTryLock(m))
        {
            PanicAdaptive("self-test: TryLock failed on re-freed mutex");
        }
        AdaptiveMutexUnlock(m);
    }

    // ---- (3) Lockdep round-trip. ------------------------------------
    // Tag with the sentinel class kLockClassUnclassified (untagged
    // path), verify that lockdep hooks no-op cleanly. Then tag with
    // a real class and verify Lock pushes / Unlock pops on the
    // held stack.
    {
        AdaptiveMutex m{};
        m.m_class_id = kLockClassUnclassified;
        AdaptiveMutexLock(m);
        AdaptiveMutexUnlock(m);

        // Use an unused-by-default class so we don't perturb the
        // shared lockdep view. kLockClassKObject is registered at
        // boot but lightly held — perfect for a synthetic test
        // that immediately unlocks. The held-stack delta around
        // Lock/Unlock is 0 (push + pop), which is the contract.
        AdaptiveMutex tagged{};
        tagged.m_class_id = kLockClassKObject;
        // Snapshot the held stack before/during/after Lock+Unlock. The
        // snapshot's depth return is the canonical "how many classes
        // are currently held" reading; a `during == before + 1` then
        // `after == before` is the contract.
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

    // ---- (4) Two-task contention via SchedCreate. -------------------
    // The owner takes the mutex and sleeps. The contender tries to
    // acquire while the owner is asleep: the spin path falls
    // through (owner off-CPU), the contender parks, the owner
    // wakes and unlocks, the wake routes the contender back to
    // the CAS, and the contender claims + releases. Final state:
    // mutex unheld, both flags set.
    g_st_mutex = AdaptiveMutex{};
    g_st_owner_acquired = 0;
    g_st_owner_releasing = 0;
    g_st_contender_acquired = 0;

    sched::SchedCreate(ContentionOwnerWorker, nullptr, "amx-st-owner");
    // Let the owner run first so it grabs the mutex before the
    // contender exists. SchedYield twice — the first yield wakes
    // the owner, the second gives it the actual claim cycle plus
    // its 1-tick window before SchedSleepTicks parks it.
    sched::SchedYield();
    sched::SchedYield();

    if (__atomic_load_n(&g_st_owner_acquired, __ATOMIC_ACQUIRE) == 0)
    {
        PanicAdaptive("self-test: contention owner never acquired the mutex");
    }

    sched::SchedCreate(ContentionContenderWorker, nullptr, "amx-st-contender");

    // Drive forward until the contender resumes. The owner sleeps
    // for 10 ticks; we yield (which is a no-op SchedYield in the
    // sense that it just re-enters Schedule()) until both flags
    // flip or we cap at a generous bound. The cap is the safety
    // net so a regression hangs the boot instead of looping
    // forever — boot-log-analyze.sh's FAIL gate fires on the panic
    // banner, not on a silent loop.
    for (u32 i = 0; i < 200; ++i)
    {
        if (__atomic_load_n(&g_st_contender_acquired, __ATOMIC_ACQUIRE) != 0)
        {
            break;
        }
        // SchedSleepTicks(1) parks us on the sleep queue for one
        // tick; the timer wakes us, by which time the owner's own
        // sleep may have expired and run + unlocked. Repeating up
        // to 200 ticks (= 2 s @ 100 Hz) gives plenty of headroom
        // over the owner's 10-tick sleep.
        sched::SchedSleepTicks(1);
    }
    if (__atomic_load_n(&g_st_contender_acquired, __ATOMIC_ACQUIRE) == 0)
    {
        PanicAdaptive("self-test: contender never resumed (park/wake path broken)");
    }
    if (__atomic_load_n(&g_st_owner_releasing, __ATOMIC_ACQUIRE) == 0)
    {
        PanicAdaptive("self-test: owner never reached release (sleep/wake path broken)");
    }
    if (AdaptiveMutexIsHeld(g_st_mutex))
    {
        PanicAdaptive("self-test: contention mutex left held after both workers ran");
    }

    arch::SerialWrite("[adaptive-mutex] self-test OK (fast path, trylock, lockdep, contention park/wake)\n");
}

} // namespace duetos::sync
