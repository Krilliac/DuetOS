#include "sync/spinlock.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "log/klog.h"
#include "sync/lockdep.h"

// Holder-tracking knob — gated on the kernel having installed
// PerCpu, since the per-CPU stack lives there. Acquires before
// PerCpuInitBsp (frame allocator init, very early heap setup)
// quietly skip the bookkeeping; the lock still works, the panic
// dump just won't have an entry for that lock.
//
// `__builtin_return_address(0)` returns the address the function
// would `ret` to — i.e. the call site of the acquire. Captured so
// the panic dump's `held locks` section can name *who* took each
// lock without a second debug build.

namespace duetos::sync
{

namespace
{

constexpr u64 kRflagsIfBit = 1ULL << 9;

inline u64 ReadRflags()
{
    u64 f;
    asm volatile("pushfq; pop %0" : "=r"(f)::"memory");
    return f;
}

[[noreturn]] void PanicSpinlock(const char* message)
{
    core::Panic("sync/spinlock", message);
}

// Push a freshly-acquired lock onto the current CPU's held-locks
// stack, capturing the caller's RIP. No-ops if PerCpu isn't up
// yet, or if the stack is already full (overflow is logged once
// per boot rather than panicking — a deep nest is its own signal).
void HeldLocksPush(SpinLock& lock, u64 caller_rip)
{
    if (!cpu::BspInstalled())
    {
        return;
    }
    cpu::PerCpu* p = cpu::CurrentCpu();
    if (p == nullptr)
    {
        return;
    }
    const u32 idx = p->held_locks_count;
    if (idx >= cpu::kPerCpuMaxHeldLocks)
    {
        // Bump the count anyway so the panic dump can show "we
        // overflowed at depth N" — the per-CPU storage just won't
        // record this specific lock. Visibility > silence.
        p->held_locks_count = idx + 1;
        return;
    }
    p->held_locks[idx] = &lock;
    p->held_lock_rips[idx] = caller_rip;
    p->held_locks_count = idx + 1;
}

// Mirror — pop the top-of-stack on release. We only assert it's
// the matching lock when tracking is fully in scope; an over-cap
// nest decremented `held_locks_count` past the array, so the
// matching pop just decrements the count without touching the
// array. Stack mismatch (release-out-of-order) is a real bug —
// loud panic with the offending pair's identities.
void HeldLocksPop(SpinLock& lock)
{
    if (!cpu::BspInstalled())
    {
        return;
    }
    cpu::PerCpu* p = cpu::CurrentCpu();
    if (p == nullptr || p->held_locks_count == 0)
    {
        return;
    }
    const u32 new_count = p->held_locks_count - 1;
    if (new_count < cpu::kPerCpuMaxHeldLocks)
    {
        if (p->held_locks[new_count] != &lock)
        {
            // Lock is being released out of acquire order — common
            // root cause of mysterious deadlocks later. Debug builds
            // panic so the offender is impossible to miss; release
            // builds log the violation and skip zeroing the wrong
            // slot (so its tracking stays as-is for the still-held
            // lock that owns it) but still pop the count below.
            core::DebugPanicOrWarnWithValue("sync/spinlock", "release out-of-order: top-of-stack lock != released lock",
                                            reinterpret_cast<u64>(&lock));
        }
        else
        {
            p->held_locks[new_count] = nullptr;
            p->held_lock_rips[new_count] = 0;
        }
    }
    p->held_locks_count = new_count;
}

} // namespace

// True iff the lock is currently held by SOME CPU. A ticket lock
// is free iff next_ticket == now_serving — both 0 at boot, equal
// any time the last holder finishes serving the most recent ticket.
inline bool LockIsHeld(const SpinLock& lock)
{
    const u32 ns = __atomic_load_n(&lock.now_serving, __ATOMIC_RELAXED);
    const u32 nt = __atomic_load_n(&lock.next_ticket, __ATOMIC_RELAXED);
    return ns != nt;
}

IrqFlags SpinLockAcquire(SpinLock& lock)
{
    const u64 flags = ReadRflags();
    arch::Cli();

    // Lockdep edge-walk: BEFORE we even claim a ticket, so the
    // "held → this" edge is recorded against the locks already on
    // the stack. Untagged locks (class_id == kLockClassUnclassified)
    // short-circuit inside the hook for one compare and a return.
    LockdepBeforeAcquire(lock.class_id);

    // Atomically claim the next ticket. Acquire ordering: any reads
    // we do inside the critical section (after the spin completes)
    // happen-after the prior holder's release-store of now_serving.
    const u32 my_ticket = __atomic_fetch_add(&lock.next_ticket, 1, __ATOMIC_ACQUIRE);

    // Spin until our ticket comes up. Plain `pause` is the right
    // hint here — we're polling a single shared cache line, so
    // SMT siblings should yield and the memory-ordering predictor
    // should treat the load as a spin-loop probe.
    while (__atomic_load_n(&lock.now_serving, __ATOMIC_ACQUIRE) != my_ticket)
    {
        asm volatile("pause" ::: "memory");
    }

    lock.owner_cpu = cpu::CurrentCpuIdOrBsp();
    // Caller's RIP — captured here, inside the function, because
    // __builtin_return_address(0) follows the standard System V
    // frame walk. The held-locks panic dump will resolve this back
    // to fn+offset via the embedded symbol table.
    HeldLocksPush(lock, reinterpret_cast<u64>(__builtin_return_address(0)));
    // After successful acquire — push onto the lockdep held stack
    // so the next acquire's edge walk sees us.
    LockdepAfterAcquire(lock.class_id);
    return IrqFlags{.rflags = flags};
}

void SpinLockRelease(SpinLock& lock, IrqFlags flags)
{
    if (!LockIsHeld(lock))
    {
        // Caller-side bug. Debug: panic. Release: log and return
        // without touching the lock or IRQ state — the lock is
        // already free, so no-op is the correct recovery.
        core::DebugPanicOrWarn("sync/spinlock", "SpinLockRelease on unheld lock");
        return;
    }
    if (lock.owner_cpu != cpu::CurrentCpuIdOrBsp())
    {
        // Same recovery shape: another CPU still owns the lock,
        // so don't bump now_serving from under it. Letting the
        // buggy releaser silently fail is safer than corrupting
        // the rightful holder's view.
        core::DebugPanicOrWarn("sync/spinlock", "SpinLockRelease by wrong CPU");
        return;
    }

    // Pop from lockdep held-class stack BEFORE the ticket advances
    // — keeps the lockdep view consistent with what's actually
    // held.
    LockdepBeforeRelease(lock.class_id);
    HeldLocksPop(lock);
    lock.owner_cpu = 0xFFFFFFFFu;

    // Hand the lock to the next ticket. Release ordering: every
    // memory write inside the critical section happens-before the
    // next holder's reads. Only this CPU writes now_serving while
    // it's the holder, so the read-modify-write doesn't race.
    __atomic_add_fetch(&lock.now_serving, 1, __ATOMIC_RELEASE);

    if ((flags.rflags & kRflagsIfBit) != 0)
    {
        arch::Sti();
    }
}

void SpinLockAssertHeld(const SpinLock& lock)
{
    if (!LockIsHeld(lock))
    {
        // Pure assertion. Debug: panic so the violated invariant
        // is impossible to miss. Release: log it and return — the
        // assertion was just a sanity check and the caller is
        // about to try to use the lock anyway, which will surface
        // any consequence.
        core::DebugPanicOrWarn("sync/spinlock", "SpinLockAssertHeld on unheld lock");
        return;
    }
    if (lock.owner_cpu != cpu::CurrentCpuIdOrBsp())
    {
        core::DebugPanicOrWarn("sync/spinlock", "SpinLockAssertHeld on lock held by another CPU");
        return;
    }
}

void SpinLockSelfTest()
{
    KLOG_TRACE_SCOPE("sync/spinlock", "SpinLockSelfTest");
    arch::SerialWrite("[sync] spinlock self-test\n");

    SpinLock lock{};
    if (LockIsHeld(lock))
    {
        PanicSpinlock("fresh lock not zero-initialised");
    }

    {
        SpinLockGuard g(lock);
        if (!LockIsHeld(lock))
        {
            PanicSpinlock("guard did not acquire");
        }
        SpinLockAssertHeld(lock);
    }
    if (LockIsHeld(lock))
    {
        PanicSpinlock("guard did not release on scope exit");
    }

    // Manual acquire / release round-trip.
    const IrqFlags flags = SpinLockAcquire(lock);
    if (!LockIsHeld(lock))
    {
        PanicSpinlock("manual acquire did not mark lock held");
    }
    // Two acquires/releases must increment both ticket counters in
    // lockstep — verify the FIFO invariant directly. After this
    // single acquire, exactly one ticket has been dispensed and
    // none served yet, so next_ticket - now_serving == 1.
    if (lock.next_ticket - lock.now_serving != 1)
    {
        PanicSpinlock("ticket counters out of sync after acquire");
    }
    SpinLockRelease(lock, flags);
    if (LockIsHeld(lock))
    {
        PanicSpinlock("manual release did not advance now_serving");
    }
    if (lock.next_ticket != lock.now_serving)
    {
        PanicSpinlock("ticket counters not equal after release");
    }

    // Held-locks tracking — the per-CPU stack must climb on
    // acquire and fall on release, INCLUDING when nested two deep.
    // Skip this section if PerCpu isn't installed yet (early boot
    // smoke runs before SchedInit). The bookkeeping itself is a
    // no-op in that mode.
    if (cpu::BspInstalled())
    {
        cpu::PerCpu* p = cpu::CurrentCpu();
        if (p == nullptr)
        {
            PanicSpinlock("CurrentCpu null after BspInstalled");
        }
        const u32 baseline = p->held_locks_count;

        SpinLock outer{};
        SpinLock inner{};
        const IrqFlags fo = SpinLockAcquire(outer);
        if (p->held_locks_count != baseline + 1)
        {
            PanicSpinlock("held_locks_count did not climb on outer acquire");
        }
        if (p->held_locks[baseline] != &outer)
        {
            PanicSpinlock("outer lock not at top of held stack");
        }
        const IrqFlags fi = SpinLockAcquire(inner);
        if (p->held_locks_count != baseline + 2)
        {
            PanicSpinlock("held_locks_count did not climb on inner acquire");
        }
        if (p->held_locks[baseline + 1] != &inner)
        {
            PanicSpinlock("inner lock not at top of held stack");
        }
        SpinLockRelease(inner, fi);
        if (p->held_locks_count != baseline + 1)
        {
            PanicSpinlock("held_locks_count did not fall on inner release");
        }
        SpinLockRelease(outer, fo);
        if (p->held_locks_count != baseline)
        {
            PanicSpinlock("held_locks_count did not return to baseline on outer release");
        }
    }

    arch::SerialWrite("[sync] spinlock self-test OK\n");
}

} // namespace duetos::sync
