#include "sync/spinlock.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"
#include "cpu/percpu.h"

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

// Atomic test-and-set via xchg — returns the previous value (0 = we
// got it, 1 = somebody else has it). The xchg instruction has an
// implicit lock prefix on every x86 implementation since the 386, so
// we don't need an explicit `lock` prefix for correctness; it is,
// however, a full memory barrier, which is exactly what we want at
// lock-entry.
inline u32 XchgU32(volatile u32& slot, u32 value)
{
    u32 prev;
    asm volatile("xchg %0, %1" : "=r"(prev), "+m"(slot) : "0"(value) : "memory");
    return prev;
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
            // root cause of mysterious deadlocks later. Surface it
            // immediately, before more state piles up.
            core::PanicWithValue("sync/spinlock", "release out-of-order: top-of-stack lock != released lock",
                                 reinterpret_cast<u64>(&lock));
        }
        p->held_locks[new_count] = nullptr;
        p->held_lock_rips[new_count] = 0;
    }
    p->held_locks_count = new_count;
}

} // namespace

IrqFlags SpinLockAcquire(SpinLock& lock)
{
    const u64 flags = ReadRflags();
    arch::Cli();

    for (;;)
    {
        if (XchgU32(lock.locked, 1) == 0)
        {
            lock.owner_cpu = cpu::CurrentCpuIdOrBsp();
            // Caller's RIP — captured here, inside the function,
            // because __builtin_return_address(0) follows the
            // standard System V frame walk. The held-locks panic
            // dump will resolve this back to fn+offset via the
            // embedded symbol table.
            HeldLocksPush(lock, reinterpret_cast<u64>(__builtin_return_address(0)));
            return IrqFlags{.rflags = flags};
        }

        // PAUSE hints the CPU that this is a spin loop; on modern
        // micro-arch this saves power and helps the memory ordering
        // predictor. Cheap. The read-first-then-xchg pattern also
        // keeps this loop from hammering the cache line with atomic
        // writes — we only retry the xchg after a plain read sees
        // the lock go free.
        while (lock.locked != 0)
        {
            asm volatile("pause" ::: "memory");
        }
    }
}

void SpinLockRelease(SpinLock& lock, IrqFlags flags)
{
    if (lock.locked == 0)
    {
        PanicSpinlock("SpinLockRelease on unheld lock");
    }
    if (lock.owner_cpu != cpu::CurrentCpuIdOrBsp())
    {
        PanicSpinlock("SpinLockRelease by wrong CPU");
    }

    HeldLocksPop(lock);
    lock.owner_cpu = 0xFFFFFFFFu;
    // Plain store is correct on x86 — regular stores are already
    // sequentially consistent with other stores. The `memory` clobber
    // is the compiler fence.
    asm volatile("" ::: "memory");
    lock.locked = 0;

    if ((flags.rflags & kRflagsIfBit) != 0)
    {
        arch::Sti();
    }
}

void SpinLockAssertHeld(const SpinLock& lock)
{
    if (lock.locked == 0)
    {
        PanicSpinlock("SpinLockAssertHeld on unheld lock");
    }
    if (lock.owner_cpu != cpu::CurrentCpuIdOrBsp())
    {
        PanicSpinlock("SpinLockAssertHeld on lock held by another CPU");
    }
}

void SpinLockSelfTest()
{
    KLOG_TRACE_SCOPE("sync/spinlock", "SpinLockSelfTest");
    arch::SerialWrite("[sync] spinlock self-test\n");

    SpinLock lock{};
    if (lock.locked != 0)
    {
        PanicSpinlock("fresh lock not zero-initialised");
    }

    {
        SpinLockGuard g(lock);
        if (lock.locked != 1)
        {
            PanicSpinlock("guard did not acquire");
        }
        SpinLockAssertHeld(lock);
    }
    if (lock.locked != 0)
    {
        PanicSpinlock("guard did not release on scope exit");
    }

    // Manual acquire / release round-trip.
    const IrqFlags flags = SpinLockAcquire(lock);
    if (lock.locked != 1)
    {
        PanicSpinlock("manual acquire did not set locked");
    }
    SpinLockRelease(lock, flags);
    if (lock.locked != 0)
    {
        PanicSpinlock("manual release did not clear locked");
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
