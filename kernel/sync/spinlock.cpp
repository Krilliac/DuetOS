#include "spinlock.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"
#include "../cpu/percpu.h"

namespace customos::sync
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

    arch::SerialWrite("[sync] spinlock self-test OK\n");
}

} // namespace customos::sync
