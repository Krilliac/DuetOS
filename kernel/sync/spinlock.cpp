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

// Raw-serial breadcrumb naming the self-deadlocked lock and BOTH
// call sites, emitted just before the panic. core::Panic's
// recursive-panic guard suppresses the rich dump precisely when the
// panic path itself would need a lock (which is exactly the
// self-deadlock case), so without this the operator gets only
// "self-deadlock" with no lock identity, class, or RIPs — undebuggable
// post-mortem. Raw serial, not klog: the klog sink and the symbol
// resolver can themselves take spinlocks, and we are mid-deadlock.
void EmitSelfDeadlockDiag(const SpinLock& lock, u64 recursive_rip)
{
    arch::SerialWrite("[spinlock] SELF-DEADLOCK lock=");
    arch::SerialWriteHex(reinterpret_cast<u64>(&lock));
    arch::SerialWrite(" class_id=");
    arch::SerialWriteHex(lock.class_id);
    arch::SerialWrite(" class=\"");
    const char* cn = LockdepClassName(lock.class_id);
    arch::SerialWrite((cn != nullptr) ? cn : "unclassified");
    arch::SerialWrite("\" owner_cpu=");
    arch::SerialWriteHex(lock.owner_cpu);
    arch::SerialWrite(" recursive_acquire_rip=");
    arch::SerialWriteHex(recursive_rip);

    // Walk THIS CPU's held-locks stack for the RIP where the lock was
    // originally acquired (the still-held instance we're colliding
    // with). Same guards as HeldLocksPush — no PerCpu yet ⇒ skip.
    u64 orig_rip = 0;
    if (cpu::BspInstalled())
    {
        cpu::PerCpu* p = cpu::CurrentCpu();
        if (p != nullptr)
        {
            u32 n = p->held_locks_count;
            if (n > cpu::kPerCpuMaxHeldLocks)
            {
                n = cpu::kPerCpuMaxHeldLocks;
            }
            for (u32 i = 0; i < n; ++i)
            {
                if (p->held_locks[i] == &lock)
                {
                    orig_rip = p->held_lock_rips[i];
                    break;
                }
            }
        }
    }
    arch::SerialWrite(" original_acquire_rip=");
    arch::SerialWriteHex(orig_rip);
    arch::SerialWrite("\n");
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

// True iff the lock is held AND the current CPU is its holder — i.e.
// a blocking acquire from here would claim a fresh ticket and spin on
// now_serving forever (we'd never advance it; with IF off, fatally).
// owner_cpu is only meaningful while held, and while WE hold it no
// other CPU can change it, so this read is race-free for the case it
// reports true on (a stale read from a just-released foreign lock
// names that CPU's id, never ours — no false positive). Shared by
// the blocking acquire (panics) and the try path (returns Deadlock).
inline bool HeldBySelf(const SpinLock& lock)
{
    return LockIsHeld(lock) && lock.owner_cpu == cpu::CurrentCpuIdOrBsp();
}

IrqFlags SpinLockAcquire(SpinLock& lock)
{
    const u64 flags = ReadRflags();
    arch::Cli();

    // Self-deadlock guard. A ticket lock re-acquired by its own
    // current holder claims a fresh ticket and then spins on
    // now_serving forever — and we just did Cli(), so this CPU can
    // never advance now_serving to free itself. That is an
    // unrecoverable silent hang with zero output: the single
    // hardest deadlock to diagnose post-mortem. Always-on (not
    // DEBUG_ASSERT): a hang is catastrophic in release too, and
    // turning it into a panic banner is strictly better in every
    // build. Lockdep does NOT cover this — it tracks lock CLASSES
    // (the AA self-edge is not an inversion) and skips untagged
    // locks entirely. Callers that can recover should use
    // SpinLockTryAcquire, which detects the same condition via the
    // shared HeldBySelf predicate but returns ErrorCode::Deadlock
    // instead of panicking.
    if (HeldBySelf(lock))
    {
        EmitSelfDeadlockDiag(lock, reinterpret_cast<u64>(__builtin_return_address(0)));
        PanicSpinlock("self-deadlock: SpinLockAcquire of a lock this CPU already holds");
    }

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

namespace
{

// Shared core for both try variants. Disables IRQs, refuses a
// self-held lock (Deadlock), then makes up to `attempts`
// non-blocking ticket claims. A ticket lock is free iff
// next_ticket == now_serving; we CAS next_ticket from that value to
// +1, which both reserves the ticket and — because it equalled
// now_serving — leaves us already being served, so we hold the lock
// with zero spin. On give-up, IRQ state is fully restored and
// `on_exhausted` (Busy for fail-fast, Timeout for the bounded form)
// is returned. The lockdep edge-walk fires ONLY on the success
// path, mirroring RwLockTryAcquire* — a declined attempt must not
// record a held→this edge it never actually took.
core::Result<IrqFlags> TryAcquireImpl(SpinLock& lock, u32 attempts, core::ErrorCode on_exhausted, u64 caller_rip)
{
    const u64 flags = ReadRflags();
    arch::Cli();

    auto restore_irq = [&]
    {
        if ((flags & kRflagsIfBit) != 0)
        {
            arch::Sti();
        }
    };

    if (HeldBySelf(lock))
    {
        restore_irq();
        KLOG_DEBUG_V("sync/spinlock", "try-acquire declined: self-held", static_cast<u64>(core::ErrorCode::Deadlock));
        return core::Err{core::ErrorCode::Deadlock};
    }

    for (u32 i = 0; i < attempts; ++i)
    {
        u32 expected = __atomic_load_n(&lock.now_serving, __ATOMIC_RELAXED);
        if (__atomic_load_n(&lock.next_ticket, __ATOMIC_RELAXED) == expected &&
            __atomic_compare_exchange_n(&lock.next_ticket, &expected, expected + 1, false, __ATOMIC_ACQUIRE,
                                        __ATOMIC_RELAXED))
        {
            // Won the ticket; it already equals now_serving, so the
            // lock is ours with no spin. Bookkeeping mirrors the
            // tail of SpinLockAcquire.
            lock.owner_cpu = cpu::CurrentCpuIdOrBsp();
            LockdepBeforeAcquire(lock.class_id);
            HeldLocksPush(lock, caller_rip);
            LockdepAfterAcquire(lock.class_id);
            return IrqFlags{.rflags = flags};
        }
        if (i + 1 < attempts)
        {
            asm volatile("pause" ::: "memory");
        }
    }

    restore_irq();
    KLOG_DEBUG_V("sync/spinlock", "try-acquire declined: contended", static_cast<u64>(on_exhausted));
    return core::Err{on_exhausted};
}

} // namespace

core::Result<IrqFlags> SpinLockTryAcquire(SpinLock& lock)
{
    return TryAcquireImpl(lock, 1, core::ErrorCode::Busy, reinterpret_cast<u64>(__builtin_return_address(0)));
}

core::Result<IrqFlags> SpinLockTryAcquireFor(SpinLock& lock, u32 max_spins)
{
    // At least one attempt even if the caller passes 0 — "try with a
    // zero budget" still means "try once".
    return TryAcquireImpl(lock, max_spins == 0 ? 1 : max_spins, core::ErrorCode::Timeout,
                          reinterpret_cast<u64>(__builtin_return_address(0)));
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

    // Try-lock paths. The Busy (held-by-another-CPU) leg can't be
    // exercised on a single CPU before AP bring-up — like the
    // RwLock / SeqLock contention self-tests, this is a
    // cooperative-single-CPU form that covers the self-held and
    // free-lock legs; the cross-CPU Busy leg lands with the
    // SMP-stress sweep.
    {
        SpinLock t{};

        // Free lock → fail-fast try succeeds and actually holds it.
        core::Result<IrqFlags> r = SpinLockTryAcquire(t);
        if (!r.has_value())
        {
            PanicSpinlock("SpinLockTryAcquire failed on a free lock");
        }
        if (!LockIsHeld(t))
        {
            PanicSpinlock("SpinLockTryAcquire did not mark the lock held");
        }

        // Held by THIS CPU → both try variants must decline with
        // Deadlock (graceful self-unlock; no panic, no hang).
        core::Result<IrqFlags> self = SpinLockTryAcquire(t);
        if (self.has_value() || self.error() != core::ErrorCode::Deadlock)
        {
            PanicSpinlock("SpinLockTryAcquire on self-held lock did not return Deadlock");
        }
        core::Result<IrqFlags> self_for = SpinLockTryAcquireFor(t, 64);
        if (self_for.has_value() || self_for.error() != core::ErrorCode::Deadlock)
        {
            PanicSpinlock("SpinLockTryAcquireFor on self-held lock did not return Deadlock");
        }
        SpinLockRelease(t, r.value());
        if (LockIsHeld(t))
        {
            PanicSpinlock("try-acquired lock still held after release");
        }

        // Bounded try on a now-free lock → success.
        core::Result<IrqFlags> rb = SpinLockTryAcquireFor(t, 64);
        if (!rb.has_value())
        {
            PanicSpinlock("SpinLockTryAcquireFor failed on a free lock");
        }
        SpinLockRelease(t, rb.value());

        // Guard: acquires on a free lock, auto-releases on scope exit.
        {
            SpinLockTryGuard g(t);
            if (!g || !g.held() || !LockIsHeld(t))
            {
                PanicSpinlock("SpinLockTryGuard did not acquire a free lock");
            }
        }
        if (LockIsHeld(t))
        {
            PanicSpinlock("SpinLockTryGuard did not release on scope exit");
        }

        // Guard on a self-held lock: declines, scope exit is a no-op,
        // the original holder's lock stays held until WE release it.
        const IrqFlags hold = SpinLockAcquire(t);
        {
            SpinLockTryGuard g(t);
            if (g || g.held() || g.reason() != core::ErrorCode::Deadlock)
            {
                PanicSpinlock("SpinLockTryGuard on self-held lock did not decline with Deadlock");
            }
        }
        if (!LockIsHeld(t))
        {
            PanicSpinlock("declined SpinLockTryGuard wrongly released the held lock");
        }
        SpinLockRelease(t, hold);
    }

    arch::SerialWrite("[sync] spinlock self-test OK\n");
}

} // namespace duetos::sync
