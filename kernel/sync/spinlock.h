#pragma once

#include "sync/lockdep.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — kernel spinlock primitive.
 *
 * FIFO ticket lock with interrupt save/restore. Used to guard data
 * structures that are accessed from both IRQ context and task
 * context, or from multiple CPUs once SMP lands.
 *
 * Design:
 *   - Two u32s: `next_ticket` is the dispenser, `now_serving` is the
 *     ticket currently holding the lock. Acquire atomic-fetch-adds
 *     `next_ticket` to claim a ticket, then spins reading
 *     `now_serving` until equality. Release increments `now_serving`
 *     to hand the lock to the next ticket in line.
 *   - FIFO fairness: waiters are served in the order they arrived.
 *     A burst of acquires from N CPUs cannot lock-starve any
 *     individual one — the ticket they each grabbed bounds wait
 *     time at "ticket - now_serving" predecessors.
 *   - Zero-initialized = unlocked. Safe to declare `constinit` /
 *     `static SpinLock x{};` anywhere. Both ticket fields start at
 *     0, which means "ticket 0 is being served and is also the next
 *     to be handed out" → the lock is free. The class_id field also
 *     zero-initialises to `kLockClassUnclassified` (0), so untagged
 *     locks bypass lockdep with a single compare-and-skip.
 *   - Acquire disables interrupts on the calling CPU (saving the
 *     previous RFLAGS.IF so nested acquires restore correctly on
 *     release) before grabbing a ticket.
 *   - Release increments `now_serving` with release ordering and
 *     restores RFLAGS.IF.
 *   - Owner-CPU tracking is debug-only; `owner_cpu` is written under
 *     the lock and read only for diagnostics. Do not rely on it for
 *     correctness.
 *   - `class_id` ties the lock into the lockdep-lite locking-order
 *     graph. Tagged locks get `LockdepBefore/AfterAcquire` and
 *     `LockdepBeforeRelease` calls in their acquire/release paths.
 *     Untagged locks pay nothing.
 *
 * Scope limits:
 *   - Not recursive. A CPU that re-acquires a lock it already holds
 *     will deadlock itself. `SpinLockAssertHeld` is offered for
 *     callers that want to document the invariant.
 *   - Single shared `now_serving` cache line. MCS queueing (one
 *     wait slot per waiter) is a future move when ticket contention
 *     shows up as cache-line ping-pong in profiles.
 *   - Waiters spin — no fallback to sleep. Holding a spinlock across
 *     any blocking call (SchedYield, WaitQueueBlock, KMalloc if it
 *     ever blocks) is a contract violation. Kernel code holding a
 *     spinlock must stay on-CPU.
 *
 * Context: kernel. Safe to use in IRQ context and task context.
 */

namespace duetos::sync
{

struct SpinLock
{
    // Ticket dispenser: each Acquire fetch-adds this and uses the
    // pre-increment value as its ticket number. Wraps cleanly at
    // u32 — even at 1 ns per acquire, wrap takes ~4.3 s of constant
    // contention on a single lock, well past any realistic critical
    // section. The pair (next_ticket, now_serving) is free iff they
    // are equal.
    volatile u32 next_ticket;

    // Ticket currently holding the lock. Acquire spins until its
    // ticket equals this value; Release increments it.
    volatile u32 now_serving;

    // Diagnostic only: CPU index of current holder (or 0xFFFFFFFF if
    // unlocked). Never consulted for correctness.
    volatile u32 owner_cpu;

    // Lockdep class. Default 0 = `kLockClassUnclassified` —
    // untagged locks skip the lockdep hooks entirely. Tag with a
    // canonical class ID from `lockdep.h` (kLockClass*) at the
    // lock's declaration site to opt into locking-order
    // validation. Keeping this u16 lets the struct stay packed
    // alongside the diagnostic owner_cpu.
    LockClass class_id;
};

/// Saved interrupt state returned by Acquire, consumed by Release. The
/// caller must pass the exact value back; mixing up guards across
/// locks corrupts the IF restoration.
struct IrqFlags
{
    u64 rflags;
};

/// Acquire the lock. Disables interrupts on the current CPU, saves the
/// prior RFLAGS, atomically grabs a ticket, then busy-waits until that
/// ticket is being served. FIFO ordering across competing CPUs.
[[nodiscard]] IrqFlags SpinLockAcquire(SpinLock& lock);

/// Release the lock and restore the caller's prior interrupt state.
/// Panics (via kernel Halt) in debug builds if the lock isn't held or
/// isn't held by the current CPU.
void SpinLockRelease(SpinLock& lock, IrqFlags flags);

/// Debug helper: panics if the lock isn't currently held. Useful at the
/// top of a function that assumes a caller grabbed the lock.
void SpinLockAssertHeld(const SpinLock& lock);

/// Default spin budget for `SpinLockTryAcquireFor`. Sized for the
/// "spinlocks are held briefly" contract above — long enough to ride
/// out a short critical section on another CPU, short enough that a
/// genuinely stuck lock fails fast instead of masking the bug.
constexpr u32 kSpinTryDefaultSpins = 4096;

/// Non-blocking acquire. Never spins and never panics: returns the
/// same `IrqFlags` as `SpinLockAcquire` on success (pass it back to
/// `SpinLockRelease` exactly as for a blocking acquire), or an error
/// the caller can back off on instead of deadlocking:
///   - `ErrorCode::Deadlock` — THIS CPU already holds the lock; a
///     blocking acquire here would self-deadlock (and panic).
///     Retrying will never help. This is the graceful "self-unlock"
///     escape: control returns to the caller instead of hanging.
///   - `ErrorCode::Busy`     — the lock is held by another ticket /
///     CPU right now; a later retry may succeed.
/// Interrupt state is fully restored before any error return.
[[nodiscard]] core::Result<IrqFlags> SpinLockTryAcquire(SpinLock& lock);

/// Bounded ("stricter") try-acquire. As `SpinLockTryAcquire`, but on
/// a Busy lock it retries up to `max_spins` `pause`-spaced attempts
/// before giving up with `ErrorCode::Timeout`. A self-held lock still
/// returns `ErrorCode::Deadlock` immediately — spinning can never
/// clear a lock this CPU is itself holding.
[[nodiscard]] core::Result<IrqFlags> SpinLockTryAcquireFor(SpinLock& lock, u32 max_spins = kSpinTryDefaultSpins);

/// RAII guard — acquires on construction, releases on destruction. The
/// guard is non-copyable / non-movable so it always releases on the
/// same scope level it acquired on.
class SpinLockGuard
{
  public:
    explicit SpinLockGuard(SpinLock& lock) : m_lock(lock), m_flags(SpinLockAcquire(lock)) {}
    ~SpinLockGuard() { SpinLockRelease(m_lock, m_flags); }

    SpinLockGuard(const SpinLockGuard&) = delete;
    SpinLockGuard& operator=(const SpinLockGuard&) = delete;
    SpinLockGuard(SpinLockGuard&&) = delete;
    SpinLockGuard& operator=(SpinLockGuard&&) = delete;

  private:
    SpinLock& m_lock;
    IrqFlags m_flags;
};

/// RAII guard for the try path. Attempts the (optionally bounded)
/// try-acquire on construction; releases on destruction ONLY if it
/// succeeded — a declined acquire makes scope exit a clean no-op.
/// Non-copyable / non-movable so the release pairs with the acquire
/// on the same scope level. Test `held()` / `bool(guard)` before
/// touching the protected data; `reason()` gives the failure code.
class SpinLockTryGuard
{
  public:
    explicit SpinLockTryGuard(SpinLock& lock) : m_lock(lock), m_result(SpinLockTryAcquire(lock)) {}
    SpinLockTryGuard(SpinLock& lock, u32 max_spins) : m_lock(lock), m_result(SpinLockTryAcquireFor(lock, max_spins)) {}

    ~SpinLockTryGuard()
    {
        if (m_result.has_value())
        {
            SpinLockRelease(m_lock, m_result.value());
        }
    }

    SpinLockTryGuard(const SpinLockTryGuard&) = delete;
    SpinLockTryGuard& operator=(const SpinLockTryGuard&) = delete;
    SpinLockTryGuard(SpinLockTryGuard&&) = delete;
    SpinLockTryGuard& operator=(SpinLockTryGuard&&) = delete;

    bool held() const { return m_result.has_value(); }
    explicit operator bool() const { return m_result.has_value(); }

    /// Failure code when `!held()`. Undefined to call when held.
    core::ErrorCode reason() const { return m_result.error(); }

  private:
    SpinLock& m_lock;
    core::Result<IrqFlags> m_result;
};

/// Reentrant RAII guard. Acquires on construction unless THIS CPU
/// already holds the lock (a nested call under an outer guard), in
/// which case it is a no-op that leaves ownership with the outer
/// holder. Blocks (FIFO) when another CPU holds the lock. Releases
/// on destruction ONLY if this guard performed the acquire.
///
/// Purpose: lets a subsystem wrap every PUBLIC entry point in one
/// lock even when those entries legitimately call one another
/// (e.g. AllocateContiguousFrames -> AllocateFrame), without
/// splitting each function into a public + `*Locked` worker. A
/// plain `SpinLockGuard` would self-deadlock on the nested call;
/// this detects the self-held case via `SpinLockTryAcquire`'s
/// `ErrorCode::Deadlock` and skips the re-acquire. IRQ state is
/// owned by the outermost (acquiring) guard, matching the
/// irqsave/irqrestore pairing of the non-reentrant guard.
class SpinLockRecursiveGuard
{
  public:
    explicit SpinLockRecursiveGuard(SpinLock& lock) : m_lock(lock), m_owned(false)
    {
        core::Result<IrqFlags> r = SpinLockTryAcquire(lock);
        if (r.has_value())
        {
            m_flags = r.value();
            m_owned = true;
            return;
        }
        if (r.error() == core::ErrorCode::Deadlock)
        {
            return; // already held by this CPU — nested call, no-op
        }
        // Busy: another CPU holds it. Block FIFO like a plain guard.
        m_flags = SpinLockAcquire(lock);
        m_owned = true;
    }

    ~SpinLockRecursiveGuard()
    {
        if (m_owned)
        {
            SpinLockRelease(m_lock, m_flags);
        }
    }

    SpinLockRecursiveGuard(const SpinLockRecursiveGuard&) = delete;
    SpinLockRecursiveGuard& operator=(const SpinLockRecursiveGuard&) = delete;
    SpinLockRecursiveGuard(SpinLockRecursiveGuard&&) = delete;
    SpinLockRecursiveGuard& operator=(SpinLockRecursiveGuard&&) = delete;

  private:
    SpinLock& m_lock;
    IrqFlags m_flags{};
    bool m_owned;
};

/// Acquire/release round-trip + ownership assertions on a local lock.
/// Called from kernel_main to catch gross breakage early. On a single
/// CPU this only exercises the IF save/restore + xchg path; real SMP
/// contention testing waits for AP bring-up.
void SpinLockSelfTest();

} // namespace duetos::sync
