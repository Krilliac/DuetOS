#pragma once

#include "../core/types.h"

/*
 * DuetOS — kernel spinlock primitive (v0).
 *
 * Test-and-set spinlock with interrupt save/restore. Used to guard
 * data structures that are accessed from both IRQ context and task
 * context, or from multiple CPUs once SMP lands.
 *
 * Design:
 *   - Zero-initialized = unlocked. Safe to declare `constinit` /
 *     `static SpinLock x{};` anywhere.
 *   - Acquire disables interrupts on the calling CPU (saving the
 *     previous RFLAGS.IF so nested acquires restore correctly on
 *     release) and then busy-waits on an atomic CAS.
 *   - Release writes zero back to the word and restores RFLAGS.IF.
 *   - Owner-CPU tracking is debug-only; `owner_cpu` is written under
 *     the lock and read only for diagnostics. Do not rely on it for
 *     correctness.
 *
 * Scope limits:
 *   - Not recursive. A CPU that re-acquires a lock it already holds
 *     will deadlock itself. `SpinLockAssertHeld` is offered for
 *     callers that want to document the invariant.
 *   - No priority inheritance / MCS queueing. Fine for the contention
 *     levels we expect at v0 (single CPU, rare IRQ-vs-task contention).
 *     Upgrade to ticket / MCS when contention shows up in profiles.
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
    // 0 = free, 1 = held. Intentionally u32 (not bool) — xchg on a u32
    // is one instruction on x86_64 and lets us expose a stable ABI for
    // assembly callers later.
    volatile u32 locked;

    // Diagnostic only: CPU index of current holder (or 0xFFFFFFFF if
    // unlocked). Never consulted for correctness.
    volatile u32 owner_cpu;
};

/// Saved interrupt state returned by Acquire, consumed by Release. The
/// caller must pass the exact value back; mixing up guards across
/// locks corrupts the IF restoration.
struct IrqFlags
{
    u64 rflags;
};

/// Acquire the lock. Disables interrupts on the current CPU, saves the
/// prior RFLAGS, then busy-waits until the lock word flips from 0 to 1
/// via `xchg` (implicitly atomic on x86).
[[nodiscard]] IrqFlags SpinLockAcquire(SpinLock& lock);

/// Release the lock and restore the caller's prior interrupt state.
/// Panics (via kernel Halt) in debug builds if the lock isn't held or
/// isn't held by the current CPU.
void SpinLockRelease(SpinLock& lock, IrqFlags flags);

/// Debug helper: panics if the lock isn't currently held. Useful at the
/// top of a function that assumes a caller grabbed the lock.
void SpinLockAssertHeld(const SpinLock& lock);

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

/// Acquire/release round-trip + ownership assertions on a local lock.
/// Called from kernel_main to catch gross breakage early. On a single
/// CPU this only exercises the IF save/restore + xchg path; real SMP
/// contention testing waits for AP bring-up.
void SpinLockSelfTest();

} // namespace duetos::sync
