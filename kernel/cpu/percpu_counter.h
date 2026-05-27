#pragma once

#include "acpi/acpi.h"
#include "sync/spinlock.h"
#include "util/types.h"

/*
 * DuetOS — split per-CPU counter with bounded slop.
 *
 * SHAPE
 *   A 64-bit signed global with a per-CPU stash buffer. Hot writers
 *   (Add) bump only their CPU's stash; when the absolute stash value
 *   exceeds `batch`, the stash is folded into the global under a
 *   short spinlock and reset to zero.
 *
 * READS
 *   - `ReadApproximate()` — single atomic load of `m_global`. Cheap.
 *     Drifts from the true sum by at most `batch * NR_CPUS` because
 *     each CPU may hold up to `±batch` un-folded units in its stash.
 *   - `ReadExact()` — sums every stash under the spinlock. Linear in
 *     `NR_CPUS`; intended for diagnostics, panic dumps, self-tests.
 *
 * WHEN TO USE
 *   - Free-page count, open-handle count, network packet counters,
 *     scheduler stats — any read-mostly counter where the bounded
 *     drift is acceptable for routing decisions and where the cost
 *     of a global atomic on every increment would dominate.
 *
 * WHEN NOT TO USE
 *   - Counters that participate in correctness predicates (e.g. a
 *     resource-quota gate that must round-trip an exact value).
 *     Use a plain global atomic, or the seqlock pattern, instead.
 *   - Counters that are written from ONE CPU only (a dedicated
 *     worker, a single-producer queue). A `__atomic_*` on a u64
 *     under that CPU is already as cheap as it gets.
 *
 * THREAD-SAFETY / CONTEXT
 *   `Add` is safe from any kernel context: it takes the spinlock
 *   ONLY on the (rare) fold path, so the hot path is wait-free for
 *   a single CPU. Acquisition disables IRQs on the calling CPU
 *   (SpinLockAcquire's contract), so the stash read-modify-write
 *   is uninterruptible. IRQ handlers may call Add freely.
 *
 *   Both Read paths are safe from any context too, though
 *   ReadExact takes the spinlock and is therefore not appropriate
 *   for a hard-IRQ hot path.
 */

namespace duetos::cpu
{

class PercpuCounter
{
  public:
    /// Construct a counter with the given fold threshold. Smaller
    /// `batch` → tighter slop bound on ReadApproximate but more
    /// fold-path acquires per N adds.  The default 32 matches
    /// Linux's `FBC_BATCH` for small-to-medium counters and gives
    /// a worst-case approximate drift of 32 * kMaxCpus = 1024.
    explicit PercpuCounter(i64 batch = 32);

    /// Add `delta` to the counter. Fast path is a per-CPU stash
    /// update; the fold to the global runs only when the stash
    /// absolute value crosses `m_batch`.
    void Add(i64 delta);

    /// Cheap read of the global, atomic-relaxed. Drifts from the
    /// true sum by at most `m_batch * kMaxCpus`.
    i64 ReadApproximate() const;

    /// Exact read: sums every per-CPU stash + the global under the
    /// lock. O(kMaxCpus); use sparingly.
    i64 ReadExact();

    /// Reset the counter to `value`. Self-test only — production
    /// callers should construct a fresh counter rather than reset
    /// a shared one (a Reset racing with Add is a contract bug, not
    /// a supported pattern).
    void Reset(i64 value = 0);

  private:
    // Global counter — updated only inside the fold path under
    // `m_lock`, but read by `ReadApproximate` without the lock via
    // an atomic-relaxed load. Signed because callers (free-page
    // count, refcount-style counters) can go negative transiently
    // across CPUs even when the true sum stays >= 0.
    i64 m_global;

    // Fold threshold. Set at construction; never changes.
    i64 m_batch;

    // Per-CPU stash. Indexed by `cpu::CurrentCpuIdOrBsp()`. Only
    // written by the owning CPU (with IRQs disabled via the
    // spinlock acquire pattern in Add) — so cross-CPU readers
    // (ReadExact) take `m_lock` to serialize against the fold
    // path's writes to the same slot.
    i64 m_stash[acpi::kMaxCpus];

    // Lock taken on the fold path (when a stash crosses batch) and
    // on ReadExact. Hot Add calls — the common case where the
    // stash hasn't yet crossed the threshold — never acquire it.
    sync::SpinLock m_lock;
};

/// Boot self-test. Constructs a counter, exercises Add on the BSP
/// (validating fold + bound), spawns a workpool to drive Add from
/// multiple worker threads (validating per-CPU-stash isolation
/// under concurrent writers), and asserts ReadExact equals the
/// expected total. Wired into `BootBringupKernelServices` AFTER
/// the workpool is initialised.
void PercpuCounterSelfTest();

} // namespace duetos::cpu
