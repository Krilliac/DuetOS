#pragma once

#include "util/types.h"

/*
 * DuetOS — lockdep-lite, v0 (plan D1 infra).
 *
 * WHAT
 *   A locking-order validator. Maintains a directed graph
 *   `(class A) -> (class B)` recording every "lock A was held when
 *   lock B was acquired" pairing observed at runtime. If both
 *   `A -> B` and `B -> A` ever appear, the order is inverted —
 *   under SMP this is a latent deadlock waiting to happen.
 *
 * WHY THIS, NOT FULL LOCKDEP
 *   Linux's lockdep is a beast: per-class state, recursion, RCU
 *   tracking, irqs-enabled context flags. v0 captures the 90%
 *   case (cycle detection between primary classes) at <300 lines.
 *   Class identification is by u16 ID assigned at the call site;
 *   per-instance disambiguation lands when there's a workload
 *   that needs it.
 *
 * SCOPE FOR THIS COMMIT
 *   - Graph storage + edge recording + cycle detection.
 *   - Held-class stack (single global, fine until SMP ships;
 *     per-CPU upgrade is one ifdef once kPerCpu lands real).
 *   - Self-test that synthesises `A then B` followed by `B then A`
 *     and asserts an inversion is reported.
 *
 *   NOT IN SCOPE (tracked as D1 follow-ups in the plan):
 *   - Hooking SpinLock / Mutex / RwLock acquire/release paths.
 *     Those changes need a `class_id` field added to each lock
 *     type and would touch every initialiser; deferred.
 *   - Promoting warnings to panics after a stabilisation window.
 *   - Per-CPU held stack via the SMP scaffolding.
 *
 * USAGE PATTERN (once primitives are hooked up)
 *
 *     // In some early init code, after the lockdep module is up:
 *     LockdepRegisterClass(kLockClassFrameAllocator, "frame_allocator");
 *     LockdepRegisterClass(kLockClassKHeap,           "kheap");
 *     LockdepRegisterClass(kLockClassSched,           "sched");
 *
 *     // In SpinLockAcquire (future):
 *     LockdepBeforeAcquire(lock.class_id);
 *     /// hardware acquire here ///
 *     LockdepAfterAcquire(lock.class_id);
 *
 *     // In SpinLockRelease (future):
 *     LockdepBeforeRelease(lock.class_id);
 *     /// hardware release here ///
 *
 * THREADING
 *   The graph is mutated under a single SpinLock (in lockdep.cpp).
 *   Lockdep itself uses raw `arch::Cli/Sti` for its critical
 *   section to avoid recursion through SpinLockAcquire when the
 *   primitives are eventually instrumented.
 */

namespace duetos::sync
{

using LockClass = u16;

/// Sentinel: locks with this class ID are skipped entirely. Default
/// for any uninitialised lock — the cost of unclassified locks is
/// zero overhead in the lockdep hooks (single compare-and-skip).
inline constexpr LockClass kLockClassUnclassified = 0;

/// Maximum number of distinct lock classes. Sized as 256 → graph
/// storage of 256 × 32 bytes = 8 KiB BSS. Way more than realistic
/// kernel needs; raising it doubles graph memory.
inline constexpr LockClass kLockClassMax = 256;

/// Maximum simultaneous holders per CPU. A code path that acquires
/// more than this many locks at once trips a warning and lockdep
/// degrades to "skip the deepest lock" — the existing kernel
/// already caps held-lock-stack depth at 8 in panic snapshots, so
/// matching that is the right v0 budget.
inline constexpr u32 kLockdepHeldMax = 8;

/// Optional metadata: associate a stable name with a class ID so
/// inversion reports can print something readable. Multiple
/// registrations with the same ID are allowed (the last name
/// wins; useful for late-binding tags during driver load).
/// IDs at or beyond `kLockClassMax` are silently ignored.
void LockdepRegisterClass(LockClass id, const char* name);

/// Returns the registered name for `id`, or "?" if unregistered /
/// out of range.
const char* LockdepClassName(LockClass id);

/// Call BEFORE acquiring a lock with class `id`. Walks the held
/// stack:
///   - For each currently-held class `H`, sets the graph edge
///     `H -> id` (we now know "H was held when id was acquired").
///   - If the reverse edge `id -> H` already exists, an inversion
///     is recorded: increments the detected-inversions counter
///     and logs one line via klog. Continues — does NOT panic, so
///     a known-good kernel boot can still complete with a noisy
///     graph.
///
/// `id == kLockClassUnclassified` is a no-op.
void LockdepBeforeAcquire(LockClass id);

/// Call AFTER successfully acquiring a lock with class `id`.
/// Pushes `id` onto the held stack. Pairs with
/// `LockdepBeforeRelease`. `kLockClassUnclassified` is a no-op.
void LockdepAfterAcquire(LockClass id);

/// Call BEFORE releasing a lock with class `id`. Removes one
/// occurrence of `id` from the held stack. v0 finds the topmost
/// matching entry (LIFO with skipping); a "release in the middle"
/// is allowed because some patterns release one lock while still
/// holding another. `kLockClassUnclassified` is a no-op.
void LockdepBeforeRelease(LockClass id);

/// Total inversions detected since boot. Cheap to read (one u64
/// load). The runtime checker / `inspect locks` (future) reports
/// this; non-zero is a kernel bug to triage.
u64 LockdepInversionsDetected();

/// Total edges currently recorded. Stabilises after a few seconds
/// of normal kernel operation; a steadily-growing edge count past
/// the warm-up phase indicates a code path is acquiring locks in
/// orders never previously seen.
u64 LockdepEdgesRecorded();

/// Boot-time self-test. Registers two scratch classes, simulates
/// `acquire(A); acquire(B); release(B); release(A)` (the good
/// order), then `acquire(B); acquire(A); release(A); release(B)`
/// (the inversion), asserts the inversion counter went up by
/// exactly 1. Also exercises the unclassified-skip path and
/// the held-stack overflow guard. Panics on mismatch.
void LockdepSelfTest();

} // namespace duetos::sync
