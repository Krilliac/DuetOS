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
 * SCOPE
 *   - Graph storage + edge recording + cycle detection.
 *   - Per-CPU held-class stack (`acpi::kMaxCpus` slots, indexed
 *     by `cpu::CurrentCpuIdOrBsp()` inside `Cli`) for spinlock
 *     classes; per-task held-class stack threaded through
 *     `Task` + the context-switch boundary for sleeping mutex
 *     classes (so a mutex held across a yield-and-resume on a
 *     different CPU stays attributed to the holding task).
 *   - Self-test that synthesises `A then B` followed by `B then A`
 *     and asserts an inversion is reported.
 *
 *   NOT IN SCOPE (tracked as D1 follow-ups in the plan):
 *   - Hooking every SpinLock / Mutex / RwLock instance — class
 *     IDs are wired at the primary acquire/release sites; per-
 *     instance disambiguation arrives when a workload needs it.
 *   - Promoting warnings to panics after a stabilisation window.
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

/// Canonical class IDs for the kernel's hot global locks. Tagging
/// is opt-in: a lock declared without `class_id` set stays
/// unclassified and bypasses the lockdep hooks. IDs in the
/// 0x01..0x3F range are reserved for hot globals; the self-test
/// uses 0x40..0xFF for scratch classes (see lockdep.cpp).
///
/// ==========================================================
/// CANONICAL KERNEL LOCK HIERARCHY (acquire-top-down only)
/// wiki/security/Linux-CVE-Audit.md class GG.
/// ==========================================================
///
/// Acquire in this order when nested. Releasing is LIFO (any
/// order that respects "no lock outlives a lock acquired after
/// it"). Lockdep flags any inversion against this graph as a
/// "deadlock waiting to happen" — fix the code, not the rule.
///
///   1.  kLockClassSched         (scheduler runqueue / wait-queue)
///   2.  kLockClassCompositor    (UI compositor — runs from kernel task)
///   3.  kLockClassKObject       (IPC object refcount ledger)
///   4.  kLockClassKStack        (kernel-stack arena)
///   5.  kLockClassFat32         (FAT32 driver mutex)
///   6.  kLockClassWifi          (WiFi driver mutex)
///   7.  kLockClassBreakpoints   (kernel-debug breakpoint table)
///   8.  kLockClassCleanroomTrace (cleanroom-mode trace ring)
///   9.  kLockClassPciConfig     (PCI configuration access)
///
/// ABSOLUTE RULES (do not violate even with lockdep off):
///
///   - **No sleeping with a spinlock held.** The scheduler's
///     `WaitQueueBlock` already requires interrupts off (Cli);
///     a spinlock held across a wake-or-block can deadlock the
///     CPU. Locks 1..9 above are spinlocks or mutexes; the
///     mutex variants (Fat32, Compositor) MAY sleep but the
///     spinlock variants (Sched, KObject) MUST NOT be held
///     across a sleep.
///
///   - **No lock held across CR3 switch.** `AddressSpaceActivate`
///     flips CR3; any lock whose backing data lives in the
///     outgoing AS becomes inaccessible immediately. Drop every
///     lock before the switch.
///
///   - **No lock held across TlbShootdownAddr / Range.** The
///     shootdown spins waiting for peer-CPU acks; if those
///     peers are blocked on the same lock, you deadlock. See
///     wiki/security/Linux-CVE-Audit.md class FF.
///
/// PRE-LANDING FOR PER-CPU RUNQUEUES (B2-followup):
/// The single-CPU sched lock today is conservative — every wake
/// serialises through it. When `g_sched_lock` splits per-CPU,
/// inter-CPU wakes will need to acquire a SECOND CPU's
/// runqueue lock, and the rule "always lower-cpu-id first"
/// gets added to this list. Until then, hold at most one
/// runqueue lock at a time.
inline constexpr LockClass kLockClassSched = 0x01;
inline constexpr LockClass kLockClassKObject = 0x02;
inline constexpr LockClass kLockClassKStack = 0x03;
inline constexpr LockClass kLockClassPciConfig = 0x04;
inline constexpr LockClass kLockClassBreakpoints = 0x05;
inline constexpr LockClass kLockClassCleanroomTrace = 0x06;
inline constexpr LockClass kLockClassWifi = 0x07;
/// FAT32 driver mutex (`fs/fat32.cpp::g_fat32_mutex`). Serialises
/// every block-IO + path-walk; held across reads/writes to the
/// underlying storage device. Acquire ordering: BELOW the
/// scheduler / kobject classes (FAT32 ops can run on a worker
/// task and may want to allocate KObjects mid-call), ABOVE any
/// future per-NVMe-queue lock. Tagged D1-followup, 2026-04-27.
inline constexpr LockClass kLockClassFat32 = 0x08;
/// Compositor mutex (`drivers/video/widget.cpp::g_compositor_mutex`).
/// Serialises the per-frame widget tree walk + dirty-region
/// accumulation. Held during framebuffer flushes. Acquire
/// ordering: ABOVE the scheduler / kobject classes (compositor
/// runs from a kernel task and never holds another global lock
/// across a flush). Tagged D1-followup, 2026-04-27.
inline constexpr LockClass kLockClassCompositor = 0x09;

/// Maximum simultaneous holders per CPU. A code path that acquires
/// more than this many locks at once trips a warning and lockdep
/// degrades to "skip the deepest lock" — once a push is dropped,
/// the matching release later finds nothing on the held stack and
/// emits "release with no matching held entry" once per orphaned
/// release.
///
/// The original v0 cap of 8 matched the panic-dump snapshot cap,
/// but steady-state DuetOS already reaches a deeper nest in
/// production paths: fs/fat32 path resolution holds fs/vfs +
/// fs/fat32 + handle-table + sched + several mutexes (kmutex,
/// kfile pool, compositor flush). Once the late Phase::Userland
/// self-tests (ELF/DLL/Win32-custom/load-balance) populate the
/// heap, the steady-state fs/compositor pump can hit 30+ levels
/// on long-running boots, especially during compositor↔fat32
/// inversion-warning storms where every detected inversion adds
/// to the held-stack churn. 128 gives ~10× the observed real
/// maximum so the lockdep view stays accurate without inflating
/// the per-CPU memory footprint meaningfully (128 × 1 byte =
/// 128 B per CPU).
inline constexpr u32 kLockdepHeldMax = 128;

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

/// Per-task held-set support. A sleeping `sched::Mutex` is held
/// ACROSS context switches; with a single global held stack, two
/// tasks independently and correctly holding two different
/// mutexes get reported as a lock-order inversion (the classic
/// compositor↔fat32 false positive — see wiki Roadmap). The
/// scheduler snapshots the running task's held stack into the
/// outgoing Task immediately before `ContextSwitch`, and restores
/// the resumed task's on the way back in (in `SchedFinishTaskSwitch`,
/// AFTER the fresh-AP guard and only for a Running task — attempt 1
/// restored at the very top, before that guard, and an
/// intermittent AP-bringup race dereferenced a not-yet-armed
/// `Current()`). Spinlocks are never live across a switch except
/// the scheduler-lock handoff, which is symmetric and absorbed by
/// `LockdepBeforeRelease`'s not-found no-op, so no per-class tag
/// is needed. Both run under lockdep's own cli critical section;
/// a fresh task's zero-initialised buffer (depth 0) is the
/// correct empty held-set.
///
/// `LockdepHeldSnapshot` copies up to `cap` entries into `out`
/// and returns the depth written. `LockdepHeldRestore` overwrites
/// the global held stack with `in[0..depth)`.
u32 LockdepHeldSnapshot(LockClass* out, u32 cap);
void LockdepHeldRestore(const LockClass* in, u32 depth);

/// Total inversions detected since boot. Cheap to read (one u64
/// load). The runtime checker / `inspect locks` (future) reports
/// this; non-zero is a kernel bug to triage.
u64 LockdepInversionsDetected();

/// Set the promote-to-panic policy (plan D1-followup). When
/// true, any subsequent inversion is a hard panic instead of a
/// klog warning. Default false — a boot under instrumentation
/// can complete with a noisy graph so the operator can collect
/// evidence first. The shell `lockdep panic on|off` command
/// flips this; CI eventually pins it to ON. Past inversions
/// (already detected) are unchanged; only new detections are
/// affected.
void LockdepSetPromoteToPanic(bool enabled);

/// Read the current promote-to-panic policy. Cheap bool load;
/// useful for the shell to print "panic-on-inversion: on/off"
/// in `inspect lockdep`.
bool LockdepPromoteToPanic();

/// Total edges currently recorded. Stabilises after a few seconds
/// of normal kernel operation; a steadily-growing edge count past
/// the warm-up phase indicates a code path is acquiring locks in
/// orders never previously seen.
u64 LockdepEdgesRecorded();

/// Register the canonical names for the kLockClass* constants
/// declared above (sched / kobject / kstack / pci-config /
/// breakpoints). Called from `kernel_main` after the lockdep
/// self-test so any subsequent SpinLock acquire that crosses a
/// tagged class fires its hooks against named classes — inversion
/// reports become readable instead of "class 0x01 vs class 0x03".
/// Idempotent; safe to call more than once.
void LockdepRegisterCanonicalClasses();

/// Reset all lockdep state — held-class stack on every CPU, the
/// edge-graph, the inversion counter, the promote-to-panic
/// knob. Pairs with `LockdepRegisterCanonicalClasses` so the
/// lockdep subsystem can be a driver fault domain (E3-followup):
/// teardown calls `LockdepReset`, init re-registers the
/// canonical class names + carries on. Used to re-baseline the
/// graph after triaging a noisy inversion run.
void LockdepReset();

/// Boot-time self-test. Registers two scratch classes, simulates
/// `acquire(A); acquire(B); release(B); release(A)` (the good
/// order), then `acquire(B); acquire(A); release(A); release(B)`
/// (the inversion), asserts the inversion counter went up by
/// exactly 1. Also exercises the unclassified-skip path and
/// the held-stack overflow guard. Panics on mismatch.
void LockdepSelfTest();

} // namespace duetos::sync
