# Kernel Synchronization Primitives

> **Audience:** Kernel hackers, driver authors
>
> **Execution context:** Kernel — sleeping vs. non-sleeping primitives are
> distinct; see the table below
>
> **Maturity:** Spinlock + RCU + Seqlock active; rwlock + lockdep functional

## Overview

DuetOS keeps the synchronization toolbox in one place
([`kernel/sync/`](../../kernel/sync/)) so every other subsystem picks from a
known menu of primitives instead of inventing its own. The menu is deliberately
small — every name on it is described here, and code that grows a new
primitive (lock-free queue, hazard pointer, etc.) should land in this
directory first so callers can find it.

The kernel is preemptive and SMP-aware, but only the boot CPU is online in v0
until the SMP AP bring-up slice lands (see
[SMP AP Bring-up Scope](../advanced/SMP-AP-Bringup-Scope.md)). Most primitives
are written for the SMP case and exercise the same IRQ-save / IRQ-restore
brackets even on uniprocessor.

## Primitive Selection Table

| Primitive | File | Sleeps? | IRQ-safe? | Use when |
|-----------|------|---------|-----------|----------|
| `SpinLock` | [`spinlock.h`](../../kernel/sync/spinlock.h) | no | yes (saves IFLAGS) | Short critical sections, IRQ + process contexts mix |
| `Mutex` (via `KMutex` in `ipc/`) | [`ipc/kmutex.h`](../../kernel/ipc/kmutex.h) | yes | no | Long critical sections in process context |
| `AdaptiveMutex` | [`adaptive_mutex.h`](../../kernel/sync/adaptive_mutex.h) | maybe (spins first, parks if needed) | no | Contended mutex where the holder is usually about to release |
| `RwLock` | [`rwlock.h`](../../kernel/sync/rwlock.h) | yes | no | Read-mostly data structures, process context only |
| `Seqlock` | [`seqlock.h`](../../kernel/sync/seqlock.h) | reader: no, writer: no | yes (writer disables IRQ) | Read-side wants no atomics; writer rare |
| `RCU` | [`rcu.h`](../../kernel/sync/rcu.h) | reader: no | yes | Read-mostly, no reader blocking, deferred reclaim |
| `Lockdep` | [`lockdep.h`](../../kernel/sync/lockdep.h) | n/a | n/a | Verification only — register every lock class on first use |

The choice rule is: pick the leftmost row in the table that satisfies the
context constraint. If the call site can run from IRQ, drop to `SpinLock` or
`Seqlock`; if you need a multi-CPU reader that never blocks, use `RCU`.

## Spinlock

[`SpinLock`](../../kernel/sync/spinlock.h) is a FIFO ticket lock. Two
operations matter:

```cpp
SpinLockGuard guard{lock};  // disables IRQs, takes ticket, spins
// ...critical section...
// guard destructor releases the ticket + restores IFLAGS
```

Properties:

- **IRQ-safe**: `Acquire()` saves `IFLAGS`, masks interrupts, takes the ticket;
  `Release()` releases the ticket then restores `IFLAGS` only if it was set on
  entry. Safe to take from any context including timer IRQ.
- **FIFO**: tickets prevent starvation on the unfair backoff path GCC would
  otherwise pick under contention.
- **Assertion API**: `SpinLockAssertHeld(lock)` for "this code path must run
  under `lock`" — paired with lockdep this catches subsystem invariants at the
  call site that wrote the bug, not the one that tripped over it.

`SpinLock` is the workhorse — every allocator, runqueue, handle table, and
driver IRQ tail uses it.

### Deadlock-aware try-acquire

The blocking `SpinLockAcquire` has exactly two outcomes on a lock it can't
take: it spins (contended) or it **panics** (the calling CPU already holds
it — an otherwise-silent self-deadlock). Callers that can recover instead of
hanging use the try API:

```cpp
core::Result<IrqFlags> r = SpinLockTryAcquire(lock);   // never spins, never panics
if (r.has_value())
{
    // hold it — pass r.value() back to SpinLockRelease as usual
}
else if (r.error() == core::ErrorCode::Deadlock)
{
    // THIS CPU already holds `lock`; retry is futile — restructure / back off
}
// else core::ErrorCode::Busy — another CPU holds it; a later retry may win
```

Return-code contract:

- **`Deadlock`** — this CPU already holds the lock. The shared `HeldBySelf`
  predicate is the same one the blocking path panics on; the try path returns
  it as a typed error instead (the "self-unlock" escape — control returns to
  the caller, no hang, no panic banner).
- **`Busy`** — held by another ticket/CPU right now (`SpinLockTryAcquire`,
  fail-fast).
- **`Timeout`** — `SpinLockTryAcquireFor(lock, max_spins)` exhausted its
  `pause`-spaced spin budget (default `kSpinTryDefaultSpins`). A self-held
  lock still returns `Deadlock` immediately — spinning can never clear a lock
  this CPU holds.

`SpinLockTryGuard` is the RAII form: it attempts the (optionally bounded)
acquire on construction, releases on scope exit **only if** it succeeded
(`held()` / `bool(guard)`), and exposes the failure code via `reason()`. A
declined guard makes scope exit a clean no-op. Lockdep edges are recorded
only on the success path, so a declined attempt never pollutes the
locking-order graph. This is the AB/BA-safe primitive the per-CPU
work-stealing path is specified to use.

## Mutex (KMutex)

Sleeping mutex. The kernel object lives in [`kernel/ipc/kmutex.h`](../../kernel/ipc/kmutex.h)
because it is reachable from user-mode by handle as well as from kernel-side
callers. See [IPC](IPC.md) for the kernel-object refcount story; this section
is a pointer.

The kernel never holds a `KMutex` across a sleeping operation that depends on
the mutex (no recursion, no nested blocking I/O). The lockdep class for each
mutex must be registered on first use.

## Adaptive Mutex

[`AdaptiveMutex`](../../kernel/sync/adaptive_mutex.h) is an illumos-style
spin-then-park mutex, interface-compatible with the `sched::Mutex`
parking pattern. The uncontested fast path is the same CAS-claim; the
slow path is what distinguishes it:

- **Holder on-CPU** → spin (reading `holder->on_cpu` with acquire
  semantics each iteration). Release is imminent, so busy-waiting beats
  paying two context-switch costs to park and unpark.
- **Holder off-CPU** (blocked / sleeping / ready elsewhere) → park on
  the mutex's `sched::WaitQueue`.
- **Spin cap** `kAdaptiveSpinLimit` (10000 iterations, ~50 µs) is the
  safety net: a runaway holder stuck on its own CPU falls through to
  the park path rather than pinning a peer forever.

```cpp
void AdaptiveMutexLock(AdaptiveMutex& m);            // spin-then-park
void AdaptiveMutexUnlock(AdaptiveMutex& m);          // wakes one waiter (FIFO)
bool AdaptiveMutexTryLock(AdaptiveMutex& m);         // non-blocking
bool AdaptiveMutexIsHeld(const AdaptiveMutex& m);    // diagnostic only
```

It is a strict Pareto improvement over always-park `sched::Mutex`: the
uncontested case is identical, the contended case is at worst what
`sched::Mutex` already pays. **Not** recursive, **not** IRQ-safe (both
the spin and park paths can block; IRQ-context callers use `SpinLock`),
no priority inheritance, and no timed acquire (use `MutexLockTimed` for
that). Lockdep integration mirrors `sched::Mutex` via the `m_class_id`
field; untagged mutexes short-circuit the hooks. A boot self-test
(`AdaptiveMutexSelfTest`, called from `boot_bringup.cpp` after the
SpinLock self-test) exercises the fast path, `TryLock`, lockdep
round-trip, and two-task contention, emitting
`[adaptive-mutex] self-test OK`.

## RwLock

[`RwLock`](../../kernel/sync/rwlock.h) is a sleeping reader-writer lock on top
of a `Mutex` + condition variable. It is **not IRQ-safe** by design: the read
path can block waiting for a writer to release. Use it for trees or tables
where readers vastly outnumber writers and where readers are running in
process context (filesystem caches, module registry).

If you need a read-side that never blocks, use [Seqlock](#seqlock) or
[RCU](#rcu) instead.

## Seqlock

[`Seqlock`](../../kernel/sync/seqlock.h) gives a lock-free reader against a
locked writer:

```cpp
do {
    u32 seq = SeqlockReadBegin(sl);
    // copy fields ...
} while (SeqlockReadRetry(sl, seq));
```

- Writer takes a spinlock, increments seq to odd, writes, increments seq to
  even — the reader retries any read that observed an odd seq or a mismatched
  seq across copy.
- Excellent for "timekeeper snapshot" / "topology table" / per-CPU stat
  shapes — the reader does no atomics, no IRQ-mask, and never blocks.
- Bad fit when the read-side copies a large struct: every byte must be
  consistent on retry, so big payloads multiply work under contention.

## RCU

[`RCU`](../../kernel/sync/rcu.h) is a lite read-copy-update with deferred
reclaim. Two halves:

- **Read path**: `RcuRead()` brackets a critical section. Nothing in the
  bracket blocks; nothing in the bracket touches a writer-managed pointer
  past a `RcuRead()` exit.
- **Reclaim**: `RcuCall(ptr, free_fn)` queues a callback to fire after every
  currently-executing read-side critical section has finished. The
  draining itself runs from the heartbeat thread (`RcuTick()`).

Used for: capability tables, the syscall name index, anything where a writer
swaps a pointer and the old value's lifetime is the union of all in-flight
read-side critical sections. **Not** a general "all reads are free" magic
button — the reclaim cadence is set by `RcuTick()` cadence.

## Lockdep

[`Lockdep`](../../kernel/sync/lockdep.h) records the lock acquisition order
the first time it sees a pair `(A, B)` and panics if a subsequent path
tries `(B, A)`. The contract:

- **Register** each lock class on first use with `LockdepRegisterClass(name)`.
- **Bracket** real acquisitions with `LockdepBeforeAcquire()` /
  `LockdepAfterAcquire()` / `LockdepBeforeRelease()`. The spinlock and mutex
  primitives do this automatically; raw locks need manual brackets.
- Lockdep is "lite" — it catches AB-BA at the moment it happens, but does not
  yet implement the full graph cycle detector that Linux's lockdep ships.
  Adequate for kernel-of-DuetOS scale; revisit if the lock graph crosses 30+
  nodes.

- **Per-task held-set.** The held-class stack is logically per-task, not
  global. A sleeping `sched::Mutex` is held across context switches; with a
  single shared stack, two tasks independently and correctly holding two
  different mutexes were reported as a false AB-BA inversion (the
  compositor↔fat32 case, ~40×/boot). The scheduler snapshots the running
  task's held set into the outgoing `Task` immediately before
  `ContextSwitch` (`LockdepHeldSnapshot`) and restores the resumed task's
  in `SchedFinishTaskSwitch` (`LockdepHeldRestore`) — placed *after* the
  fresh-AP guard and gated on `state == Running`, because restoring at the
  top of that function raced an unarmed AP's `current_task` and crashed
  intermittently during AP bring-up. Fresh tasks are seeded
  `[kLockClassSched]` so the trampoline's first `g_sched_lock` release is
  balanced. Verified false-positive-free across an 8-boot determinism
  sweep; this is the precondition for the fail-stop `g_promote_to_panic`
  gate.

`LockdepReset()` is wired to the boot self-test and to the panic path so a
late-boot crash doesn't poison subsequent test runs.

## Common Pitfalls

- **Spinlock + sleep**: never call a function that can sleep (e.g. `KMalloc`
  if you grow past one slab, `KFile` I/O, condition wait) while holding a
  spinlock. The runtime checker scans for this.
- **IRQ context restrictions**: anything reachable from a timer or device
  IRQ must use IRQ-safe primitives only (`SpinLock`, `Seqlock` reader,
  `RCU` reader). Touching a `KMutex` from IRQ is a triple-fault waiting
  to happen.
- **Zero-init**: every embedded primitive expects zero-initialised storage to
  be "unlocked / empty". `KMalloc` returns dirty memory — wrap the
  primitive in a struct that's `memset(0)`'d at construction. See
  [Coding Standards](../tooling/Coding-Standards.md#zero-init-pattern).
- **Lock ordering inversions**: when adding a new lock class, register it
  before any caller takes it, and exercise the realistic
  acquire-order in a smoke test so lockdep catches the regression.

## Known Limits / GAPs

- **MCS spinlock**: ticket spinlock under high contention degrades to
  cache-line-bounce. Per-CPU MCS queueing is a tracked optimisation; revisit
  once a profile shows it.
- **Full lockdep graph**: cycle detection is one-step; deep cycles
  (`A → B → C → A`) are not yet caught. Add when the kernel's lock graph
  grows past ~30 named classes.
- **RCU grace-period detection**: `RcuTick()` is a single counter advanced
  on the heartbeat. A true tree-RCU is overkill for the current core count;
  revisit when SMP scales past 8 CPUs.

## Related Pages

- [Memory Management](Memory-Management.md) — allocators that wrap their own
  IRQ-save brackets on top of these primitives
- [Scheduler](Scheduler.md) — runqueue locking
- [IPC](IPC.md) — `KMutex`, `KEvent`, `KSemaphore` kernel objects layered on
  top of `SpinLock` + wait queues
- [SMP AP Bring-up Scope](../advanced/SMP-AP-Bringup-Scope.md) — when SMP
  scaling enters the lock fan-out picture
- [Coding Standards](../tooling/Coding-Standards.md) — zero-init pattern,
  member naming conventions
