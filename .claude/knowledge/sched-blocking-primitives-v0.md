# Scheduler Blocking Primitives v0 — Sleep, Wait Queues, Mutex

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The v0 scheduler started as round-robin with only `Ready`, `Running`,
and `Dead` states. On top of that we've now added three blocking
primitives that share a common pattern: a task flips to a non-runnable
state, gets parked on a data structure owned by the thing it's waiting
on, and is moved back to `Ready` by whoever eventually satisfies the
wait.

1. **Sleep** — `SchedSleepTicks(n)`. Task parks on the global
   sleep queue (sorted by `wake_tick`). The timer IRQ's `OnTimerTick`
   wake path scans the head of the queue and promotes any expired
   entry to `Ready`.
2. **Wait queue** — `WaitQueue` + `WaitQueueBlock` /
   `WaitQueueWakeOne` / `WaitQueueWakeAll`. A user-owned FIFO of
   tasks blocked on some event. The waker decides when to promote.
3. **Mutex** — `Mutex` + `MutexLock` / `MutexUnlock` / `MutexTryLock`.
   Built on top of a `WaitQueue` with FIFO hand-off (Unlock assigns
   `owner = next_waiter` BEFORE waking it, so there's no
   thundering-herd re-race).

Worker self-test in boot: three threads each bump a shared counter
five times while holding the demo mutex. Final counter is `0x0F` (15);
prints interleave but no value is ever skipped. If the mutex machinery
were broken, two workers would read the same `before` and both write
`before + 1`, losing one increment.

## Context

Applies to:

- `kernel/sched/sched.h` — declares `TaskState::{Sleeping,Blocked}`,
  `WaitQueue`, `Mutex`, and the `SchedSleepTicks` /
  `WaitQueueBlock` / `MutexLock` API
- `kernel/sched/sched.cpp` — owns `g_sleep_head`, `g_tasks_sleeping`,
  `g_tasks_blocked`; defines `OnTimerTick`, `WaitQueueBlock`,
  `WaitQueueWakeOne`, `WaitQueueWakeAll`, `MutexLock`, `MutexUnlock`,
  `MutexTryLock`
- `kernel/arch/x86_64/timer.cpp` — `TimerHandler` calls
  `sched::OnTimerTick(TimerTicks())` every tick (the sleep wake path)

Depends on the core scheduler (`scheduler-v0.md`) and the LAPIC timer
(`lapic-timer-v0.md`). Unblocks: driver IRQ waits, producer/consumer
pipelines, any kernel code that needs to block pending an event.

## Details

### Task state machine (current)

```
            SchedCreate                      Schedule() picks us
    (none) ────────────▶ Ready ──────────────────────▶ Running
                         ▲  ▲                          │
                         │  │                          │
        OnTimerTick wake │  │ WaitQueueWake*       SchedSleepTicks
        (expired)        │  │ (Mutex hand-off inc.)    │
                         │  │                          ▼
                      Sleeping ◀─────── Running ───▶ Blocked
                         ▲                              ▲
                         │                              │
                         └──── via WaitQueueBlock ──────┘
                               (actually Blocked, not Sleeping;
                                the arrow above is wrong; see code)

                          Schedule() sees Running
                                 │
                                 ▼
                     [SchedExit] ──▶ Dead
```

Invariants:

- `Running` means exactly one CPU is currently executing this task.
  Single-CPU today, per-CPU `g_current` tomorrow.
- `Ready` ⟺ on the runqueue (`g_run_head` / `g_run_tail` FIFO).
- `Sleeping` ⟺ on the sleep queue (`g_sleep_head`, sorted by
  `wake_tick`).
- `Blocked` ⟺ on some `WaitQueue` (user-owned, FIFO).
- `Dead` is terminal. No transition out.

A task is on **exactly one** queue at a time, or on no queue iff it's
`Running`. Cross-linking is a bug.

### Interrupt discipline

Every blocking primitive follows the same pattern:

```cpp
arch::Cli();
// 1. Check condition; maybe go blocking.
// 2. Mutate queue state.
// 3. Schedule() — may context-switch out.
// 4. Back from Schedule; we've been woken.
arch::Sti();
```

The CLI closes the race between "decide to block" and "someone else
wakes us before we're on the queue". Without it, an IRQ could wake us
when we haven't enqueued yet, and then our own `Schedule` would park us
with nobody holding a reference to us — deadlock. The `Schedule` call
does not touch RFLAGS; IF state persists across the context switch
round-trip.

Callers of the wake primitives (`WaitQueueWakeOne`, `WaitQueueWakeAll`,
`MutexUnlock`) **must also hold IF=0**. `MutexUnlock` handles this
itself; direct `WaitQueueWakeOne` callers from task context must
`arch::Cli()` / `arch::Sti()` around the call. IRQ handlers already
run with IF=0, so wakes from IRQ context are fine as-is.

### Sleep queue — sorted insert, head-only wake

Sleeping tasks live on `g_sleep_head`, a singly-linked list sorted
ascending by `wake_tick`. `SleepqueueInsert` walks the list once
(O(n)). `OnTimerTick` repeatedly pops the head while `tick_now >=
head->wake_tick` (the common case moves 0 or 1 nodes per tick).

Tick comparisons use a wrap-safe compare:

```cpp
static_cast<i64>(now - deadline) >= 0
```

This keeps the comparison correct even across the 64-bit tick wrap
(happens at 100 Hz after ~5.8 billion years — not a practical concern,
but free to get right).

### WaitQueue — dumb FIFO, FIFO wake

Two pointers, head + tail. `WaitQueueBlock` appends the caller and
calls `Schedule`. `WaitQueueWakeOne` pops head, sets `Ready`, pushes
onto the runqueue, sets `g_need_resched`. The wake does NOT context-
switch immediately; it just makes the woken task runnable so the next
`Schedule()` (from the timer, from a yield, or from the caller finishing
whatever they're doing) picks it up.

### Mutex — hand-off vs. thundering-herd

`Unlock` does **hand-off**: when waking a waiter, it sets
`m->owner = next` **before** waking. The woken task's `MutexLock`
returns with the lock already held (by itself). Compare to
thundering-herd: wake everyone, clear owner, let them re-race → loses
FIFO fairness and wastes cycles.

Consequence: a woken waiter of `MutexLock` must NOT try to re-acquire
the lock. The fast path in `MutexLock` is:

```cpp
if (m->owner == nullptr) { m->owner = current; return; }   // fast
WaitQueueBlock(&m->waiters);                               // slow
// when we return here, m->owner == current (hand-off did it)
```

Any future addition of non-mutex wakers on the same queue would break
this — don't reuse `m->waiters` for anything else.

### `MutexUnlock` by non-owner is a panic

`MutexUnlock` checks `m->owner == g_current` and halts the kernel if
not. This catches the two common bugs: unlocking a mutex you never
locked, and re-entrant unlock (double-unlock). The cost is one compare
per unlock — worth it to turn an elusive corruption bug into an
immediate panic.

### Self-test (in `core/main.cpp`)

Three worker threads, each doing:

```cpp
for (u64 i = 0; i < 5; ++i) {
    MutexLock(&s_demo_mutex);
    u64 before = s_shared_counter;
    busy_wait(~2ms);                // guarantee contention
    s_shared_counter = before + 1;
    SerialWrite("... counter=...\n");
    MutexUnlock(&s_demo_mutex);
    SchedSleepTicks(1);             // 10 ms nap → hits sleep path
}
```

Signals the test gives:

- Final `counter=0x0F` after 15 prints → mutex serialises correctly.
- Prints interleave (e.g. A, C, B, A, C, B, …) → preemption works
  while the mutex is held; workers do in fact contend.
- No print shows a skipped value (e.g. no jump from 0x05 to 0x07) →
  the critical section is mutually exclusive.
- All workers eventually run → no starvation; FIFO hand-off works.

### Regression canaries

- **Counter ends at less than 0x0F** → mutex isn't actually mutually
  exclusive. Check that `MutexLock`'s slow path really blocks (not a
  busy wait that returns with owner != null).
- **One worker hogs every lock, others starve** → hand-off broken.
  Likely `Unlock` is clearing owner without assigning to next waiter,
  so the first to re-lock (often the just-unlocked task, already hot on
  the CPU) wins.
- **Kernel hangs after first `MutexLock` contention** →
  `WaitQueueBlock` is not setting state to `Blocked`, or `Schedule`
  is picking the blocked task anyway. Double-check state transitions.
- **`MutexUnlock by non-owner` panic on legitimate code** → a caller
  is double-unlocking or unlocking a mutex it never locked.
- **Sleeping task never wakes** → `OnTimerTick` not wired into
  `TimerHandler`, or sleep queue insert put the task at the wrong
  position (ascending-by-wake-tick violated).

## Notes

- **No condition variables yet.** The classic "wait for condition with
  mutex held, atomically drop mutex on block" pattern isn't built.
  Workaround: drop the mutex, sleep briefly, re-check. Build a real
  condvar the first time a caller actually needs one.
- **No timed waits on WaitQueue.** `WaitQueueBlock` blocks until wake;
  no "block for up to N ticks" API. Add when the first caller needs
  it (USB timeouts, semaphore trywait, etc.).
- **No interruption / cancellation.** A blocked task cannot be pulled
  off its WaitQueue by a third party. When we add signals or thread
  cancellation, the cancel path must be able to remove a task from
  whatever queue it's on.
- **Recursion not supported on `Mutex`.** Locking a mutex you already
  hold deadlocks (the slow path parks you on your own wait queue,
  which only your own Unlock can drain — catch-22). Add an owner-
  check fast path if a recursive variant ever becomes necessary.
- **Priority inversion exists.** No priorities today, so moot. Once
  priorities land, the mutex will need priority inheritance or at
  least priority ceiling, or a high-priority task behind a low-
  priority one on a contended mutex will stall indefinitely.
- **No SMP.** Everything assumes single CPU. SMP bring-up will:
  - wrap WaitQueue head/tail with a spinlock,
  - wrap Mutex owner/waiters with a spinlock,
  - make `g_need_resched` per-CPU,
  - handle the remote-wake case (wake a task currently about to be
    scheduled on another CPU → needs IPI).
- **See also:**
  - [scheduler-v0.md](scheduler-v0.md) — base round-robin +
    preemption; this doc is the blocking layer on top.
  - [lapic-timer-v0.md](lapic-timer-v0.md) — drives the sleep queue.
  - [kernel-heap-v0.md](kernel-heap-v0.md) — allocator behind
    `Task` structs; `WaitQueue` and `Mutex` are typically embedded in
    driver/subsystem structs so they don't add allocations of their
    own.
