# Scheduler

> **Audience:** Kernel hackers
>
> **Execution context:** Kernel — `Schedule()` runs after IRQ EOI or in `cli` cooperative paths
>
> **Maturity:** SMP-online — per-CPU runqueues, work-stealing, reschedule-IPI, cluster-aware wake placement, periodic active load balancer; single global `g_sched_lock` (per-CPU lock split deferred)

## Overview

The DuetOS scheduler is preemptive, kernel-thread first, and SMP. Each
CPU has its own runqueue (Normal + Idle bands) stored in `cpu::PerCpu`.
`SchedInit` wraps `kernel_main` as task 0 (the boot task) on the BSP;
`SchedStartIdle` spawns a per-CPU idle task (`idle-bsp` on the BSP,
`idle-apN` on each AP) that loops on `sti; hlt` so each CPU's runqueue
is never empty. `SchedCreate(entry, arg, name)` spawns a regular kernel
thread with its own 64 KiB stack on the spawning CPU's runqueue. Sleep
/ wait queues / mutexes layer on top.

Cross-CPU work routing: every Task carries a `last_cpu` field updated
on every `Schedule()` switch-in. `RunqueuePush(t)` enqueues on
`t->last_cpu`'s runqueue (cache affinity) and fires a reschedule-IPI
(vector `0xF8`, see `arch::SmpSendReschedIpi`) at the target CPU when
it's not the current one — wake-to-run latency drops from ~10 ms (next
tick) to microseconds.

Idle CPUs steal: when `RunqueuePopRunnable` finds the local runqueue
empty, `StealNormalFromPeer` walks peer CPUs round-robin and lifts one
Normal-band task. Stolen tasks have their `last_cpu` updated to the
stealer so the next wake routes here.

## Task Struct

```cpp
struct Task {
    u64         id;
    TaskState   state;       // Ready | Running | Dead
    u64         rsp;         // saved SP (valid only when NOT running)
    u8*         stack_base;
    u64         stack_size;  // 16 KiB today
    const char* name;
    Task*       next;        // intrusive runqueue link
};
```

## Context Switch ABI

```
ContextSwitch(u64* old_rsp_slot, u64 new_rsp)
```

Pushes the six SysV callee-saved GPRs (rbx, rbp, r12..r15), stashes the
SP into `*old_rsp_slot`, adopts `new_rsp`, pops, `ret`s. The return
target is whatever quad is on top of the new stack — either the
previous `Schedule()` return address (for a resumed task) or
`SchedTaskTrampoline` (for a fresh task).

## EOI-then-Schedule Ordering (critical)

The IRQ dispatcher's order is fixed:

```cpp
handler();                                  // TimerHandler sets need_resched
if (vector != 0xFF) LapicEoi();             // ack THIS IRQ first
if (sched::TakeNeedResched()) Schedule();   // may context-switch
```

EOI **must** come before `Schedule()`. Otherwise the LAPIC's in-service
bit for vector 0x20 stays set across the switch, the next timer tick
on this CPU is suppressed, and the kernel hangs after a single tick.

## First-run IF=0 Trap

A fresh task's first instruction must be `sti` (in `SchedTaskTrampoline`).
A previously-run task is resumed via the IRQ path, which `iretq`s with
`RFLAGS.IF` restored from the saved frame. A fresh task arrives via
plain `ContextSwitch`, which does not touch `RFLAGS`, so it would run
with interrupts disabled forever.

## Runqueue

Per-CPU singly-linked FIFO, head + tail, in two priority bands
(Normal + Idle). The four head/tail pointers live in `cpu::PerCpu`
(`runq_head_normal`, `runq_tail_normal`, `runq_head_idle`,
`runq_tail_idle`). The running task is **not** on the queue.
`Schedule()` re-enqueues the previous task (if still `Ready`) on its
`last_cpu` runqueue before popping the local head. Dead tasks are
reaped — `SchedExit` pushes the dying task onto the global zombie
list and wakes a reaper thread (`g_reaper_wq`) that frees the stack
+ Task struct.

Preemption (timer IRQ -> `need_resched`, per-CPU) and cooperative
yield (`SchedYield()` -> `cli + Schedule + sti`) coexist; both push
the current task to the tail and pop the head.

**Lock granularity**: today every per-CPU runqueue is still
covered by the single global `g_sched_lock`. The data structures
are per-CPU; the lock is not. Splitting the lock per-CPU is a
follow-up — every Schedule() call on every CPU still serialises
on `g_sched_lock`.

**Lock-passing across `ContextSwitch`**: `Schedule()` holds
`g_sched_lock` across the stack swap. The source CPU writes the
lock pointer + saved IRQ flags into its `cpu::PerCpu`'s
`ctxsw_lock_to_release` slot; the resumed code (`SchedFinishTaskSwitch`
in `Schedule()` post-switch, or `SchedTaskTrampoline` for fresh tasks)
drains the slot and releases. Mirrors Linux's `prepare_task_switch`
/ `finish_task_switch`. Closes the SMP race where a peer CPU could
wake `prev` between an early lock release and the actual stack swap.

**Work-stealing**: when `RunqueuePopRunnable` finds the local
runqueue empty, `StealNormalFromPeer` walks peer CPUs round-robin
(starting from `cpu_id+1`) and lifts the head of the first non-empty
peer Normal-band queue. Stolen tasks have their `last_cpu` updated
so the next wake routes to the stealer.

The walk is **two-pass cluster-aware**: pass 0 visits only peers
that share `self`'s `cluster_id` (NUMA node, or package on UMA
boxes); pass 1 covers cross-cluster peers. On a single-cluster
machine pass 0 finds every peer (every `cluster_id == 0`) so the
behaviour is identical to the pre-clustering scheduler — no
regression. See [CPU Topology](CPU-Topology.md) for how cluster
IDs are assigned at boot.

**Periodic active balancing**: covers the case neither wake
placement nor work-stealing can — two CPUs both busy with
long-running tasks, neither going idle, no new wake events. Fired
from `OnTimerTick` every `kBalancePeriodTicks` (8 ticks ≈ 80 ms at
100 Hz), phase-shifted by `cpu_id` so different CPUs balance on
different ticks. Migrates one Ready task from the heaviest
same-cluster peer when `peer.runq_normal_len ≥ self.runq_normal_len
+ kBalanceMargin` (margin = 4). After one migration the delta drops
to 2, which equals `kClusterPlacementMargin` — the wake-side floor
— so the system settles without oscillation.

Cross-cluster active migration is intentionally absent: the cache
penalty for crossing a NUMA / package boundary dwarfs the imbalance
cost. Cross-cluster idle peers are handled by work-stealing's pass 1.
Operator-pinned steady-state load uses `SchedSetAffinity`.

Boot self-test: `sched-loadbalance-selftest` (Phase::Userland)
verifies the decision function — same-cluster scoping, margin
threshold, UP short-circuit. Emits one `[sched-loadbalance-selftest] PASS`
line so CI can grep for it.

## Blocking Primitives (sister doc)

`SchedSleepTicks`, `WaitQueue`, and `Mutex` were added on top of the
core scheduler. They share the task state machine but have their own
invariants:

- `SchedSleepTicks(n)` enqueues the current task on a sleep timer
  list, blocks, and is woken by the timer IRQ when its deadline
  expires.
- `WaitQueue::Block` enqueues the current task on a queue and yields;
  `WaitQueue::WakeOne` / `WakeAll` move tasks back to the runqueue.
- `Mutex` is implemented over `WaitQueue` — uncontended fast path is
  a CAS, contended path blocks on the queue.
- `WaitQueueBlockTimeout(deadline_ticks)` couples the two: woken
  whichever fires first (signal vs timeout). Used by driver
  command-completion paths.
- `WorkPool` (`kernel/sched/workpool.h`) is the consolidating
  primitive on top of `Mutex` + `Condvar`: N worker tasks pulling
  `(fn, arg)` items from a shared bounded FIFO. Subsystems that
  would otherwise hand-roll a one-shot `SchedCreate` per request
  use `WorkPoolSubmit` instead — items run concurrently across
  CPUs, back-pressure on a full queue is automatic, and the
  pool's `Drain` / `Shutdown` give a clean quiescence point. Boot
  self-test (`workpool-selftest`, Phase::Sched) exercises Submit
  blocking, Drain, and worker join.

The contract: every block-yields-to-scheduler primitive must clear
`Running` before pushing onto a wait list, and the corresponding wake
must transition `Ready` and re-enqueue.

## Known Limits / GAPs

- **Single global `g_sched_lock`.** Per-CPU runqueues are in place
  (`cpu::PerCpu`) but every mutation still serialises on one global
  ticket spinlock. Per-CPU lock split is Roadmap **B2-followup** —
  defer until profiles show contention.
- **No priorities beyond Normal/Idle.** Within Normal every task is
  equal weight. The Win32 priority class is wired (`Process::win32_priority_class`)
  but the scheduler ignores it; aging / decay rides on the per-CPU
  lock split (Roadmap T8-01-followon).
- **No userland scheduling specifics in the core yet.** Ring 3 entry
  added TSS + IST stacks and CR3 swap on context switch where the
  target task's `AddressSpace` differs.

## Related Pages

- [Memory Management](Memory-Management.md) — `Task` structs and stacks
  come from `KMalloc`
- [Boot Path](Boot.md) — when scheduler comes online
- [Process Model](Process-Model.md)
- [SMP AP Bringup Scope](../advanced/SMP-AP-Bringup-Scope.md)
