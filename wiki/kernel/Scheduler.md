# Scheduler

> **Audience:** Kernel hackers
>
> **Execution context:** Kernel — `Schedule()` runs after IRQ EOI or in `cli` cooperative paths
>
> **Maturity:** v0 (round-robin, single CPU + idle); SMP-aware bringup pending

## Overview

The DuetOS scheduler is preemptive, kernel-thread first. `SchedInit`
wraps `kernel_main` as task 0 (the boot task). `SchedStartIdle` spawns
a dedicated `idle-bsp` task that loops on `sti; hlt` so the runqueue is
never empty. `SchedCreate(entry, arg, name)` spawns a regular kernel
thread with its own 16 KiB stack. Sleep / wait queues / mutexes layer
on top.

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

Singly-linked FIFO, head + tail. The running task is **not** on the
queue. `Schedule()` re-enqueues the previous task (if still `Ready`)
before popping the head. Dead tasks are reaped — `SchedExit` pushes
the dying task onto a zombie list and wakes a reaper thread
(`g_reaper_wq`) that frees the stack + Task struct.

Preemption (timer IRQ -> `need_resched`) and cooperative yield
(`SchedYield()` -> `cli + Schedule + sti`) coexist; both push the
current task to the tail and pop the head.

## Blocking Primitives (sister doc)

`SchedSleepTicks`, `WaitQueue`, and `Mutex` were added on top of the
core scheduler. They share the task state machine but have their own
invariants. See `.claude/knowledge/sched-blocking-primitives-v0.md`.

## Known Limits / GAPs

- **No SMP yet.** Single CPU. SMP bringup will introduce per-CPU
  runqueues, work-stealing, irq-save spinlock around the runqueue, and
  per-CPU `need_resched`. See [SMP AP Bringup Scope](../advanced/SMP-AP-Bringup-Scope.md).
- **No priorities.** Every task is equal weight. A real-time class can
  layer on without rewriting the core (separate priority-0 runqueue
  checked first).
- **No userland scheduling specifics in the core yet.** Ring 3 entry
  added TSS + IST stacks and CR3 swap on context switch where the
  target task's `AddressSpace` differs.

## Related Pages

- [Memory Management](Memory-Management.md) — `Task` structs and stacks
  come from `KMalloc`
- [Boot Path](Boot.md) — when scheduler comes online
- [Process Model](Process-Model.md)
- [SMP AP Bringup Scope](../advanced/SMP-AP-Bringup-Scope.md)
