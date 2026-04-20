# Scheduler v0 — Round-robin Kernel Threads with Preemption

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The kernel runs multiple threads now. `SchedInit` wraps `kernel_main` as
task 0 (the idle/boot task). `SchedCreate(entry, arg, name)` spawns a
kernel thread with its own 16 KiB stack. The LAPIC timer IRQ sets a
`need_resched` flag; the IRQ dispatcher calls `Schedule()` after EOI.
Round-robin runqueue, single CPU, kernel-only threads. Self-test in
boot: three worker threads print name + iteration + current tick count,
each exit after 5 iterations; boot log interleaves A/B/C, proving
preemption works.

## Context

Applies to:

- `kernel/sched/sched.{h,cpp}` — public API and runqueue
- `kernel/sched/context_switch.S` — `ContextSwitch` + `SchedTaskTrampoline`
- `kernel/arch/x86_64/timer.cpp` — `TimerHandler` now calls
  `SetNeedResched` after the heartbeat print
- `kernel/arch/x86_64/traps.cpp` — `TrapDispatch` consults
  `TakeNeedResched` AFTER EOI and calls `Schedule()` if set

Depends on the kernel heap (for `Task` structs and per-task stacks) and
on the LAPIC timer (for the tick source). Unblocks: sleep/wait queues,
mutexes, IPC, the first userland process.

## Details

### Task struct

```cpp
struct Task {
    u64         id;
    TaskState   state;         // Ready | Running | Dead
    u64         rsp;           // saved SP — valid only when NOT running
    u8*         stack_base;    // lowest address of the 16 KiB kernel stack
    u64         stack_size;
    const char* name;
    Task*       next;          // intrusive runqueue link
};
```

`rsp` is meaningful only when the task is off-CPU. While it's running,
the CPU's RSP holds the live value; `rsp` in the struct is stale.

### Context switch ABI

```
ContextSwitch(u64* old_rsp_slot, u64 new_rsp)
```

Pushes the six SysV callee-saved GPRs (rbx, rbp, r12..r15), stashes the
resulting SP into `*old_rsp_slot`, adopts `new_rsp`, pops the
counterparts, `ret`s. The return target is whatever quad is on top of
the new stack.

Two cases for what's on top of the new stack:

1. **Task was previously running and got switched out.** On top is the
   return address from some prior `ContextSwitch` call inside
   `Schedule()` or `SchedYield()`. Execution resumes there; from the
   task's POV `Schedule()` / `SchedYield()` simply returns.
2. **Task is fresh (never ran).** On top is `SchedTaskTrampoline`,
   planted by `SchedCreate`. It sets `rdi = rbp` (arg) and `call`s
   `rbx` (entry fn). When entry returns, trampoline tail-calls
   `SchedExitC` so the task dies cleanly instead of falling off its
   stack.

### Fresh-task stack layout (from `SchedCreate`)

From `rsp` (low addr) upward:

```
[rsp + 0x00]  r15 = 0
[rsp + 0x08]  r14 = 0
[rsp + 0x10]  r13 = 0
[rsp + 0x18]  r12 = 0
[rsp + 0x20]  rbp = arg        (moved to rdi in trampoline)
[rsp + 0x28]  rbx = entry fn   (call target in trampoline)
[rsp + 0x30]  return address = SchedTaskTrampoline
[rsp + 0x38]  padding quad     (keep entry RSP 16-aligned)
```

After `ContextSwitch`'s six pops + `ret`, RSP lands at `[base + 0x38]`
with the padding on top — i.e., 16-byte-aligned, which is what SysV's
"after-call" alignment expects.

### The first-run IF=0 trap (and why `sti` lives in the trampoline)

A task that has run before is switched back in via whatever path wrote
its `rsp` — typically an IRQ handler. When that task finally `iretq`s,
the CPU restores `RFLAGS` from the saved value, which had `IF=1`, so
interrupts are re-enabled automatically.

A **fresh** task is different: `ContextSwitch` does not touch `RFLAGS`,
and the typical caller of `Schedule()` is the timer IRQ dispatcher,
where the CPU cleared `IF` on entry. Without intervention, the fresh
task would run forever with interrupts disabled — never preempted,
never taking its own timer IRQ.

Fix: `SchedTaskTrampoline`'s first instruction is `sti`. That path only
matters on first-run-ever; the "previously ran, being resumed" path
doesn't go through the trampoline, so the `sti` is a no-op at worst.

### EOI-then-Schedule ordering (critical)

The IRQ dispatcher does:

```cpp
handler();                                 // TimerHandler sets need_resched
if (vector != 0xFF) LapicEoi();            // acknowledge THIS IRQ
if (sched::TakeNeedResched()) Schedule();  // may context-switch
```

EOI **must** come before `Schedule()`. If we switched away first, the
LAPIC would still have the in-service bit set for vector 0x20. The next
timer tick on this CPU would be suppressed — one tick would fire, then
nothing. The scheduler would look completely dead after a single IRQ.

Symptom if you get this wrong: workers print exactly once then the
whole kernel hangs at the first context switch. Fix is exactly one
line, but diagnosing it from a hang is painful — hence the comment in
the dispatcher.

### Runqueue

Singly-linked FIFO, head + tail pointers. `RunqueuePush` appends;
`RunqueuePop` takes from head. Running task is NOT on the queue —
`Schedule()` enqueues the previous task (if still Ready) before
popping the next one. Dead tasks are never re-enqueued.

Complexity: O(1) push + pop, O(n) iteration. For v0's handful of tasks,
the constant factor dominates anything else we could do.

### Preemption and cooperative yield coexist

- **Preemption:** timer IRQ sets `need_resched`; dispatcher calls
  `Schedule()` after EOI. Current task's state is `Running`; after
  `Schedule()` it's re-enqueued as `Ready`.
- **Cooperative yield:** task calls `SchedYield()` directly — `cli +
  Schedule + sti`. Same machinery, different trigger.

Both paths push the current task to the tail, pop the head. On a
single-CPU system this is true round-robin.

### Self-test (in `core/main.cpp`)

Three worker threads print a line per iteration; each runs 5
iterations. A busy-wait burns ~10 ms of CPU between prints so the
timer has at least one chance to preempt each iteration. Expected log
after scheduler init (order of A/B/C lines may interleave arbitrarily):

```
[sched] online; task 0 is "kboot"
[sched] created task id=0x01 name="worker-A" rsp=…
[sched] created task id=0x02 name="worker-B" rsp=…
[sched] created task id=0x03 name="worker-C" rsp=…
[boot] All subsystems online. Entering idle loop.
[timer] tick=0x64
[sched] A i=0x0 ticks=0x64
[sched] B i=0x0 ticks=0x65
[sched] C i=0x0 ticks=0x66
[sched] A i=0x1 ticks=0x68
...
```

Signals to confirm the machinery works:
- All three workers print at least once → context-switch into a fresh
  task works (trampoline + stack primer correct).
- `ticks=` values keep increasing between worker prints → timer IRQs
  are still firing across context switches (EOI ordering correct).
- A, B, C each print 5 times → preemption + re-entry works repeatedly.
- Tasks eventually stop printing → `SchedExit` path works.

### Regression canaries

- **All workers print exactly once, then kernel goes silent** → classic
  EOI-after-Schedule bug. The first context switch leaves the LAPIC
  with in-service bit set; no further timer IRQs are delivered.
- **First worker print faults immediately** → fresh-task stack is
  wrong. Mis-ordered pushes, off-by-8 alignment, wrong return address
  slot. `llvm-objdump -d` on ContextSwitch + SchedTaskTrampoline,
  compare stack against the diagram above.
- **Tasks run but never preempt each other** → timer handler isn't
  setting `need_resched`, or the dispatcher isn't checking it. Sprinkle
  one `SerialWrite` in each path to isolate.
- **Single worker runs forever, others starve** → runqueue invariant
  broken. `Schedule()` must re-enqueue the previous Running task
  before it pops the head; otherwise the previous runner drops off
  entirely.
- **Worker's RIP is garbage after N iterations** → stack overflow.
  16 KiB should be plenty for boot-era code, but recursive / alloca-
  heavy code will blow it. Widen `kKernelStackBytes` or switch to a
  guard-page design once the page-table API supports it.
- **`SchedExit` fires then kernel faults** → the trampoline's fallback
  `cli + hlt` after `SchedExitC` isn't reached (which is correct —
  SchedExitC is [[noreturn]]); if you DO see a fault there, the
  SchedExit path is returning when it shouldn't be.

## Notes

- **Blocking primitives live in a sister doc.** `SchedSleepTicks`,
  `WaitQueue`, and `Mutex` were added on top of this core scheduler —
  they share the task state machine but have their own invariants and
  regression canaries. See
  [sched-blocking-primitives-v0.md](sched-blocking-primitives-v0.md).
- **No priorities.** Every task is equal. A real-time class can go on
  top of this without rewriting the core — introduce a separate
  priority-0 runqueue that's checked first.
- **Dead tasks are now reaped.** `SchedExit` pushes the dying
  task onto a zombie list and wakes the reaper thread via
  `g_reaper_wq`. The reaper (`ReaperMain` in `sched.cpp`) runs
  on its own stack, pops zombies, and `KFree`s the stack + Task
  struct. Boot log shows `[I] sched/reaper : reaped task id
  val=0xN` per freed task. SMP will need to also check that the
  zombie isn't `Running` on a peer CPU before the reaper touches
  it — see `runtime-recovery-strategy.md` Class C.
- **No SMP.** Everything assumes single CPU. SMP bring-up will:
  - replace `g_current` with a per-CPU variable
  - add per-CPU runqueues + work-stealing
  - put the runqueue behind an irq-save spinlock
  - make `need_resched` per-CPU
- **No userland yet.** Ring-3 entry will add TSS + IST stacks, user-
  page-table swaps on context switch, syscall entry/exit paths.
  `ContextSwitch` will need to save/restore CR3 and the user-mode
  stack pointer when the target task is a user thread.
- **The busy-wait in the self-test is intentional.** Once sleep lands,
  the workers become `Sleep(10ms)`.
- **See also:**
  - [lapic-timer-v0.md](lapic-timer-v0.md) — provides the tick source;
    `TimerHandler` was extended to set `need_resched`.
  - [kernel-heap-v0.md](kernel-heap-v0.md) — allocates `Task` structs
    and per-task 16 KiB stacks.
  - [gdt-idt-v0.md](gdt-idt-v0.md) — `TrapDispatch` is where the
    `Schedule()` call lives.
