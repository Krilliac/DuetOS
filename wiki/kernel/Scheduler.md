# Scheduler

> **Audience:** Kernel hackers
>
> **Execution context:** Kernel — `Schedule()` runs after IRQ EOI or in `cli` cooperative paths
>
> **Maturity:** SMP-online — per-CPU runqueues, work-stealing, reschedule-IPI, cluster-aware wake placement, periodic active load balancer, SMT-aware placement, hybrid P/E-core bias, hard CPU affinity, MWAIT low-power idle; single global `g_sched_lock` (per-CPU lock split deferred)

## Overview

The DuetOS scheduler is preemptive, kernel-thread first, and SMP. Each
CPU has its own runqueue (Normal + Idle bands) stored in `cpu::PerCpu`.
`SchedInit` wraps `kernel_main` as task 0 (the boot task) on the BSP;
`SchedStartIdle` spawns a per-CPU idle task (`idle-bsp` on the BSP,
`idle-apN` on each AP) that loops on a low-power idle so each CPU's
runqueue is never empty. The idle uses `MONITOR`/`MWAIT` (C1 hint)
when CPUID.1:ECX[3] is set — the core drops into an MWAIT-C1 power
state that is at least as deep as a bare `HLT` — and falls back to
`sti; hlt` verbatim otherwise. Wake semantics are unchanged: an IRQ
(timer tick or reschedule IPI) breaks `MWAIT` exactly as it breaks
`HLT`, and the monitored cell is a per-idle-task (per-CPU) stack
byte nothing ever writes, so there is no lost-wakeup window beyond
the one `sti; hlt` already had. `SchedCreate(entry, arg, name)` spawns a regular kernel
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
    u64         stack_size;  // 64 KiB today
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

## Trampoline RSP Reservation (sub rsp, 16)

The very first instruction of `SchedTaskTrampoline` after `endbr64` is
`sub $0x10, %rsp` — a 16-byte stack reservation that keeps RSP below
`slot_top` for the entire trampoline lifetime. Without it, a kernel-mode
IRQ landing in the trampoline's narrow `RSP == slot_top` windows pushes a
40-byte iretq frame whose top quad (SS = `kKernelDataSelector` = `0x10`)
lands at `slot_top - 8`, overwriting the planted `&SchedTaskTrampoline`
return address. The proactive RA-slot validator in `Schedule()` then
panics the task on its next switch-in with `observed=0x10`; the pre-
validator shape was a wild `ret` jumping to `0xffffffffe014Nfe7`
(NX_VIOLATION inside the kstack arena). Pre-fix rate: ~60% on SMP=8
release boots. Post-fix rate: 0/30. See
[`Design-Decisions.md`](../reference/Design-Decisions.md) entry
"2026-05-23 — SchedTaskTrampoline reserves 16 bytes so RSP never sits at
slot_top" for the full rationale and rejected alternatives.

`16` (not `8`) keeps RSP 16-aligned per SysV. The 8 dead bytes between
RSP and the planted RA are never read or written by trampoline code.

## Runqueue

Per-CPU singly-linked FIFO, head + tail, in two priority bands
(Normal + Idle). The four head/tail pointers live in `cpu::PerCpu`
(`runq_head_normal`, `runq_tail_normal`, `runq_head_idle`,
`runq_tail_idle`). The running task is **not** on the queue.
`Schedule()` re-enqueues the previous task (if still `Ready`) on its
`last_cpu` runqueue before popping the local head. Dead tasks are
reaped by a reaper thread (`g_reaper_wq`) that frees the stack + Task
struct.

**Deferred-zombie handoff (the reaper UAF invariant).** A dying task is
**never** published to the global zombie list while a CPU is still
executing on its kernel stack — doing so lets a peer-CPU reaper
`FreeKernelStack` those pages out from under the in-flight
`ContextSwitch`, whose `rsp`/`rip` save/restore then reads freed, reused
memory and resumes wild (the "boot-tail wild-jump" cascade). Instead the
terminating task is stashed into the per-CPU
`ctxsw_dying_task_to_zombie` slot, and **`SchedFinishTaskSwitch`** —
which runs on the *next* task's stack, after `ContextSwitch` has
committed the rsp swap and the dying task is provably off-CPU on every
peer — promotes it to `g_zombies` and wakes the reaper.
`SchedFinishTaskSwitch` is the **single** zombie-publish site; both
termination paths funnel through the slot:

- **`SchedExit`** — cooperative/`[[noreturn]]` exit.
- **`Schedule()`'s `kill_requested` branch** — budget-/policy-kill
  (`FlagCurrentForKill`: tick-budget, sandbox-denial, fs-write-rate,
  fault-react, canary). This path historically pushed to `g_zombies`
  inline (before its `ContextSwitch`) and was the residual UAF the
  2026-05-22 SMP=8 fix missed; it now uses the same deferred slot.

Three permanent guards stand on the resume/reap path: a resume-context
validator before every `ContextSwitch` (rejects a `next` that is `Dead`
or whose `rsp` is outside its own kstack), a reaper reachability scan
(panics if a to-be-freed task is still on any runqueue or any CPU's
`current_task`), and a `RunqueuePop` sanity WARN+probe.

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

**`ScheduleLockedHandoff(flags)`**: the same scheduler step, entered
with `g_sched_lock` *already held* by the caller. Every blocking
primitive (`WaitQueueBlock`, `WaitQueueBlockTimeout`,
`SchedSleepTicks`, `SchedSleepUntil`, `CondvarWait`,
`CondvarWaitTimeout`, and `MutexLock`'s contended path) acquires the
lock, marks the caller Blocked/Sleeping + enqueues it, then calls
this — so "decide to wait" and "actually leave the CPU" are one
indivisible region. The previous `{ SpinLockGuard g(g_sched_lock);
enqueue; } Schedule();` shape reopened a gap (lock dropped before
`Schedule()` re-acquired) that a peer-CPU waker could exploit to
dispatch a not-yet-descheduled task on a second CPU. The AP boot
sentinel is created `no_requeue` (never `RunqueueOrSuspendPush`-ed —
its `rsp`/`stack_base` are placeholders) and per-CPU idle tasks are
affinity-pinned to their owning CPU. A residual heavy-churn SMP
double-run remains — see the Roadmap entry "SMP task double-run
under heavy scheduler churn".

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

**Hard CPU affinity**: each `Task` carries a `u32 affinity_mask`
(bit `1u << cpu_id` = allowed). The default is the `kAffinityAll`
(`~0u`) sentinel — `TaskAllowedOn` is then unconditionally true and
every placement path is byte-for-byte identical to the pre-affinity
scheduler. A narrowed mask (via `SchedSetAffinityMask`, or the Linux
`sched_setaffinity` thunk which feeds it the low 32 bits of the user
`cpu_set_t`) is a *hard* pin enforced at every decision point:
`TargetPerCpuFor` retargets a forbidden routing hint to the lowest
allowed CPU; `PickClusterPlacement` skips forbidden peers;
`StealNormalFromPeer` and `BalancePullOnce` refuse to pull a task
onto a CPU it may not run on; and `RunqueuePopRunnable` has a
backstop that re-homes a task found on a now-forbidden runqueue
(covers a runtime mask change). An all-online mask collapses back to
`kAffinityAll` so "pin to every CPU" keeps the fast path.
GAP: steal/balance inspect only the peer's queue *head*, so a
pinned head can shadow a deeper stealable task — acceptable for v0,
revisit on profile evidence. GAP: a task already *running* when its
mask narrows migrates at its next reschedule, not instantly (no
cross-CPU preemption kick in v0). `SchedSetAffinity(t, cpu)` remains
as a one-CPU convenience wrapper over `SchedSetAffinityMask`.

**SMT-aware placement**: `EffectiveLoad(p)` returns `p->runq_normal_len`
plus `kSmtSiblingPenalty` (2) when an SMT sibling of `p` (a CPU with
the same `cpu::Topology::core_group`) already has Normal-band work.
`PickClusterPlacement` and `PickBalanceVictim` compare effective load
instead of raw length, so under light load runnable threads spread
across distinct physical cores before two land on the SMT siblings of
one core. The penalty equals `kClusterPlacementMargin`, so an idle
logical CPU on a busy core looks exactly as loaded as a logical CPU on
an idle core that already has 2 queued tasks — the same equilibrium
that keeps wake placement from oscillating. `StealNormalFromPeer` is
**intentionally not SMT-weighted**: it is the idle-pull path (`self`
is going idle), so giving it work can never produce a two-on-one-core
result, and weighting it would only risk the byte-for-byte non-SMT
ordering invariant. On non-SMT / undecoded CPUs the penalty is always
0 (`core_group == kTopologyUnknownCoreGroup` or `smt_sibling_count ==
0`), so every decision is byte-for-byte identical to the pre-SMT
scheduler. The default QEMU smoke topology exposes SMT
(`-smp 4,sockets=1,cores=2,threads=2`); `DUETOS_SMP=4` reproduces the
flat non-SMT boot.

**Hybrid P/E-core bias**: `EffectiveLoad` adds a second,
independent penalty (`kHybridEcorePenalty`, also 2) when the CPU is
an E-core (`cpu::Topology::core_class == kCoreClassEff`) *and* an
idle P-core still exists. So latency-sensitive Normal-band work
fills idle P-cores first, but once every P-core is busy the penalty
lifts and E-cores are used normally — no E-core starvation. The two
penalties stack (an E-core whose SMT sibling is also busy is the
least preferred). On non-hybrid parts every `core_class` is
`kCoreClassUnknown`, the predicate never fires, and the result is
byte-for-byte identical to the pre-hybrid scheduler. QEMU does not
model Intel hybrid, so the path is dormant in CI (the self-test
SKIPs); the contract is locked by the decision-function test for
real hardware.

Boot self-tests (Phase::Userland): `sched-loadbalance-selftest`
verifies the balancer decision function — same-cluster scoping, margin
threshold, UP short-circuit. `smt-placement-selftest` verifies the
`EffectiveLoad` sibling penalty, that `PickClusterPlacement` prefers a
fully-idle physical core over an SMT sibling of a busy core, the
non-SMT identity, and the one-`smt_primary`-per-`core_group`
invariant; it SKIPs on non-SMT guests. `affinity-mask-selftest`
verifies the mask API (reject-empty/null, single-pin,
all-mask→sentinel collapse, getaffinity round-trip, routing-hint
retarget) and that `TargetPerCpuFor`/`PickClusterPlacement` never
select a forbidden CPU while an unrestricted task routes identically
to a no-task call; it SKIPs on <2-CPU guests.
`hybrid-placement-selftest` verifies the E-core penalty applies
only while an idle P-core exists and lifts when every P-core is
busy; it SKIPs on non-hybrid guests (every QEMU guest).
`idle-power-selftest` checks the MWAIT feature gate (cached MONITOR
bit vs a fresh CPUID, CpuInfo initialised) and reports the selected
idle path; it PASSes on every guest (no SKIP). Each emits one
`[<name>] PASS` (or `SKIP`) line so CI can grep for it.

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

## Runtime power bias

`SchedSetPowerBias(PowerBias)` / `SchedPowerBias()` (sched.h) is a
runtime hint, **not** a correctness input. It scales only how often
the *active* load balancer fires: `PowerSave` stretches the period
from `kBalancePeriodTicks` (8) to `8 × kPowerSaveBalanceFactor` (32
ticks ≈ 320 ms), so a lightly-loaded battery box does far fewer
cross-CPU spinlock walks, task migrations, and wakeup IPIs. The core
`Schedule()` path is untouched — under-balancing costs some
load-distribution optimality, never correctness. The per-tick cost
is one byte read + one branch (no function call on the hot path);
the bias byte is set rarely from one task (the env [autonomic
engine](Environment.md#autonomic-rule-engine) on a power-policy
transition) and read on every timer tick — the same racy-but-fine
contract as `g_total_ticks`.

This is deliberately a *balancer-cadence* lever, not a fake
tick-rate or quantum knob: the 100 Hz tick and the round-robin
quantum are compile constants with no safe runtime knob, so faking
one would be a facade. Balancer cadence is a real, observable,
reversible effect (boot log: `sched : power bias changed to=...`;
shell: `autonomic`). See Design-Decisions 2026-05-18.

## Related Pages

- [Memory Management](Memory-Management.md) — `Task` structs and stacks
  come from `KMalloc`
- [Boot Path](Boot.md) — when scheduler comes online
- [Process Model](Process-Model.md)
- [SMP AP Bringup Scope](../advanced/SMP-AP-Bringup-Scope.md)
