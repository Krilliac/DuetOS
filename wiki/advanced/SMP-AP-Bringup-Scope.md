# SMP AP Bring-up — Scope & Staged Plan

_Last updated: 2026-05-06_

## Status: SMP online

All five staged commits (A–E) plus the per-CPU runqueue refactor and
work-stealing have landed. APs run kernel tasks; cross-CPU wakes fire
reschedule-IPIs; idle CPUs steal from busy peers. The single
remaining limitation is lock granularity — every per-CPU runqueue is
still covered by one global `g_sched_lock`. Splitting the lock
per-CPU is the next slice when contention shows up in profiles.

## Why this doc exists (historical)

The original 2026-04-20 plan staged the SMP bring-up across five
small commits to keep each diff reviewable. Below preserves that
plan as a reference for how the work was decomposed; the "What's
landed" section reflects current reality.

## What's landed

- `kernel/sync/spinlock.{h,cpp}` — xchg-based spinlock with IF
  save/restore (entry 017 in decision log).
- `kernel/cpu/percpu.{h,cpp}` — `PerCpu` struct addressable via
  `IA32_GS_BASE`; BSP's struct installed in `kernel_main`. Holds
  per-CPU `current_task`, `need_resched`, runqueue head/tail,
  `tss` pointer, and the lock-pass slot.
- `kernel/acpi/acpi.{h,cpp}` — MADT parses type-0 LAPIC entries;
  `acpi::CpuCount()` + `acpi::Lapic(i)` enumerate the APs.
- `kernel/arch/x86_64/smp.{h,cpp}` — IPI-send helper (`SmpSendIpi`
  wraps the LAPIC ICR dance), discovery, AP trampoline copy,
  per-AP allocation (PerCpu + GDT bundle + stack), full
  INIT-SIPI-SIPI sequence with online-flag polling, reschedule-IPI
  helper (`SmpSendReschedIpi`).
- `kernel/arch/x86_64/ap_trampoline.S` — real-mode → long-mode
  trampoline at physical 0x8000.
- `kernel/sched/sched.cpp` — lock-passing across `ContextSwitch`,
  per-CPU runqueue data layout, `Task::last_cpu` cache-affinity
  routing, `SchedEnterOnAp` for AP scheduler join, work-stealing in
  `RunqueuePopRunnable` via `StealNormalFromPeer`.
- `kernel/arch/x86_64/gdt.{h,cpp}` — per-AP GDT clone + TSS body +
  three IST stacks (#DF / #MC / #NMI) allocated by `AllocateApGdt`,
  loaded on the AP via `LoadGdtForCurrent`. `TssSetRsp0` routes
  via `cpu::CurrentCpu()->tss` so each CPU's RSP0 update lands on
  the right TSS.
- `kernel/arch/x86_64/timer.{h,cpp}` — `LapicTimerStartOnCurrent`
  arms the local LAPIC timer on the calling CPU using the cached
  calibration from BSP's `TimerInit`.

### AP per-CPU register-state ordering (2026-05-19, resolved)

Three per-CPU **registers** (not tables) must be set up on each AP
in this order during `ApEntryFromTrampoline`, or the AP corrupts
shared state / triple-faults — see Design-Decisions 2026-05-19:

1. `LoadGdtForCurrent(bundle)` first. Its `mov %ax, %gs` reloads
   GS's hidden base from the kernel-data descriptor (base 0),
   which **zeroes `IA32_GS_BASE`** as a side effect.
2. **Then** `WriteMsrGsBase` / `WriteMsrKernelGsBase` — writing the
   AP's per-CPU pointer before step 1 is dead (clobbered before any
   gs-relative read; every `cpu::CurrentCpu()` then saw GSBASE=0).
3. **Then** `IdtLoadForCurrent()` — IDTR is per-CPU; the trampoline
   only loads a transition GDT and `IdtInit` lidt'd only the BSP,
   so without this the AP's first timer tick #GP → #DF → triple
   fault (silent on serial). Must precede LAPIC enable / `sti`.

`cpu::CurrentCpu()` additionally resolves the real CPU by LAPIC ID
when GSBASE is non-kernel, instead of assuming BSP — a gated
`kCurrentCpuGsbaseFallback` probe + `OnTimerTick` count sentinel
catches any regression (clean boot stays at zero). This closed the
intermittent SMP "task double-run" (`MUTEX-NONOWNER` /
`release-out-of-order` under `gui-fuzz.sh 18`) and the silent
AP triple fault in one slice.

## Known limitations / GAPs

1. **`g_sched_lock` is still global.** Every per-CPU runqueue is
   covered by the same lock; every `Schedule()` call on every CPU
   serialises through it. Per-CPU lock split is a follow-up when
   profiles show contention. The lock-passing protocol generalises
   directly — the slot in `PerCpu` already references a pointer.
2. **`g_ticks` multi-writer race** — every CPU's
   `LapicTimerStartOnCurrent`-fed handler increments the same
   global. Bounded misbehaviour (lost / duplicated tick observation
   in load average); scheduling is driven by per-CPU `need_resched`
   not the absolute tick. Atomic-`g_ticks` upgrade roadmapped
   separately.
3. **AP boot sentinel stack leak.** Each AP keeps the trampoline
   allocated 16 KiB stack referenced by its boot sentinel forever
   (the sentinel never re-enqueues, so `Schedule()` never resumes
   it). Bounded at 16 KiB × kMaxAps = 512 KiB worst case.
4. **Per-package LAPIC frequency variance.** `LapicTimerStartOnCurrent`
   reuses BSP's calibration assuming a homogeneous package — true
   on every commodity x86 today, but a future heterogeneous
   platform will need per-CPU recalibration.
5. **Single ring-3 path on APs not yet exercised.** Per-AP TSS +
   IST landed, but no ring-3 task has run on an AP. Ring-3-on-AP
   is a separate validation slice when a workload lands.

## Staged plan (when we come back)

**Commit A — trampoline assembly + parameter block**

Write `kernel/arch/x86_64/ap_trampoline.S` carefully. Use `.set`
constants for trampoline-internal offsets; use absolute literal
addresses (trampoline base is always 0x8000) for memory operands so
GNU as doesn't trip on the two-symbol-in-one-operand restriction.
Test incrementally:
1. Start with just `cli; hlt` in real mode — verify AP halts via
   QEMU `info cpus`.
2. Add protected-mode transition — verify the transition doesn't
   triple-fault.
3. Add long-mode transition + jump to a dummy C++ function that
   does `serial_write("AP alive"); hlt;` — verify the line appears.

**Commit B — full AP bring-up wired into `SmpStartAps`**

Replace the v0 log-only `SmpStartAps` with the actual copy-trampoline
+ INIT-SIPI-SIPI sequence. Each AP:
1. BSP allocates AP's stack (16 KiB) + PerCpu (heap).
2. BSP writes trampoline parameter block.
3. BSP sends INIT + waits + SIPI + waits + SIPI again.
4. BSP polls `online_flag` with ~200 ms timeout.
5. AP enters `ApEntryFromTrampoline`, writes GSBASE, enables LAPIC,
   sets `online_flag = 1`, halts.

**Commit C — scheduler spinlock**

Add `sync::SpinLock g_sched_lock{}` protecting runqueue +
sleepqueue + zombie list + stats. Acquire at each entry point,
release at each exit. No context-switch-across-lock yet — `Schedule`
acquires, picks next task, releases BEFORE `ContextSwitch`. Single-
CPU safety argument: `ContextSwitch` is atomic wrt preemption (IRQ
fires on the same CPU, gets dispatcher, dispatcher sees consistent
scheduler state because the lock is released).

Known correctness gap: on SMP, another CPU could wake a task and try
to schedule it between our release-lock and our ContextSwitch. The
standard fix is to hold the lock across the switch and have the
incoming task release it — adds a runqueue-lock token that travels
with the context. Defer that subtlety to Commit D.

**Commit D — lock-passing ContextSwitch**

Pass an `IrqFlags` save token through ContextSwitch so the incoming
task releases the scheduler lock on its first instruction. Mirrors
Linux's `prepare_task_switch` / `finish_task_switch` pattern.

**Commit E — AP scheduler join**

Each AP's `ApEntryFromTrampoline` calls `SchedEnterOnAp()` which:
1. Installs an idle task for this CPU.
2. Arms this CPU's LAPIC timer at 100 Hz.
3. Enters the scheduler loop.

From this point each AP picks tasks from the shared runqueue.
Load balancing is "whoever asks first" — work-stealing is a future
optimisation.

## Open questions to resolve before Commit C

- **Lock acquire order when multiple scheduler data structures are
  involved.** If `WaitQueueBlock` inserts into a WaitQueue AND
  touches the runqueue, what order? Probably: wait queues get their
  own lock, runqueue lock is innermost. Document in
  `sched-blocking-primitives-v0.md` when it lands.
- **Does Mutex's `waiters` WaitQueue need a separate lock?** Probably
  not — today it's touched only under the sched lock. Revisit if
  profiles show contention.
- **Panic-on-SMP behaviour.** Today `core::Panic` halts the calling
  CPU. On SMP the other CPUs keep running on potentially
  inconsistent state. Need a broadcast-NMI halt. See recovery
  strategy §"Class A" revisit markers.

## Estimated effort

Commits A + B alone: ~3-4 hours of focused work including QEMU
debug cycles. Commits C-E: another 4-6 hours. Total ≈ 1.5-2 focused
sessions. Doable; just not same-day work.

## See also

- `smp-foundations-v0.md` — the spinlock + PerCpu primitives already
  in place.
- `scheduler-v0.md` + `sched-blocking-primitives-v0.md` — the
  subsystems that need the SMP-safe refactor in Commit C.
- `runtime-recovery-strategy.md` — the Class A "broadcast-halt peer
  CPUs" gap flagged above.
- `design-decisions-log.md` entries 017, 018, 019, 020 — the recent
  foundations this builds on.
