# SMP AP Bring-up — Scope & Staged Plan

_Last updated: 2026-04-20_

## Why this doc exists

The current kernel is single-CPU. Making it multi-CPU involves a
real→long-mode trampoline, precise INIT-SIPI-SIPI timing, per-AP
state (stack, PerCpu, GDT/TSS later), and a scheduler-side refactor
(runqueue spinlock, migrate `g_current` + `g_need_resched` into
PerCpu).

This doc captures the staged plan so a future session can pick up
where today's left off. We've landed the **foundations** already —
the remaining work is the trampoline itself and the scheduler's
SMP-safe refactor.

## What's landed

- `kernel/sync/spinlock.{h,cpp}` — xchg-based spinlock with IF
  save/restore (entry 017 in decision log).
- `kernel/cpu/percpu.{h,cpp}` — `PerCpu` struct addressable via
  `IA32_GS_BASE`; BSP's struct installed in `kernel_main`.
- `kernel/sched/sched.cpp` — `g_current` + `g_need_resched` migrated
  to `cpu::CurrentCpu()->{current_task, need_resched}`. On single
  CPU this is a no-op; on SMP the accessors automatically resolve
  to the executing CPU's PerCpu.
- `kernel/acpi/acpi.{h,cpp}` — MADT parses type-0 LAPIC entries;
  `acpi::CpuCount()` + `acpi::Lapic(i)` enumerate the APs.
- `kernel/arch/x86_64/smp.{h,cpp}` — IPI-send helper (`SmpSendIpi`
  wraps the LAPIC ICR dance) + discovery scaffolding
  (`SmpStartAps` logs each AP candidate).

## What's NOT landed yet

1. **Real-mode → long-mode trampoline.** ~150 lines of GNU-as
   Intel-syntax assembly with careful two-symbol arithmetic
   workarounds. Needs iterative QEMU testing — not safe to write
   "blind" and commit.
2. **Trampoline parameter block + relocation.** BSP writes
   pml4_phys / stack_top / entry_fn / cpu_id / online_flag into
   the fixed offsets within the 4 KiB page at physical 0x8000
   before each SIPI.
3. **INIT-SIPI-SIPI sequence per AP** using `SmpSendIpi`. INIT
   assert + 10 ms wait + SIPI + 200 µs wait + second SIPI. Intel
   SDM Vol. 3A §8.4.4 gives the canonical sequence.
4. **AP-side C++ entry** (`ApEntryFromTrampoline(cpu_id)`): write
   GSBASE from `g_ap_percpus[cpu_id]`, enable LAPIC, increment
   `g_cpus_online`, halt. Scheduler-join comes in step 6.
5. **Scheduler SMP-safe refactor.** Wrap `g_run_head` / `g_run_tail`
   / `g_sleep_head` / `g_zombies` / `g_tasks_*` accesses in a
   `sync::SpinLock`. Handle the lock-passing-across-context-switch
   subtlety (the lock is released by the task we context-switch
   **into**, not the task we switch **from** — see Linux's
   `finish_task_switch` for prior art).
6. **AP joins scheduler.** AP entry calls a new `SchedEnterOnAp()`
   that installs an idle task for this CPU, arms the LAPIC timer,
   and enters the scheduler loop. Each AP's timer fires
   independently; the shared runqueue feeds tasks to whichever CPU
   asks for one first.
7. **Per-AP TSS + IST** — needed when ring 3 lands (the TSS carries
   the kernel-mode stack pointer used on user→kernel trap entry).
   Not strictly needed for ring-0-only SMP but we'll land it
   alongside ring 3 rather than doing it twice.

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
