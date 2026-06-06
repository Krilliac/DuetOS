# DuetOS Roadmap — pending and deferred work

> **Audience:** Maintainers, contributors picking the next slice
>
> **Maturity:** Living document; edit when an item lands or a new gap is found

This page consolidates every multi-session work item that is **not
yet in tree**. Each entry names the surface that owns the gap and
the residual that remains, so a contributor can pick one without
re-deriving the field.

**Policy:** when a roadmap item lands, **delete its entry here in
the same commit that delivers the code**, record the landing in
[`Design-Decisions`](Design-Decisions.md), and update the owning
subsystem wiki page. Landed work does **not** live on this page —
if you find a "shipped / landed / DONE" paragraph here, it is
cleanup debt: move the residual up and delete the rest.

---

## Kernel / runtime

### B2-followup — split `g_sched_lock` per-CPU

- **Residual:** per-CPU runqueue head/tail live in `cpu::PerCpu`,
  but every mutation still serialises on one global
  `g_sched_lock`. Split it per-CPU so steady-state contention
  drops to local-only `Schedule()` calls; wake paths take the
  target CPU's lock briefly; work-stealing uses the existing
  try-lock primitive (`SpinLockTryAcquire` /
  `SpinLockTryAcquireFor` / `SpinLockTryGuard`,
  `kernel/sync/spinlock.h`) to avoid AB/BA deadlock.
- **Blocks on:** nothing technical — deferred until a profile
  shows contention on `g_sched_lock`. For most workloads the
  global lock is acceptable.
- **Cascading items unlocked when this lands:**
  - Index the lockdep / event-trace / soft-lockup `g_per_cpu`
    arrays by current-CPU ID (currently keyed on `g_per_cpu[0]`
    aliases).
  - SMP-stress versions of the RwLock + SeqLock + KMailbox
    contention self-tests.
  - MLFQ priority bands (the T8-01-followon row) — band-aware
    enqueue/steal becomes a one-slice add-on once the lock is
    per-CPU.
  - Buddy coalescing + per-CPU lock-free allocator fast paths
    (frame warm-pool / slab magazine) — correctness is already
    in place under one global allocator lock; this is the
    scalability follow-on.
  - Move LAPIC-divider + tick-frequency programming out of
    `arch::TimerInit` into `time::TimerConfigure(hz)` once an
    ARM64 / generic-timer backend justifies the abstraction.

### Lockdep held-set must be per-task, not global

- **Residual:** `kernel/sync/lockdep.cpp` keeps the held-class
  stack in a single global array (`g_per_cpu[0]`). Correct for
  spinlocks (can't be held across a context switch) but **wrong
  for sleeping `sched::Mutex`**: two tasks each correctly holding
  a different sleeping mutex across a yield are reported as a
  lock-order inversion (observed: compositor↔fat32, ~40×/boot,
  no real cycle). Per-CPU indexing (the B2 cascading item) does
  not fix this — a task holding a sleeping mutex can resume on a
  different CPU, so the held-set must follow the *task*.
- **Approach:** give each `Task` its own held-stack and swap it
  at the context-switch boundary; spinlock classes stay on a
  per-CPU stack, mutex classes move to the per-task one. Avoid
  threading a `Task*` through every lockdep hook (reintroduces
  the lockdep↔sched recursion the TU header avoids).
- **Attempt 1 reverted (2026-05-17):** the minimal form
  (`LockdepHeldSnapshot` before `ContextSwitch`,
  `LockdepHeldRestore` at the top of `SchedFinishTaskSwitch`)
  was correct on one long boot but a 6-boot determinism sweep
  (`tools/test/boot-determinism-sweep.sh`) caught an
  **intermittent** hard panic on the AP-bring-up path
  (`KASSERT WaitQueueBlock on non-Running task`). Root: the
  restore was inserted *above* the existing not-yet-armed-AP
  guard, so `Current()` deref'd a partial `PerCpu` on a fresh
  AP. (The nearby `[ubsan] tm-detail PerCpu/u32/Task` lines are
  pre-existing benign noise, ~4×/clean boot — not the signal.)
- **Attempt 2 — LANDED (snapshot/restore half):** the per-task
  carry is now wired per the constraints above. `Task` owns
  `lockdep_held[kLockdepHeldMax]` + `lockdep_held_depth`
  (`kernel/sched/sched.cpp`); `ScheduleLockedHandoff` snapshots the
  outgoing task's held set just before `ContextSwitch`;
  `SchedFinishTaskSwitch` restores the resumed task's set *after*
  the fresh-AP `lock_ptr == nullptr` guard, gated on
  `self != nullptr && self->state == TaskState::Running` (exactly
  the attempt-2 design constraint — the held-set now follows the
  *task* across a cross-CPU resume, so the compositor↔fat32 false
  inversion from a sleeping mutex held across a yield no longer
  fires). Fresh tasks are seeded `[kLockClassSched], depth=1` so
  the first `SchedFinishTaskSwitch` pop balances.
- **SMP `release out-of-order` symptom — RESOLVED (2026-05-19):**
  the occasional `sync/spinlock : release out-of-order` line under
  4-CPU churn was NOT caused by the held-stack storage design — it
  was a symptom of the SMP cross-CPU corruption that also drove the
  "SMP task double-run" item (now deleted, fixed in the same
  slice). Root: an AP ran kernel code with a non-kernel GSBASE
  (`LoadGdtForCurrent`'s `mov %gs` zeroed `IA32_GS_BASE` and the
  AP's per-CPU pointer was written *before* that, not after), so
  `cpu::CurrentCpu()` silently returned the BSP slot and the AP
  read/wrote the BSP's `g_per_cpu[0]` held-stack alias (plus
  `current_task` / the `ctxsw_lock_to_release` lock-pass slot).
  Compounded by APs never executing `lidt` (no per-CPU IDTR), which
  triple-faulted them on the first timer tick. Fixes: GSBASE +
  KERNEL_GS_BASE now programmed *after* `LoadGdtForCurrent`;
  `IdtLoadForCurrent()` added to the AP path; `cpu::CurrentCpu()`
  resolves the real CPU by LAPIC ID instead of assuming BSP, with a
  gated `kCurrentCpuGsbaseFallback` probe + count sentinel
  (`OnTimerTick`) so any future swapgs/AP-GS regression is caught.
  Gated by a 6-boot determinism sweep (3/3 APs online, byte-stable,
  zero panic/triple/fallback) + a 6/6-clean `gui-fuzz.sh 18` SMP
  matrix. `g_promote_to_panic` may now be reconsidered.
  - **Recurrence — ROOT-CAUSED + FIXED (2026-06-01, dedicated SMP slice).**
    Reproduced the `sync/spinlock : release out-of-order` line under
    `x86_64-release-audit` at ~2/12 boots (17%; one escalated to a
    serial self-deadlock panic). Root cause: the AP runs its ENTIRE
    `CpuhpBringUp` chain — including the `StartingGdt` / `StartingGsBase`
    states — BEFORE `CpuhpStartGsBase` programs a kernel GSBASE, so
    every `cpu::CurrentCpu()` in that window has GSBASE=0 and falls into
    the LAPIC-ID resolver. That resolver scanned only up to
    `arch::SmpCpuIdLimit()`, which the 2026-05-22 "deferred g_cpu_id_limit
    bump" fix deliberately keeps from covering the booting AP until it
    signals online. So the LAPIC match FAILED and the resolver returned
    `&g_bsp_percpu`: the AP pushed `g_state_lock` / `g_frame_lock` onto
    the BSP's per-CPU held-locks stack and stamped `owner_cpu=BSP`. Once
    `CpuhpStartGsBase` ran, GSBASE became valid and the AP's later
    releases hit its OWN slot, leaving the BSP's stack with a phantom
    entry → `release out-of-order` on the next release; the raw-serial
    diagnostic then re-entered `g_serial_lock` and self-deadlocked. The
    two prior fixes (2026-05-19 LAPIC fallback, 2026-05-22 deferred bump)
    were each correct but mutually undermining. Fix: `cpu::CurrentCpu()`'s
    LAPIC fallback now scans the full allocated-slot space
    (`acpi::kMaxCpus`) instead of `SmpCpuIdLimit()` — the AP's
    `g_ap_percpus[cpu_id]` + `lapic_id` are stamped before SIPI, so the
    booting AP's real slot is always found; scheduler wake-routing still
    uses `SmpCpuIdLimit()` + the `PerCpu::online` predicate, so routing
    behaviour is unchanged. Verified: 17/17 clean `x86_64-release-audit`
    boots (zero out-of-order / self-deadlock / panic, `online=4/4`, all
    self-tests PASS, `boot-log-analyze` verdict OK) + 2/2 clean
    `x86_64-release` boots. One file changed: `kernel/cpu/percpu.cpp`.
- **Per-CPU held-stack storage — LANDED (2026-05-22).** The
  global `g_per_cpu[0]` alias is gone. `kLockdepCpuMax =
  acpi::kMaxCpus`, each CPU indexes its own slot via
  `cpu::CurrentCpuIdOrBsp()`, and the re-entry guard
  (`PerCpuHeld::in_lockdep`) moved into the per-CPU struct too.
  `LockdepCriticalSection` reads the slot AFTER `Cli` so a
  migration can't corrupt a peer's slot. The shared edge graph
  + counters use `__atomic_fetch_or` (bit) and `SatAtomicAdd`
  (counters) for cross-CPU safety. Verified with 5/5-clean
  `tools/test/smp-stress-sweep.sh 8 8 5` (release SMP=8) and
  no inversions in the lockdep self-test under the new
  storage layout.
- **LockKind class-tag split — LANDED (2026-05-26).** Upstream
  `90867be5 sync/lockdep: WITNESS-style lock-kind taxonomy +
  LOCKDEP_ASSERT_HELD` shipped the WITNESS-style three-variant
  enum `LockKind { Spin, Sleep, Irq }` with acquire-time
  enforcement: a `Sleep` acquire while holding a `Spin` / `Irq`
  class is a BUG (the Sleep acquire may yield but the CPU has
  IRQs off and another task can't run on it). Counter:
  `g_kind_violations`. Catches the violation at the OFFENDING
  ACQUIRE SITE — better diagnostic than an after-the-fact
  snapshot-time audit. Companion primitive
  `LOCKDEP_ASSERT_HELD(class_id)` lets a callee assert a
  caller's invariant directly. Spinlock-vs-mutex separation is
  now explicit at the API for every kind: sched/kobject/kstack/
  pci-config/breakpoints/cleanroom-trace are `Spin`, wifi/
  fat32/compositor are `Sleep`.
- **Blocks on:** a workload that produces a false inversion the
  per-CPU + per-task pair doesn't already absorb. None
  observed since 2026-05-22.

### SmpStartAps offline-AP routing hang — LANDED (2026-05-22)

Under SMP=8 release, `boot-determinism-sweep.sh` consistently
reported `aps=?` for every run — the post-AP-bringup
`[smp] online=N/M` structural sentinel never fired, even though
the boot reached `bringup-complete` cleanly. Tracing pinned the
hang inside `SmpStartAps`'s per-AP loop:

  1. The BSP runs the loop body for AP[1]: kmallocs its PerCpu,
     allocates GDT/TSS/IST stacks via `AllocateApGdt`, kmallocs a
     stack, registers the slot at `g_ap_percpus[cpu_id]`, bumps
     `g_cpu_id_limit` to cover it, then sends INIT IPI.
  2. The 10ms INIT→SIPI delay called `sched::SchedSleepTicks(1)`,
     parking the BSP boot task on the sleep queue.
  3. Timer IRQ at `g_tick_now + 1` woke the task. The wake-side
     `RunqueuePush` → `PickClusterPlacement` looked across
     in-cluster peers and saw `g_ap_percpus[1]` (just allocated,
     runq_normal_len == 0) — a "less loaded" target. Routed the
     BSP boot task to AP[1]'s runqueue.
  4. AP[1] hadn't actually started yet (no SIPI). Its runqueue
     was a memory address; nothing was draining it.
  5. BSP went idle; init-wedge eventually fired but `[smp] online=`
     was never emitted, so the determinism rig reported the
     ambiguous `aps=?`.

Fix landed in two layers (belt-and-braces):

1. **`g_cpu_id_limit` deferred bump** — `SmpStartAps` now waits
   to advance the scheduler's wake-side iteration key until
   AFTER `WaitForApOnline` confirms the AP signalled itself
   online. The slot in `g_ap_percpus[]` still has to be written
   before the AP runs (the AP reads it during early bringup),
   but the scheduler can't see it as a routing target until
   it's actually serviceable.

2. **`PerCpu::online` predicate** — new flag, set true for the
   BSP in `PerCpuInitBsp`, flipped true for each AP at the
   end of its `SmpStartAps` loop iteration. `PickClusterPlacement`
   and `TargetPerCpuFor` skip slots with `online == false`,
   so a future feature that brings a CPU offline at runtime
   (hot-plug, power-management quiesce, watchdog kill) can flip
   the flag and immediately stop the scheduler routing wakes
   to it without having to coordinate `g_cpu_id_limit`.

   Either layer alone closes the 2026-05-22 race; both together
   survive a future reordering of the AP-bring-up sequence.

Also added a one-shot `[smp] online=1/?` emission on the
trampoline-bloat early-return path so the determinism sweep's
`aps` column always reports a real count instead of `?`.

**Infrastructure to catch the next one cheap.** Same slice
landed several pieces of debug infrastructure so a future
session investigating a similar regression doesn't repeat the
six-rebuild manual probe-injection loop:

- `kernel/arch/x86_64/delay.h::Delay10msApproximate()` — single
  source of truth for short busy-waits that work under both
  QEMU TCG (the emulator doesn't advance virtual-time inside a
  bare `pause` loop with LTO) and real hardware. SmpStartAps's
  INIT→SIPI wait now calls this instead of open-coding the recipe.
- `DUETOS_SCHED_ROUTING_TRACE` build option — flag-gated
  `KLOG_DEBUG` lines at every wake-side `RunqueuePush`
  attributing the routing decision (source CPU, last_cpu hint,
  preferred, target, task name, priority). Compiled out by
  default; turn on to make a routing regression a single grep.
- `tools/test/boot-progress-localizer.sh` — reads any boot log
  and reports the LAST ordered sentinel reached vs the FIRST
  not-reached. Catches "where did the boot stop?" in one
  command instead of eyeballing the tail.
- `tools/qemu/babysit-boot.sh` — wraps `run.sh`; on
  timeout-without-completion auto-runs the localizer +
  `boot-log-analyze.sh` and writes a single diagnosis report.
  Canonical "run a boot and tell me if it broke" entry point.

Verified: 15/15 single boots clean (`[smp] online=8/8`),
6/6 determinism sweep boots OK (`/tmp/sweep3.log`), plus a
re-run of the sweep after the `PerCpu::online` predicate +
`Delay10msApproximate` infrastructure landed (`/tmp/sweep4.log`).

### SMP=8 saturation use-after-free — LANDED (2026-05-22)

The intermittent SMP=8 release-stress `#GP at
RIP=0xdedededededededede` (kheap freed-poison pattern) was a
real reaper-races-dying-task UAF in the scheduler's
exit/reap handoff. The historical comment in `SchedExit`
called the gap out:

    > Single-CPU safety argument: once Schedule() below
    > context-switches away, this task's Current() assignment
    > is gone and only the zombie pointer references the
    > struct. [...] SMP bring-up will need to also verify the
    > task isn't `Running` on a peer CPU before the reaper
    > touches it.

That verify-before-reap half wasn't done. Race:

  1. CPU A — Task T calls `SchedExit`. Marks T as Dead, pushes
     T onto `g_zombies`, wakes the reaper, calls `Schedule`.
  2. CPU B — Reaper wakes, pops T, calls
     `FreeKernelStack(T->stack_base)` — unmaps + frees the
     stack pages.
  3. CPU A — Still mid-`Schedule`. `ContextSwitch` is executing
     ON T's stack while saving rsp/rip and loading the new
     task's regs. The reader gets back kheap freed-poison
     (0xDE bytes), interpreted as a return address → `ret`
     jumps to 0xdedede... → non-canonical #GP. Symptom matches
     the panic dump byte-for-byte.

**Fix (commit `1f07c97`):** per-CPU deferred-zombie. `SchedExit`
stashes the dying task into
`pcpu->ctxsw_dying_task_to_zombie` BEFORE the context switch.
`SchedFinishTaskSwitch` — which runs on the NEW task's stack
AFTER `ContextSwitch` has committed the rsp swap — promotes
the deferred entry to `g_zombies` and wakes the reaper. By
that point the dying task is provably off-CPU on every peer.

Adjacent races fixed in the same slice:

- `Process::refcount` and `AddressSpace::refcount`: plain
  `++`/`--` was racy under SMP. Now CAS-loop retain +
  `__atomic_sub_fetch` release.
- `g_zombies` list mutation: reaper's detach now takes
  `g_sched_lock` for consistency with the deferred-zombie
  producer.

Verified with a 20-repeat UAF-hunt harness
(`/tmp/uaf-hunt.sh 20 5 8 60`): zero panics. Pre-fix rate was
~1/5-1/15 (the panic-dump cleanup that landed earlier in the
slice made the bug VISIBLE; this commit makes it not happen).
The panic-dump path itself was also hardened in the same slice
(`WriteCurrentTaskLabel` defensive guards, `DumpStackWindow`
page-clamp, `PlausibleKernelAddress` upper bound extended
through the kstack arena) so a future regression in the same
area is readable immediately instead of corrupted.

### SMP=8 (4c × 2t) AP-bringup recursive fault under x86_64-debug

- **Symptom:** booting `tools/qemu/run-stress.sh cpu` on
  **x86_64-debug only** with `DUETOS_SMP=8,sockets=1,cores=4,threads=2`
  reproducibly hits a recursive #-fault during the **first AP**'s
  bring-up at ~70 ms after `[arch/smp] starting AP apic_id val=0x1`.
  Captured 2026-05-22; symptom-line in the serial log:

  ```
  [t=97644.875ms] [D] fs/fat32 : ...corrupted bytes... path=""
  [recursive-fault] vec=0x...  rip=0x... — short-circuiting panic dump
  ```

  The vec/rip on the recursive-fault line render mostly as
  spaces / non-printable bytes — the panic-mode SerialWrite is
  bypassing `g_serial_lock`, so the BSP's hex digits and a
  concurrent AP-side writer interleave at the wire level. The
  underlying first fault is therefore lost to corruption.

  **Bound:** x86_64-release at SMP=8 boots clean and runs the
  10s-8-worker stress to `[stress] done` (verdict OK, no
  inversions). x86_64-debug at SMP=4 also boots clean. So the
  AP-bringup storm under KASAN/UBSAN instrumentation noise is
  the trigger — neither SMP=8 alone nor debug alone is enough.
- **Likely shape:** an AP's first timer IRQ enters the trap path
  while KASAN/UBSAN shadow-map machinery is still initialising
  for that AP's stack/IST region, AND `Current()` on that AP is
  the bootstrap sentinel rather than a fully-armed task. The
  UBSAN report path itself takes a lock that races. **Not** the
  GSBASE/lidt root that PR #320 fixed — that one trace-bounds at
  "AP online" and the recursive-fault never reaches it.
- **Reusable harness:** `tools/test/smp-stress-sweep.sh 20 8 5`
  re-triggers the scenario with per-repeat log capture so a
  future investigation can grep `build/x86_64-debug/smp-stress-N.log`
  for the first fault line.
- **Bounded fix landed** (`arch/traps,serial: serialize recursive-fault
  dump through g_serial_lock try-lock`): `HaltOnRecursiveFault` now
  snapshots vec/rip into locals before formatting, pre-formats the
  entire line into a stack buffer, and emits it through
  `SerialWriteNRecursiveFault` — which try-acquires `g_serial_lock`
  (non-blocking) first, falling back to the `PanicEmitTryClaim`
  bounded-spin serializer only if the lock is held (BSP mid-dump).
  The `vec=0x   __  rip=0x   __` interleaving symptom is suppressed.
  Re-run `tools/test/smp-stress-sweep.sh 20 8 5` with this fix in
  tree to read the real first-fault site in the now-clean log.
- **Root cause still open:** the underlying AP-bringup fault (likely
  KASAN/UBSAN shadow-map race on first timer IRQ with a sentinel
  `Current()`) has not been identified. See GAP marker in
  `SerialWriteNRecursiveFault` (serial.cpp). Blocks on: clean log
  from the harness pointing at the actual first-fault RIP.

### SMP=4 boot-tail wild-jump cascade (post-x509 self-test) — LANDED (2026-06-05)

**Root cause: boot-stack overflow.** The reproducible SMP=4 `x86_64-debug`
cascade that faulted immediately after `[x509-verify-selftest] PASS`
(next self-test `HttpSelfTest` never printed) was **not** a reaper/
scheduler UAF — it was the **128 KiB boot stack overflowing** under the
deep post-x509 network self-test chain (`TlsSocketSelfTest` /
`HttpSelfTest` → TLS handshake → x509-verify → ASN.1 → RSA/EC crypto),
all of which run on the BSP boot task's stack.

**Evidence chain that pinned it:**
- A full `-d int` capture showed the wild context was a `ContextSwitch`/
  `ret`-shaped resume to **`RIP=0`** with **`RSP=0xffffffff800dfc40`**
  (phys `0xdfc40`, **~140 KiB BELOW `stack_bottom=0x102000`**), `CR2` a
  per-boot `rdtsc`-shaped value.
- An instrumented run (resume validator extended to reject
  `stack_base==nullptr` resumes below the kernel-image floor, unbuffered
  serial) produced **no validator output** before the cascade, and
  neither did the `ContextSwitch` ret gate (`context_switch.S`), the
  kernel-mode `iretq` RIP gate (`exceptions.S`), the retpoline, nor the
  trampoline gate — all of which range-check `[_text_start,_text_end)`
  and would catch a saved `RIP=0`. Since **no gate fired**, the transfer
  was an **ungated plain `ret`** off a scribbled stack frame, not a
  scheduler resume of a freed Task. (`CR2`=the live TSC further proves
  vaddr 0 was *executed* — the boot PML4 identity-maps `0..1 GiB` RWX, so
  the wild `ret` ran low-RAM bytes instead of faulting.)
- `rsp` ~140 KiB below a 128 KiB stack ⇒ ~268 KiB demand ⇒ a ~140 KiB
  overflow. Because the higher-half **2 MiB map is RW**, the overflow
  grew SILENTLY through the boot sections into reserved low RAM instead
  of faulting (the old `boot.S` "overflow faults immediately" claim was
  false under that mapping). This is the same deep-load-chain pressure
  that already forced the boot stack's documented `16→64→128 KiB` bumps.

**Fix (verified):** grow the boot stack `128 KiB → 512 KiB`
(`kernel/arch/x86_64/boot.S`). With 512 KiB, `DUETOS_SMP=4
DUETOS_CPU=qemu64` (TCG) `x86_64-debug` boots **past** the former crash
point — `[x509-verify-selftest] PASS` → all eight `[net/http-selftest]
PASS` lines → `TlsSocketSelfTest` → steady-state runtime (`kheartbeat`
heap/frame stats, `cpu_busy_pct≈23%`) to **215 s guest uptime** with
**zero** `v=0e`/`v=0d` runaway in the `-d int` log and **zero** panics.
Pre-fix this faulted byte-identically (incl. on `origin/main`).

**Follow-ups (hardening, not blockers):**
1. **Boot-stack guard page** — map a 4 KiB not-present page just below
   `stack_bottom` so a *future* overflow faults at the boundary
   (attributable `#PF`) instead of silently corrupting low RAM. Needs a
   2 MiB→4 KiB split in `boot.S` (the page below `stack_bottom` shares the
   first 2 MiB with `.text.boot`, which is dead after the higher-half
   jump, so it can double as the guard). This makes the `boot.S`
   "overflow faults immediately" guarantee actually true.
2. **`#PF`/`#GP`/`#DF` on IST stacks** so trap delivery survives a corrupt
   `RSP` and the `[wild-kernel-rip]` forensic can fire on a whole-frame
   scribble (today the nested push on the bad rsp triple-faults first).
3. **Move deep self-tests off the boot task** (Linux/xv6 model: the boot
   task becomes idle; heavy work runs on properly-stacked workers) so
   boot-stack demand stays bounded regardless of self-test depth.

**Adjacent real fixes landed alongside (both kept, both orthogonal to the
overflow root):**
- **Kill-path reaper UAF** — `Schedule()`'s `kill_requested` branch pushed
  the dying task to `g_zombies` inline (before its `ContextSwitch`), the
  same reaper-frees-running-stack UAF the 2026-05-22 SMP=8 fix closed for
  `SchedExit`. Now routes through the per-CPU deferred-zombie slot;
  `SchedFinishTaskSwitch` is the single post-switch zombie-publish site
  for both termination paths.
- **Resume-validator hardening** — the validator now rejects
  `stack_base==nullptr` resumes with `rsp` below the kernel-image floor
  (defence-in-depth for a corrupt boot/idle resume; verified false-fire-
  safe across a full boot).

**Diagnostic scaffolding (stays in tree):**
`tools/qemu/triage-truncated-boot.sh`, the `[wild-kernel-rip]` /
`[panic-precis]` forensics, `run.sh`'s `DUETOS_SERIAL_FILE=` unbuffered
COM1 route (essential here — the `-d int` log was the only reliable
capture because QEMU 8.2 TCG+SMP `abort()`s on its own BQL assertion when
the guest faults mid-boot), and the `kernel/sched/sched.cpp` resume/reaper
guards.

### Topology — cluster-scoped IPI fan-out

- **Residual:** the *cluster-scoped* fan-out (one ICR write to
  the CPUs of one scheduler cluster, not all peers) needs x2APIC
  *logical* destination mode (LDR/cluster addressing) on top of
  the physical-mode x2APIC already in tree.
- **Blocks on:** profile evidence that a per-cluster (not
  all-peer) fan-out is workload-justified — reschedule is
  single-target, shootdown is kernel-AS-broadcast or
  per-AS-targeted, never per-cluster. Pre-emptive build avoided.
  (Clustering v0, NUMA frame allocator, wake/periodic balance,
  SMT + hybrid P/E bias, hard affinity, MWAIT idle, single-ICR
  broadcast, and x2APIC enablement all landed — see
  [CPU Topology](../kernel/CPU-Topology.md) /
  [Scheduler](../kernel/Scheduler.md).)

### KMalloc slab routing + real KASAN

- **Residual:** (1) route small `KMalloc` calls through pre-built
  size-classed slab caches automatically (today opt-in via direct
  `SlabAlloc`); (2) **real KASAN** — shadow-memory mapping,
  compiler-plugin integration, per-access shadow lookup. Big
  lift; deferred until a use-after-free hunt needs it. (Slab
  allocator + freed-object poison landed.)

### Linux CVE audit — invariants to honour before the surface lands

Each must be honoured **when the matching surface lands**, not
retrofitted after. See
[`Linux-CVE-Audit`](../security/Linux-CVE-Audit.md) for the
verdict matrix. (Classes E, M, N, O, CC, FF, GG, II-scaffolding
landed.)

- **Class D — COW / `fork()`.** Dirty-bit clear-and-fault must be
  atomic w.r.t. any region-shrink primitive (`madvise(DONTNEED)`).
  Mirror Linux's `FOLL_WRITE` gate in the v0 design.
- **Class C — zero-copy sendmsg / IPsec.** Every externally-backed
  skb fragment carries an ownership marker; every in-place
  transform refuses to operate on a marked fragment. Bake into
  the network-stack ABI from day one.
- **Class B — user-facing crypto API.** An AF_ALG-equivalent must
  refuse src/dst aliasing on user scatterlists for any op that
  doesn't byte-copy the full output.
- **Class I — Bluetooth upper stack.** L2CAP / RFCOMM / SDP
  parser invariants per class C.
- **Class L — IPv6 reassembly.** Every fragment length/offset
  comparison uses `len > end - off` form (never `end - len`).
- **Class K — FS write paths.** Re-audit when ext4 write / NTFS
  directory parsing / any write-remount path lands.
- **Class V — programmable kernel filters.** Do **not** adopt an
  unprivileged-JIT BPF-equivalent; gate any programmable filter
  behind a capability or a formally-verified interpreter.
- **Class W — GPU command submission.** Interpose a kernel
  translation step producing a verified-shape submission the user
  cannot edit post-validation, before any user-mode GPU
  command-buffer surface.
- **Class II follow-up (apply the KASLR slide).** Candidate slide
  is computed at boot (`KaslrGetCandidateSlide`); the follow-on
  builds the kernel PIE, emits a relocation table the early-boot
  stub iterates, applies the slide, and flips
  `KaslrGetKernelSlide` to return it. **Same work as T5-03.**
  Must land before any multi-tenant deployment.
- **When to revisit:** every time a high-impact public
  Linux/Windows kernel CVE drops, walk the audit doc and update
  verdicts before the next slice lands in the affected area.

### Intel CET enable

- **Scope:** write `IA32_S_CET` / `IA32_PL0_SSP`, allocate
  shadow stacks, recompile with `-fcf-protection=branch`.
- **Blocks on:** kernel-image rebuild flag wiring + per-task
  shadow-stack allocator + per-IDT-vector ENDBR64 prologue.
  Probe (`arch::CetGet`) is in place to gate the enable code.
- **When to land:** when a test-fleet machine advertises
  CET-SS / CET-IBT and a workload benefits from software-enforced
  CFI on top of the silicon protection.

### KPTI enable (settled — DEFERRED)

- **Status:** runtime probe
  (`arch::CpuMitigationsGet().needs_kpti`) is in tree; on a
  `RDCL_NO=0` boot it emits a loud serial WARN.
- **Why deferred:** every CPU in the hardware-target matrix
  reports `RDCL_NO=1` in silicon, making KPTI a 5–30% syscall
  cost mitigating an attack the hardware already prevents.
- **Re-open triggers:** a target-fleet CPU lacking `RDCL_NO=1`,
  or a workload that crosses a trust boundary the hardware can't
  enforce.

---

## Storage and filesystem

### FAT32 — driver-wide mutex saturation under concurrent writers

- **Residual:** `kernel/fs/fat32.cpp:68` declares one global
  `sched::Mutex g_fat32_mutex` (`Fat32Guard` RAII at every public
  entry) protecting both metadata (BPB, FAT chain cache, path
  cache) AND the **single** I/O staging buffer `g_scratch[4096]`.
  Every lookup / read / write / mkdir / rename serializes on it.
  Correct (the recursive-entry handling in `Fat32Guard::Fat32Guard`
  is the standard pattern) but **two saturation corners** are
  visible without rewriting the locking:
  1. **Priority inversion** — there is no priority inheritance
     today. A low-priority task holding the mutex while a
     high-priority task waits is blocked by a peer at the same
     scheduling class. v0 has one priority band so the symptom
     is "fair-share starvation under contention," not a hard
     hang — but `Process::win32_priority_class` is wired
     (T8-01-followon) and the moment band-aware enqueue lands
     this becomes a real inversion.
  2. **Livelock under wake-storm** — many tasks repeatedly
     contesting `g_fat32_mutex` spend cycles waking + parking
     instead of doing FS work. Repro under stress=cpu workloads
     that touch FAT32 from the boot tail: `fs/fat32 : lookup`
     debug lines fire hundreds of times per second per worker,
     each round-tripping through `MutexLock` / `MutexUnlock` and
     the per-task held-stack snapshot/restore.
- **Lock-free path-cache fast path — LANDED (2026-05-22).** The
  smallest-concrete-fix bullet's original "per-CPU `g_scratch`"
  approach turned out to be invasive (the buffer is read
  throughout the parsers, not just by `ReadSector`), so the
  actually-smallest fix that helps shipped instead: a
  seqlock-guarded `PathCacheGetSeqlock` probed BEFORE
  `Fat32Guard` in `Fat32LookupPath`. Every cache-hit lookup —
  the boot-storm pattern of repeated NOTES.TXT / TEST.* /
  TRTEST.BIN / KERNEL.FIX probes — now skips the mutex acquire
  + held-stack push + cli/sti + release entirely. Writers
  (under the mutex) bump a per-entry `write_seq` to odd before
  fields, back to even after; readers (lock-free) snapshot the
  seq before + after their copy and bail on any mismatch. The
  generation counter store became `__ATOMIC_RELEASE` so
  concurrent invalidation downgrades to a miss instead of a
  stale entry. Saves a `MutexLock`/`MutexUnlock` round-trip per
  cache hit — observable on `tools/test/fat32-concurrent.sh`
  contention metric.
- **Residual (per-CPU `g_scratch` + lock-drop during block-IO):**
  the actual "release the mutex during the slow block read"
  win still needs the buffer split. Audit-wise that's:
  thread a `scratch_ptr` parameter through ReadSector /
  ReadCluster and the BPB / DirEntry parsers in fat32.cpp,
  fat32_dir.cpp, fat32_lookup.cpp, fat32_read.cpp,
  fat32_write.cpp, fat32_create.cpp — about 40 call sites and
  every consumer line that reads `g_scratch[N]`. With the
  buffer per-CPU, the mutex can be dropped around the
  `BlockDeviceRead` itself (the slow path). Larger but
  mechanical; gated until a workload shows the path-cache
  fast-path doesn't already absorb the contention.
- **Baseline measurement (2026-05-22 — gates the refactor):**
  `tools/test/fat32-concurrent.sh 30` on x86_64-release reports
  zero `fs/fat32 : lookup` debug lines, zero `MutexLock waiter`
  parking sentinels, zero non-deliberate lockdep inversions,
  and zero `fs/fat32 [E]` lines over the 30 s window. The
  path-cache fast path is doing its job — boot-storm probes
  (NOTES.TXT / TEST.* / TRTEST.BIN / KERNEL.FIX et al.) all
  retire lock-free before the slow walker is consulted, so the
  driver-wide mutex never serialises under the present
  workload. Per the gate below, the per-CPU `g_scratch` +
  lock-drop refactor stays deferred — the cost (≈ 120
  reference-site edits across 5 TUs, in the same area as the
  just-landed SMP=8 UAF fix) does not buy a measurable win
  today. Revisit when a workload shows the seqlock probe
  missing (e.g. write-heavy + sustained eviction beyond the
  32-slot cache) or when a profile attributes wall-time to
  the in-mutex `BlockDeviceRead`.
- **Larger refactor (deferred):** split into per-volume mutex +
  per-cache RwLock + lock-free FAT entry cache. Wants its own
  slice once the path-cache fast path + per-CPU scratch are
  measured.
- **Saturation harness:** `tools/test/fat32-concurrent.sh`
  spawns the linux-smoke synfs + win32 PE smokes concurrently
  and captures the boot log. Look for `fs/fat32 : lookup`
  line-rate vs `MutexLock waiter` parking lines as the
  contention signal. (Script-side fix landed 2026-05-22 — the
  `|| echo 0` fall-back was chained onto `grep -c`, which
  already prints 0 on no-match and exits 1, so on a clean run
  the variable captured "0\n0" and the arithmetic below it
  bombed with "syntax error in expression". Replaced with `;
  true` so a clean baseline run completes its report.)
- **Blocks on:** evidence that the path-cache fast path didn't
  close the live livelock corner. The 2026-05-22 baseline run
  above shows it HAS closed it under the present workload, so
  this entry stays gated until a future workload shows the
  symptom.

### Stage 6 — per-process namespace roots (residual)

- **Residual:** teach `Process::root` to carry a `VfsNode` (or a
  thin `VfsDir*` handle) so a sandboxed process can be rooted at
  a non-ramfs subtree (e.g. `/disk/0/SANDBOX`). Today every
  process root is a `const RamfsNode*`; trusted roots see the
  global mount namespace by policy and custom roots can expose
  individual graft points, but the root itself can't be a
  non-ramfs backend node. The wider syscall surface (open / stat
  / readdir) still lands in `RamfsNode*` for ramfs fall-through —
  migrating those is a per-syscall follow-on once a workload
  demands a non-ramfs sandbox root. (Global-namespace VFS mount
  registry + cross-mount resolver landed.)

### Stage 7+ — writable / native FS / NTFS read

In rough priority:

1. **Native DuetOS FS** — journalled, ext-like, done in Rust.
   Partly landed (DuetFS v3) — see **DuetFS follow-ups** below.
2. **NTFS read-only** — required by the Windows-PE pillar to load
   a `.exe` from a real NTFS partition. (NTFS metadata walker +
   read path landed, including VFS integration: `VfsResolve` on an
   NTFS mount surfaces an `Ntfs`-tagged `VfsNode` that the shell
   read path streams via `NtfsReadMftRecord` → `NtfsResolveData` →
   `NtfsReadFile`; ext4 read-only landed identically — see
   `Ext4Lookup` / `NtfsLookup` in `kernel/fs/mount.cpp` and the
   `[ext4-selftest]` / `[ntfs-selftest]` "VFS resolve verified"
   boot gates. ext4 walks **multi-component** paths (`/sub/file`)
   via `Ext4FindInDir`; **residual:** NTFS resolve is still
   single-component (root + direct children) — multi-component
   needs a generic `NtfsFindInDir` over an arbitrary record's $I30
   index, mirroring the ext4 template. NTFS *write* is a separate
   item — **T7-04** below.)

### Foreign-FAT interop read — explicit opt-in mount

- **Residual:** `Fat32Probe` now adopts ONLY DuetOS-owned volumes
  (BPB serial `kDuetOsVolumeId` + label `kDuetOsVolumeLabel`, via
  `Fat32VolumeIsDuetOsOwned`). A FAT32 volume without those markers —
  a Windows EFI System Partition, a real Linux FAT, a USB stick — is
  recognised and logged but **not** registered, so it can never become
  `Fat32Volume(0)` and have the boot persistence sinks write into it.
  This closed the bare-metal vector where DuetOS wrote `KERNEL.LOG` /
  `KERNEL.FIX` into a foreign partition.
- **Gap:** the long-term FAT32 *interop-read* goal (mount a foreign
  FAT read-only for `.exe` loading / data import) now needs an
  **explicit, user-invoked, read-only mount path** that bypasses the
  ownership gate deliberately — it must register the foreign volume at
  an index ≥1 (never slot 0) and mark it read-only so no sink targets
  it. Not wired at boot today; marked `// GAP:` in
  `kernel/fs/fat32.cpp` (`Fat32Probe` foreign-volume branch).
- **Owner:** `kernel/fs/fat32.cpp`, `kernel/fs/mount.cpp`.

### Crash-dump persistence — real-hardware verification

- **Residual:** an unforced panic on an installed laptop is the
  last step to graduate this from "shipped" to "lived through it
  once." The encode + transport layers (QEMU debugcon + in-RAM
  minidump + NVMe/AHCI reserved-region + installer
  `kDuetCrashDumpTypeGuid` partition) are all in tree.
- **Safety invariant (landed):** the disk-persist path writes ONLY
  into a DuetOS-owned `kDuetCrashDumpTypeGuid` partition, discovered
  via `GptFindCrashDumpRegion` and bounds-checked by
  `GptCrashDumpRegionSane`. There is **no** "tail of namespace"
  fallback — on a disk DuetOS didn't partition (a real machine's SSD
  with Windows/Linux installed) a crash dump is NOT written to disk
  (the serial/debugcon copy still emits). `DiskPersistSelfTest` SKIPs
  (rather than writing) when no owned reservation exists, so the
  real-HW verification above requires booting the **installer** first
  to lay the crash-dump partition; until then disk persistence is
  intentionally inert.

---

## Drivers

### Audio — real-hardware audible + per-producer cursors

- **Residual:** (1) real-hardware audible validation (no HW in
  CI — the QEMU smoke proves the routed-codec DMA path:
  `[audio-selftest] DMA LPIB advanced (routed, audible path)`);
  (2) per-producer write cursors — today producers all choose
  their own `frame_offset` and the additive `WritePcmS16Stereo`
  path composes (saturating-add) when two writes hit the same
  offset, but staggered-offset multi-stream needs a per-producer
  cursor table anchored ahead of LPIB. (Saturating-add mixer +
  explicit `WritePcmS16StereoOverwrite` for fill-the-buffer
  producers landed.)
- **Owner:** `kernel/drivers/audio/`,
  `kernel/subsystems/audio/`.

### Wireless — real-hardware verification

- **Residual / blocks on:** real-hardware verification cycles;
  firmware-package signing root / key IDs; per-vendor MSI/MSI-X
  IRQ wiring; iwlwifi TFD descriptor build / doorbell / per-RBD
  data buffers; installer integration for the offline Wi-Fi
  firmware kit (`tools/firmware/prepare-wifi-firmware.py` output
  staged from install media before the network picker opens).
  The AR9271/AR7010 `ath9k_htc` open-firmware scaffold is in tree
  (`kernel/drivers/net/ath9k_htc{,_fw,_upload}.{h,cpp}`) but
  needs a physical dongle — open firmware exists for no on-board
  commodity Wi-Fi chip. (Data-decode + control tier + crypto +
  4-way handshake + per-vendor upload + ring scaffolds + regdb
  US/EU/JP + 802.11d Country-IE intersector all landed; 17
  self-tests pass.)
- **Unlocks:** Network flyout SSID picker, Settings → Network →
  Wi-Fi tab, captive-portal handler.
- **Owner:** `kernel/drivers/net/wireless/`, `kernel/net/wireless/`.

### iwlwifi — live-silicon TX / RX

- **Residual:** PCIe MSI-X negotiation (IVAR LUT writes at
  `CSR_MSIX_IVAR_AD_REG = 0x2890`, route every cause to vec 0 for
  single-vector start); per-TFD `iwl_pcie_txq_build_tfd` (legacy
  format: 20 TBs, `__le16 hi_n_len` packed, `HBUS_TARG_WRPTR =
  0x460` doorbell); RX queue init via `FH_RSCSR_*` (`0xBC0`,
  `0xBC4`, `0xBC8` — note write-ptr must be multiple of 8);
  `iwl_rx_packet` cmd dispatch on `REPLY_RX_MPDU_CMD` →
  wdev::OnDataRx. ALIVE handler in MSI-X "other" vector.
- **Reference:** `drivers/net/wireless/intel/iwlwifi/pcie/{tx,rx,trans}.c`
  in Linux. Start with legacy gen1 (7000/8000/9000) — gen2's BC
  table + dynamic scheduler is a separate slice.
- **Owner:** `kernel/drivers/net/iwlwifi_rings.cpp` (598 lines),
  `kernel/drivers/net/iwlwifi.cpp`.

### ath9k_htc — HTC service negotiation

- **Residual:** post-firmware-upload HTC state machine. Wait for
  `HTC_MSG_READY_ID` on `USB_REG_IN_PIPE`, send
  `HTC_MSG_CONFIG_PIPE_ID`, then `HTC_MSG_CONNECT_SERVICE_ID` for
  `WMI_CONTROL_SVC` / `WMI_BEACON_SVC` / `WMI_MGMT_SVC`. Surface
  `WmiSend(cmd_id, buf)` to wdev. `WMI_INIT_CMDID` →
  `WMI_SET_CHANNEL_CMDID` → `WMI_START_RECV_CMDID` lights up the
  scan path.
- **Reference:** `drivers/net/wireless/ath/ath9k/{htc_hst,hif_usb}.c`.
- **Owner:** `kernel/drivers/net/ath9k_htc.cpp` (301 lines).

### USB mouse — high-DPI real-hardware verification

- **Residual:** plug in a high-DPI USB mouse and verify the
  device-supplied HID Report descriptor produces the expected
  12/16-bit X/Y layout, button mask, wheel, and AC-Pan fields on
  real interrupt-IN reports. (Descriptor-driven decoding +
  injector + synthetic self-tests landed.)
- **Owner:** `kernel/drivers/usb/`.

### Intel iGPU command submission (GGTT batch + 2D BLT)

- **Today:** the RCS ring at MMIO 0x2000 is programmed and the boot
  self-test verifies `MI_STORE_DWORD_IMM` read-back. Everything
  graphics-accelerated still falls back to a software rasterizer.
- **Plan (research landed 2026-05-29 — see
  [`GPU-Implementation-Notes` §Intel](GPU-Implementation-Notes.md)):**
  five slices, in order —
  1. **Forcewake + GT-init** — hold RENDER+GT domains (Gen9 set/ack
     `0xA278`/`0x0D84` + `0xA188`/`0x130044`) with the Gen9–11
     fallback-ack erratum, RC6 off, un-stop the ring via
     `RING_MI_MODE`.
  2. **GGTT manager** — encode 64-bit PTEs (`phys | present`, LM=0),
     write through the BAR0 GTTMMADR upper-half alias, scratch-fill
     all slots, allocate GPU-VA above the GMADR aperture.
  3. **Batch submission + breadcrumb** — `MI_BATCH_BUFFER_START`
     (full 48-bit lo/hi addr) from a GGTT batch, `wmb` before the
     `RING_TAIL` doorbell, PIPE_CONTROL post-sync seqno + poll.
  4. **2D BLT → GDI accel (the T4-03 win)** — `XY_COLOR_BLT`
     (ROP `0xF0` fill) + `XY_SRC_COPY_BLT` (ROP `0xCC` copy) on the
     BCS ring; wire GDI `FillRect`/`BitBlt` to it.
  5. **Display detect/modeset** (independent) — GMBUS EDID read +
     `SDEISR`/`GEN11_DE_HPD_ISR` connector detect + primary-plane
     reprogram (keep firmware timings; defer PLL math).
- **Verification ceiling:** QEMU has no Intel-iGPU model, so the
  encoders (PTE / MI_* / BLT command builders) are pinned by boot
  self-tests asserting exact DWORDs (run + PASS under QEMU), but the
  MMIO submission paths are gated and **unverified on silicon** — they
  need a Gen9 NUC (Skylake/Kaby-Lake, no Optimus) + serial UART. The
  non-destructive proof ladder is in the notes page.
- **Blocks:** GPU-accelerated GDI paint (Track 4 → T4-03), DirectX
  real-device backends, multi-monitor mode-set.
- **Owner:** `kernel/drivers/gpu/intel_gpu.{h,cpp}` + a new GGTT/BLT unit.

### Multi-monitor / runtime resolution change

- **Today:** single linear framebuffer, mode set at boot via
  Bochs VBE; EDID parser landed, hot-plug detect missing.
- **Blocks on:** per-vendor GPU drivers (Intel/AMD/NVIDIA all
  probe-only), mode-set negotiation.
- **Owner:** `kernel/drivers/gpu/`.

### Brightness — per-vendor register backlight

- **Residual:** per-vendor *register* backlight (Intel/AMD PWM,
  vendor WMI / Fn-key hotkeys) for laptops that do brightness
  outside ACPI `_BCM`; wire the UI brightness control + Fn-key
  events to `AcpiBacklightSet`. (ACPI `_BCL`/`_BQC`/`_BCM` path +
  EC driver landed.)

### Battery + ACPI suspend (residual — shared with ACPI S5)

- **Residual:** S3 / S0ix suspend-to-RAM wake-vector +
  context save/restore. EC `_Qxx` read path
  (`AcpiEcReadQueryByte` / `AcpiEcDispatchPendingQuery`) and
  per-bit `_Lxx`/`_Exx` GPE walking in the `env-monitor` task
  both landed 2026-05-26 — lid-close / AC plug/unplug events
  routed through either EC `_Qxx` or per-GPE method now fire
  the firmware's handler. Battery / AC / lid *state* readable
  via `_LID`/`_PSR`, SCI power-button path, ACPI S5 soft-off
  incl. `_PTS`/`_GTS`, and the GPE `_Qxx` event surface all
  landed. Open work: S3 trampoline + per-driver Suspend/Resume
  callback contract (the harder half, per the research notes).

### Bluetooth, Printer, Webcam

- **Bluetooth residual (SMP-gated frontier):** the connection
  manager — LE scan/connect, SMP pairing/bonding, GATT-HOGP
  service discovery — so a real BT keyboard can associate on its
  own; plus general L2CAP signalling / RFCOMM / SDP for
  non-keyboard profiles. (HCI codec, HID-keyboard upper stack,
  btusb transport, xHCI interrupt-IN primitive landed; invoked
  via `bt probe`.)
- **Printer:** USB printer-class driver + IPP / PostScript /
  raster pipeline.
- **Webcam:** UVC USB-Video class driver.

### Source-tree GAP markers

Live edge-case index — the v0 happy path skips these:

- `kernel/drivers/net/iwlwifi_rings.cpp` — legacy <7000-series
  RBD format; real MSI-X interrupt-driven dispatch (TX-completion
  polling + periodic-poll wiring landed).
- `kernel/mm/dma.cpp` — ARM64 port (`dsb ishst` + per-line
  `dc cvac`).
- `kernel/subsystems/translation/translate.cpp` — `rseq`
  (restartable sequences).

Re-derive the full inventory with `git grep -nE "// (STUB|GAP):"`.

---

## Win32 / NT subsystem

### Locale / format-picture surface (residual)

Landed 2026-05-29: `kernel32!MulDiv`, `user32!wsprintf{A,W}`/`wvsprintf{A,W}`
(were MISSING), and `kernel32!GetDateFormat{A,W}`/`GetTimeFormat{A,W}` now
honor their format-picture string (were `(void)fmt`-ignored). Remaining,
same clean en-US-table pattern (verifiable via the `hello_winapi` pe-winapi
smoke):

- **`GetNumberFormatA/W`** still ignores its `NUMBERFMT` picture
  (`userland/libs/kernel32/kernel32_io.c` ~`GetNumberFormatA`,
  `(void)fmt;`): grouping commas, decimal places, separators. The
  easiest next item — mirrors the `GetDateFormat` picture work.
- **`GetLocaleInfoW`** — widen the LCType table
  (`kernel32_locale.c`): `LOCALE_SSHORTDATE`/`SLONGDATE`/`STIMEFORMAT`/
  `SCURRENCY`/`SDAYNAME1..7`/`SMONTHNAME1..12` (reuse the day/month
  tables added for GetDateFormat).
- **`LCMapStringW`** — add `LCMAP_SORTKEY` (an upcased ordinal key is
  valid en-US/invariant) and standalone `NORM_IGNORECASE`
  (`kernel32_io.c` ~`LCMapStringW`, currently case-map only).
- **`shlwapi!wnsprintf{A,W}`, `StrToIntEx`** — bounded printf + parse;
  can share the `user32` restricted-printf core.

### DirectX real device backends

- **Still gated:** HLSL bytecode execution (the `d3dcompiler.dll`
  frontend emits a DXBC-shaped blob the draw path ignores; a
  DXBC->SPIR-V transpiler would feed the now-live in-kernel
  SPIR-V interpreter — see [Vulkan ICD](../subsystems/Vulkan-ICD.md)),
  texture sampling, geometry/hull/domain/compute shaders,
  multi-stream input, Z-buffer, D3D9 fixed-function lighting,
  real GPU command-ring submission.
- **Blocks on:** per-vendor GPU drivers landing real
  command-ring submission; D3D→Vulkan thunk wiring (the Vulkan
  ICD v1 lifecycle + SPIR-V interpreter + userland `vulkan-1.dll`
  thunk + `SYS_VK_CALL` syscall all landed; the D3D side still
  returns `E_FAIL` and must redirect through the Vulkan path.
  With shaders now executable in-kernel AND the userland
  vulkan-1.dll bridge live, the thunk slice is "translate
  D3D11/12 Clear+Draw+Present API into the matching VkCmd* +
  bind a known-good SPIR-V pipeline" instead of the previous
  "wait for shader execution to land first.")
  (D3D9/11/12 COM vtables + shared software rasterizer + DXGI
  swap-chain present into compositor windows landed.)

### Windowing — modal dialogs, common controls

- **Residual:** common controls, multi-threaded message queues.
  Menu GAPs: `TPM_LEFTBUTTON`/`TPM_RIGHTBUTTON` activation
  filtering, menubars + `LoadMenu` resource loading. See
  [`Compositor`](../subsystems/Compositor.md) §"Popup Menus" for
  live state. (Message pump, GDI paint, popup menus +
  `WM_CONTEXTMENU` + `TPM_*` flags, modal dialog primitive,
  native scroll bars with drag-the-thumb + click-on-track,
  interactive Move/Size via `modal_input.{h,cpp}`, Files-app
  rename UI, Trash + ramfs Files per-row context menus landed.)

### Winsock async surface

- **Deferred:** Overlapped I/O + IOCP-backed socket reads
  (kernel32's IOCP plumbing exists but isn't wired into the
  socket read path — see **IOCP consolidation** below);
  kernel-direct event signaling at the moment of socket activity
  (today's `WSAWaitForMultipleEvents` is a 10 ms polling loop);
  `fWaitAll == TRUE` semantics (current impl returns on first
  ready event). (Synchronous BSD subset + the `WSAEvent*` /
  `WSAEventSelect` / `WSAEnumNetworkEvents` async surface +
  kernel `SocketPollEvents` producer landed.)

### `WSAAsyncSelect` (Win32 socket → window-message delivery)

- **Cost:** ~200 LoC in `userland/libs/ws2_32/ws2_32.c` plus a
  helper thread per process. Zero kernel change — the existing
  `kSockOpPollEvents` producer is enough.
- **Design:** process-global socket→{hwnd, msg, events, armed,
  fired} registry. One helper thread polls every 10 ms (same
  cadence as the existing `WSAWaitForMultipleEvents` loop), AND
  `events & armed`, calls `PostMessageA(hwnd, msg, s,
  MAKELONG(bit, 0))` for each set bit, then clears that bit from
  `armed`. Re-arm when `recv`/`send`/`accept` returns
  `WSAEWOULDBLOCK`.
- **Reference:** ReactOS `dll/win32/msafd/misc/dllmain.c`
  (`WSPAsyncSelect`, `SockAsyncThread`). Wine's `server/sock.c`
  has the kernel-push variant.
- **Unlocks:** Legacy GUI networked PE apps (FTP/IRC/telnet
  clients, classic Outlook Express). Implement before IOCP
  because (a) lower kernel change, (b) broader app coverage.
- **Owner:** `userland/libs/ws2_32/`, `userland/libs/user32/`.

### IOCP for sockets (Win32)

- **Cost:** ~300 LoC for a new `KCompletionPort` kernel object
  (`kernel/ipc/kcompletion.{h,cpp}`) + new sub-ops on
  `SYS_HANDLE_OP`: `kCompPortCreate(concurrency)`,
  `kCompPortAssociate(port, handle, key)`,
  `kCompPortPost(port, key, bytes, ovl)`,
  `kCompPortGet(port, &key, &bytes, &ovl, timeoutMs)`. New socket
  sub-op `kSockOpOverlapped(kind, sock, buf, len, ovl_uptr)`
  returns `WSA_IO_PENDING` and posts completion to the associated
  port.
- **Reference:** Wine `dlls/ws2_32/socket.c` overlapped path +
  `WS_AddCompletion` → `NtRemoveIoCompletion`.
- **Ordering:** ship `WSAAsyncSelect` first (no kernel change);
  IOCP follows when a real overlapped-using PE binary is in test.
- **Owner:** `kernel/ipc/`, `userland/libs/ws2_32/`.

### TCP sender-side SACK (RFC 6675)

- **Cost:** ~600 LoC sender + ~24 B scoreboard head per TCB +
  amortised ~16 B per outstanding hole.
- **Design:** FreeBSD-style tail-queue of `sackhole {start, end,
  rxmit}` per TCB. On every ACK, walk inbound SACK blocks ↔
  scoreboard; implement `IsLost()` and `NextSeg()` per RFC 6675
  §3. On loss → enter fast recovery, set `Pipe`, retransmit
  `NextSeg()` candidates until `Pipe` hits cwnd.
- **Reference:** `sys/netinet/tcp_sack.c` (FreeBSD, ~1100 LoC).
  Linux's equivalent lives inline in `net/ipv4/tcp_input.c`
  (`tcp_sacktag_write_queue` and friends) — readable but tightly
  coupled to skb-chain state we don't have.
- **State:** receiver-side SACK emission already landed; this is
  the half that turns SACK into a real recovery win on lossy
  paths.
- **Owner:** `kernel/net/tcp_segment.cpp`, new
  `kernel/net/tcp_sack.{h,cpp}` if the scoreboard grows large.

### TCP ECN data plane (IP-layer ECT/CE threading)

- **Cost:** ~200 LoC across `stack.cpp` IPv4 emit/recv +
  `tcp_segment.cpp` ACK path.
- **Design:** on outbound IP data segments for `ecn_ok` TCBs, set
  TOS bits 0..1 to `10` (ECT(0)); on inbound IP CE-marked
  segments (TOS bits = `11`), flag the receiving TCB
  `peer_ce_pending = true`; on the next outbound ACK, set
  ECE=1; on inbound ECE, halve `cwnd`, set `sent_cwr=true`; next
  outbound data segment carries CWR=1, clears `sent_cwr`.
- **Reference:** RFC 3168 §6.1.2-§6.1.5; Linux
  `net/ipv4/tcp_input.c::tcp_ecn_*` family.
- **State:** SYN-time negotiation landed (per-TCB `ecn_ok` bit
  set on both sides). Data plane is the missing half.
- **Pairs with:** AccECN (RFC 9768) — 4 counters per direction
  for L4S / DOCSIS prioritisation. Land in same slice.
- **Owner:** `kernel/net/stack.cpp`, `kernel/net/tcp_segment.cpp`.

### TCP CUBIC congestion control (RFC 9438) — LANDED (2026-05-29, PR #366)

Implemented as integer-only `kernel/net/tcp_cubic.cpp` (port of Linux
tcp_cubic.c), wired into the CA branch with a `max(cubic, reno)` floor
(can never underperform NewReno) and a `Tcb.cubic.enabled` kill switch.
Loss reaction beta=717/1024 at both 3-dup and RTO sites; verified by
deterministic `tcp_selftest::TestCubic`. NOTE: throughput benefit is
unobservable on QEMU's zero-RTT loopback — needs real-HW / high-RTT
validation; flip `cubic.enabled=false` if it ever misbehaves on silicon.
**BBR** remains deferred indefinitely (needs a pacer + delivery-rate
estimator + 4-state machine, ~2000 LoC).

### IPv6 dual-stack

- **Cost:** ~3000 LoC + ~15 KB state.
- **Design:** mirror lwIP's `src/core/ipv6/` (smallest correct
  IPv6 reference at ~3000 LoC). Cross-reference OpenBSD
  `sys/netinet6/` for the cleaner protocol layering. Address
  widening: 4-byte → 16-byte union on every `addr_t`; per-socket
  +10 B for AF+V6ONLY+scope+flowinfo; per-TCB +24 B for
  dual-family endpoints; prefix list + default-router list +
  neighbor cache ~6 KB total.
- **Approach:** AF_INET6 as the native type with v4-mapped
  addresses (`::ffff:0:0/96`) bridging. NOT separate AF_INET +
  AF_INET6 codepaths.
- **Required pieces:** NDP (NS/NA), Router Discovery (RS/RA),
  prefix-info → SLAAC, MLD (mandatory for solicited-node
  reception), fragment reassembly (sender-side fragmentation can
  defer to PMTUD-discovered minimum MTU + don't-fragment).
- **Owner:** new `kernel/net/ipv6/` subdirectory; subsystem page
  follows the same shape as `Network-Stack.md`.

### Open-firmware adoption (per Wireless / GPU)

- See [Open Firmware Landscape 2026](../drivers/Open-Firmware-Landscape-2026.md)
  for the full decision matrix. Concrete next slices:
  - **Wire ath9k_htc HTC service negotiation against
    `qca/open-ath9k-htc-firmware` builds** — first physical-
    hardware Wi-Fi target with zero closed firmware.
  - **`.duetfw` package signing root** — Ed25519 offline HSM
    project root + yearly intermediate; signer-key-ID format as
    SHA-256 truncated to 16 B (Sigstore convention).
  - **Quarterly firmware-landscape refresh** — rotate
    `Open-Firmware-Landscape-2026.md` every quarter; key items
    to recheck: Nexmon supported chips, openwifi releases, any
    Realtek open-firmware emergence (currently zero).

---

## End-user features

### Chrome tactility (Pass A) — residual polish + Pass A verification

The chrome-tactility plan
(`docs/superpowers/plans/2026-05-24-duetos-chrome-tactility.md`)
landed 23 of its 28 tasks: blend math + atlas-based 9-slice soft
shadow + 7 new Theme fields + per-theme intensity matrix +
runtime override (cmdline + shell) + chrome paint integration
on windows, modals, snap previews, taskbar tabs + strip, menu
panels + the WindowPaintFocusGlow helper. See
[`Compositor`](../subsystems/Compositor.md#chrome-tactility-pass-a)
for the subsystem summary.

The residuals waiting on visual verification or follow-on work:

- **VBox boot verification** (Task 27 step 5 of the plan).
  QEMU verification landed on 2026-05-24: all four
  `*-selftest` PASS sentinels fire on the canonical
  `x86_64-debug-fast` boot, the boot-log-analyzer TACTILITY
  section reports `blend=1 shadow=1 theme-matrix=1 umbrella=1
  probe fires=0`, and `tools/test/tactility-screenshot-matrix.sh
  classic` produces a 2.3 MB 1024×768 PPM at
  `build/shots/classic-debug-fast.ppm`. VBox still wanted per
  the [`vbox-bringup-pr266`](../../docs/...) memory entry —
  LAPIC / GS-base differences from QEMU sometimes catch what
  QEMU doesn't.
- **(VERIFIED 2026-05-24)** HighContrast pixel-diff invariant
  (plan §8.5 step 6). Empirically confirmed via
  `tools/test/hc-invariant-check.sh`: HighContrast captured
  twice under tactility=auto (theme matrix says off) + once
  under tactility=off (runtime override) shows the
  auto-vs-override diff (324 px) is below the inter-boot
  noise floor itself (333 px). The 333 px noise floor is the
  live taskbar widgets — clock display, uptime ticker,
  network-state cell, cursor PS/2-timing anti-aliasing —
  which vary independently of any chrome code. Together with
  the structural argument (HighContrast.tactility_enabled
  = false → ThemeTactilityEffective = false → every
  `*Shadow` site routes through the legacy fallback branch),
  the invariant is closed for this branch.
- **Menu scale-pop animation** (Task 18 full of the plan). The
  menu panel pop from 95% to 100% on open would need a per-
  panel scale factor threaded through `MenuRedraw` + the
  `MenuItemAt` hit-test so the click target stays aligned with
  the painted bounds while the animation runs. Discrete
  refactor; visual verification mandatory.
- **Cursor micro-shadow** (Task 21 of the plan, plan-marked
  stretch). Per-frame cost is the heaviest in the spec —
  cursor moves every PS/2 packet at up to 60 Hz. Also requires
  enlarging the cursor backing-store to cover the shadow halo
  so the shadow region restores when the cursor moves, instead
  of leaving a trail. Defer until soak shows headroom.
- **Per-tab pressed state** (out of plan scope). The taskbar
  per-tab paint reads a CursorPosition-derived hover state but
  the input layer transitions straight from press to dispatch
  without a paint-time pressed bit. An input-state refactor
  that surfaces per-widget pressed-bits would light up the
  press overlay that the chrome-tactility plan describes.
- **Menu row hover wash + force-dirty on flips** (Tasks 18 row-
  wash + 23 of the plan). The existing solid-accent hover-row
  fill in `MenuRedraw` is already a strong affordance; layering
  a tactility wash on top would compound. Task 23's
  force-dirty-on-flip pattern needs `WidgetFlag::*` bit-flip
  call sites that don't exist in this codebase — the current
  bool-state model doesn't have flip points to instrument.
- **WM z-order click bleed-through re-verification.** User reported
  on 2026-05-25 (amber-theme VBox boot, screenshot at 00:59) that
  "apps beneath the ones on top i clicked bleed through." Visible
  bleed in that screenshot predates `7ecfa12c security/guard: pause
  desktop compose while modal prompt is up` by 21 min and is most
  likely the same desktop-compose-vs-guard-prompt race that commit
  fixes. Code inspection of `WindowRaise` + `DesktopCompose` +
  `FramebufferEndCompose` diff scan found the z-order repaint path
  architecturally correct in isolation (gradient marks full-screen
  damage → diff scan finds all changed pixels → blit). Commit
  `e13159be video/wm: force full-screen snapshot invalidation on
  WindowRaise` lands a belt-and-suspenders: when `WindowRaise`
  actually reorders, post a full-screen `FramebufferInvalidateSnapshot`
  so the next `EndCompose` unconditionally flushes shadow→live +
  resyncs the snapshot. Re-verify on the next VBox session WITHOUT
  triggering a guard prompt; if bleed still observable, the root
  cause is elsewhere (cursor backing mismatch, a draw path bypassing
  `MarkDamage`, or a paint primitive writing to `g_info.virt`
  directly during compose) and a follow-up slice is needed.

When a residual ships, delete its bullet here and update the
[`Compositor`](../subsystems/Compositor.md) subsystem page's
"Deferred from Pass A" call-out.

### Chrome tactility (Pass B) — residual polish + Pass B verification

The first-impression moments plan
(`docs/superpowers/plans/2026-05-24-duetos-pass-b.md`)
landed all 25 tasks: boot splash with motion + phase ticker, animated
wallpaper with arc rotation / pulse / topo drift, login GUI with
backdrop clock + avatar card + atlas-shadow + focus-glow password
field + sign-in button. See
[`Compositor`](../subsystems/Compositor.md#first-impression-moments-pass-b)
for the subsystem summary.

QEMU verification complete (2026-05-24): all Pass B self-tests fire
(`[splash-selftest] PASS`, `[wallpaper-motion-selftest] PASS`,
`[login-gui-selftest] PASS`, `[pass-b-selftest] PASS`); the
boot-log-analyzer PASS B section reports `splash=1 wallpaper-motion=1
login-gui=1 umbrella=1 probe fires=0`; no Pass A regressions;
soak reports zero wallpaper/splash/login errors, zero real soft-lockup
warnings, zero compositor missed ticks.

The residuals waiting on visual verification:

- **VBox boot verification.** Pairs with the Pass A VBox residual
  above. Same approach: boot the matrix under VirtualBox after QEMU
  verification; LAPIC / GS-base differences from QEMU sometimes catch
  what QEMU doesn't. Run after the Pass A VBox verification is cleared.
- **Screenshot matrix for splash / login surfaces.** The
  `tactility-screenshot-matrix.sh --splash --login --wallpaper`
  invocation from the spec §10 criterion 1 requires QEMU PPM capture
  (`-screendump`), which is infra-limited in the headless WSL dev
  environment. Cleared automatically when VBox visual verification runs
  (the GUI boot produces the visible frames the spec calls for).

Follow-on items surfaced during live VBox testing of Pass B:

- **Mouse-click positioning under headless QEMU rel-mode.**
  `tools/test/qmp-click.sh` ships in two modes — `abs` for display
  setups and `rel` for headless. The rel-mode "snap to origin via
  Δ=-65535 then move by (X, Y)" pattern is reliable for the snap part
  but the move-by-(X,Y) sometimes doesn't fully propagate through the
  PS/2 driver under fast successive calls (observed: cursor stays at
  origin after a click on (400, 400)). Needs a per-call settling
  delay or per-axis ack from the kernel-side PS/2 ringbuffer; for now,
  treat headless QEMU mouse-click as best-effort and re-issue if the
  cursor doesn't land. Abs-mode users (real display, `usb-tablet`)
  are unaffected.

When a residual ships, delete its bullet here and update the
[`Compositor`](../subsystems/Compositor.md) subsystem page's
"Deferred from Pass B" call-out.

### Chrome typography (Pass C) — residual polish + Pass C verification

The typography hierarchy plan
(`docs/superpowers/plans/2026-05-24-duetos-pass-c.md`)
landed all 21 planned tasks plus 5 settings sub-panel migrations + 1
drive-by comment fix (27 commits total). New module
`kernel/drivers/video/chrome_text.{h,cpp}` owns the four-tier
dispatch (Display 72 px / Title 16 px / Body 13 px / Caption 11 px),
with Regular + Bold weights backed by Liberation Sans Regular and a
newly-baked Liberation Sans Bold companion. Boot sentinels
`[chrome-text-selftest] PASS` and `[pass-c-selftest] PASS
(chrome-text=ok)` fire under the `if constexpr (kBootSelfTests)`
umbrella. See
[`Compositor`](../subsystems/Compositor.md#typography-hierarchy-pass-c)
for the subsystem summary.

Per-task verification: every implementation subagent ran a debug
boot smoke after its commit; all 21 tasks reported all three Pass C
sentinels green plus the bold-font load line, with no PANIC / TRIPLE
/ new non-deliberate FAIL. The `pass-c-soak.sh` 30 s rig (Task 19)
PASSed against commit `ad680846`. Full end-to-end acceptance run
(debug + release builds, hosted ctest, soak, screenshot matrix,
clang-format on all touched TUs together) is **deferred — pending
host disk space** at the time of branch wrap (WSL vhdx couldn't grow
on a 29 MB-free C:). Re-run once disk is freed; expected to be clean
based on per-task evidence.

Residuals carried into Pass D / future polish:

- **Bitmap themes collapse Caption to Body at scale 1** (both =
  8 px). Acceptable v0 — bitmap font is single-size; the role split
  is recovered automatically on any TTF theme. Add a 6×8 micro-font
  asset if a bitmap-theme reviewer reports the visual collapse is
  confusing.
- **No italic, no Thin / Medium / Heavy weights.** Intentional v0
  omission. Extend `ChromeTextWeight` + bake the asset when a design
  need lands.
- **VBox boot verification.** Pairs with the Pass A / Pass B VBox
  residuals above — boot the typography matrix under VirtualBox to
  pick up anything QEMU smokes don't. The
  `tactility-screenshot-matrix.sh --typography` rig (Task 18) is
  the canonical surface set (login + lock + wallpaper × 10 themes
  = 30 PPMs) once the host can rebuild the kernel.elf.
- **Avatar monogram is Title Bold** — fits the 40 px circle today.
  If avatar grows above ~40 px or shrinks below ~24 px, the Bold
  Title metric may need a dedicated "hero monogram" role between
  Display and Title.

When a residual ships, delete its bullet here and update the
[`Compositor`](../subsystems/Compositor.md) subsystem page's
"Pass C — Typography Hierarchy" call-out.

### App widgets (Pass D) — residual polish

The app-widgets plan
(`docs/superpowers/plans/2026-05-25-duetos-pass-d.md`)
landed the library at
`kernel/drivers/video/app_widgets/{widget.h,widget_group.h,
app_button.{h,cpp}, app_label.{h,cpp}, app_panel.{h,cpp},
app_divider.{h,cpp}, app_list_row.{h,cpp}, app_toolbar.{h,cpp},
app_input.{h,cpp}, app_scrollbar.{h,cpp}, self_test.{h,cpp}}`
plus 28 per-app migrations and the acceptance scaffolding
(`tools/test/pass-d-soak.sh` 60 s regression guard,
`tactility-screenshot-matrix.sh --apps` mode). Boot sentinels
`[app-widgets-selftest] PASS` and
`[pass-d-selftest] PASS (widgets=ok, apps=28/28)` fire under the
`if constexpr (kBootSelfTests)` umbrella. See
[`AppWidgets`](../subsystems/AppWidgets.md) for the subsystem
reference and
[`Compositor`](../subsystems/Compositor.md#app-widgets-pass-d)
for the integration summary.

Per-task verification: every implementation subagent ran a debug
boot smoke after its commit; all 28 app migrations report their
per-app sentinel green plus both umbrella sentinels, with no
PANIC / TRIPLE / oom-slab-fault. The `pass-d-soak.sh` 60 s rig
PASSes against commit `5dd79097` (28/28 apps green + Pass A/B/C
umbrellas all green + no soft-lockups).

Residuals carried out of Pass D:

- **Apps not migrated** — six `.cpp` files under `kernel/apps/`
  intentionally stay on raw paint (or have no paint surface):
    - `dbg.cpp`, `dbg_core.cpp` — debug overlays must work when
      half the kernel is wedged; raw paint by design.
    - `gfxdemo_modes.cpp`, `gfxdemo_modes_vk.cpp` — the demos
      exercise primitive APIs directly; widget chrome would
      defeat the demonstration.
    - `notes_persist.cpp` — pure data layer; no paint surface.
    - `trash.cpp` — facade module providing Files' trash mode;
      no chrome of its own.
  Don't migrate these without a compelling reason; the carve-out
  rationale is documented in
  [`AppWidgets`](../subsystems/AppWidgets.md#carve-outs).
- **Carve-outs preserved (raw paint regions inside migrated
  apps)** — Files' folder/list grid, Calendar's month/week/day
  cells, Terminal's cell grid, Hexview's byte grid,
  Gfxdemo's content region, Dbg_render's overlay layer all
  paint raw. Each app's `RenderContent()` runs after
  `group.PaintAll(compose)` into the carved-out rect; the
  widget group owns the chrome only. This pattern is the
  recommended shape for future apps with fixed-grid surfaces.
- **VBox visual verification** — pairs with the Pass A / Pass B /
  Pass C VBox residuals above. Boot the
  `tactility-screenshot-matrix.sh --apps` 3 surfaces × 10 themes
  = 30 PPM reference set under VirtualBox to pick up anything
  QEMU smokes don't.
- **Per-app window screenshots deferred to VBox.** The
  `--apps` matrix mode captures three chrome surfaces (login,
  wallpaper, lock) per theme because qmp.sh can't open
  Calculator / Notes / etc. headlessly — QMP key+click driving
  the Start menu isn't implemented (qmp.sh supports
  `screendump` / `powerdown` / `quit` / `status` only). When
  full per-app shots become valuable, either extend qmp.sh
  with a `keys` / `click` subcommand routed through QMP
  `input-send-event`, or capture them manually under VBox.
- **gfxdemo legacy sentinel.** Predates the
  `[<app>-selftest] PASS` convention and emits
  `[gfxdemo] self-test OK (sin LUT, FxMul, PRNG, Mandelbrot,
  chrome)` instead. `pass-d-soak.sh` accepts either form;
  next time gfxdemo gets touched, normalise its emission to
  the standard sentinel and drop the soak's special case.

Potential Pass E items (deferred — none of these are committed):

- **Layout managers** — today every widget gets explicit
  `Rect bounds` set at construction. A `VBox` / `HBox` /
  `Grid` layout manager would compute bounds from constraints
  + content size, eliminating manual coordinate maths.
- **Extended widget set** — `Checkbox`, `Slider`, `Progress`,
  `Tabs`, `Tooltip`, `Spinner`, `RadioGroup`. Each is one
  widget pair following the existing shape.
- **Event-routing hub** — today every app calls
  `group.DispatchEvent(event)` directly from its mouse /
  keyboard reader. A hub that knows about window focus +
  z-order would route automatically (the window manager
  already does this for chrome; widgets could plug in).
- **Animation system** — Pass A's tactility uses
  static shadow textures; an animation hook (interpolate
  state.flags transitions over N ms) would let press / hover
  feel kinetic without each widget hand-rolling it.

When a residual ships, delete its bullet here and update the
[`AppWidgets`](../subsystems/AppWidgets.md) subsystem page.

### RBAC + elevation broker — v1 follow-ups

- **v1 — Argon2id with lazy migration.** Blake2b primitive
  (RFC 7693) is in tree and passes the Appendix-A vectors;
  Argon2id (RFC 9106) sits on top. **Blocked on a record-format
  extension** — the 56-byte `PasswordHashRecord` can't carry
  Argon2id's memory/time/parallelism params; needs a V2 shape
  sized for both old PBKDF2 + new Argon2id rows. See
  [`RBAC-and-Elevation`](../security/RBAC-and-Elevation.md#argon2id-rollout).
- **v1 — Persistence.** `/system/secrets/` holds the account +
  role tables encrypted at rest; Argon2id-derived key wraps the
  table; TPM seals the wrap key when that driver lands. Until
  then `AuthInit` / `RbacInit` re-seed defaults every boot and
  runtime additions are lost.
- **v1 — First-boot installer flow.** Replace the hardcoded
  `admin / admin` seed with a userland install wizard launched
  by init when `/system/secrets/` is empty. Blocks on the
  persistence work above.
- **v1 — Secure Attention Key.** Reserve Ctrl+Alt+Del at the
  PS/2 driver level → kernel-drawn full-screen broker prompt, so
  a paranoid user can force a known-good prompt. The v0 modal is
  drawn under the compositor lock but doesn't pre-empt a focused
  full-screen surface. (v0 broker + role table + grace cache +
  CLI/GUI prompt + `NtAdjustPrivilegesToken` facade routing
  landed.)

### Suspend-to-RAM (S3 / S0ix)

Consolidated S3 / S0ix wake-vector + context save/restore
residual. The GPE `_Qxx` / `_Lxx` / `_Exx` dispatch half of this
entry landed 2026-05-26 (EC query-byte read +
`env-monitor`-task GPE walker — see "Battery + ACPI suspend"
above). What remains: the trampoline blob below 1 MiB, CPU /
device context save/restore via `kernel/arch/x86_64/acpi_wakeup.{S,cpp}`,
and the per-driver Suspend/Resume callback contract in a new
`kernel/power/` subsystem. Research notes document the FACS
wake-vector handshake, the trampoline mode-transition sequence,
and the device-state save surface. (ACPI S5 soft-off incl.
`_PTS`/`_GTS` in §7 order, reboot chain, and lid/AC/battery
*state* reads all landed — see the Battery row above.)

### Device Manager — eject + hot-unplug + virtio per-class I/O

- **Residual:** `Eject` capability gating; a hot-unplug driver
  path (AHCI / xHCI don't support it yet); virtio per-class
  queue-setup + I/O (rng/blk/net probes are attach-only in v0 —
  see **VirtIO per-class polish** below). (PCI + USB + VirtIO
  read-only device tables landed.)

### Network Status — real RF scan + multi-iface lease

- **Residual:** a real wireless backend (per the Wireless row)
  so the SSID list reflects an actual RF scan rather than the
  empty placeholder; multi-iface DHCP lease tracking (single
  lease today). (Iface table, rx/tx counters, firewall-drop
  column, routing/DNS section, Wi-Fi-scan section UI landed.)

### Terminal emulator (windowed userland shell)

- **Today:** `Ctrl+Alt+T` opens the kernel shell (ring-0).
- **Blocks on:** console-multiplex refactor — the kernel shell
  is wired to a single global `ConsoleWrite`; a windowed
  terminal needs the shell to take a per-session sink.
- **Owner:** `userland/shell/` + a PTY layer.

### PNG / JPEG / PDF / video viewers

- **Today:** BMP works (`kernel/apps/imageview.cpp`).
- **Blocks on:** PNG needs a zlib port (none in tree); JPEG
  needs a Huffman+IDCT decoder; PDF is huge; video needs HDA.

### IME / non-Latin input

- PS/2 + xHCI HID drivers hardcode US layout. Blocks on an
  input-method framework refactor.

### Locale / language switching

- UI strings are C++ literals in `kernel/apps/*.cpp`. Blocks on
  a string-table layer with id → text indirection; refactor
  across all apps.

### Disk installer — real-hardware boot verification

- **Residual:** boot an installed disk on real UEFI hardware.
  The orchestration layer (`install <handle> INSTALL [--duetfs]`
  → GPT with ESP / system / crash-dump partitions, FAT32 or
  DuetFS system partition, GRUB stub, real `BOOTX64.EFI` stamped
  to the spec-mandated removable path, opt-in kernel-ELF embed
  via `DUETOS_INSTALLER_KERNEL_EMBED`) is all in tree and the
  layout math runs a boot self-test every boot.

### System updater

- **Blocks on:** code-signing infrastructure + A/B kernel-slot
  layout (state machine landed — see **A/B kernel slots** below).

### Accessibility — screen reader + on-screen keyboard

- **Residual:** screen reader (blocks on an AT-SPI-equivalent
  kernel surface); on-screen keyboard (blocks on a widget-slot
  bump). (Magnifier landed.)

---

## Rust subsystems

The Rust bring-up checklist is **closed out** — thirteen
production crates are live with C++ callers. Future Rust work
happens only through the two channels documented in
[`Rust-Subsystems`](../tooling/Rust-Subsystems.md): existing
crates growing to cover their successor surface, or a new
crate landing **with** its first real C++ caller. Not triggers:
"memory safety is cool" / "a library exists in Rust". The
crate-authoring rules also live in that page.

### DuetFS follow-ups

DuetFS v3 ships per-block CRCs, sym/hard links, fsck, on-disk
auto-mount, userland syscall surface, auto-symlink resolution,
and `mkfs.duetfs`. Image cap is 4 MiB (single-block CRC table).
Pending, in rough priority:

1. **Multi-block CRC table** — restore the 32/128 MiB image cap.
2. **CoW** — copy-on-write file-data writes on top of the existing
   journal (journal already lands per `journal.rs`).
3. **Separate dirent table** — decouple hard-link names from the
   inode's `name` (today's v3 caveat).
4. **Indirect extents** — files needing > 8 extents.
5. **Multi-block dirs + B-tree directory index** — bump the
   1024-child cap.

(AES-XTS + Argon2 KDF encryption tier in `crypto.rs`, LZ4
compression in `compress.rs`, and snapshots in `snapshot.rs`
all landed.)

---

## Imported backlog — remaining rows

The "Full Project TODO" import (2026-05-09) is closed except the
rows below; everything else landed and is recorded in
[`Design-Decisions`](Design-Decisions.md) /
[`Win32-Surface-Status`](Win32-Surface-Status.md). Syscall numbers
are ABI — do not reuse retired numbers.

| ID | Scope | Pri | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T4-03 | gfx | P2 | Intel iGPU Gen9+/Xe driver basics: GTT setup, command ring, 2D blitter acceleration (PCI probe + register peek + software fallback landed). | BitBlt-heavy paths use the Intel blitter instead of software fills. |
| T5-01 | mm | P1 | Full `STATUS_GUARD_PAGE_VIOLATION` delivery to userland for `PAGE_GUARD` pages — **now unblocked** (T6-02 x64 SEH landed). v0 silently re-arms the guard (the next write succeeds); the reserve/commit split + protection bits + `VirtualQuery` already shipped. | A PE relying on the guard-page exception (not just silent stack-grow) sees `STATUS_GUARD_PAGE_VIOLATION`. |
| T5-03 | mm | P2 | Real KASLR in the UEFI loader (memory-map scan, random 2 MiB-aligned base in a 64 MiB window, boot-info handoff, boot-log report). **Same work as Linux-CVE Class II follow-up.** | Two cold boots show different kernel `.text` load addresses. |
| T6-05 | win32 | in progress — fault #1 fixed, fault #2 open | MSVC C++ EH (`__CxxFrameHandler3` + `_CxxThrowException`). Two distinct faults were conflated. **Fault #1 (FIXED 2026-05-18):** vcruntime140→ntdll imports (`NtRaiseException`/`RtlUnwindEx`/`RtlCaptureContext`) bound to a catch-all NO-OP because `kernel/proc/spawn.cpp` resolved each preloaded DLL's imports against only the DLLs loaded *before* it, and ntdll is listed after vcruntime140 in `preload_set[]`. Fixed by an order-independent cross-preload reconciliation pass (re-resolve every preloaded image against the full set once assembled). Verified: those imports now resolve via-dll; zero kernel regressions (120 self-tests pass, seh_try still PASS, boot-log-analyze OK). **Fault #2 (OPEN — real remaining blocker):** `cxxeh_pe` still faults `0xC0000005`. The kernel logs `[win32/seh] faulting rip val=0x23d8` and that value is the **raw trap-frame RIP = an absolute VA** (`seh_dispatch.cpp:196` logs `frame->rip` unmodified). `0x23d8` is a bare RVA inside cxxeh_pe `.rdata` EH-metadata (ThrowInfo/CatchableType, RVA 0x2300–0x2568). **Definitive conclusion: an FH3 transfer jumped to a bare `.rdata` RVA with `image_base` NOT added (or ==0)** — not import resolution, not a struct-layout bug (`catchblock_info`/`cxx_function_descr` x64 layouts verified correct in `vcruntime140.c:193-228`). **Three candidates, in `userland/libs/vcruntime140/vcruntime140.c`:** (a) `cxx_frame_handler` line 455 `funclet = image_base + cb->handler` with `disp->ImageBase` (line 395) wrong/0 — depends on how our ntdll's `RtlLookupFunctionEntry`/dispatcher fills `DISPATCHER_CONTEXT.ImageBase` for a Win32 PE; (b) line 456 `cont = cxx_call_funclet(...)` returning a bad continuation; (c) line 461 `RtlUnwindEx(frame, cont, …)` (our ntdll) mishandling `TargetIp`. **Next slice:** add gated DEBUG output (vcruntime140 must import `kernel32!WriteConsoleA` or a debug syscall — it has no print path today) dumping `disp->ImageBase`, `cb->handler`, `funclet`, `cont` for the first throw; one rebuild+boot identifies which is `0x23d8`. Reproduce with `DUETOS_SMOKE_PROFILE=pe-hello DUETOS_TIMEOUT=120 tools/qemu/run.sh`; grep `ring3-cxxeh-pe` / `[cxxeh] RESULT`. GAPs (post-unblock): copy-ctor catch objects, strict inner-frame dtor ordering, FH4 compressed FuncInfo, ESTypeList, rethrow. | A PE `try { throw 42; } catch(int){}` resumes in the catch and exits 0. |
| T7-04 | fs | P2 | Scoped NTFS write: create, write, truncate, delete, rename with MFT/index/journal/bitmap updates; no compression/encryption/ADS for v0. | PEs can perform basic writes to NTFS volumes. |
| T8-01-followon | sched | P1 | MLFQ priority aging/decay + work-stealing priority behaviour. `Process::win32_priority_class` is wired today; the scheduler ignores it. Rides on the per-CPU `g_sched_lock` split (B2-followup). | A high-priority thread preempts a low-priority thread within one 10 ms tick. |
| T10-04 | build | P2 | Extend hosted `ctest` to mirror the PE-parser contract (Result / string / syscall_error / cvt / text_hash / d3dcompiler / damage_rect / wild_address / disk_path / vfs_resolve / registry_path already wired). PE parser is kernel-only — use the algorithmic-contract pattern (re-state the routine inline, assert canonical cases) as primitives grow self-contained. | Host `ctest` covers Result + PE parser + VFS + registry + string helpers without QEMU. |

---

## Tier-1/2 follow-ups (next-slice integration points)

The kernel-side primitive is in tree for each; what's missing is
the per-call wiring.

### VirtIO — virtio-blk concurrency + IRQ

- **Lands:** (1) IRQ wire-up so consumers don't busy-poll for
  already-serviced I/O; (2) multiple in-flight descriptor chains
  so a second caller isn't fully serialised behind the first
  (depends on IRQ-driven completion first — the poll model
  tracks one chain). (Read/write/flush/discard + per-device
  serialising mutex landed; `VIRTIO_BLK_F_DISCARD` negotiated and
  consumed by FS-layer batch trim, 2026-05-27.)

### VirtIO — per-class polish

- **Lands:** virtio-blk concurrency + IRQ (above);
  virtio-console multiport (`VIRTIO_CONSOLE_F_MULTIPORT` +
  control-queue protocol); virtio-balloon inflate/deflate policy
  (the "when do we agree to give up memory?" half — spec
  dispatch is straightforward); virtio-input statusq for LED /
  force-feedback delivery (eventq + EV_REL + EV_ABS already
  landed — virtio-tablet absolute coordinates are converted to
  `MousePacket` deltas at the driver boundary so the unified
  one-source-of-truth pointer API stays intact);
  IRQ wire-up across rng/blk/net/console/balloon/input. (Every
  per-class probe v0 + RX/TX poll tasks landed.)

### IOCP — primitive consolidation

- **Lands:** (1) migrate the legacy
  `kernel/subsystems/win32/iocp_job.{h,cpp}`
  (`SYS_IOCP_CREATE/SET/REMOVE/CLOSE` 159–162) onto the newer
  KObject-shaped `IocpPort` (`kernel/ipc/iocp.{h,cpp}`) so
  per-process storage sits in `kobj_handles` alongside KMutex /
  KEvent — a re-routing patch in the four `SysIocp*` syscalls,
  the shapes are wire-compatible; (2) add `SYS_IOCP_POST`
  (`PostQueuedCompletionStatus`) — a thin Win32-shaped wrapper
  over the existing `IocpTryPost`. (The new KObject primitive +
  blocking `IocpWait` + self-test landed.)

### A/B kernel slots — installer + GRUB cfg

- **Lands:** (1) installer — `CmdInstall` writes the new kernel
  to `SlotKernelPath(Other(active))`, validates, then
  `BeginInstall` + `SaveVia(<fat32-writer>, &state)` so the new
  state persists on the ESP (the FAT32 writer callback is the
  only new code); (2) GRUB cfg — two menuentries, one per slot,
  with the active slot as `set default` and the matching
  `slot=a`/`slot=b` on each `multiboot2` line. (State machine,
  parser/writer, watchdog mark-healthy, callback-based
  persistence helpers landed.)

### PE-compat smoke — per-PE structured pass/fail

- **Lands:** a kernel-side aggregator that counts per-PE PASS
  lines and emits `[pe-compat-smoke] passed=N failed=M
  skipped=K`. Requires every smoke PE to standardise its PASS
  line (`[ring3-<n>-smoke] PASS` / `... FAIL <reason>`) — one
  small per-PE source edit; the aggregator watches the serial
  stream via the klog ring. (Per-API PASS/FAIL + the
  `[pe-compat-smoke] battery complete` anchor landed.)

---

## Testing / fuzzing

> **CI wiring landed.** `.github/workflows/build.yml` now has a
> `fuzz` job (sibling of `check-rust`/`build-debug`) that runs
> `FUZZ_SECONDS=90 tools/test/fuzz-all.sh` on every push/PR,
> uploading `crash-*` artifacts on failure. The optional cron
> long-run (`FUZZ_SECONDS=900` + persisted corpus cache) remains
> a future follow-up, not a blocker.

### Fuzz harness — next parser targets (residual)

Untrusted-input byte parsers still **without** a harness, in
rough bug-probability order (hand-written C++ bit/TLV parsers
first — that is where every memory-safety bug found so far
lived; the Rust-backed parsers held up). All follow the
established `tests/fuzz/` pattern (host harness + `host_shim/`
stubs + a `seeds/gen_*_seeds.py`); the codec/cert ones are pure
`bytes → struct` and need *less* shimming than the FS probes.

- **AML interpreter** — `kernel/acpi/aml.cpp`, `aml_eval.cpp`.
  Firmware-provided bytecode the kernel *executes*; large
  attack surface, heavier harness (needs an ACPI namespace
  stub).
- **CDC-ECM + RNDIS** — `kernel/drivers/usb/cdc_ecm.cpp`,
  `rndis.cpp`. Device-supplied configuration/data-frame bytes;
  parser surface beyond the standard class-descriptor walker.
  (The class-descriptor + HID-report-descriptor walkers under
  `usb_class_desc.cpp` + `hid_descriptor.cpp` are now both
  fuzzed via the Rust-backed harnesses landed 2026-05-26.)<!--
  Retired bullets — seeded + fuzzed 2026-05-26:
  X.509 (seeds/gen_x509_seeds.py — openssl-subprocess + embedded
  RSA-2048 reference cert + 128-byte truncation seed; fuzz_x509
  ≈ 244k runs/s + 551 new units added past the format gate);
  EDID + CEA-861 (seeds/gen_{edid,cea861}_seeds.py + host_shim/
  edid_stubs.cpp ConsoleWrite no-op stub; fuzz_edid ≈ 407k/s,
  fuzz_cea861 ≈ 511k/s); USB class-descriptor + HID report-
  descriptor (fuzz_usbclass + fuzz_usbhid via the
  usbclass/usbhid Rust rlib + panic=abort staticlib pattern;
  fuzz_usbclass ≈ 1.05M/s, fuzz_usbhid ≈ 639k/s — both clean);
  TLS records/handshake (fuzz_tls + seeds/gen_tls_seeds.py —
  five parsers (TlsPeekRecord / TlsPeekHandshake /
  TlsParseServerHello / TlsParseCertificateLeaf /
  TlsParseServerHelloDone) dispatched by a 1-byte selector;
  6 seeds covering each entry point at ≈ 982k runs/s clean);
  Image decoders (fuzz_bmp / fuzz_tga / fuzz_jpeg / fuzz_png
  harnesses + seeds + duetos_img_meta Rust shim were already
  in tree from prior slices — bullet was stale).
-->
- **Bluetooth HCI/HID** — `kernel/net/bluetooth/hci.h`,
  `hid.h`. Untrusted radio peer.
<!-- Disassembler bullet retired 2026-05-26: fuzz_disasm harness
     + host_shim/disasm_stubs.cpp + seeds/gen_disasm_seeds.py
     landed; fuzz_disasm runs ≈ 50k execs/s clean on the canonical
     five-family seed corpus (prologue / ALU / control / SIMD /
     unknown-as-db). Auto-picked up by tools/test/fuzz-all.sh via
     the established seeds/gen_<name>_seeds.py convention. -->


**Blocks on:** nothing — independent slices, one parser each,
same recipe. Pick the top unstruck bullet, land harness +
(any) fix, strike the bullet in the same commit.

---

## How to graduate an item

When a roadmap item lands:

1. **Delete its entry from this page** in the same commit.
2. Add a [`Design-Decisions`](Design-Decisions.md) entry (one
   per non-trivial commit).
3. Update [`History`](../getting-started/History.md) if the
   landing changes a project-level milestone.
4. Update the owning subsystem wiki page's "Known Limits".

If an item is wrong-sized for a single commit, write a slice plan
into the relevant subsystem page and keep a one-line index
pointer here — **not** a landed-work paragraph.
