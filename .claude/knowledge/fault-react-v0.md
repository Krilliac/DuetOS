# FaultReact v0/v1 — self-defensive fault-reaction dispatcher

**Type:** Decision + Pattern + Observation
**Status:** Active — v1 shipped (trap-deferred queue + heartbeat drain + runtime_checker / soft_lockup / ubsan migrated + `inspect fault-react` shell command + real `KillProcess`). All v0 follow-ups landed.
**Last updated:** 2026-05-01

## What v0 deliberately did NOT do, and what v1 added

v0 deliberately deferred the trap-handler integration, the
ubsan / runtime_checker / soft_lockup migrations, the shell
command, and `KillProcess`. v1 lands everything except
`KillProcess` (genuinely blocked).

### v1 — trap-handler deferred queue (LANDED)

- `FaultReactReportFromTrap(domain_id, kind, faulting_rip)` —
  trap/IRQ/NMI-safe. Records `(kind, faulting_rip)` in a per-
  domain pending slot AND calls `FaultDomainMarkRestart` so the
  lossless restart backbone still fires. Plain stores only —
  no klog, no allocation, no locking. Producer write order is
  `kind/rip first → valid=true last` so a torn read on the
  consumer side observes either "valid=false" (skip) or a
  fully-populated record.
- `FaultReactDrainPending()` — heartbeat-thread-safe. Snapshots
  + clears each pending slot, builds a `FaultEvidence`, calls
  `FaultReactDispatch` (which may panic). Called from
  `kheartbeat` BEFORE `FaultDomainTick` so a `RestartDomain`
  reaction's re-MarkRestart is picked up by the same beat.
- Per-domain single-slot model (rather than a ring): if a
  domain hits twice before drain, the second overwrites the
  first and `FaultReactPendingOverwriteCount()` increments.
  Lossless restart backbone via `MarkRestart` ensures the
  bool-driven restart still fires regardless of overwrite.
- Trap handler in `kernel/arch/x86_64/traps.cpp` calls
  `FaultReactReportFromTrap` instead of `FaultDomainMarkRestart`
  directly. Uses `InternalInvariant` kind (not `KernelPageFault`)
  because an extable hit means recovery WAS planned — the
  kernel-page-fault floor isn't supposed to fire.

### v1 — reporter migrations (LANDED)

| Reporter | Before | After | FaultKind | Outcome delta |
|----------|--------|-------|-----------|---------------|
| `runtime_checker` `Report()` | direct `Panic("health", ...)` for Heal-failure + critical-no-heal | `FaultReactDispatch(...)` followed by `Panic` (unreachable; floor escalates) | `MemoryCorruption` | Same observable outcome (Halt). Dispatch counter now reflects health escalations; per-domain policy hook for "kernel/health" available for future fine-tuning. |
| `soft_lockup` `TickInternal()` warn site | `KLOG_WARN_V("soft-lockup", ...)` | `FaultReactDispatch(kFaultDomainInvalid, ...)` (decays Restart→Continue, logs at Warn) | `SoftLockup` | Same observable outcome (log + return). Rate-limit gate stays at the soft_lockup layer. |
| `ubsan` `Report()` | direct serial / klog log | per-line serial preserved verbatim + `FaultReactDispatch(kFaultDomainInvalid, ...)` | `Unknown` (Degraded severity) | Same observable outcome (log + return). UBSan reports now show up in `inspect fault-react` counters. |

### v1 — shell command (LANDED)

`inspect fault-react` (in `kernel/shell/shell_debug.cpp`):

- Console: `dispatched=N continue=N retry=N restart=N kill=N
  halt=N domains=N (PER-DOMAIN POLICY ON COM1)`.
- COM1: per-domain breakdown with `id name policy=default|override`.

Wired into the existing `inspect` umbrella's dispatch table +
help text.

## v0 — original infrastructure (still current)

A single chokepoint that consumes a `(FaultDomainId, FaultEvidence)`
pair, asks the per-subsystem reaction policy what it wants, applies a
kernel-owned floor, and executes the resulting reaction
(`Continue` / `RetryNow` / `RestartDomain` / `KillProcess` / `Halt`).

Files:

- `kernel/diag/fault_react.h` — `FaultKind`, `FaultSeverity`,
  `FaultEvidence`, `FaultReaction`, dispatcher API + deferred-queue API.
- `kernel/diag/fault_react.cpp` — default policy table,
  `FaultReactPolicyFloor`, `FaultReactDispatch`, deferred-queue
  state, drain, self-test (8 cases).
- `kernel/diag/recovery.{h,cpp}` — `DriverFault(name, reason, domain_id)`
  overload routes through the dispatcher.
- `kernel/diag/heartbeat.cpp` — `FaultReactDrainPending()` runs
  before `FaultDomainTick()` on each beat.
- `kernel/arch/x86_64/traps.cpp` — extable-hit path uses
  `FaultReactReportFromTrap` (trap-safe).
- `kernel/diag/runtime_checker.cpp` / `soft_lockup.cpp` /
  `ubsan.cpp` — all migrated to dispatch through FaultReact.
- `kernel/shell/shell_debug.cpp` — `inspect fault-react` command.
- `kernel/core/main.cpp` — `FaultReactSelfTest` registered after
  `FaultDomainSelfTest`.

## Why

Before v0, every fault-reporting site picked its own reaction:

- `DriverFault` logged + counted; nothing recovered.
- The trap handler called `FaultDomainMarkRestart` directly when an
  extable row had a domain, otherwise routed through the per-vector
  trap response policy in `traps.cpp`.
- `runtime_checker` / `soft_lockup` / `ubsan` each used
  `DebugPanicOrWarn` plus an ad-hoc log line.

There was no chokepoint where a kernel-owned policy could clamp a
misjudged reaction. A buggy policy demoting a corruption-class
fault to "Continue" was structurally possible because nothing
above the call site enforced a floor. v0 introduces that floor.

The user's framing was "self-reflection and polymorphism" — each
subsystem inspects its own state (restart_count, attempt_count,
evidence) and picks a reaction for itself; different subsystems
pick differently; the kernel keeps the floor.

## Shape

```
reporter site                FaultReactDispatch                 reaction
────────────────────────     ──────────────────────────────     ─────────
DriverFault(...,id) ───►     policy = FaultReactGetPolicy(id)
                             choice = policy(evidence)
                             floor  = FaultReactPolicyFloor(ev)
                             chosen = max(choice, floor)
                             execute(chosen) ───────────────►   log / mark
                                                                / kill / halt
```

`FaultReaction` is **strictly ordered** (Continue < RetryNow <
RestartDomain < KillProcess < Halt). The dispatcher uses
`max(policy_choice, floor)` against this ordering. New values must
be appended at the end, never inserted in the middle — the
ordering is part of the contract.

### Policy registration

Per-domain policies live in a parallel `g_policies[kPolicySlotCount]`
array indexed by `FaultDomainId`. The `FaultDomain` struct itself
is unchanged so existing tests and call sites stay valid.
`nullptr` in a slot means "use the default policy."

### Default policy table

Pure function of `kind` (ignores evidence). Conservative:

| Kind                 | Default reaction      |
|----------------------|-----------------------|
| DeviceTimeout / DmaError / UnexpectedStatus / FirmwareLied / Hung | RestartDomain |
| RetryExhausted       | RestartDomain         |
| InternalInvariant / SoftLockup | RestartDomain (floor may upgrade to Halt) |
| UserPageFault        | KillProcess           |
| KernelPageFault / MemoryCorruption / StackCanaryFailed | Halt |
| Unknown              | Continue (floor still applies) |

### Kernel-owned floor

Independent of any subsystem policy. Returns the strictest
reaction the dispatcher MUST apply for the (source, kind) pair:

- `source` starts with `kernel/mm` or `mm/` → at least `Halt`.
- `kind == MemoryCorruption / StackCanaryFailed / KernelPageFault`
  → at least `Halt`.
- `severity == Critical` → at least `RestartDomain`.
- everything else → `Continue` (no floor; policy choice wins).

### Decay rule

`RestartDomain` decays to `Continue` when `domain_id ==
kFaultDomainInvalid` — there's nothing to mark, so emitting an
Error log line for an action that won't happen would be
misleading.

## Wiring delta

- `DriverFault(name, reason)` — UNCHANGED. Existing call sites
  still log + count.
- `DriverFault(name, reason, domain_id)` — NEW. Routes through
  `FaultReactDispatch` after mapping `DriverFaultReason → FaultKind` +
  `→ FaultSeverity`. Drivers that have already registered a fault
  domain (USB xHCI does this today via `DriverDomainRegister`)
  pass the id; the dispatcher's chosen reaction may panic.
- Boot self-test `FaultReactSelfTest` runs after
  `FaultDomainSelfTest` in `kernel_main`.

## What v1 still does NOT do

1. **`KillProcess` is now real.** Earlier doc revisions claimed
   this was blocked on the ring-3 process model. That was
   wrong — `core::Process`, `core::CurrentProcess`,
   `sched::FlagCurrentForKill(KillReason)`, `sched::SchedKillByPid`,
   and `sched::SchedKillByProcess` were already in by the time
   v1 landed. The dispatcher's `KillProcess` branch now calls
   `FlagCurrentForKill(KillReason::UserKill)` against the
   current task's `Process`. The kill is asynchronous: the
   flag is set, the next `Schedule()` converts it into a Dead
   transition, the reaper drops the `Process` ref, and
   `ProcessRelease` tears down the AS / fds / handles / caps
   through its existing chain. A new decay rule escalates
   `KillProcess → Halt` when `CurrentProcess() == nullptr`
   (boot task / heartbeat drain / kernel-only reporters) —
   asking for a user-task kill from kernel context is a
   category mismatch, and the kernel-owned floor errs strict.
   Self-test verifies: (a) the default policy maps
   `UserPageFault → KillProcess`, and (b) boot-test context
   has no current Process (the decay rule would otherwise
   escalate to Halt and panic the boot — which is exactly
   why the test does NOT dispatch the evidence directly).
   No live caller reports `UserPageFault` to FaultReact yet,
   so the kill path is wired but unexercised on real
   workloads; first real consumer will be the trap handler's
   ring-3 #PF path once it's migrated.
2. **No NMI / #MC integration — and on analysis, the obvious
   migration is wrong.** Two paths exist; neither is right
   for the watchdog's confirmed-wedge case:
   - **Deferred dispatch via `FaultReactReportFromTrap`.**
     NMI-safe, but the heartbeat drains pending slots, and
     the watchdog detects exactly the case where the
     heartbeat is dead (timer IRQ stopped firing →
     `kheartbeat` won't run). Dispatch never fires.
   - **Direct `FaultReactDispatch` from NMI.** Dispatcher
     logs through klog, which is not NMI-safe.
   The current direct `Panic("nmi-watchdog", ...)` on
   confirmed wedge is correct: emergency serial output, no
   klog, no dispatcher state. The dispatcher counters miss
   the event, but a wedged box is going to halt anyway —
   counters are recorded in volatile RAM that won't survive
   the halt. The only real enhancement would be a
   pre-`Panic` "increment dispatched + halt counter" hook
   that's NMI-safe (plain atomics, no klog) — niche, not
   worth the API surface until there's a concrete consumer.
   The earlier "straightforward migration" framing was
   wrong; this entry now records why.
3. **Per-domain single-slot, not a ring.** If a domain hits
   twice before the heartbeat drains, the second overwrites
   the first kind/rip and `FaultReactPendingOverwriteCount()`
   increments. The lossless restart backbone via
   `FaultDomainMarkRestart` ensures the bool-driven restart
   still fires regardless of overwrite. If a real workload
   shows the overwrite counter rising, replace the slot with
   a small bounded ring — design noted but not built.
4. **`fault_react.cpp` is 527 lines** (above the 500-line
   guideline). It does ONE coherent job (dispatcher + drain +
   self-test), so splitting it now would be premature.
   Splitting `FaultReactSelfTest` into a `fault_react_selftest.cpp`
   sibling is the obvious move when the file grows further or
   when the self-test diverges from the dispatcher's
   internals.

## Self-test coverage (v0 + v1)

`FaultReactSelfTest()` exercises:

1. Strict policy + recoverable kind → `RestartDomain` (drained
   by `FaultDomainTick`, init/teardown counters verified).
2. Permissive policy + recoverable kind → `Continue`.
3. Permissive policy + Critical severity → floor upgrades to
   `RestartDomain`.
4. `nullptr` policy reverts to default.
5. `RestartDomain` decays to `Continue` when domain is unbound.
6. Dispatch counter tally matches expected calls.
7. **(v1)** Trap-deferred path: `FaultReactReportFromTrap`
   sets the pending slot + arms the lossless backbone;
   `FaultReactDrainPending` clears the slot and dispatches.
8. **(v1)** Overwrite counter increments when a domain hits
   twice before drain; second write wins.

Plus three floor-only spot checks for `kernel/mm` prefix,
`MemoryCorruption` kind, and the recoverable-no-floor case.
Plus a KillProcess policy spot check (`UserPageFault →
KillProcess`) and a sanity check that the boot self-test
runs with `CurrentProcess() == nullptr` — the decay rule
would escalate to Halt if the test tried to dispatch a
KillProcess-class evidence directly, so the test verifies
the policy + the decay precondition without firing the
panic.

## Files inventory

```
kernel/diag/fault_react.h         229 lines — header (v0+v1 API)
kernel/diag/fault_react.cpp       571 lines — impl + drain + self-test + real KillProcess
kernel/diag/recovery.h            203 lines — DriverFault overload
kernel/diag/recovery.cpp          128 lines — DriverFault overload impl
kernel/diag/heartbeat.cpp         156 lines — drain call before tick
kernel/arch/x86_64/traps.cpp      999 lines — extable path uses ReportFromTrap
kernel/diag/runtime_checker.cpp  1391 lines — Heal-fail + Panic via dispatcher
kernel/diag/soft_lockup.cpp       240 lines — warn site via dispatcher
kernel/diag/ubsan.cpp             338 lines — Report() via dispatcher
kernel/shell/shell_debug.cpp     2023 lines — `inspect fault-react`
```

`fault_react.cpp` is the only file above the 500-line
guideline (see follow-up #4 above). Everything else is within
budget.

## Resume prompt

> FaultReact v1 is complete on
> `claude/self-defensive-error-handling-Vp3Xc`. v0
> deliverables (dispatcher, kernel-owned floor, default policy
> table, parallel policy registry, `DriverFault(...domain_id)`
> overload, boot self-test) plus v1 deliverables (trap-handler
> deferred queue + heartbeat drain, `runtime_checker` /
> `soft_lockup` / `ubsan` migrations, `inspect fault-react`
> shell command, real `KillProcess` via
> `sched::FlagCurrentForKill(UserKill)` with decay-to-Halt
> when current is kernel-only) are all landed. All four v0
> follow-ups are done. Pending v1
> follow-ups: (a) NMI watchdog migration — analysed and
> **rejected**: deferred dispatch can't fire (heartbeat is
> dead by definition when watchdog trips) and direct dispatch
> from NMI is unsafe (klog isn't NMI-safe); the existing
> direct `Panic` is correct. A niche pre-`Panic` counter
> hook is possible but not worth the API surface yet. (b)
> Per-domain pending-slot upgrade to a small ring if
> `FaultReactPendingOverwriteCount()` shows stress in real
> workloads — needs workload data first. (c) Split
> `fault_react_selftest.cpp` out of `fault_react.cpp` if the
> file grows further — at 527 lines today, one cohesive job;
> defer until it grows. See the "What v1 still does NOT do"
> section above for full context.
