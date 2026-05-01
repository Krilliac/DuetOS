# FaultReact v0 — self-defensive fault-reaction dispatcher

**Type:** Decision + Pattern + Observation
**Status:** Active — DriverFault wired; trap-path + ubsan/runtime_checker wiring deferred
**Last updated:** 2026-05-01

## What

A single chokepoint that consumes a `(FaultDomainId, FaultEvidence)`
pair, asks the per-subsystem reaction policy what it wants, applies a
kernel-owned floor, and executes the resulting reaction
(`Continue` / `RetryNow` / `RestartDomain` / `KillProcess` / `Halt`).

Files:

- `kernel/diag/fault_react.h` (189 lines) — `FaultKind`,
  `FaultSeverity`, `FaultEvidence`, `FaultReaction`, dispatcher API.
- `kernel/diag/fault_react.cpp` (402 lines) — default policy table,
  `FaultReactPolicyFloor`, `FaultReactDispatch`, self-test.
- `kernel/diag/recovery.{h,cpp}` — `DriverFault(name, reason, domain_id)`
  overload routes through the dispatcher.
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

## What v0 deliberately does NOT do

1. **No trap-handler integration.** The trap handler still calls
   `FaultDomainMarkRestart` directly for extable hits. Wiring
   `FaultReactDispatch` into the trap path requires care —
   the dispatcher takes locks indirectly (klog) and trap context
   may not be safe for that. The current tiered trap-response
   policy (`TrapResponseFor`) is a peer of the dispatcher in
   v0; consolidation comes when both can be NMI-safe.
2. **No ubsan / runtime_checker / soft_lockup wiring.** Those
   sites still call `DebugPanicOrWarn`. They CAN be migrated
   one at a time without any churn to the dispatcher; the
   skip is "scope," not "blocked."
3. **No shell command.** `fault-react status` (counters + per-
   domain policy table dump) is a sensible follow-up but not
   required for v0.
4. **No NMI / #MC support.** `FaultReactDispatch` is process /
   IRQ / soft-IRQ safe but logs through klog. NMI context
   should keep using `FaultDomainMarkRestart` directly and let
   the heartbeat thread call the dispatcher later if a richer
   decision is needed.
5. **`KillProcess` is a STUB.** Logs loudly; doesn't actually
   tear down anything. Real implementation lands with the
   ring-3 process model.

## Self-test coverage

`FaultReactSelfTest()` exercises:

1. Strict policy + recoverable kind → `RestartDomain` (drained
   by `FaultDomainTick`, init/teardown counters verified).
2. Permissive policy + recoverable kind → `Continue`.
3. Permissive policy + Critical severity → floor upgrades to
   `RestartDomain`.
4. `nullptr` policy reverts to default.
5. `RestartDomain` decays to `Continue` when domain is unbound.
6. Dispatch counter tally matches expected calls.
7. Floor spot checks for `kernel/mm` prefix, `MemoryCorruption`
   kind, and recoverable-no-floor case.

## Files inventory

```
kernel/diag/fault_react.h    189 lines — header
kernel/diag/fault_react.cpp  402 lines — impl + self-test
kernel/diag/recovery.h       203 lines (was 184) — DriverFault overload
kernel/diag/recovery.cpp     128 lines (was 63) — DriverFault overload impl
kernel/core/main.cpp         — added include + DUETOS_BOOT_SELFTEST
```

All files are below the project's size thresholds.

## Resume prompt

> Continue the FaultReact v0 work landed on
> `claude/self-defensive-error-handling-Vp3Xc`. The dispatcher,
> kernel-owned floor, default policy table, parallel policy
> registry, `DriverFault(...domain_id)` overload, and boot
> self-test are all in. Open follow-ups from
> `.claude/knowledge/fault-react-v0.md`'s "What v0 deliberately
> does NOT do" section: (1) trap-handler integration —
> consolidate `TrapResponseFor` and `FaultReactDispatch` once
> both can be NMI-safe; (2) migrate `ubsan` /
> `runtime_checker` / `soft_lockup` reporters one TU at a time;
> (3) `fault-react status` shell command for counters + per-
> domain policy table; (4) `KillProcess` real implementation
> when ring-3 process kill lands.
