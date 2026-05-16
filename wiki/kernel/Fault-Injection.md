# Fault Injection

> **Audience:** Kernel hackers, SREs, anyone validating panic / page-fault / OOM paths
>
> **Execution context:** Kernel — `Trigger()` is callable from any kernel context that may take a sleeping mutex (the OomSlab path uses one). NOT safe from IRQ context.
>
> **Maturity:** v0 — four fault classes (NullDeref, Panic, OomSlab, MachineCheck); single-TU harness

## Overview

Panic-path bugs and slab-exhaustion bugs are some of the cheapest to introduce and the most expensive to find in the wild. The fault-injection harness gives DuetOS a deliberate, cap-gated way to exercise those paths from inside the running kernel, so a regression surfaces on a developer machine instead of in the field.

The harness lives in [`kernel/diag/fault_inject.{h,cpp}`](../../kernel/diag/fault_inject.h). The control flow is a single `switch` over three enum values; no registry, no plugin surface, no runtime configuration.

## What it is — and isn't

It **is**:
- A first-class trigger for the kernel's panic / `#PF` / slab-OOM recovery paths.
- Cap-gated on `kCapDiag`; reachable from kernel shell (`fault-inject <class>`) and from any future user-mode caller that holds the cap.
- A boot self-test for the recoverable class (`OomSlab`), so the path is exercised on every boot.

It **isn't**:
- A fuzzer. One call → one fault. Classes are picked by name, not at random.
- A recovery mechanism. `NullDeref`, `Panic`, and `MachineCheck` halt the box; reboot is the cure.
- Pluggable. The class set is closed at compile time.

## Fault classes (v0)

| Class | Numeric | Returns? | What it does | Path exercised |
|-------|---------|----------|--------------|----------------|
| `NullDeref` | 1 | No | Volatile load from `0xFFFFFFFFEDEAD000` — a kernel VA the paging layout reserves for future use ([`kernel/mm/paging.h`](../../kernel/mm/paging.h)). | Kernel `#PF` trap dispatcher in [`kernel/arch/x86_64/traps.cpp`](../../kernel/arch/x86_64/traps.cpp). |
| `Panic` | 2 | No | Calls `core::Panic("diag/fault_inject", "[fault-inject] forced panic")`. | Full panic banner + diagnostic dump + halt in [`kernel/core/panic.cpp`](../../kernel/core/panic.cpp). |
| `OomSlab` | 3 | `Result<void, ErrorCode>` | Creates a private 64 B slab cache and drains it via an intrusive freelist until `SlabAlloc` returns `nullptr`, then frees every object and destroys the cache. | Recoverable OOM path in [`kernel/mm/slab.cpp`](../../kernel/mm/slab.cpp). |
| `MachineCheck` | 4 | No | Raises vector 18 (`int $18`). Software-raised, so the `MCi_STATUS` banks are clean and the decode reports the `NO BANK VALID` verdict before the dispatcher panics. Proves the #MC path routes → decodes → halts without itself triple-faulting. | #MC trap wiring in [`kernel/arch/x86_64/traps.cpp`](../../kernel/arch/x86_64/traps.cpp) → MCA bank decode in [`kernel/arch/x86_64/machine_check.cpp`](../../kernel/arch/x86_64/machine_check.cpp). |

`OomSlab` is capped at `1 << 20` allocations (~64 MiB of kheap-backed storage) as a safety net against runaway loops. On a host whose kheap is bigger than the cap, the trigger returns `Err{ErrorCode::BadState}` — the cap was reached without observing exhaustion.

The `Panic` class's message intentionally starts with the literal substring `[fault-inject]` so post-mortem `grep` distinguishes intentional from real panics.

## Probe

One probe fires every time `Trigger()` runs — **before** the trigger itself, so the log ring captures even the non-returning classes:

| Probe name | Default arm | Value field |
|------------|-------------|-------------|
| `diag.fault_inject_fired` | `ArmedLog` | `FaultClass` enum value (1 / 2 / 3 / 4) |

An attached GDB can `b duetos::debug::ProbeFire` to break at the harness frame; the trigger lives one stack frame up. See [Debugging](../tooling/Debugging.md) for the attach flow.

## Logging shape

Every call emits one `KLOG_WARN` line at entry:

```
[W] diag/fault_inject : entering fault class  val=0x<hex>
```

Verbose detail goes through `KLOG_DEBUG_V` / `KLOG_DEBUG_S` so it's compiled out at release log-floors and runtime-suppressed at default thresholds; raise `loglevel d` to see the slab drain count and per-class details.

The boot self-test emits exactly one line to raw COM1 on PASS:

```
[fault-inject-selftest] PASS (oom-slab drained)
```

On FAIL it fires `kBootSelftestFail` (sub-check = 1) and emits a `[W] diag/fault_inject_selftest : [fault-inject-selftest] FAIL ...` line.

## Cap gate

`kCapDiag = 9` ([`kernel/proc/process.h`](../../kernel/proc/process.h)) gates every reach to the harness:

- The kernel shell's `fault-inject` command uses `RequireCap(kCapDiag, "FAULT-INJECT")` ([`kernel/shell/shell_dispatch.cpp`](../../kernel/shell/shell_dispatch.cpp)), so the operator must elevate to root first.
- The userland surface `SYS_DIAG_FAULT_INJECT = 204` is in [`kernel/syscall/cap_table.def`](../../kernel/syscall/cap_table.def). Missing cap returns `-EACCES` and records a sandbox denial in the standard way.

`kCapDiag` is part of `kProfileTrusted` (every trusted process gets it) and the `root` RBAC seed role. It is **not** in the developer / netop / auditor / sandbox seeds, so an untrusted PE cannot reach the syscall even with the userland thunk in hand.

## Shell command

```
$ fault-inject
FAULT-INJECT: USAGE:
    FAULT-INJECT NULL-DEREF   KERNEL #PF FROM AN UNMAPPED VA
    FAULT-INJECT PANIC        DELIBERATE KERNEL PANIC
    FAULT-INJECT OOM-SLAB     DRAIN A SLAB TO SlabAlloc==nullptr
    FAULT-INJECT MCE          RAISE #MC (VECTOR 18) + DECODE MCA BANKS
```

The `null-deref`, `panic`, and `mce` arguments halt the box; `oom-slab` returns to the shell with a recoverable status line.

## Syscall surface

```c
// User-mode contract (eq. of the kernel-shell command):
//   rdi = FaultClass (1 = NullDeref, 2 = Panic, 3 = OomSlab, 4 = MachineCheck)
// Returns:
//    0   on a clean OomSlab drain
//  -EINVAL  for an out-of-range FaultClass
//  -EACCES  if kCapDiag is missing
//  (no return)  for NullDeref / Panic / MachineCheck
syscall(SYS_DIAG_FAULT_INJECT /* = 204 */, fc);
```

`SYS_DIAG_FAULT_INJECT` exists for future user-mode diagnostics; no v0 CLI tool ships against it.

## Self-test contract

`FaultInjectSelfTest()` is registered as the `fault-inject-selftest` initcall in [`kernel/core/main.cpp`](../../kernel/core/main.cpp), in `Phase::Sched` (alongside `SlabSelfTest()`) — the harness needs the slab subsystem online.

Only the recoverable `OomSlab` class is exercised at boot; the other three halt the box and cannot run from a self-test context. CI greps for the PASS line:

```bash
grep -nE "\[fault-inject-selftest\] PASS" /tmp/duetos-*.log
```

Exactly one match means the harness ran and the OOM path is alive.

## Known limits

- `GAP:` the `0xFFFFFFFFEDEAD000` VA assumes the reserved zone above the kernel MMIO arena stays unmapped. A future slice that carves the region (e.g. an upper-half NUMA arena) must update `kUnmappedKernelVa` in [`fault_inject.cpp`](../../kernel/diag/fault_inject.cpp) accordingly.
- The OomSlab safety cap (`1 << 20` objects) is unreachable on small kheap configurations but can mask a real slab regression on a host with > 64 MiB free kheap. The contract surfaces this as `Err{ErrorCode::BadState}` rather than silently passing.
- IRQ-context callers are out of scope — `OomSlab` walks `mm::SlabAlloc`, which takes a sleeping mutex on the slow path.

## See also

- [Diagnostics](Diagnostics.md) — the broader diag surface
- [Capabilities](../security/Capabilities.md) — how `kCapDiag` fits
- [Debugging](../tooling/Debugging.md) — attaching GDB to a probe fire
