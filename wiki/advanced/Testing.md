# Testing

> **Audience:** All contributors
>
> **Execution context:** Host (hosted unit tests) + on-target (boot-time self-tests)
>
> **Maturity:** v0 — hosted unit tests + boot smoke profile matrix

## Overview

DuetOS testing has two halves:

1. **Hosted unit tests** under `tests/`. Run with `ctest` against
   the host toolchain. Don't require QEMU.
2. **On-target self-tests**. Compiled into the kernel; run during
   the boot smoke. Each subsystem ships its own self-test (`mm`
   self-test, paging self-test, scheduler self-test, vfs self-test,
   etc.). A failure panics the kernel, which the smoke harness
   detects.

## Hosted Unit Tests

```bash
cd build/<preset> && ctest --output-on-failure
```

Tests live in `tests/`. Each test file builds into a small executable
that links against the units under test as object libraries.

## Boot Smoke

The QEMU smoke gate is the canonical "did it run?" test. See
[QEMU Smoke Tests](../tooling/QEMU-Smoke.md).

## On-Target Self-Tests

Each subsystem owns its own self-test. The pattern is:

- Self-test runs once during init.
- Output is `[<subsys>] self-test ...` lines on the serial console.
- A pass ends with `[<subsys>] self-test OK`.
- A fail ends with a `[panic] <subsys>: <invariant>` line.

Examples seen on every healthy boot:

```
[mm] frame allocator self-test OK
[mm] kernel heap self-test OK
[mm] paging self-test OK
[sched] online; ...
[reg-fopen-test] all checks passed
```

## Pentest Suite

Adversarial probes that try to break sandbox invariants, run as part
of boot. See [Attack Simulation](../security/Attack-Simulation.md).

## Coverage

There is no coverage report yet. KASAN-equivalent in the kernel and
ASan/UBSan/LSan for hosted tests are the primary correctness
sanitizers; line coverage is a follow-up item.

## Adding a Test

- **Hosted unit test**: drop a `.cpp` in `tests/<subsys>/` and a
  `CMakeLists.txt` rule that calls `add_executable` + `add_test`.
- **On-target self-test**: add a `<subsys>SelfTest()` function
  called from the subsystem's `Init()`. Keep output terse — every
  line costs serial bandwidth on every boot.
- **Pentest probe**: add to `kernel/security/pentest/` following
  the existing probe pattern — `jail`, `nx`, `priv`, `badint`,
  `kread`, and `crosspid` are the templates. Each probe runs in
  ring 3 with `CapSetEmpty`, fires the syscall under test, and
  records a sandbox-denial event the kernel side asserts on.

## Related Pages

- [QEMU Smoke Tests](../tooling/QEMU-Smoke.md)
- [Build System](../tooling/Build-System.md)
- [Debugging](../tooling/Debugging.md)
- [Attack Simulation](../security/Attack-Simulation.md)
- [Contributing](Contributing.md)
