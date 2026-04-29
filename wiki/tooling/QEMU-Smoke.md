# QEMU Smoke Tests

> **Audience:** All contributors
>
> **Execution context:** Host (QEMU child process + serial log on stdout)
>
> **Maturity:** Stable — profile matrix; isa-debug-exit + serial spinlock

## Overview

The canonical "did it boot?" gate is `tools/qemu/run.sh`. It launches
QEMU with the standard DuetOS configuration, watches the serial log
on stdout, and returns success if the boot reaches the canonical
end-of-init line within a timeout.

```bash
DUETOS_TIMEOUT=30 tools/qemu/run.sh build/x86_64-debug/duetos.iso
```

## Profile Matrix

The smoke harness was redesigned from a monolithic single-job into
**per-profile parallel jobs** — each profile (BIOS+i440FX, BIOS+q35,
UEFI+q35, virtio-gpu, e1000-net, etc.) runs in parallel, isolated
from the others. See
`.claude/knowledge/qemu-smoke-profile-matrix-v0.md`.

The CTest entry point is:

```bash
DUETOS_TIMEOUT=30 tools/test/ctest-boot-smoke.sh build/x86_64-debug
```

## Key Knobs

- `DUETOS_TIMEOUT=N` — overall timeout in seconds.
- `DUETOS_SETTLE=N` — extra seconds to wait after the boot completes
  before snapshotting the framebuffer (used by
  `tools/qemu/screenshot-theme.sh`).

See the script header for the full env-var list.

## isa-debug-exit + Serial Spinlock

The smoke harness uses QEMU's `isa-debug-exit` device — a write to a
specific I/O port lets the kernel exit QEMU with a chosen exit code.
Combined with a serial-output spinlock for ordered prints, this gives
deterministic pass/fail outcomes from in-kernel tests.

## Hosted Unit Tests

`build/<preset>/ctest --output-on-failure` runs the hosted unit tests
under `tests/`. These do not require QEMU.

## Screenshot Capture

`tools/qemu/screenshot.sh` and `tools/qemu/screenshot-theme.sh` boot
DuetOS, wait `DUETOS_SETTLE` seconds, snapshot the framebuffer to
PNG. Used to capture `docs/screenshots/`.

## Related Pages

- [Build System](Build-System.md)
- [Debugging](Debugging.md)
- [Logging and Tracing](../kernel/Logging-And-Tracing.md)
- [Boot Path](../kernel/Boot.md)
