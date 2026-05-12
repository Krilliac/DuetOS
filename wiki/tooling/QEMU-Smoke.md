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
from the others. Each profile reports its result through a
structural sentinel (`[smoke] profile=<name> complete`) on the
serial log so CI can grep the stream and assert pass/fail.

The CTest entry point is:

```bash
DUETOS_TIMEOUT=30 tools/test/ctest-boot-smoke.sh build/x86_64-debug
```

## Key Knobs

- `DUETOS_TIMEOUT=N` — overall timeout in seconds.
- `DUETOS_SETTLE=N` — extra seconds to wait after the boot completes
  before snapshotting the framebuffer (used by
  `tools/qemu/screenshot-theme.sh`).
- `DUETOS_BOOT_WAIT_SECS=N` — `screenshot.sh` polling budget for the
  boot marker (default 60). Bump under TCG-only hosts where the
  ~9:1 wall:guest ratio pushes the marker past 60 s.
- `DUETOS_BOOT_MARKER="..."` — override the boot-complete marker
  `screenshot.sh` greps for (default `bringup-complete`). The
  default fires once every subsystem including the compositor has
  composed, well before the post-bringup PE smoke spawns settle.
- `DUETOS_GRUB_ENTRY=N` — `screenshot.sh` navigates the GRUB
  menu to entry N before booting. Use the `(autologin)` entries
  (5/6 for Classic/Slate10, 10/11 for Amber/Duet) to skip the
  login gate and capture the composed desktop.

See the script header for the full env-var list.

## Emulator boot speed

Under QEMU TCG (no `/dev/kvm`) the wall:guest ratio is ~9:1, so a
30 s guest boot becomes ~5 min wall. The kernel takes two steps to
prioritise interactive use on emulators:

- The 1 Hz raw-serial `[tick-irq]` wedge-detection heartbeat in
  `kernel/arch/x86_64/timer.cpp` fires at 5 Hz instead. Serial is
  the dominant slow path; the kheartbeat scheduler thread already
  provides the higher-resolution stats view.
- `boot=desktop` under an emulator skips the Ring3 / PE smoke
  spawns by default. The smokes are regression coverage that CI
  invokes explicitly via `smoke=<profile>`; the interactive
  desktop user pays minutes for tests they didn't ask for. Pass
  `pe-smokes=1` on the cmdline to re-enable them (CLI debug /
  regression workflow).

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
