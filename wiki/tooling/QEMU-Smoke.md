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

- `DUETOS_QMP=0` — disable the QMP control socket (default on). When
  on, `run.sh` exposes `build/<preset>/qmp.sock`; query it without
  disturbing the serial log or a live GDB session via
  `tools/qemu/qmp.sh status | screenshot <out.ppm> | quit`.
- `DUETOS_BOOT_STALL=<phase>|smoke-tail` — debug injection: `run.sh`
  bakes `boot-stall=<value>`. A `<phase>` value (`earlycon physmem
  paging heap idt apic time percpubsp sched smp drivers vfs userland`)
  wedges that `core::Phase`'s `BootPhaseEnter` — demonstrates ladder
  localisation (the log stops at `[boot] phase=<phase> begin`).
  `smoke-tail` is the watchdog proof: it deterministically exercises
  the structured STUCK → `TestExit` → harness-decode path (see the
  watchdog GAP below for why a `<phase>` value cannot prove it under
  a smoke profile).

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

## Boot Observability

`kernel/diag/boot_observe.{h,cpp}` instruments the single
`core::RunPhase` choke point so every boot emits an ordered, parseable
phase ladder and, just before the smoke sentinel, a machine-readable
report. This replaces the old `diag::BootProgress` RDTSC-cycle markers
(deleted) and lets the harness localise a failure to a phase instead
of grepping a fragile multi-line signature list.

### Serial line ABI (stable; harness greps these)

```
[boot] phase=<name> begin
[boot] phase=<name> complete t=<ms> dur=<Nms|Nms(tsc)|Ncyc(pre-clock)|unknown>
[boot] phase=<name> FAIL ec=<hexbyte> err=<hex>
[boot] phase=<name> STUCK ec=<hexbyte> (init-wedge: no serial progress)
[boot-report] begin
[boot-report] phase=<name> dur_ms=<n|unknown>     (one per entered phase)
[boot-report] selftests pass=<n> fail=<n>
[boot-report] total_ms=<n|unknown>
[boot-report] result=pass
[boot-report] end
```

`dur` carries one of four shapes:

  - `dur=<N>ms` — ms-clock was online at both endpoints (HPET / TSC
    clocksource registered). Highest fidelity.
  - `dur=<N>ms(tsc)` — ms-clock was online at finalize but NOT at
    enter; converted via the calibrated TSC cycle delta. Same
    accuracy on real hardware; less reliable under hypervisor TSC
    virtualisation.
  - `dur=<N>cyc(pre-clock)` — neither endpoint had a registered
    monotonic clocksource; phases run before `Phase::Time`
    (`TimekeeperInit`) finalise into this shape, with `<N>` the raw
    TSC cycle delta. Convert to ms post-hoc by dividing by the
    boot's calibrated `g_tsc_freq_hz`.
  - `dur=unknown` — neither HPET nor TSC was sampleable; rare,
    indicates a serious bring-up regression.

`t=0` lines are pre-`Phase::Time` finalisations (`time::MonotonicNs()`
returns 0 until `TimekeeperInit` registers HPET / TSC). A phase is
"active" from its `begin` until the next phase's `begin`; the last
phase is finalised by the report. The fix-journal / translator
structured summaries are emitted immediately above the report and
stay independently greppable.

### Hierarchical exit codes

`arch::TestExit(b)` makes QEMU exit `(b<<1)|1`; `b` stays ≤ 0x7F.
Top nibble = class, low nibble = `core::Phase` ordinal (0..12).
`profile-boot-smoke.sh` decodes `b=(rc-1)>>1` and prints a
phase-named message instead of timing out the full wall budget.

| Class | byte `b`   | QEMU exit     | Meaning                          |
|-------|------------|---------------|----------------------------------|
| Pass  | `0x10`     | `0x21` (33)   | smoke sentinel reached           |
| Hung  | `0x20\|ord`| `0x41`..`0x59`| watchdog: phase exceeded budget  |
| Fail  | `0x40\|ord`| `0x81`..`0x99`| a `RunPhase` callback returned Err |
| Panic | `0x70\|ord`| `0xE1`..`0xF9`| kernel panic (incl. boot selftest) |

Hung / Fail / Panic only `TestExit` under a smoke profile; bare-metal
/ interactive boots keep BSoD-and-halt and the existing init-wedge
escalation.

### Hang watchdog

There is **no separate wall-clock budget** — the RunPhase boundaries
are too coarse and emulation-speed-dependent (the Sched→Smp span is
most of a boot), so a per-phase budget false-fires under TCG. Instead
the structured exit rides the **existing** init-wedge detector in
`kernel/arch/x86_64/timer.cpp`, which uses an environment-independent
*no-serial-progress* heuristic (~15 s of silent heartbeats while the
timer IRQ keeps firing). When that detector concludes the boot is
wedged it calls `diag::BootWatchdogOnWedge()`, which attributes the
wedge to the active phase, emits the `STUCK` line, and — under a
smoke profile — `TestExit`s with the HungInPhase code. No second
watchdog, no false positives on a chatty-but-slow phase.

**GAP:** the byte-delta init-wedge detector only fires on *total*
serial silence (every other thread quiet) with the timer IRQ still
firing — the signature of an early single-thread deadlock before the
scheduler brings up background log threads. It is correct for that
real shape but is, by construction, not reproducible by a simple
injected stall once the scheduler is running (soft-lockup / fix-
journal threads keep serial chatty). A `<phase>`-valued stall also
can't prove it: a smoke profile `TestExit`s before the post-`sti`
phases (`smp`/`userland`), and `sched` is entered with interrupts
still masked.

So the `smoke-tail` injection proves the genuinely-new surface
deterministically — the `STUCK` line, the `EncodeExit` byte,
`arch::TestExit`, and the harness decode — by calling
`diag::BootWatchdogOnWedge()` directly. The *trigger* (the existing
byte-delta detector calling that function at its existing fire
point) is one reviewed line, not new code, and is covered by the
detector's own probe.

```bash
DUETOS_BOOT_STALL=smoke-tail DUETOS_TIMEOUT=300 \
  tools/test/profile-boot-smoke.sh bringup build/x86_64-debug
# → [boot] phase=<last> STUCK ec=0x2? (init-wedge: no serial progress)
#   harness: BOOT PHASE FAILURE (qemu_rc=..., decoded=hung phase=...);
#   exit 1
```

## isa-debug-exit + Serial Spinlock

The smoke harness uses QEMU's `isa-debug-exit` device — a write to a
specific I/O port lets the kernel exit QEMU with a chosen exit code
(see the hierarchical scheme above). Combined with a serial-output
spinlock for ordered prints, this gives deterministic, phase-attributed
pass/fail outcomes from in-kernel tests.

## Hosted Unit Tests

`build/<preset>/ctest --output-on-failure` runs the hosted unit tests
under `tests/`. These do not require QEMU.

## Screenshot Capture

`tools/qemu/screenshot.sh` and `tools/qemu/screenshot-theme.sh` boot
DuetOS, wait `DUETOS_SETTLE` seconds, snapshot the framebuffer to
PNG. Used to capture `docs/screenshots/`.

## Code Path Coverage

At smoke-profile completion the kernel emits one structured
sentinel that `tools/test/boot-log-analyze.sh` parses:

```
[kpath] visited=412/1023 (40%) cats=site:5/5 syscall:23/256 vector:14/256 initcall:48/48 probe=12 fix=3
```

Plus `KERNEL.KPATH.TSV` on the FAT32 root volume. The offline
diff tool `tools/test/kpath-coverage.sh` compares a baseline TSV
against a current TSV and reports newly-visited and newly-cold
sites:

```
tools/test/kpath-coverage.sh known-good.tsv build/x86_64-release/KERNEL.KPATH.TSV
```

Returns nonzero on regression (any newly-cold site, or visited%
drop past the configured threshold — default 5pp). Slot into CI
alongside `boot-log-analyze.sh`. Full details:
[Code Path Ledger](../kernel/Code-Path-Ledger.md).

## Related Pages

- [Build System](Build-System.md)
- [Debugging](Debugging.md)
- [Logging and Tracing](../kernel/Logging-And-Tracing.md)
- [Code Path Ledger](../kernel/Code-Path-Ledger.md)
- [Boot Path](../kernel/Boot.md)
