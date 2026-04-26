# klog overhaul — Trace level, scopes, metrics, sinks, ANSI colour

**Last updated:** 2026-04-21
**Type:** Observation
**Status:** Active

## Description

Five-commit progression that turned the kernel logger from a thin
"severity + u64 hex" wrapper into a structured logging subsystem.
Every existing call site benefits automatically; new call sites
have richer primitives to choose from. Default boot remains quiet
(Info+ runtime threshold); deeper instrumentation is opt-in via
shell commands.

## Context

Applies to:

- `kernel/core/klog.{h,cpp}` — the logger itself.
- `kernel/shell/shell.cpp` — `loglevel`, `dmesg`, `logcolor`
  commands.
- `kernel/core/main.cpp` — file-sink install, metrics
  checkpoints.
- 14+ subsystem `.cpp` files now use `KLOG_*` instead of
  `arch::SerialWrite` for boot-phase logging (see commit
  history for the full migration list).

Does not apply to:

- `kernel/core/panic.cpp` — must stay self-contained; klog may
  itself be broken when panic runs.
- `arch/x86_64/traps.cpp`, `core/syscall.cpp` — IRQ / syscall
  hot paths; klog-from-IRQ works but volume would be unmanageable.
- `core/ring3_smoke.cpp` — adversarial test scaffolding using
  direct `SerialWrite` by design.

## Details

### What landed (in chronological order)

1. **Human-readable timestamps + decimal alongside hex** —
   `[t=123.456ms]` from HPET, `[t~50ms]` fallback from scheduler
   tick, `val=0x8000 (32768)` for sub-1-trillion values.
2. **String + pair helpers + ANSI colour + once-macros** —
   `LogWithString`, `LogWith2Values`, `KLOG_ONCE_INFO/_WARN`.
   Cyan/yellow/red colour wrapping the severity tag only.
3. **AHCI/IOAPIC density + Win32 no-op flags + dmesg filter +
   tmpfs sink** — converted boot logs to denser multi-value form,
   PE loader marks no-op stubs as Warn, `dmesg w` filters,
   `/tmp/boot.log` captures Info+ via a third sink slot.
4. **Trace level + scopes + metrics + hang dump** —
   `LogLevel::Trace`, `KLOG_TRACE_SCOPE` RAII, in-flight scope
   tracker dumped on panic, `KLOG_METRICS` resource snapshot.
5. **Coverage spread across mm/, acpi/, fs/, arch/, sync/,
   win32/, cpu/** — 14 previously-uncovered files now report
   init via TRACE_SCOPE and surface failures via WARN/ERROR.

### Levels (low → high)

| Level | Tag | Colour | Compile | Default runtime |
|-------|-----|--------|---------|-----------------|
| Trace | `[T]` | cyan | yes (gated by `if constexpr`) | dropped |
| Debug | `[D]` | dim | yes | shown |
| Info  | `[I]` | none | yes | shown |
| Warn  | `[W]` | yellow | yes | shown |
| Error | `[E]` | bold red | yes | shown |

### Helper inventory

```cpp
// Plain
KLOG_TRACE / DEBUG / INFO / WARN / ERROR (subsys, msg)

// With one labelled u64 value (rendered hex + decimal):
KLOG_TRACE_V / INFO_V / WARN_V / ERROR_V (subsys, msg, value)

// With one labelled C-string:
KLOG_INFO_S / WARN_S (subsys, msg, label, str)

// With two labelled u64 values on one line:
KLOG_INFO_2V / WARN_2V (subsys, msg, label_a, val_a, label_b, val_b)

// At-most-once-per-call-site (per-site .bss bool guard):
KLOG_ONCE_INFO / WARN (subsys, msg)

// Function scope: enter + exit + elapsed_us (RAII):
KLOG_TRACE_SCOPE(subsys, name)

// Resource snapshot — heap, frames, ctx-switches, tasks:
KLOG_METRICS(subsys, label)
```

### Shell commands

- `loglevel [t|d|i|w|e]` — toggle runtime threshold.
  `loglevel t` enables the function-scope trace timeline.
- `dmesg [t|d|i|w|e]` — dump the log ring with optional
  severity filter. `dmesg w` shows Warn+, etc.
- `logcolor [on|off]` — toggle ANSI codes on serial. Off is
  useful for log capture / CI diffs.
- `lsblk` / `lsgpt` — registry views (block devices, partitions).

### Sinks

Three sink slots:

1. Serial (always on, COM1) — full timestamp + ANSI colour.
2. Framebuffer tee — `SetLogTee(writer)`. Stripped output;
   per-line, no timestamps.
3. File sink — `SetLogFileSink(writer)` with optional
   `SetLogFileSinkMinLevel`. main.cpp installs a tmpfs sink
   that appends each Info+ line to `/tmp/boot.log` (capped at
   tmpfs's 512 B; verified in boot via post-bringup readback).

### Hang diagnosis via in-flight scope table

`TraceScope` claims a slot in a fixed 16-entry global table on
construct, releases on destruct. `core::Panic` replays still-
active slots:

```
[panic] --- 2 scope(s) still running at panic ---
[panic]   drivers/nvme :: NvmeInit   running_us=11423
[panic]   drivers/pci  :: PciEnumerate   running_us=21800
```

If a function entered but never exited, its slot survives the
panic — that's the hang, named and timed. Scope table full →
one-shot warn.

### Resource metrics

`KLOG_METRICS(subsys, label)` emits one structured line:

```
[I] boot : metrics bringup-complete   heap_used=66128   heap_free=2031024 \
                                      frames_free=130112   ctx_switches=0   tasks_live=3
```

main.cpp drops two checkpoints around the bring-up so a glance
shows what driver init cost (heap + frames consumed since the
last checkpoint).

## Notes

- **Trace cost when filtered:** one load + compare + branch per
  call site, ~zero. The `if constexpr` macro gate folds Trace
  to nothing if the compile-time floor is ever raised above it.
- **Ring buffer:** 64 entries, each carries timestamp + level
  + subsystem + message + value. `DumpLogRing` (panic path)
  prints with timestamps. `DumpLogRingTo(writer)` for shell.
- **No format strings.** Fixed-shape helpers cover every need
  without `snprintf`'s footgun. If a third value or a non-u64
  numeric type ever needs logging, add a new helper rather
  than reaching for varargs.
- **Per-site guards in macros.** Every `KLOG_TRACE_SCOPE` /
  `KLOG_ONCE_*` macro creates a static guard tied to `__LINE__`
  so two scopes in the same function don't collide and two
  identical once-warns from different sites both fire once.
- **See also:**
  - `boot-smoke-harness.md` (if present) — CI hooks that diff
    boot logs may need `logcolor off` for byte-exact comparison.
  - `runtime-recovery-strategy.md` — the original "every
    failure path must log loud or panic" decision that made
    these helpers necessary.
