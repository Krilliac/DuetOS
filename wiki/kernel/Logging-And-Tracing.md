# Logging and Tracing

> **Audience:** Kernel hackers, driver authors, debuggers
>
> **Execution context:** Kernel — `klog` is async-safe (lock-free ring + sink dispatch)
>
> **Maturity:** v0 stable

## Overview

`klog` is the kernel-wide logging facility. It is intentionally
**not** `printf` — log lines are tagged with severity, scope, and
metric metadata; sinks fan out to the serial console, an in-RAM ring
buffer, and (when graphics are up) the kernel-log window.

`SerialWrite` is the early-bringup primitive used before `klog` is
online. It writes a raw byte sequence to COM1 and is safe to call from
panic handlers.

## Key APIs

```cpp
// kernel/log/klog.h
KLOG_INFO("subsys", "value=%u", value);
KLOG_WARN("subsys", "..."); 
KLOG_ERR ("subsys", "...");
KLOG_TRACE("subsys", scope_id, "...");

// kernel/util/serial.h (raw bringup)
SerialWrite("[boot] ...");
```

Each line is timestamped with the current LAPIC tick. The `subsys`
string (a 3-8 char tag) routes through scope filters that the kernel
shell can adjust at runtime (`klog scope mm trace`, etc.).

## Sinks

- **Serial sink (COM1)** — primary output during QEMU smoke and
  bringup. Color codes are emitted as ANSI when the host terminal
  supports them.
- **Ring buffer sink** — fixed-size lock-free in-RAM ring. Crash dump
  prints the last N entries inline. The cleanroom-trace surface reads
  the ring without bumping reader cursors so the boot survey is
  non-destructive.
- **Window sink** — once the compositor is up, a Kernel Log window
  (rendered through `kernel/apps/`) tails the ring into a window.

## Log Persistence

Once the FAT32 root volume is probed, the early-boot tmpfs file sink is
replaced by a disk-backed sink
([`kernel/log/klog_persist.h`](../../kernel/log/klog_persist.h)). It
appends every Info+ line to `KERNEL.LOG` on the FAT32 root so a boot's
log survives a reboot for post-mortem inspection.

- **Install** — `KlogPersistInstall()` runs once after the FAT32 probe.
  It truncates `KERNEL.LOG`, installs the file sink, and replays the
  current log ring through it so pre-install Info+ history is captured.
  Returns false (no-op) if no FAT32 volume is mounted. Idempotent.
- **Flush** — `KlogPersistFlush()` drains the 4 KiB scratch to disk; it
  is called on the 1 Hz UI tick so a long-uptime log reflects the ring
  within roughly a second. Safe to call when the sink isn't installed.
- **Cross-boot retention** — on install, `KERNEL.LOG` ages to
  `KERNEL.0`, the existing `KERNEL.<i>` archive chain shifts down one
  slot, and the oldest is dropped. A bounded number of past boots
  (depth 4 currently) are kept on disk.
- **Mid-boot rotation** — when `KERNEL.LOG` would grow past 256 KiB on
  the next flush, the same chain shift runs in-place, so a long-running
  boot doesn't grow the on-disk log unbounded.

`KlogPersistSelfTest()` writes a marker, flushes, reads back the tail of
`KERNEL.LOG`, and asserts the marker is present; it prints PASS / FAIL /
SKIP to COM1 (SKIP when FAT32 isn't mounted).

## Trace Scopes

Trace scopes carry a 32-bit scope_id. Filtering is by `subsys` plus
`scope_id`, so a single subsystem can keep multiple low-volume trace
streams (e.g. `mm` `frame_alloc` vs `mm` `unmap`) and the operator can
enable one without drowning the log in the other.

## STUB / GAP Markers

Stub-marker convention from `CLAUDE.md`:

- `// STUB:` — handler returns a constant / does nothing /
  returns -ENOSYS / returns the wrong target. Real callers WILL
  behave incorrectly.
- `// GAP: <missing> -- <revisit>` — handler is correct on the v0
  happy path but a documented edge case is unimplemented.

The grep audit baseline is:

```bash
git grep -nE "// (STUB|GAP):"
```

`docs/sync-wiki.sh` counts these into the Home.md statistics block.

## Crash Dump

The crash dump path lives in `kernel/diag/`. Triggered on any
unhandled exception, it:

- Dumps GPRs with symbol resolution (`addr2sym`-style).
- Decodes register bits (CR0, CR4, EFER, RFLAGS).
- Symbolizes RIP, RSP, RBP, CR2 against the embedded kernel symbol
  table.
- Tags VA regions (cr2/rsp/rbp/rip vs known mm regions).
- Prints peer-CPU NMI snapshots once SMP lands.
- Prints per-CPU held-locks.
- Prints the last N klog ring entries inline.
- Walks page tables for `cr2` and `rip`.
- Snapshots Architectural LBR if CPU supports it.
- Records per-task syscall trail and per-process VM info.

It also emits a structurally-valid Windows minidump (`.dmp`,
`MDMP`-magic, `CONTEXT_X64` + `ThreadList` + `ModuleList` +
`MemoryList` + `ExceptionStream` + `SystemInfo`) byte-by-byte over
QEMU's debugcon (port `0xE9` → `${BUILD_DIR}/duetos.dmp` on the
host). Loadable in Visual Studio / WinDbg / VSCode-cppvsdbg / Python
`minidump` library / Mozilla `minidump-stackwalk`. Real-hardware
persistence (raw-block write to a reserved LBA) is on the
[Roadmap](../reference/Roadmap.md#crash-dump-persistence-to-disk).

## Code Path Coverage

For "did this code path execute?" rather than "what did it log?",
see the [Code Path Ledger](Code-Path-Ledger.md). The `KPATH(...)`
macro is a peer of `KBP_PROBE(...)` — both record execution at a
named site, but KPath also auto-enrolls every syscall / IDT
vector / initcall / probe / fix-journal record and emits a single
structured sentinel that CI greps (`[kpath] visited=N/M ...`).

## Related Pages

- [Code Path Ledger](Code-Path-Ledger.md) — KPath ledger, the
  global "what fired this boot?" surface.
- [Debugging](../tooling/Debugging.md) — `addr2sym`, `disasm-at.sh`,
  `decode-panic.sh`
- [QEMU Smoke Tests](../tooling/QEMU-Smoke.md)
- [Boot Path](Boot.md)
