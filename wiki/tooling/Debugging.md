# Debugging

> **Audience:** All contributors
>
> **Execution context:** Host (post-mortem) + on-target (kernel shell)
>
> **Maturity:** v0 stable — symbol resolution, disasm, panic decoding

## Overview

DuetOS ships with a small but pointed debug toolkit. The two halves
are:

1. **On-target tooling**: a kernel shell with `addr2sym`, `inspect`
   subcommands, runtime invariant checker, breakpoints (kCapDebug
   gated).
2. **Off-target tooling**: `tools/debug/` shell scripts that consume
   the serial log and the kernel image.

## On-target Tooling

### `addr2sym`

Kernel-shell command. Takes an address, returns the nearest symbol +
offset using the embedded kernel symbol table. Used to symbolize
panic dumps interactively.

### `inspect` umbrella

`inspect <subcmd>` in the kernel shell:

- `inspect syscalls <path>` — scan an executable, find every
  `syscall` / `int 0x80` / `int 0x2E` / `sysenter` site, recover the
  preceding `mov eax, imm32`, cross-reference against NT / Linux /
  native syscall tables.
- `inspect opcodes <path>` — first-byte opcode histogram +
  instruction-class counters over a file's executable sections.
- `inspect arm` — latch the next spawn so we scan whatever gets
  loaded next.

The kernel shell also exposes ~15 `inspect *` subcommands that read
cheap counter accessors across every subsystem (sched / mm / fs /
net / sync / lockdep / event-trace / perf / nmi-watchdog), plus
`domain list` / `domain restart` for live driver-domain control,
`cpufeatures` rollup, and `tracer dump|kind|reset` / `perf dump` /
`lockdep panic on|off`.

### Breakpoints

`kernel/debug/breakpoints.cpp` exposes a kernel-mode breakpoint
subsystem with hardware DR gates. Phase 4 added static `KBP_PROBE`
macros that compile to a single `int3` if the matching breakpoint is
armed; today there are sites at `panic.enter`, `sandbox.denial`,
`win32.stub_miss`, `mm.kernel_pagefault`, `trap.kernel_gpf`,
`trap.kernel_ud`, `mm.heap_alloc_fail`, `mm.phys_alloc_fail`,
`smp.ap_online`, `ring3.spawn`, `proc.create`, `proc.destroy`,
`loader.pe_load`, `loader.elf_load`, `sched.thread_exit`,
`sched.context_switch`, plus 8 `KBP_PROBE` sites covering kernel-fault,
OOM, SMP, loader, and exit edges.

`SYS_DEBUG` is gated by `kCapDebug`.

### Runtime Invariant Checker

`kernel/diag/runtime_checker.cpp` runs periodic sweeps of:

- Heap chunk integrity
- Frame allocator bitmap consistency
- Scheduler runqueue invariants
- CRx register sanity
- Stack canary integrity
- Stack-overflow approach detection
- `.text` baseline hash (`g_baseline_text_full_hash` covers the
  full `.text`; the spot hash covers `kernel_main`-anchored hot
  windows; both must match)

A violation raises a panic with the failing invariant named.

## Off-target Tooling

`tools/debug/` ships:

- **`disasm-at.sh <kernel.elf> <addr>`** — disassemble a window
  around an address from a kernel ELF.
- **`decode-panic.sh <serial.log>`** — parse a panic dump and emit a
  cleaned-up stack trace with symbols resolved.
- **`duetos-gdb-attach.sh`** + **`duetos-gdb-cmd.sh`** — attach to
  the in-kernel GDB server (TCP, QEMU pty / software null-modem, or
  USB-UART to real iron).
- **`duetos-gdb-monitor.py`** — DuetOS-aware `monitor` client.
  Speaks raw GDB-remote and drives the `duet <verb>` surface via
  `qRcmd` (capability bitsets, IPC handles, the Win32 window list,
  probe/kdbg/watch control, …). Boots with `DUETOS_GDB_DEMO=ON`
  for a guaranteed stop, runs the command(s), detaches.

## Live Debug — In-kernel GDB Server

`DUETOS_GDB_SERVER` (default-ON in `x86_64-debug`) exposes a feature-
complete GDB server inside the kernel. Supported packets: `qSupported
/ qXfer:features:read` (24-reg `target.xml`) `/ g/G/m/M/H/c/s/Z0..Z4/
z0..z4/D/k/vCont/vCont? + qfThreadInfo/qsThreadInfo/qC/T`. Trap-frame
plumbing rolls RIP back on `#BP` and clears TF on `#DB`. SW + HW
breakpoints route through `kernel/debug/breakpoints`; install errors
translate `BpError → distinct GDB E1n codes` (E12 = NoHwSlot for the
5th-watchpoint case).

Three transports: TCP (default), QEMU pty (software null-modem),
real `/dev/ttyUSB*` (USB-UART cable to iron). Async Ctrl-C stop, SMP
NMI rendezvous, multi-thread visibility (peers as GDB threads with
read+write registers via `Hg`+`G`+commit-on-release), and `vCont`
resume verb all landed.

VSCode one-click attach via `.vscode/launch.json` +
`tools/debug/vscode-{start,stop}-qemu.sh`. The only deferred item is
`vCont;s` step on a peer thread — see [Roadmap](../reference/Roadmap.md#gdb-stub-completion-peer-thread-step).

### DuetOS `monitor` (qRcmd) — `duet …` command surface

Stock GDB sees raw registers/memory; it cannot express DuetOS
state. The kernel answers the standard GDB `monitor` (`qRcmd`)
packet with a `duet <verb>` command surface, so the SAME
transport/stop-loop carries DuetOS-aware introspection + control.
Use it from stock gdb (`monitor duet ps`) or
`tools/debug/duetos-gdb-monitor.py ps`.

Verbs (read-only introspection): `ps`, `caps <pid>`, `threads`,
`handles <pid>`, `vm <pid>`, `mods <pid>`, `win`, `win32 <pid>`,
`reg <HKLM|HKCU> <path>`. Control (kernel-owned debug
facilities only): `probe list|arm|disarm`, `kdbg list|mask|on|off`,
`watch list|add|del`, `trip list|del`, `dump` (minidump from the
stop-point context). `duet help` lists them.

**Stop-only**, exactly like stock `monitor`: commands dispatch
from inside the stop loop, so the target must be stopped (a
breakpoint, Ctrl-C, or the `DUETOS_GDB_DEMO` int3) first. The
reply is a single packet, hard-truncated with a `[truncated]`
sentinel if a report overflows; `O`-packet streaming is deferred.

**Trust model.** The surface inherits the same boundary as the
`M`/`G` write packets — physical-serial access to a stopped
target. No `kCapDebug` check is added (there is no authenticated
principal on a raw serial line). Read verbs route through public
kernel APIs; mutating verbs touch only kernel-owned debug
facilities — never subsystem internals. Boot self-test sentinel:
`[gdb-monitor-selftest] PASS`.

## Crash Dump

The crash dump path lives in `kernel/diag/` (`diag_decode.cpp`,
`recovery.cpp`, supporting modules). On any unhandled exception it:

- Dumps GPRs with symbol resolution.
- Decodes register bits (CR0, CR4, EFER, RFLAGS).
- Symbolizes RIP, RSP, RBP, CR2 against the embedded symbol table.
- Tags VA regions (cr2/rsp/rbp/rip vs known mm regions).
- Prints peer-CPU NMI snapshots (when SMP lands).
- Prints per-CPU held-locks.
- Prints the last N klog ring entries inline.
- Snapshots Architectural LBR (when CPU supports it).
- Records per-task syscall trail and per-process VM info.
- Emits a structurally-valid Windows minidump (`.dmp`,
  `MDMP`-magic, `CONTEXT_X64` + `ThreadList` + `ModuleList` +
  `MemoryList` + `ExceptionStream` + `SystemInfo`) over QEMU's
  debugcon (port `0xE9 → ${BUILD_DIR}/duetos.dmp`). Loadable in
  WinDbg / Visual Studio / VSCode-cppvsdbg / Python `minidump`
  library / Mozilla `minidump-stackwalk`.

## Cleanroom Trace Boot Survey

The cleanroom-trace surface reads the trace ring buffer without
bumping reader cursors so a boot-time survey is non-destructive.
Useful template for adding new trace scopes — see
`kernel/diag/cleanroom_trace.cpp`.

## Related Pages

- [Logging and Tracing](../kernel/Logging-And-Tracing.md)
- [QEMU Smoke Tests](QEMU-Smoke.md)
- [Coding Standards](Coding-Standards.md)
