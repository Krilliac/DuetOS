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

See `.claude/knowledge/inspect-umbrella-v0.md`.

### Breakpoints

`kernel/debug/breakpoints.cpp` exposes a kernel-mode breakpoint
subsystem with hardware DR gates. Phase 4 added static `KBP_PROBE`
macros that compile to a single `int3` if the matching breakpoint is
armed.

`SYS_DEBUG` is gated by `kCapDebug`. See
`.claude/knowledge/breakpoints-v0.md`.

### Runtime Invariant Checker

`kernel/diag/runtime_checker.cpp` runs periodic sweeps of:

- Heap chunk integrity
- Frame allocator bitmap consistency
- Scheduler runqueue invariants
- CRx register sanity
- Stack canary integrity
- Stack-overflow approach detection

A violation raises a panic with the failing invariant named. See
`.claude/knowledge/runtime-invariant-checker-v0.md`.

## Off-target Tooling

`tools/debug/` ships:

- **`disasm-at.sh <kernel.elf> <addr>`** — disassemble a window
  around an address from a kernel ELF.
- **`decode-panic.sh <serial.log>`** — parse a panic dump and emit a
  cleaned-up stack trace with symbols resolved.

See `.claude/knowledge/debug-tooling-symbol-disasm.md`.

## Crash Dump

The crash dump path lives in `kernel/diag/` (`diag_decode.cpp`,
`recovery.cpp`, supporting modules). On any unhandled exception it:

- Dumps GPRs with symbol resolution
- Decodes register bits (CR0, CR4, EFER, RFLAGS)
- Symbolizes RIP, RSP, RBP, CR2 against the embedded symbol table
- Tags VA regions (cr2/rsp/rbp/rip vs known mm regions)
- Prints peer-CPU NMI snapshots (when SMP lands)
- Prints per-CPU held-locks
- Prints the last N klog ring entries inline

See `.claude/knowledge/crash-dump-v0.md`.

## Cleanroom Trace Boot Survey

The first live read of the trace ring buffer is documented in
`.claude/knowledge/cleanroom-trace-boot-survey-v0.md`. Useful template
for adding new trace scopes.

## Related Pages

- [Logging and Tracing](../kernel/Logging-And-Tracing.md)
- [QEMU Smoke Tests](QEMU-Smoke.md)
- [Coding Standards](Coding-Standards.md)
