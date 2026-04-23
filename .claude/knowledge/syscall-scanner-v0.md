# Syscall scanner v0 — operator-triggered `sysscan` shell command

**Type**: Observation
**Status**: Active
**Last updated**: 2026-04-23

## What it does

A ~200-line kernel-resident partial x86_64 decoder that walks a
byte range and emits one log line per syscall-issuing idiom it
finds, cross-referenced against the NT / Linux / native syscall
tables for name + coverage classification.

Shell command:

- `sysscan kernel` — scan the kernel's own `.text` (linker-
  exported `_text_start` .. `_text_end`). Useful as a negative
  test — the kernel doesn't issue syscalls, so all hits there
  are incidental byte sequences and surface as `<no-table-hit>`.
- `sysscan <path>` — read a FAT32 file, auto-detect PE /
  ELF / raw-bytes, locate the executable section, scan.

Output goes to COM1. One line per site up to
`kMaxSitesLogged = 64`; excess sites are counted in the summary
line's `dropped=` column.

## Recognised idioms

| Bytes      | Instruction   | ABI               |
|------------|---------------|-------------------|
| `0F 05`    | `syscall`     | Linux / NT x86_64 |
| `CD 80`    | `int 0x80`    | Native CustomOS   |
| `CD 2E`    | `int 0x2E`    | Legacy NT         |
| `0F 34`    | `sysenter`    | 32-bit fast path  |

For each site the scanner walks back up to 32 bytes looking for
the canonical `B8 ii ii ii ii` (`mov eax, imm32`) encoding to
recover the syscall number. Misses surface as
`nr=<no mov eax,imm32 within 32B>`.

## Coverage classification

The recovered number is cross-referenced against three tables:

- **Linux** — `subsystems::translation::LinuxName` +
  `LinuxSyscallLookup` (for `Implemented` flag). Meaningful for
  `syscall`.
- **NT** — `subsystems::translation::NtName`. Meaningful for
  `syscall` / `int 0x2E`.
- **Native** — an in-module mirror of the SYS_0..46 name table.
  Meaningful for `int 0x80`.

A site with no hit in any table is tallied as `unknown=`. This
is exactly the signal an operator needs: "the binary wants to
call syscall N, we have no idea what that is, don't run it".

## Log format

Per-site:

```
[sysscan] site va=0x<VA> kind=<syscall|int80|int2e|sysenter> nr=0x<N>
          linux="<name>"(impl|unimpl) nt="<name>" native="<name>"
```

Summary (always emitted):

```
[sysscan] summary base=... size=... sites=N recovered=M
          linux_known=A (impl=B) nt_known=C native_known=D (impl=E) unknown=F
[sysscan] summary kinds: syscall=... int80=... int2e=... sysenter=...
```

## Intentional non-features (bloat guard)

- **Not a full disassembler.** No REX / prefix tracking, no
  ModRM / SIB parsing, no instruction-boundary reconstruction.
  False positives (matching `0F 05` inside a longer
  instruction's operand) are accepted as the price of the
  narrow scope. They surface as unknown-number sites or
  recovered-number-with-no-table-hit — both visible in the log.
- **Not automatic.** PE / ELF load paths do not pre-scan.
  Operator triggers explicitly.
- **Not vendored.** No Capstone / Zydis dependency.
- **No live-process scanning yet.** v0 targets kernel text +
  on-disk files. Scanning a running process's code pages
  across possibly-unmapped regions is a future slice.

## Files

- `kernel/debug/syscall_scan.h` — public API + report/site
  structs.
- `kernel/debug/syscall_scan.cpp` — decoder + PE/ELF
  section locator + FAT32 file read path.
- `kernel/CMakeLists.txt` — `debug/syscall_scan.cpp` added to
  kernel-stage1 sources.
- `kernel/core/shell.cpp` — `sysscan` command + help line +
  `kCommandSet` entry.

## Validation

Offline byte-count against the release kernel .text:

```
.text off=0x2000 size=0x75bb9 vaddr=0xffffffff8010a000
syscall=0x0F05: 5, int80=0xCD80: 16, int2e=0xCD2E: 2, sysenter=0x0F34: 1
```

All 24 matches are expected false positives (the kernel never
issues syscalls). The scanner's `<no-table-hit>` column is the
sieve that makes this noise distinguishable from real hits.
