# `inspect` umbrella v0 — operator-triggered RE / triage toolkit

**Type**: Observation
**Status**: Active
**Last updated**: 2026-04-23

## What it is

A single shell command `inspect <sub>` that groups every
reverse-engineering / triage helper the kernel ships with.
Each subcommand is narrowly scoped and shares one FAT32 reader
plus one PE/ELF header parser instead of every feature
reinventing them. This replaced the standalone `sysscan`
command when the second RE feature (`opcodes`) landed.

## Subcommands

### `inspect syscalls kernel | <path>`

Unchanged from the earlier `sysscan` implementation. Walks a
byte range, matches the four syscall-issuing idioms
(`0F 05` syscall, `CD 80` int 0x80, `CD 2E` int 0x2E,
`0F 34` sysenter), walks back up to 32 bytes looking for
`B8 ii ii ii ii` (`mov eax, imm32`) to recover the syscall
number, and cross-references against the NT / Linux / native
tables. Output per site:

```
[inspect-sc] site va=... kind=syscall nr=... linux="..."(impl) ...
[inspect-sc] summary base=... sites=N recovered=M linux_known=... ...
```

The `<no-table-hit>` and unknown-number rows are the signal
that distinguishes false-positive byte matches from real
syscall sites.

### `inspect opcodes <path>`

Walks the executable section (PE `.text` / ELF PT_LOAD with
PF_X / raw bytes) and emits two signals to COM1:

1. **First-byte opcode histogram, top 16.** Sorted by
   frequency — REX.W `0x48`, CALL `0xE8`, MOV `0x89` and
   their siblings float to the top on any real binary.
2. **Instruction-class counters.** Each "interesting"
   opcode start is assigned to exactly one bucket:

   | Class           | Bytes                             |
   |-----------------|-----------------------------------|
   | `jump_near`     | `E9 / EB / 0F 80..8F`            |
   | `call_near`     | `E8`                              |
   | `ret_near`      | `C2 / C3 / CA / CB`               |
   | `int_imm`       | `CD xx` (excl. 0x80 / 0x2E)       |
   | `nop`           | `90` + `0F 1F ...`                |
   | `syscall_idiom` | `0F 05 + CD 80 + CD 2E + 0F 34`   |
   | `rex_prefix`    | `40..4F`                          |
   | `lock_prefix`   | `F0`                              |
   | `rep_prefix`    | `F2 / F3`                         |
   | `seg_prefix`    | `26 / 2E / 36 / 3E / 64 / 65`     |
   | `osz_prefix`    | `66 / 67`                         |

The secondary `esc_0f[256]` counter tracks which `0F xx`
two-byte opcodes appear, useful for "this PE is mostly
multi-byte NOPs" triage.

### `inspect arm on | off | status`

A one-shot latch. `inspect arm on` sets a single boolean;
the next ring-3 spawn (ELF / PE / Linux-ELF — all three paths
hook it) calls `InspectOnSpawn(name, bytes, size)`, which
runs an `inspect opcodes` scan against the in-memory image
and then auto-disarms. Designed for:

```
> inspect arm on
INSPECT ARM: ARMED - OPCODES SCAN WILL FIRE ON NEXT SPAWN
> exec /bin/unknown.exe
[inspect] arm fired on spawn: name="/bin/unknown.exe"
[inspect-op] top-16 first-byte opcodes:
...
```

`inspect arm off` cancels a pending arm. `inspect arm status`
prints the current state. The latch is a `volatile bool`;
single-threaded x86_64 loads/stores are atomic, no lock
needed (shell and spawn path never race on the same line).

## Files

- `kernel/debug/inspect.h` — umbrella public API.
- `kernel/debug/inspect.cpp` — shared FAT32 reader + PE/ELF
  header parser + arm latch + opcodes scanner.
- `kernel/debug/syscall_scan.{h,cpp}` — syscall-site
  scanner (backs `inspect syscalls`). Now uses the shared
  loader helpers from `inspect.h` — no more duplicated
  FAT32 / PE / ELF parsers.
- `kernel/proc/ring3_smoke.cpp` — `SpawnElfFile`,
  `SpawnElfLinux`, `SpawnPeFile` each call
  `duetos::debug::InspectOnSpawn(...)` before
  `ProcessCreate`.
- `kernel/shell/shell.cpp` — `CmdInspect` dispatcher + four
  subcommand handlers + `kCommandSet` entry + help line.
- `kernel/CMakeLists.txt` — `debug/inspect.cpp` added to
  kernel-stage1 sources.

## Design notes

### Free-standing kernel quirks (memset / memcpy traps)

The opcode report struct is 2 KiB (two 256-entry `u32`
histograms + per-class counters). Two pitfalls:

1. **Return-by-value** of a 2 KiB struct forces the compiler
   to emit a `memcpy` — which the freestanding kernel can't
   link. Fix: both `OpcodeScanRegion` and `OpcodeScanFile`
   return `void`; the report lives in a file-scope
   `g_op_report` that gets overwritten per scan. Every
   existing caller discards the value anyway.
2. **Value-init `{}`** of a 2 KiB struct likewise lowers to
   `memset`. Fix: local helper `ByteZero` with a
   `volatile u8*` loop (same pattern used in
   `kernel/fs/fat32.cpp` / `fs/exfat.cpp`).

A plain `bool taken[256] = {};` inside `BuildTopN` also
tripped the memset trap — moved to a file-scope static with
an explicit reset loop.

### Why one umbrella, not four top-level commands

When `sysscan` was the only RE tool, a top-level command was
fine. The second feature (`opcodes`) arrived with a shared
"scan a file on FAT32, auto-detect PE vs ELF" prologue, so
factoring out `InspectReadFatFile` / `InspectFindPeText` /
`InspectFindElfText` was the anti-bloat move. The subcommand
naming (`inspect <x>`) keeps every future addition
(`imports`, `strings`, `headers`, `diff`, `patch`, `bp`…) in
one namespace — one help screen, one mental model.

### Trade-off not taken

Considered keeping `sysscan` as a deprecated alias for one
release. Skipped — no other operator has the repo, so
renaming costs nothing.

## Intentional non-features (bloat guard)

- **Not a full disassembler.** No REX / ModRM / SIB / disp
  tracking. The opcodes scan classifies the first byte (or
  `0F`-escape two-byte form) and moves on. False positives
  (a `0F 05` byte sequence inside a longer instruction's
  operand) surface as unknown-number sites or class counters
  that don't add up to the byte histogram — both visible.
- **Not vendored.** Zero third-party deps.
- **Not automatic** for syscalls or opcodes — operator
  triggers explicitly. The `arm` latch is the single
  exception, and it's explicitly one-shot so it can't fire
  on spawns the operator didn't mean to inspect.
- **No live-process scanning.** Today's scope is kernel text
  + on-disk files + in-memory spawn images. Walking a running
  process's code pages across possibly-unmapped regions is a
  future slice.

## Future subcommands (sketched, not built)

Each would live as a separate `.cpp` sharing the loader
helpers; no new top-level shell commands.

- `inspect imports <path>` — walk PE IAT / ELF dynsym, log
  each import + its source DLL / SO.
- `inspect strings <path>` — ASCII / UTF-16LE string scan
  with a minimum-length filter.
- `inspect headers <path>` — structured PE / ELF header
  dump (more verbose than the current `PeReport`).
- `inspect diff <a> <b>` — byte-level diff of two
  executables' code sections.
- `inspect patch <path> <offset> <bytes>` — scratch-buffer
  byte patch with a pre/post histogram diff.
- `inspect bp <path>` — cross-reference kernel breakpoint
  table against an image's symbol table.
