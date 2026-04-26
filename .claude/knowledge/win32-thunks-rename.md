# Win32 stubs.cpp/.h renamed to thunks.cpp/.h

**Last updated:** 2026-04-25
**Type:** Decision
**Status:** Active

## Description

The file holding hand-assembled bytecode for Win32 IAT entries was
historically named `kernel/subsystems/win32/stubs.{cpp,h}`. The
"stub" name was misleading: most entries do real work — they
translate the Windows x64 calling convention into the DuetOS
native syscall ABI and issue `int 0x80`. Only a small subset
(`kOffReturnZero`, `kOffReturnOne`, `kOffCritSecNop`,
`kOffMissLogger`) are genuine no-op stubs.

The file (and its public symbols) were renamed to use the
standard Windows-loader term *thunk* — small, ABI-bridging
bytecode an indirect call lands on. Genuine no-op stubs keep
their `kOffReturn*` / `kOffCritSecNop` / `kOffMissLogger` names
to flag them as such.

## Context

Applies to anyone reading the Win32 subsystem source for the
first time. The file is ~5600 lines, the bulk of which is
`constexpr u8 kThunksBytes[] = { ... }` with one row of bytes
per Win32 API and an inline assembly-style comment on each row.
At a glance this looks like a mountain of stub no-ops; in reality
it is the *output* of a hand-assembler embedded into the kernel
as data.

## Details

### Rename map

| Before                            | After                              |
|-----------------------------------|------------------------------------|
| `subsystems/win32/stubs.h`         | `subsystems/win32/thunks.h`        |
| `subsystems/win32/stubs.cpp`       | `subsystems/win32/thunks.cpp`      |
| `Win32StubsPopulate`              | `Win32ThunksPopulate`              |
| `Win32StubsLookup`                | `Win32ThunksLookup`                |
| `Win32StubsLookupKind`            | `Win32ThunksLookupKind`            |
| `Win32StubsLookupCatchAll`        | `Win32ThunksLookupCatchAll`        |
| `Win32StubsLookupDataCatchAll`    | `Win32ThunksLookupDataCatchAll`    |
| `kWin32StubsVa`                   | `kWin32ThunksVa`                   |
| `kStubsBytes`                     | `kThunksBytes`                     |
| `kStubsTable`                     | `kThunksTable`                     |
| `StubEntry` / `StubHashEntry`     | `ThunkEntry` / `ThunkHashEntry`    |
| `BuildStubHashTable`              | `BuildThunkHashTable`              |
| `DUETOS_WIN32_STUBS_VALIDATE_LIN` | `DUETOS_WIN32_THUNKS_VALIDATE_LIN` |

`IsLikelyDataImport` and `kWin32ThreadExitTrampVa` were unaffected.
`kOff<Name>` constants for individual entries kept their names.

### Why the bytecode lives in one file

Documented in detail in the top-of-file comment of
`kernel/subsystems/win32/thunks.h`. Three reasons in short:

1. **One contiguous code page.** All thunks share a single R-X
   page mapped at `kWin32ThunksVa`. The IAT slots store absolute
   VAs of the form `kWin32ThunksVa + offset`, so the offsets in
   `kOff<Name>` MUST be valid indices into one byte array.
   Splitting across TUs would mean computing offsets at link
   time, which kills the `consteval`-built sorted hash table
   used for O(log N) lookup at PE load.
2. **No second user-mode build.** Hand-assembled bytes in a
   `constexpr u8[]` need only the host C++ compiler. A `.S` file
   would mean a second cross-compile target with its own linker
   script, plus extracting symbol offsets from the resulting
   object — overkill for ~5 KiB of code.
3. **Position-independent at runtime.** The bytes are copied
   verbatim into a freshly-allocated frame. There are no
   relocations to apply because every absolute VA the thunks
   reference is a kernel-controlled fixed address.

### Mechanical procedure used for the rename

```bash
git mv kernel/subsystems/win32/stubs.h   kernel/subsystems/win32/thunks.h
git mv kernel/subsystems/win32/stubs.cpp kernel/subsystems/win32/thunks.cpp

# Bulk symbol rename in renamed files + callers (longest names first)
sed -i \
  -e 's/\bWin32StubsLookupDataCatchAll\b/Win32ThunksLookupDataCatchAll/g' \
  -e 's/\bWin32StubsLookupCatchAll\b/Win32ThunksLookupCatchAll/g' \
  -e 's/\bWin32StubsLookupKind\b/Win32ThunksLookupKind/g' \
  -e 's/\bWin32StubsLookupHashed\b/Win32ThunksLookupHashed/g' \
  -e 's/\bWin32StubsLookupLinear\b/Win32ThunksLookupLinear/g' \
  -e 's/\bWin32StubsLookup\b/Win32ThunksLookup/g' \
  -e 's/\bWin32StubsPopulate\b/Win32ThunksPopulate/g' \
  -e 's/\bkWin32StubsVa\b/kWin32ThunksVa/g' \
  ...
  $FILES
```

After running, build under `cmake --preset x86_64-release` and
fix any TU that still `#include "stubs.h"` (thread_syscall.cpp
needed to be caught manually because the include was searched
relative to the same directory).

## Notes

- **See also:** [Win32 stubs callee-saved rdi/rsi bug](win32-stubs-rdi-rsi-abi.md) — historical entry written before the rename; the bug it documents is still real and fixed in the same thunk bytecode.
- The bulk anti-bloat split happened in two commits: first
  `Win32ProcEnvPopulate` + `Win32LogNtCoverage` left stubs.cpp
  for `proc_env.{cpp,h}` / `nt_coverage.{cpp,h}`; then the file
  itself was renamed from "stubs" to "thunks". Net effect: a
  ~5800-line file is now a ~5600-line file *plus* meaningful
  doc, with the two clearly-separable concerns moved out.
