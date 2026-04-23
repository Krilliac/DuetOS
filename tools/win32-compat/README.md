# Win32 / NT compatibility tooling

Reference data + generators that map between **NT syscall numbers** (the
`ntdll!Nt*` ABI that real Windows binaries see when they bypass
`kernel32`) and the CustomOS internal `SYS_*` enum (`kernel/core/syscall.h`).

## Why this exists

CustomOS already runs Win32 PE binaries by patching their Import Address
Table to redirect `kernel32!CreateFileW`, `kernel32!WriteFile`, etc. to
per-process stubs that issue our internal `SYS_*` numbers via `int 0x80`.
That works for any PE that actually links against `kernel32.dll`.

Real-world Windows binaries occasionally **bypass `kernel32` entirely**
and call `ntdll!NtCreateFile` directly. `ntdll`'s NT stubs look like:

```
ntdll!NtCreateFile:
    mov r10, rcx       ; SystemCall calling convention
    mov eax, 0x55      ; <-- NT syscall number — version-specific
    syscall
    ret
```

For a binary like that to work on us, our kernel needs to recognise
`eax = 0x55` as "open a file" — which means we need to know which
NT syscall numbers correspond to which operations, on the Windows
version we want to be ABI-compatible with.

## What's here

| File                              | Purpose                                                        |
| --------------------------------- | -------------------------------------------------------------- |
| `nt-syscalls-x64.csv`             | The raw j00ru syscall table — 506 NT syscalls × 35 versions    |
| `gen-nt-shim.py`                  | Generator that emits `nt_syscall_table_generated.h`            |
| `nt-syscalls-bedrock.txt`         | Generator output: 292 universal NT calls (every version)       |
| `nt_syscall_table_generated.h`    | Header committed into the source tree (no Python at build)     |

## Provenance

`nt-syscalls-x64.csv` is a verbatim copy of
`https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/nt.csv`
authored by Mateusz "j00ru" Jurczyk over many years of reverse-engineering.
The data is factual ABI information extracted from Microsoft's `ntoskrnl.exe`
binaries — function names are public Microsoft API identifiers, syscall
numbers are facts about a binary. Used here under the same legal posture
that lets Wine / ReactOS / every Windows interop project consume this kind
of catalogue: facts are not copyrightable, ABI numbers are an
interoperability primitive, no creative expression is being replicated.

If j00ru's repo gets a `LICENSE` file in the future and the terms are
incompatible with this use, swap to the equivalent ReactOS table or
extract our own from a Windows install.

## Regenerating

```sh
python3 tools/win32-compat/gen-nt-shim.py \
    --csv tools/win32-compat/nt-syscalls-x64.csv \
    --version "Windows 11 and Server (11 25H2)" \
    --out kernel/subsystems/win32/nt_syscall_table_generated.h
```

Commit both the CSV and the regenerated header. The build does NOT invoke
Python — the header is checked in.

## Scoreboard

The generated header tracks which NT bedrock calls have a CustomOS
mapping vs which are still `kSysNtNotImpl`. A boot-time log line will
print "ntdll bedrock coverage: N/M" once the shim is wired in (slice TBD).

## Not goals (for now)

- We don't ship a real `ntdll.dll`. The shim layer (when it lands) will
  be tiny per-process stubs analogous to the existing kernel32 stubs.
- We don't claim version-exact compatibility. Picking Win11 25H2 numbers
  means binaries targeting that version's NT ABI will work; older
  binaries with hard-coded older numbers may need their own routing.
