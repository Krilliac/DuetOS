# windows-kill.exe — real-world PE test vector

`windows-kill.exe` is a third-party Windows console utility
vendored into this repo as a **test vector for the kernel PE
loader's diagnostic path** (`kernel/core/pe_loader.cpp` —
`PeReport`).

## What it exercises

Unlike `userland/apps/hello_pe/hello.c` (freestanding, empty
import table), this binary is a real-world x64 Windows PE
that imports 100 functions across 12 DLLs (kernel32, ntdll,
advapi32, msvcp140, vcruntime140, dbghelp, and seven UCRT
api-set stubs). It has base relocations, TLS, SEH unwind
tables (`.pdata`), resources (`.rsrc`), and the canonical
x64 `ImageBase = 0x140000000`.

The v0 kernel PE loader cannot **run** this binary — there's
no Win32 subsystem yet, nothing to resolve its imports
against. But `PeReport` can parse and log every one of those
imports on boot, producing a concrete measurement of the gap
between what we have (v0 freestanding-only) and what running a
real Windows program would require.

See `.claude/knowledge/pe-subsystem-v0.md` for the full
analysis of the diagnostic output.

## Provenance

Copied unmodified from the `nodemon` npm package bundled with
the dev environment:

    /opt/node22/lib/node_modules/nodemon/bin/windows-kill.exe

Size: 80384 bytes · SHA: can be regenerated via
`sha256sum windows-kill.exe`.

## Why this file, specifically?

Chrome would be ideal (matches the user's "run Chrome" ask)
but the dev sandbox blocks `dl.google.com`, and Chrome ships
hundreds of MB of DLLs — unfit for embedding as a
`constexpr u8[]` into the kernel ELF. `windows-kill.exe` is
the smallest on-host PE that exercises every `PeReport`
branch (sections, imports, relocs, TLS, resources, SEH) at a
file size that doesn't balloon the boot image.

## Not for execution

This file is NEVER executed by CustomOS — the kernel rejects
it at `PeValidate` with `PeStatus::ImportsPresent`. The
diagnostic output IS the contribution.
