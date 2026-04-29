# Linux ABI

> **Audience:** Kernel hackers, ELF/Linux thunk authors
>
> **Execution context:** Userland (Linux ELF) -> `syscall` -> translation -> int 0x80
>
> **Maturity:** Translation layer in place; Linux ELF spawn is the next slice

## Overview

`kernel/subsystems/linux/` is a **guest ABI translator** — the same
shape as `kernel/subsystems/win32/`. A second entry ABI into the
DuetOS kernel so a Linux ELF binary can issue `syscall` and have it
hit a DuetOS syscall after going through the translation unit at
`kernel/subsystems/translation/`.

```
[ Linux ELF binary ]
        |  syscall  (NR in rax, args in rdi/rsi/rdx/r10/r8/r9)
[ NT-shape translation layer ]    kernel/subsystems/translation/
        |  args & NR remapped
[ Native DuetOS syscall ]          int 0x80, kCap-gated
```

## Why a Translator and Not a Linux Kernel

DuetOS has one kernel. The Linux subsystem is **not** a guest Linux
kernel — it's an ABI shim that lets Linux binaries reach the same
DuetOS subsystems a native binary would. Same TCP stack, same VFS,
same registry. See [Subsystem Isolation](../kernel/Subsystem-Isolation.md).

## Status

The translation surface is in place; ELF spawn + the first Linux PE
running end-to-end is the next slice. Today the path is sketched but
not exercised on every boot. See
[Linux Networking Port Opportunities](../advanced/Linux-Networking-Port-Opportunities.md)
for a sample of code that could be lifted from the Linux kernel into
DuetOS's net stack (with full attribution + license-compatible
rewrites).

## Key Difference from Win32 Path

- **No DLL preload set.** Linux ELFs use `glibc` / `musl` statically
  linked, or a small set of `.so`s the loader maps on demand.
- **`syscall` instruction**, not `int 0x80`. The translation layer
  uses a SYSCALL/SYSRET entry path; arg ordering is the same SysV
  convention, but the syscall *numbers* are Linux's, not ours.
- **Linux number -> DuetOS syscall mapping** is an explicit table
  in `kernel/subsystems/translation/`.

## What Will Run

The plan is for static-linked simple Linux binaries first
(`busybox`-class) to validate the translator. Dynamic-linked binaries
need the dynamic loader path which is its own slice.

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md) — peer ABI
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md) — the rules
  the Linux thunks must respect
- [Syscalls](../kernel/Syscalls.md) — the kernel side both ABIs
  converge on
- [Linux Networking Port Opportunities](../advanced/Linux-Networking-Port-Opportunities.md)
