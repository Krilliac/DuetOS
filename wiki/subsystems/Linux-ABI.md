# Linux ABI

> **Audience:** Kernel hackers, ELF/Linux thunk authors
>
> **Execution context:** Userland (Linux ELF) -> `syscall` -> translation -> int 0x80
>
> **Maturity:** active — ~360 effective syscalls; Linux ELF spawn runs every boot

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

The translator is **live and exercised every boot**. The
auto-generated coverage header
[`linux_syscall_table_generated.h:8-13`](../../kernel/subsystems/linux/linux_syscall_table_generated.h)
records 374 x86_64 syscalls in the source CSV, 267 with a `Do<Name>`
body, 93 dispatched inline — **360 effective (96% effective
coverage)**. Handlers are split across 22 `syscall_*.cpp` TUs.

Linux ELF spawn is not a sketch: `ring3_smoke.cpp` calls
`SpawnElfLinux` on every boot to launch the `linux-elf-smoke`,
`synxtest`, `synfs`, `synet`, and `synfull` self-test binaries
(ring3_smoke.cpp:777, :801, :824, :846, :877). Real signal delivery
is wired — `LinuxSignalCheckAndDeliver` (signal_deliver.h:51) walks
the pending set on the way back to user mode and
`LinuxSignalRestoreFrame` (signal_deliver.h:56) restores the trap
frame on `rt_sigreturn`.

See
[Linux Networking Port Opportunities](../advanced/Linux-Networking-Port-Opportunities.md)
for a sample of code that could be lifted from the Linux kernel into
DuetOS's net stack (with full attribution + license-compatible
rewrites).

## Threading & Locking Model

A Linux ELF runs as an ordinary DuetOS process/thread. Its syscalls
enter through `syscall_entry.S` on the SYSCALL/SYSRET path and run in
**process context** on the calling thread — no global Linux lock. The
handlers route through the same kernel primitives (`mm::*`, `sched::*`,
`fs::routing::*`) a native syscall would, so the locking discipline is
the kernel's, not the subsystem's. Signal delivery
(`LinuxSignalCheckAndDeliver`) runs on the return-to-user edge of the
delivering thread, not from an IRQ handler.

## Capability / Privilege Surface

The Linux thunks do **not** carry their own privilege model. Every
effect a Linux binary can have on the system goes through a
cap-gated native DuetOS syscall — file writes through `kCapFsWrite`,
thread creation through `kCapSpawnThread`, and so on. Linux
credential calls (`setuid`, `setgid`, capabilities, `prctl`) are
facades that satisfy the ABI shape; they do not grant or revoke
kernel authority. The kernel's `Process::caps` is the source of
truth. See [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
and [Capabilities](../security/Capabilities.md).

## Feature Families

Beyond the file/process/memory/socket core, the subsystem ships
several Linux facility families that are easy to miss in the flat
syscall table:

| Family | Source | What it covers |
|--------|--------|----------------|
| inotify | [`inotify.cpp`](../../kernel/subsystems/linux/inotify.cpp) | `inotify_init1` / `add_watch` / `rm_watch` filesystem-event watches. |
| fanotify | [`fanotify.cpp`](../../kernel/subsystems/linux/fanotify.cpp) | `fanotify_init` / `fanotify_mark` access-notification surface. |
| keyrings | [`keyrings.cpp`](../../kernel/subsystems/linux/keyrings.cpp) | `add_key` / `request_key` / `keyctl` key-management calls. |
| SysV IPC | [`sysv_ipc.cpp`](../../kernel/subsystems/linux/sysv_ipc.cpp) | `shmget`/`shmat`, `semget`/`semop`, `msgget`/`msgsnd` System V IPC. |
| POSIX mqueues | [`msg_queues.cpp`](../../kernel/subsystems/linux/msg_queues.cpp) | `mq_open` / `mq_timedsend` / `mq_timedreceive` message queues. |
| async I/O | [`syscall_async_io.cpp`](../../kernel/subsystems/linux/syscall_async_io.cpp) | `io_setup` / `io_submit` and the `io_uring_*` setup/enter surface. |
| pidfd / splice | [`pidfd_splice.cpp`](../../kernel/subsystems/linux/pidfd_splice.cpp) | `pidfd_open` / `pidfd_send_signal` plus `splice` / `tee` / `vmsplice`. |

## vDSO

Every Linux ELF process gets a one-page vDSO blob mapped at a
fixed VA (`0x50000000` today) at spawn time, painted from
`kernel/subsystems/linux/vdso/vdso.S`. Current exports:

| Offset | Symbol | Purpose |
|-------:|--------|---------|
| `0x00` | `__kernel_rt_sigreturn` | Trampoline that issues Linux SYS_rt_sigreturn (nr 15). Used by `LinuxSignalCheckAndDeliver` when the caller's `sigaction` omitted `SA_RESTORER` — same fallback path real Linux takes when libc didn't supply its own restorer. |

`Process::linux_vdso_base` / `linux_vdso_rt_sigreturn_va` hold
the per-process VA. PE / native processes leave them zero (the
mapping is Linux-ABI specific). Frame OOM during spawn leaves
the fields zero and logs a `[linux/signal] no SA_RESTORER and no
vDSO` warning at the first signal delivery on that process.

**GAP:** the blob is not yet a real ELF shared object — no PHT,
no dynamic symbol table, no `AT_SYSINFO_EHDR` in the auxv. Static
binaries that never dynamic-resolve vDSO symbols work fine.
Dynamic glibc that scans `AT_SYSINFO_EHDR` for `__vdso_*` exports
will skip the page; promoting to a proper ELF .so is a follow-up.

## Key Difference from Win32 Path

- **No DLL preload set.** Linux ELFs use `glibc` / `musl` statically
  linked, or a small set of `.so`s the loader maps on demand.
- **`syscall` instruction**, not `int 0x80`. The translation layer
  uses a SYSCALL/SYSRET entry path; arg ordering is the same SysV
  convention, but the syscall *numbers* are Linux's, not ours.
- **Linux number -> DuetOS syscall mapping** is an explicit table
  in `kernel/subsystems/translation/`.

## What Will Run

Static-linked simple Linux binaries run today — the per-boot
`synfull`-class self-tests are exactly this shape. Dynamic-linked
binaries (`glibc` that scans `AT_SYSINFO_EHDR` for vDSO exports)
still need the dynamic-loader path and the promoted ELF-`.so` vDSO;
that is its own slice (see the vDSO GAP above).

## Known Limits / GAPs / STUBs

- **Mount-aware file routing** — `syscall_file.cpp:104` carries a
  `GAP:` marker: opens currently target FAT32 volume 0 only.
  `fs::routing::OpenForProcess` returns a Win32 handle that doesn't
  fit the Linux fd shape, so a Linux-side routing helper that shares
  the mount-table walk but returns a Linux fd is deferred to a
  larger slice.
- **vDSO is not yet a real ELF `.so`** — no PHT, no dynamic symbol
  table, no `AT_SYSINFO_EHDR` in the auxv (see the vDSO section).
- **Dynamic linking** — no `ld.so` path yet; only static binaries
  are validated.
- Re-derive the live per-handler inventory with
  `git grep -nE "// (STUB|GAP):" kernel/subsystems/linux`.

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md) — peer ABI
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md) — the rules
  the Linux thunks must respect
- [Syscalls](../kernel/Syscalls.md) — the kernel side both ABIs
  converge on
- [Linux Networking Port Opportunities](../advanced/Linux-Networking-Port-Opportunities.md)
