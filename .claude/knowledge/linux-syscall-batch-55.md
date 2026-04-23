# Linux syscall batch 55 — compat-stub + FAT32-backed gap fill

**Type**: Observation
**Status**: Active
**Last updated**: 2026-04-23

## What landed

Forty new Linux x86_64 syscall handlers were added to
`kernel/subsystems/linux/syscall.cpp`, lifting primary-dispatcher
coverage from 76 → 116 handlers (29 % → 31 % of the 374-entry
ABI table). The matrix in `docs/syscall-abi-matrix.csv` reflects
the new state: `implemented` 115 → 155, `unimplemented` 756 →
716.

The batch breaks into two flavours:

### Compat-stub no-ops (subsystems v0 doesn't model)

Permission, identity, scheduling-priority, and pinning calls
all return success / sane defaults so static-musl + simple
POSIX programs make forward progress instead of bailing on
`-ENOSYS`.

| Syscall(s)                                 | Behaviour                          |
|--------------------------------------------|------------------------------------|
| `lstat` (6)                                | Alias for `stat` (no symlinks)     |
| `mremap` (25)                              | `-ENOMEM` (no remap support)       |
| `msync` (26)                               | `0` (anon mmaps; nothing to flush) |
| `mincore` (27)                             | Mark all pages resident            |
| `pause` (34)                               | Sleep huge ticks forever           |
| `flock` (73)                               | `0` (no concurrent FAT32 mounts)   |
| `chmod` / `fchmod` (90/91)                 | `0` (no permission model)          |
| `chown` / `fchown` / `lchown` (92/93/94)   | `0` (no uid/gid model)             |
| `times` (100)                              | Tick count in all four slots       |
| `setuid` / `setgid` (105/106)              | `0` (we are uid 0)                 |
| `setreuid` / `setregid` (113/114)          | `0`                                |
| `getgroups` / `setgroups` (115/116)        | `0` (no supplementary groups)      |
| `setresuid` / `setresgid` (117/119)        | `0`                                |
| `getresuid` / `getresgid` (118/120)        | Write `{0,0,0}`                    |
| `setfsuid` / `setfsgid` (122/123)          | `0`                                |
| `capget` / `capset` (125/126)              | `0` (no POSIX caps)                |
| `utime` (132)                              | `0` (no atime/mtime tracking)      |
| `mknod` (133)                              | `-EPERM` (no special files)        |
| `personality` (135)                        | `0` (default persona only)         |
| `getpriority` / `setpriority` (140/141)    | `0` (flat round-robin scheduler)   |
| `mlock` / `munlock` (149/150)              | `0` (no swap; pages always pinned) |
| `mlockall` / `munlockall` (151/152)        | `0`                                |

### FAT32-backed FS ops (real implementations)

| Syscall                | Routes through                  |
|------------------------|---------------------------------|
| `truncate` (76)        | `fs::fat32::Fat32TruncateAtPath`|
| `ftruncate` (77)       | Same, by `linux_fds[fd].path`   |
| `mkdir` (83)           | `fs::fat32::Fat32MkdirAtPath`   |
| `rmdir` (84)           | `fs::fat32::Fat32RmdirAtPath`   |
| `unlink` (87)          | `fs::fat32::Fat32DeleteAtPath`  |

Path bounce buffer + FAT32-prefix strip is shared via the new
`CopyAndStripFatPath` helper.

## Pre-existing build-breakage that had to be fixed in scope

`main` did not build: the dispatcher referenced
`kLinuxSyscallHandlersImplementedPrimary` / `Effective` symbols
the generator never emitted, and `translate.cpp` referenced an
undefined `DumpSuppressedMissSummary`. Two minimal fixes:

1. `tools/linux-compat/gen-linux-syscall-table.py` now emits the
   two extra `Primary` / `Effective` constants alongside the
   single `kLinuxSyscallHandlersImplemented`.
2. `kernel/subsystems/translation/translate.cpp` gained a
   `DumpSuppressedMissSummary(origin, table)` helper that emits
   `[translate-miss-suppressed] <origin> cumulative=N delta=M
   emitted=K`.

Without these, even the unmodified main branch fails to compile —
the green build was an artefact of the regenerated header
expecting symbols the previous generator version still emitted.

## Wiring + classifier

- All 40 handlers slot into the `LinuxSyscallDispatch(...)` switch
  in syscall.cpp (no `default` fall-through to translator).
- The generator's `Do<CamelCase>` heuristic auto-detected every
  new handler — no `NAME_ALIASES` entries needed.
- The ownership checker (`tools/linux-compat/check-syscall-ownership.py`)
  is unaffected: none of the new numbers overlap with the
  translation-unit-owned set
  (`pipe`/`socket`/`fork`/`execve`/`umask`/`statfs`/`rseq`).

## Files touched

- `kernel/subsystems/linux/syscall.cpp` — 40 new `Do*` handlers
  + 40 dispatch cases + lstat split-out from stat alias.
- `kernel/subsystems/translation/translate.cpp` — added
  `DumpSuppressedMissSummary`.
- `tools/linux-compat/gen-linux-syscall-table.py` — emit
  `Primary` + `Effective` companion constants.
- `kernel/subsystems/linux/linux_syscall_table_generated.h` —
  regenerated.
- `docs/syscall-abi-matrix.{csv,md,json}` — regenerated.
