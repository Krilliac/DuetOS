# Linux syscall batches 55-56 + NT→Linux translator

**Type**: Observation
**Status**: Active
**Last updated**: 2026-04-23

## What landed

### Batch 55 (40 handlers)

Lifted primary-dispatcher Linux coverage from 76 → 116 handlers
(29 % → 31 %). Two flavours:

Compat-stub no-ops for subsystems v0 doesn't model:
`lstat`, `mremap`, `msync`, `mincore`, `pause`, `flock`, `chmod`,
`fchmod`, `chown`, `fchown`, `lchown`, `times`, `setuid`,
`setgid`, `setreuid`, `setregid`, `getgroups`, `setgroups`,
`setresuid`, `setresgid`, `getresuid`, `getresgid`, `setfsuid`,
`setfsgid`, `capget`, `capset`, `utime`, `mknod` (-EPERM),
`personality`, `getpriority`, `setpriority`, `mlock`, `munlock`,
`mlockall`, `munlockall`.

Real FAT32-backed FS ops:
`truncate` / `ftruncate` (Fat32TruncateAtPath),
`unlink` (Fat32DeleteAtPath),
`mkdir` (Fat32MkdirAtPath),
`rmdir` (Fat32RmdirAtPath).

### Batch 56 (33 handlers + NT bridge)

Lifted Linux coverage to 142 handlers (37 %).

Process/session/accounting: `ptrace` (-EPERM), `syslog`, `setsid`,
`vhangup`, `acct`, `mount`/`umount2` (-EPERM).

Cache flushing: `sync`, `syncfs` (no cache to flush in v0).

Rename/link family (no fat32 primitives yet): `rename`, `link`,
`symlink` all return -ENOSYS.

Thread-area (x86_32 LDT — 64-bit uses `arch_prctl`):
`set_thread_area`, `get_thread_area` return -EINVAL.

I/O & scheduling priority: `ioprio_get`, `ioprio_set`,
`sched_setaffinity`, `sched_getaffinity` (mask with CPU 0 only,
BSP-only in v0).

Clocks: `clock_getres` (10 ms), `clock_nanosleep` (routes to
`nanosleep`), `getcpu` (returns 0).

The *at family — mostly delegations to existing handlers when
`dirfd == AT_FDCWD`, -EBADF otherwise:
`mkdirat` → `mkdir`, `unlinkat` → `unlink`/`rmdir` by AT_REMOVEDIR,
`linkat` → `link`, `symlinkat` → `symlink`, `renameat`/`renameat2`
→ `rename`, `fchownat` → `chown`, `futimesat`/`utimensat` → 0,
`fchmodat` → `chmod`, `faccessat`/`faccessat2` → `access`.

### NT → Linux translator

New architectural bridge: user-mode Win32 / future ntdll.dll
code can forward any NT syscall through the kernel by way of the
new `SYS_NT_INVOKE` (native syscall number 46).

`rdi` carries the NT syscall number; `rsi`..`r9` carry up to
five NT-ABI arguments. The kernel routes them through
`subsystems::translation::NtTranslateToLinux(frame)`, which
dispatches to the matching Linux `Do*` helper and maps the POSIX
errno return back to an NTSTATUS.

Wired NT calls (ten), with their Linux fallback:

| NT call                          | Number  | Linux primitive            |
|----------------------------------|---------|----------------------------|
| NtClose                          | 0x000F  | `LinuxClose` (when fd-shaped) |
| NtYieldExecution                 | 0x0046  | `LinuxSchedYield`          |
| NtDelayExecution                 | 0x0034  | `sched::SchedSleepTicks`   |
| NtQueryPerformanceCounter        | 0x0031  | `LinuxNowNs`               |
| NtGetCurrentProcessorNumber      | 0x00DA  | synthetic zero (BSP-only)  |
| NtFlushBuffersFile               | 0x004B  | `LinuxFsync`               |
| NtGetTickCount                   | 0x0171  | `LinuxNowNs / 1_000_000`   |
| NtQuerySystemTime                | 0x005A  | `LinuxNowNs` → FILETIME    |
| NtTerminateThread                | 0x0053  | `LinuxExit` [[noreturn]]   |
| NtTerminateProcess               | 0x002C  | `LinuxExit` [[noreturn]]   |

Unwired NT calls return `STATUS_NOT_IMPLEMENTED` (0xC0000002)
and log one `[nt-translate-miss]` line at the same sampling
cadence as the Linux-miss path.

The `tools/win32-compat/gen-nt-shim.py` generator now understands
`SYS_NT_INVOKE` as a `duetos_sys` value, so four bedrock NT
calls in the generated NT mapping table (`NtFlushBuffersFile`,
`NtGetTickCount`, `NtGetCurrentProcessorNumber`,
`NtTerminateThread`) now report as covered.

### Extended public Linux API

Added to `subsystems::linux` for the NT translator:
`LinuxClose`, `LinuxOpen`, `LinuxLseek`, `LinuxFstat`,
`LinuxFsync`, `LinuxNanosleep`, `LinuxSchedYield`, `LinuxExit`
(`[[noreturn]]`), `LinuxGetPid`, `LinuxMmap`, `LinuxMunmap`,
`LinuxMprotect`.

All are thin wrappers over anonymous-namespace `Do*` helpers;
arg marshalling (NTSTATUS ↔ errno, FILE_HANDLE ↔ fd,
LARGE_INTEGER ↔ timespec) stays in the translator.

## Matrix deltas

| Metric                  | Before batch 55 | After batch 56 + NT |
|-------------------------|-----------------|---------------------|
| implemented             | 115             | 189                 |
| translated              | 42              | 45                  |
| unimplemented           | 756             | 680                 |
| Linux primary coverage  | 76 (20 %)       | 142 (37 %)          |
| NT bedrock coverage     | 25/292 (8 %)    | 28/292 (9 %)        |

## Pre-existing build-breakage fixed in scope

`main` did not build — the dispatcher referenced two generated
symbols the header never emitted, and `translate.cpp` called an
undefined helper. Both fixed as part of batch 55:

1. `tools/linux-compat/gen-linux-syscall-table.py` now emits
   `kLinuxSyscallHandlersImplementedPrimary` and
   `kLinuxSyscallHandlersImplementedEffective` alongside the
   single `kLinuxSyscallHandlersImplemented`.
2. `translate.cpp` gained a `DumpSuppressedMissSummary(origin,
   table)` helper that emits
   `[translate-miss-suppressed] <origin> cumulative=N delta=M
   emitted=K`.

## Files touched

- `kernel/subsystems/linux/syscall.cpp` — batches 55 + 56
  handlers + dispatch entries + Linux* wrapper exports.
- `kernel/subsystems/linux/syscall.h` — public API additions.
- `kernel/subsystems/translation/translate.cpp` —
  `DumpSuppressedMissSummary`, `NtTranslateToLinux`, NTSTATUS
  constants, per-NT translator helpers.
- `kernel/subsystems/translation/translate.h` — declare
  `NtTranslateToLinux`.
- `kernel/core/syscall.h` — `SYS_NT_INVOKE = 46`.
- `kernel/core/syscall.cpp` — dispatch case for `SYS_NT_INVOKE`.
- `tools/linux-compat/gen-linux-syscall-table.py` — emit
  `Primary`/`Effective` constants.
- `tools/win32-compat/gen-nt-shim.py` — four new NT→SYS_NT_INVOKE
  mappings.
- `kernel/subsystems/linux/linux_syscall_table_generated.h`,
  `kernel/subsystems/win32/nt_syscall_table_generated.h`,
  `docs/syscall-abi-matrix.{csv,md,json}` — regenerated.
