# Linux-ABI syscall subsystem

**Last updated:** 2026-04-22 (post slice 19)
**Type:** Observation
**Status:** Active — four on-boot smoke tasks demonstrating the full stack; 52 syscalls implemented

## Description

Peer of `subsystems/win32/`. Runs Linux ELF binaries natively on
DuetOS by routing the x86_64 `syscall` instruction into a
dedicated in-kernel dispatcher, parallel to the native int-0x80
path that Win32 PE binaries use.

A process's `Process::abi_flavor` field decides which entry path
its ring-3 `syscall` instructions reach:
  - `kAbiNative` (0): int 0x80 → `core::SyscallDispatch`
  - `kAbiLinux` (1): `syscall` instruction → `LinuxSyscallDispatch`
    via MSR_LSTAR

Loaders (PE loader, `SpawnElfFile`, `SpawnElfLinux`) set the flag
at spawn time. ELF OS-ABI sniffing is intentionally deferred —
callers decide explicitly.

## Layout

```
kernel/subsystems/linux/
  syscall.h         Public API (SyscallInit, LinuxSyscallDispatch)
  syscall.cpp       MSR setup + syscall dispatch + all handlers
  syscall_entry.S   GAS .intel_syntax asm stub (MSR_LSTAR target)
  ring3_smoke.h     SpawnRing3Linux{,Elf,File}Smoke declarations
  ring3_smoke.cpp   Three boot-time smoke payloads + spawners
```

## Entry sequence

1. `syscall` instruction from ring 3 → CPU jumps to MSR_LSTAR
2. `linux_syscall_entry` asm stub (`syscall_entry.S`):
   - `swapgs` (user GS → kernel GS via MSR_KERNEL_GS_BASE)
   - Save user RSP into `PerCpu::user_rsp_scratch`
   - Load kernel RSP from `PerCpu::kernel_rsp`
   - Build a TrapFrame matching the int-0x80 layout
   - Call `LinuxSyscallDispatch(frame)`
3. C++ dispatcher switches on `frame->rax`, populates
   `frame->rax` with the return value
4. Entry stub pops TrapFrame → `iretq` (NOT sysret — DuetOS's
   GDT is incompatible with sysret's selector arithmetic)

## Implemented syscalls (as of slice 19)

| #   | Name             | Status                                                        |
|-----|------------------|---------------------------------------------------------------|
| 0   | read             | Real — file fds from FAT32 via scratch+slice; stdin = EOF     |
| 1   | write            | Real — fd 1/2 → COM1; file fds → in-place + extend-via-append |
| 2   | open             | Real — FAT32-backed, per-process fd table                     |
| 3   | close            | Real — releases fd slot                                       |
| 4   | stat             | Real — Fat32LookupPath + 144 B stat struct                    |
| 5   | fstat            | Real — from fd's cached entry; tty fds → S_IFCHR              |
| 6   | lstat            | Aliases stat (no symlinks)                                    |
| 8   | lseek            | Real — file fds only; tty fds return -ESPIPE                  |
| 9   | mmap             | Real — anonymous private only; bump-allocator                 |
| 10  | mprotect         | Stub — returns 0 (all user pages are RW+NX already)           |
| 11  | munmap           | Stub — returns 0, doesn't tear down pages                     |
| 12  | brk              | Real — grows RW+NX pages from Process::linux_brk_base         |
| 13  | rt_sigaction     | Stub — returns 0, no signal delivery wired                    |
| 14  | rt_sigprocmask   | Stub — returns 0                                              |
| 15  | rt_sigreturn     | Kills on entry — no signal frame to unwind                    |
| 16  | ioctl            | Stub — returns -ENOTTY / -EBADF                               |
| 17  | pread64          | Real — save-restore offset around DoRead                      |
| 18  | pwrite64         | Real — save-restore offset around DoWrite                     |
| 20  | writev           | Real — iterates iovec array calling DoWrite                   |
| 21  | access           | Real — Fat32LookupPath presence probe                         |
| 24  | sched_yield      | Real — passes through to sched::SchedYield                    |
| 32  | dup              | Real — copies fd state into lowest free slot                  |
| 33  | dup2             | Real — overwrites target slot with source's state             |
| 35  | nanosleep        | Real — rounds up to scheduler ticks, SchedSleepTicks          |
| 39  | getpid           | Real — returns Task ID                                        |
| 60  | exit             | Real — calls SchedExit                                        |
| 62  | kill             | Self-only — SchedExit; other pids return -ESRCH               |
| 63  | uname            | Real — static DuetOS / duetos / 0.1 / ...                 |
| 72  | fcntl            | Real — F_DUPFD / F_GETFD / F_SETFD / F_GETFL / F_SETFL        |
| 79  | getcwd           | Stub — returns "/" always                                     |
| 80  | chdir            | Stub — returns 0 (no per-process cwd)                         |
| 81  | fchdir           | Stub — returns 0                                              |
| 89  | readlink         | Stub — returns -EINVAL (no symlinks)                          |
| 102 | getuid           | Stub — returns 0                                              |
| 104 | getgid           | Stub — returns 0                                              |
| 107 | geteuid          | Stub — returns 0                                              |
| 108 | getegid          | Stub — returns 0                                              |
| 109 | setpgid          | Stub — returns 0                                              |
| 110 | getppid          | Stub — returns 1 (init-like)                                  |
| 121 | getpgid          | Stub — returns 0                                              |
| 124 | getsid           | Stub — returns 0                                              |
| 131 | sigaltstack      | Stub — returns 0 (no signal delivery)                         |
| 158 | arch_prctl       | Real — ARCH_SET_FS / ARCH_GET_FS; GS rejected                 |
| 186 | gettid           | Real — returns Task ID (v0 tid == pid)                        |
| 201 | time             | Real — seconds-since-boot via HPET                            |
| 202 | futex            | Stub — returns 0 (no contention for single-threaded)          |
| 218 | set_tid_address  | Stub — returns task ID, no CLONE_CHILD_CLEARTID               |
| 228 | clock_gettime    | Real — HPET-backed; all clocks monotonic-since-boot           |
| 231 | exit_group       | Real — calls SchedExit                                        |
| 234 | tgkill           | Self-only — SchedExit; other tids return -ESRCH               |
| 318 | getrandom        | Non-crypto — xorshift64 seeded from rdtsc, capped at 4 KiB    |

Unknown syscalls return -ENOSYS with a log line identifying the
number. Extend the `switch` in `LinuxSyscallDispatch` as new
workloads surface missing ones.

## Per-process state

Added to `core::Process`:
- `u8 abi_flavor` — Native/Linux selector
- `u64 user_rsp_init` — override rsp at ring-3 entry (used for
  argc/argv/envp/auxv setup)
- `u64 linux_brk_base` / `linux_brk_current` — heap anchor +
  grow cursor
- `u64 linux_mmap_cursor` — anonymous-mmap bump allocator
- `LinuxFd linux_fds[16]` — per-process fd table; slots 0-2
  reserved for tty, 3+ for files (first_cluster + size + offset)

Per-CPU (shared with entry stub via well-known offsets in
`cpu/percpu.h`):
- `u64 kernel_rsp` — scheduler updates on task switch
- `u64 user_rsp_scratch` — entry stub's rsp-swap slot

## Initial stack layout (SpawnElfLinux)

After `ElfLoad`, populates the top 96 B of the stack page with:

```
offset  0: argc = 0                    (u64)
offset  8: argv[0] = NULL              (u64 — argv terminator)
offset 16: envp[0] = NULL              (u64 — envp terminator)
offset 24: AT_PAGESZ = 6                (u64 — auxv key)
offset 32: 4096                          (u64 — auxv val)
offset 40: AT_RANDOM = 25                (u64 — auxv key)
offset 48: rand_ptr = rsp_init + 72    (u64 — auxv val: user VA)
offset 56: AT_NULL = 0                  (u64 — auxv terminator key)
offset 64: 0                             (u64 — auxv terminator val)
offset 72: 16 B xorshift-mixed rdtsc entropy
offset 88: 8 B pad
```

Sets `proc->user_rsp_init = stack_top - 96`. AT_PHDR / AT_EXECFN
are NOT supplied — musl falls back to reading the ELF's own
headers for program-header info, which works for static binaries.
Dynamic linking (PT_INTERP resolution) would need AT_PHDR +
AT_BASE + AT_ENTRY additionally.

## Boot-time smoke tasks

Every boot runs four Linux-ABI ring-3 tasks in sequence:

1. **linux-smoke** (hand-crafted AS, 14-byte payload):
   ```
   MOK
   hello linux!
   [linux] exit_group status=0x42
   ```
2. **linux-elf-smoke** (in-memory ELF via SpawnElfLinux): same
   output, different spawn path.
3. **fat-linux-elf** (reads `/fat/LINUX.ELF` from FAT32):
   ```
   [boot] Spawning /fat/LINUX.ELF via SpawnElfLinux.
   MOK
   hello fat32!
   ```
4. **linux-file-smoke** (exercises open/read/close):
   ```
   hello from fat32
   ABCDEFGHIJKLMNOdone
   ```

Five Linux-ABI tasks total — plus any on-demand `linuxexec` from
the shell.

## Known gaps

- **munmap doesn't tear down** — leaves pages mapped. Fine for
  short-lived tasks; AS teardown on process death reclaims.
- **Signals don't deliver** — rt_sigaction/rt_sigprocmask accept
  but are inert. No sigframe, no sigreturn. A real impl would
  add IRQ-return-path signal injection + a user-mode trampoline
  that sysrets back through sigreturn (which we'd then wire to
  a real unwind rather than the current "exit on entry").
- **File I/O caps at 4 KiB** — DoRead reads whole file into
  scratch then slices. DoWrite (file fds) limits single-call
  size. Larger files need a streamed read-with-offset helper
  in the FAT32 driver.
- **Calendar time is boot-relative.** clock_gettime returns
  monotonic ns since boot for every clock id. Needs RTC driver
  locking for real epoch time.
- **futex is a no-op** — fine for single-threaded, broken once
  a multi-thread workload actually contends.
- **No dynamic linking** — PT_INTERP is ignored. Only static
  binaries run.
- **No getdents64** — directory enumeration. Needs the fd table
  to accept directory handles (state=3) + Fat32ListDirByCluster
  serialization.
- **dup/dup2 copy the fd rather than sharing it.** Two fds
  backing "the same file" end up with independent offsets.
  Matters for programs that rely on shared-description
  semantics (e.g. stdio redirection patterns).
- **clone / fork / vfork / thread creation** — absent. A
  dedicated slice per primitive; clone() is the biggest
  architectural piece remaining on the Linux-ABI todo.
- **Cryptographic getrandom** — the stream is xorshift64 from
  rdtsc. Good for stack cookies + pointer mangling; NOT
  suitable for seeding TLS / session keys. Needs a real RNG
  driver + entropy source.

## Fixed since last session (2026-04-22 autopilot)

- **Per-task FS_BASE save/restore.** Scheduler now rdmsr's
  FS_BASE before ContextSwitch and wrmsr's the incoming task's
  after. See sched.cpp's `Schedule()`. Unblocks running multiple
  Linux tasks with independent TLS.
- **sys_write extends files** via Fat32AppendAtPath when the
  write crosses past EOF. Requires `char path[64]` on each
  LinuxFd — stored at open() time.
- **SpawnElfFile auto-detects ELFOSABI_LINUX** (byte 7 == 3)
  and routes to SpawnElfLinux. Only catches binaries explicitly
  marked Linux; SYSV-marked binaries (the common case) still go
  through the native path.

## How to add a new syscall

1. Add the number to the `enum : u64` in syscall.cpp.
2. Write `DoX(args)` helper returning `i64`.
3. Add a `case` arm in the dispatch switch.
4. For any new errno, add the constant near the existing set.
5. If it needs Process state, add the field + init it in
   `ProcessCreate`.

## How to run a Linux binary

From shell:
```
linuxexec /fat/SOMEFILE.ELF
```

From kernel code:
```cpp
core::SpawnElfLinux(name, bytes, len, caps, root, frame_budget,
                    tick_budget);
```

Either path sets `abi_flavor = kAbiLinux` and seeds the heap/mmap
anchors so syscalls from the loaded image route through the Linux
dispatcher.

## References

- `kernel/subsystems/linux/syscall.{h,cpp,_entry.S}` — core
- `kernel/core/ring3_smoke.cpp::SpawnElfLinux` — loader entry
- `kernel/core/process.h` — Process fields
- `kernel/cpu/percpu.h` — per-CPU layout
- `tools/qemu/make-gpt-image.py` — `/fat/LINUX.ELF` seed
- `.claude/knowledge/security-guard.md` — image-load gate that
  every ELF still traverses
