# Linux-ABI syscall subsystem

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — five on-boot smoke tasks demonstrating the full stack; 20 syscalls implemented

## Description

Peer of `subsystems/win32/`. Runs Linux ELF binaries natively on
CustomOS by routing the x86_64 `syscall` instruction into a
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
4. Entry stub pops TrapFrame → `iretq` (NOT sysret — CustomOS's
   GDT is incompatible with sysret's selector arithmetic)

## Implemented syscalls (as of 2026-04-22)

| # | Name | Status |
|---|------|--------|
| 0 | read | Real — file fds read from FAT32 via scratch+slice; stdin = EOF |
| 1 | write | Real — fd 1/2 to COM1; 4 KiB per-call cap |
| 2 | open | Real — FAT32-backed, per-process fd table |
| 3 | close | Real — releases fd slot |
| 8 | lseek | Real — file fds only; tty fds return -ESPIPE |
| 9 | mmap | Real — anonymous private only; bump-allocator at 0x7000_0000_0000 |
| 11 | munmap | Stub — returns 0, doesn't tear down pages |
| 12 | brk | Real — grows RW+NX pages on demand from Process::linux_brk_base |
| 13 | rt_sigaction | Stub — returns 0, no signal delivery wired |
| 14 | rt_sigprocmask | Stub — returns 0 |
| 16 | ioctl | Stub — returns -ENOTTY / -EBADF |
| 20 | writev | Real — iterates iovec array calling DoWrite |
| 39 | getpid | Real — returns Task ID |
| 60 | exit | Real — calls SchedExit |
| 63 | uname | Real — static CustomOS/customos/0.1/... strings |
| 102 | getuid | Stub — returns 0 |
| 104 | getgid | Stub — returns 0 |
| 107 | geteuid | Stub — returns 0 |
| 108 | getegid | Stub — returns 0 |
| 158 | arch_prctl | Real — ARCH_SET_FS / ARCH_GET_FS; GS rejected |
| 218 | set_tid_address | Stub — returns task ID, doesn't clear on exit |
| 231 | exit_group | Real — calls SchedExit |

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

After `ElfLoad`, populates the top 48 B of the stack page with:

```
offset  0: argc = 0        (u64)
offset  8: argv[0] = NULL  (u64)
offset 16: envp[0] = NULL  (u64)
offset 24: auxv[0].type = AT_NULL = 0
offset 32: auxv[0].val  = 0
offset 40: pad = 0
```

Sets `proc->user_rsp_init = stack_top - 48`. Real static-musl
wants more auxv entries (AT_PHDR, AT_PAGESZ, AT_RANDOM); v0
provides AT_NULL only since musl tolerates a minimal vector.

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

- **No FS_BASE save/restore on context switch.** v0 runs at most
  one Linux task at a time; OK for now. Adding it is per-Task
  `fs_base` field + scheduler mirror, same shape as `kernel_rsp`.
- **munmap doesn't tear down** — leaves pages mapped. Fine for
  short-lived tasks; AS teardown on process death reclaims.
- **Signals don't deliver** — rt_sigaction/rt_sigprocmask accept
  but are inert. No sigframe, no sigreturn.
- **File reads cap at 4 KiB** — DoRead reads whole file into
  scratch then slices. Larger files need a streamed
  read-with-offset helper in the FAT32 driver.
- **No write to files** — only read. Fat32WriteInPlace exists;
  wiring to sys_write on a file fd is its own slice.
- **No sys_stat / sys_fstat** — musl uses them for `isatty` /
  `fstat` probes; not required yet by any on-boot smoke.
- **No dynamic linking** — PT_INTERP is ignored. Only static
  binaries run.

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
