# Linux ABI app coverage — pattern + first-slice findings

**Type:** Pattern + Observation + Issue (consolidated)
**Status:** Active — single source for "compile and run a Linux ELF, see what fails" workflow
**Last updated:** 2026-05-02

## What this captures

The first session-driven attempt to "write Linux apps that target every
syscall, run them, see failures, fill them in" — the resulting workflow,
the bugs the failure inventory caught, and the surgical fixes that landed.

## Workflow (use this every future session)

1. **Build the failure inventory binary**: `userland/apps/synxtest/synxtest.c`
   is a freestanding static C ELF that issues each Linux syscall and
   prints `[exe] <name> rc=<rc>` (or `ok`/`FAIL`) per call. Source +
   build script (`tools/build/build-synxtest.sh`) + CMake wiring
   (`duetos_embed_blob(generated_synxtest_elf.h …)` in `kernel/CMakeLists.txt`)
   regenerate the embedded ELF on every build.
2. **Run under `DUETOS_SMOKE_PROFILE=linux`**: synxtest is hoisted out of the
   `profile==None && !IsEmulator()` gate in `kernel/core/main.cpp` so it
   runs under TCG-on-emulator too. Bounded — single ELF, single exit. The
   other 5 Linux smokes (Elf/File/Mmap/Translate/Extend) stay gated on
   bare-metal because they cumulatively burn ~50s of guest time.
3. **Collect**: `DUETOS_SMOKE_PROFILE=linux DUETOS_TIMEOUT=60 tools/qemu/run.sh > log; grep '^\[exe\]' log`.
   Each line is one syscall verdict.
4. **Fix top failures**, re-run, iterate. The non-fragmented `[exe]` lines
   each carry the syscall name (informally), so unexpected rc surfaces
   quickly.

## Build flag invariants for any Linux-ABI exerciser ELF

When adding a new freestanding Linux test app, mirror `build-synxtest.sh`:

- `--target=x86_64-unknown-none-elf` — bare metal, no host libc
- `-ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone` — kernel-loader-friendly
- `-fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables` — no
  hidden CRT calls
- **`-mno-sse -mno-sse2 -mno-mmx -mgeneral-regs-only`** — **critical**.
  Without these, clang emits `movaps %xmm0, (mem)` for stack zero-init of
  `char buf[N] = {0}`. The DuetOS kernel doesn't enable CR4.OSFXSR or wire
  per-thread #NM handling for user threads, so the first such instruction
  takes #GP and the task-killer logs:

      [task-kill] ring-3 task took #GP
        rip : 0x4005f7   (movaps %xmm0,(%rsi))

  Symptom is that the test binary runs ~3 lines and dies. Easy to diagnose
  with `objdump -d <elf> | grep -B2 <rip>`.
- Ship a tiny inline `memset` / `memcpy` in the source (clang implicitly
  emits calls to these even with `-fno-builtin`, for compound zero-init).

## First-slice findings (2026-05-02)

### Latent broken-control-flow in 2 ring3 smokes

`kernel/subsystems/linux/ring3_smoke.cpp` — both
`SpawnRing3LinuxTranslateSmoke` and `SpawnRing3LinuxExtendSmoke` had three
unbraced single-statement guards each, of the shape:

    if (foo == nullptr)
        DebugPanicOrWarn(…);
    return;

The bare `return;` fired unconditionally — both smokes were dead-on-arrival
even though `main.cpp` dispatched to them on bare-metal boots. Fix was
just adding the missing braces; the working sister smokes
(`SpawnRing3LinuxFileSmoke` / `SpawnRing3LinuxMmapSmoke` /
`SpawnRing3LinuxSmoke`) had been carrying the right pattern.

**Lesson**: any function written in a hurry that uses single-statement
ifs is a candidate for this bug. Run the smokes occasionally to catch
regressions of this shape — the `Spawn` wrapper is silent on dead-on-arrival.

### `getpid()` returned task tid, not Process pid

`subsystems/linux/syscall_proc.cpp` — `DoGetPid` returned
`sched::CurrentTaskId()`, but `SchedFindProcessByPid` resolves against
`Process::pid` — a separate counter. For sandboxed tasks the two diverge
(synxtest came up with `Process->pid=0x83`, `Task->id=0x99`).

Symptom: `pidfd_open(getpid())` came back `-ESRCH`. Anything else that
uses `getpid()` and then resolves it via `SchedFindProcessByPid` (kill,
tgkill, prlimit64 with pid != 0, …) was silently broken on sandboxed
tasks.

Fix: `DoGetPid()` returns `CurrentProcess()->pid`, falling back to
`CurrentTaskId()` only if there's no current process. `DoGetTid` stays
on `CurrentTaskId()` (correct Linux semantic for the per-thread ID).

### `getdents64` conflated `-EBADF` and `-ENOTDIR`

`subsystems/linux/syscall_misc.cpp` — guard returned `-EBADF` for both
"fd out of range / unused slot" and "fd is valid but not a dirfd".
Linux distinguishes them: `getdents64` on a valid regular file / pipe /
socket returns `-ENOTDIR` (-20), `-EBADF` only when the fd doesn't refer
to anything.

Fix: split the guard, added `kENOTDIR = -20` to `syscall_internal.h`.

## Resulting `[exe]` matrix (post-fixes)

Sandboxed (caps=`<none>`) synxtest run; `ok` / `rc=N` listed:

**Real implementations passing**: getpid, gettid, clock_gettime, uname,
getrandom, mmap anon, open + fstat + pread + mmap file + close, sched_yield,
writev, gettimeofday, sysinfo, prlimit64, madvise, getppid, getuid, getgid,
openat, newfstatat (AT_EMPTY_PATH + path), dup3, dup, dup2, fcntl,
brk, mprotect, munmap, getrusage, poll, select, set_robust_list,
pipe(create + write + read), eventfd2 + read, timerfd_create,
epoll_create1 + epoll_wait, signalfd4, inotify_init1 + add_watch + rm_watch,
**pidfd_open(self)**, memfd_create, statx, chdir, rt_sigprocmask, sigaltstack,
futex(WAKE).

**Sandbox-denied (correct, by design)**: socket (-EACCES, no kCapNet),
fork/vfork/clone(0)/execve (-EPERM, no kCapSpawnThread).

**Documented facades returning -ENOSYS**: userfaultfd, io_uring_setup,
landlock_create_ruleset.

**Unprivileged-Linux equivalents (-EPERM)**: bpf, perf_event_open, mount,
ptrace.

**Linux-correct edge returns**: getdents64 (-ENOTDIR on regular file),
readlink (-EINVAL on non-symlink), rseq (-ENOSYS via the translation TU).

## When extending synxtest

- Synxtest is one coherent file (`_start` → linear flow). 599 lines is
  fine; the per-file 500-line guideline is a "pause and think" prompt,
  not a hard cap. Splitting would add machinery (one ELF per file →
  multiple embed-blob entries → multiple SchedCreateUser sites) without
  reducing complexity.
- Use the existing `FMTI` macro for any rc-printing test — it's the
  reusable inline decimal formatter at the top of `_start`.
- Group new tests into tiers ("=== tier N: <theme> ==="), and aim for
  one syscall (or one round-trip) per `[exe]` line.
- Round-trip tests beat single-call tests: pipe + write + read >
  pipe alone; eventfd + read > eventfd alone. Round-trips catch bugs
  the guard alone misses.

## When forking new exerciser binaries

Reasons to add a sibling binary instead of expanding synxtest:

- It needs different caps (e.g. `kCapNet` to exercise sockets, or
  `kCapSpawnThread` to exercise fork). Caps are per-Process, set at
  spawn time.
- It needs a different sandbox root (e.g. networking app needs the
  fat32 root, GUI app needs framebuffer). One-Process-one-RamfsRoot.
- It needs to interact with another process (sender/receiver test —
  two binaries).
- It would otherwise grow synxtest past 600+ lines without coverage gains.

When you do, mirror the embed pipeline: `tools/build/build-<name>.sh`
+ `duetos_embed_blob(generated_<name>_elf.h …)` + a Spawn helper in
`kernel/subsystems/linux/ring3_smoke.{h,cpp}` + a dispatch site in
`kernel/core/main.cpp`. Force-add the build script (`git add -f`)
because `tools/build/` matches the repo-wide `build/` ignore pattern.

## Second-slice findings — synfs (kCapFsRead+Write FS-mut exerciser)

Same workflow, different cap set. `userland/apps/synfs/synfs.c` is
spawned with `kCapFsRead | kCapFsWrite` so each FS mutation actually
reaches the kernel handler. Targets ~30 FS-mut syscalls: access (4
forms), statfs / fstatfs, mkdir / rmdir + dup calls, openat(O_CREAT),
write, ftruncate (shrink+grow), fchmod / fchown / fsync / fdatasync,
chmod / chown / truncate, utimensat, rename / renameat2,
copy_file_range, unlink (3 forms), unlinkat(AT_REMOVEDIR), sync /
syncfs, mknod, link, symlink.

### Output convention diverges from synxtest

Synxtest's TAG-then-FMTI pattern leaves a syscall (and its kernel
logs) BETWEEN the prefix and the rc, so on a busy serial port the rc
lands on a separate line from the `[exe]` prefix and `^\[exe\]` greps
miss it. Synfs uses `report_rc(label, v)` to build the entire
`[fs] <label> rc=<v>\n` line in one buffer and writes it with a
single `sc3(SYS_write)` — atomic-line writes side-step the whole
class of interleaving. Future exercisers should adopt this pattern.

### Bugs the synfs inventory caught

1. **`DoOpen()` ignored its `flags`** (`(void)flags;`) —
   `openat(SYNFS.TMP, O_WRONLY|O_CREAT, 0644)` returned -ENOENT
   instead of creating. Cascaded ~10 follow-on tests to -2/-5.

2. **`Fat32AppendAtPath` refuses zero-byte files** (fat32_write.cpp
   `first_cluster<2` guards). The "obvious" fix — Fat32CreateAtPath
   with len=0 on O_CREAT — is a trap because the next write hits the
   AppendInDir rejection. Combined fix: don't materialise on O_CREAT;
   add a per-fd `flags` byte on `Process::LinuxFd` with
   `kLinuxFdFlagPendingCreate` (0x01); DoWrite's extend branch routes
   the FIRST extending write through Fat32CreateAtPath instead, then
   clears the flag and re-looks-up the entry to populate
   first_cluster for subsequent in-bounds writes.

3. **`Fat32{Mkdir,Rmdir}AtPath` collapse every error to bool false**
   — DoMkdir / DoRmdir mapped to `-EIO` for every failure. Fixed by
   probing with Fat32LookupPath first:
   - mkdir: lookup-exists -> -EEXIST. !lookup && !mkdir -> -EIO.
   - rmdir: !lookup -> -ENOENT. lookup-not-dir -> -ENOTDIR.
     lookup-but-rmdir-fails -> -ENOTEMPTY (best-effort).
   Added `kEEXIST=-17`, `kENOTEMPTY=-39`, `kEFBIG=-27` to
   `syscall_internal.h`.

4. **`copy_file_range` returned -EFAULT** even with two valid fds.
   `DoCopyFileRange` used DoRead/DoWrite as kernel helpers with a
   KMalloc'd bounce buffer; CopyToUser/CopyFromUser inside reject
   kernel-direct-map VAs. Rewrote to call Fat32ReadFile +
   Fat32CreateAtPath / Fat32AppendAtPath directly on a kernel buffer,
   no user-VA validation involved. Threaded pending-create resolution
   into the dst path. Sub-GAP: src reads start from offset 0 every
   iteration (Fat32ReadFile is no-offset; v0 caps stage at 4 KiB so
   prefix-then-slice works for small files; larger files get -EFBIG).

### Resulting `[fs]` matrix (post-fixes)

Passing: access (4 forms), statfs/fstatfs, mkdir+duplicate, rmdir+
non-existent (correct errnos), openat(O_CREAT)+write+ftruncate+
fchmod/fchown/fsync/fdatasync, chmod/chown/truncate/utimensat,
rename/renameat2, copy_file_range, unlink (3 forms),
unlinkat(AT_REMOVEDIR), sync/syncfs. Honest unprivileged: mknod
(-EPERM). Facades: link/symlink (-ENOSYS).

## Third-slice findings — synet (kCapNet socket exerciser)

`userland/apps/synet/synet.c` — third Linux-ABI exerciser. Same
freestanding-ELF pipeline + atomic-line-write convention, but spawned
with `kCapNet` so socket-family syscalls reach their handler instead
of bouncing off the dispatch-level kCapNet cap gate. Targets ~20
socket calls: socket() across the AF/SOCK matrix
(INET/UNIX/INET6 × STREAM/DGRAM/RAW), bind, listen, getsockname,
getpeername (unconnected -> -ENOTCONN), sendto,
recvfrom(MSG_DONTWAIT), setsockopt + getsockopt(SO_REUSEADDR) round-
trip, shutdown, close, socketpair, sendmsg.

### Bug caught

**`DoRecvfrom` ignored its `flags` argument** (`(void)flags;`) so
MSG_DONTWAIT (0x40) didn't propagate. Synet's first non-block recv
HUNG the boot — `SocketRecvDgram` blocks on `read_wq` when
`udp_count==0`. Fixed by peeking `s->udp_count` before the call:
return -EAGAIN when MSG_DONTWAIT && empty && !SHUT_RD. For
SOCK_STREAM, short-circuit non-block when !connected or SHUT_RD;
the connected-but-no-data path is a sub-GAP until a public
"stream rx available" probe exists.

### Workflow gap caught (not a code bug)

`connect()` to a port with no listener spins
`SocketConnect`'s slot-acquire + SYN-retry + handshake-wait loops
for ~3s total because the v0 TCP active-connect machine has no
fast-fail "peer never answered" path. Synet skips connect() — the
kernel's own net-smoke proves the connect path against a real peer.
This is the "scope of test ≠ scope of API" rule: synet's role is to
prove the syscall surface is wired, not to re-prove the TCP state
machine.

### Resulting `[net]` matrix

Real implementations: socket(INET/STREAM,DGRAM), bind, listen,
getsockname, sendto (returned bytes), recvfrom(MSG_DONTWAIT)
-> -EAGAIN, setsockopt + getsockopt(SO_REUSEADDR), shutdown, close,
sendmsg.

Honest unsupported: socket(INET/RAW) -> -EPROTONOSUPPORT(-93);
socket(UNIX/STREAM) -> -EAFNOSUPPORT(-97); socket(INET6/DGRAM)
-> -EAFNOSUPPORT(-97); socketpair(UNIX) -> -EOPNOTSUPP(-95);
getpeername(unconnected) -> -ENOTCONN(-107).

## Fourth-slice findings — dense ABI dispatch table

After three slice-driven exerciser passes (synxtest / synfs / synet),
the dispatcher still relied on `LinuxGapFill` + the kENOSYS default
to absorb syscall numbers we don't implement. The "did we forget X?"
audit was an open-ended scan. Closed by inserting an explicit
`kSysEnosys_<Name>` constant + dispatch case for every Linux x86_64
syscall the CSV covers (374 total).

### Naming convention for "spec-defined, intentionally not implemented"

Constants for unimplemented spec syscalls use the form
`kSysEnosys_<PascalName>` (e.g. `kSysEnosys_Setxattr`,
`kSysEnosys_FutexWaitv`). The `Enosys_` prefix is a grep target —
a future slice implementing a real handler renames the constant
back to its canonical form (`kSysSetxattr`), moves the case out of
the ENOSYS group, and points it at the new `Do<Name>` handler. The
prefix prevents the case from being silently re-promoted by accident.

### Generator gotcha — syscall handlers are sharded

`tools/linux-compat/gen-linux-syscall-table.py` originally scanned
just `syscall.cpp` for `i64 Do<Name>(...)` bodies. The codebase has
since split handlers across `syscall_<family>.cpp` peers
(syscall_socket.cpp, syscall_fd.cpp, syscall_pipe.cpp, ...). The old
"single-file" rule reported 0 primary handlers — wildly wrong. The
fixed rule: glob `syscall*.cpp` in the same directory as the
dispatcher. After the fix the manifest reports 194 primary / 201
effective / 374 total = 51% / 53% coverage.

### When NOT to add a handler

If a syscall has no plausible mapping to a DuetOS primitive
(`kSysEnosys_AfsSyscall`, `kSysEnosys_Tuxcall`, `kSysEnosys_Vserver`,
the older `kSysEnosys_TimerCreate` family that we don't intend to
support), leaving the constant in the ENOSYS group IS the answer.
The ENOSYS path is a contract: real Linux ELFs that call these
deprecated/dead syscalls expect -ENOSYS. The audit signal is "is
the kSys constant present?" — Yes for every spec syscall, even the
zombies. The implementation signal is "is it in the ENOSYS block?"
— Yes for the ~180 unimplemented entries.

## Fifth-slice findings — syscall_aux.cpp (70 new handlers)

Followed the dense-dispatch slice with three back-to-back batches in
a new TU `kernel/subsystems/linux/syscall_aux.cpp`. The TU's name
deliberately advertises "this is not a new subsystem — it's a thin
compatibility surface". Coverage went 51% → 70% primary in three
commits.

### Batch shapes (the four kinds of aux handlers)

1. **Route-through to existing scalar Do<Name>**: tkill→tgkill,
   mknodat→mknod (AT_FDCWD only), readlinkat→readlink, utimes→
   utimensat, rt_tgsigqueueinfo→tgkill (drops siginfo),
   creat→open(O_CREAT|O_WRONLY|O_TRUNC).
2. **Vector form of an existing scalar**: preadv/pwritev (loop
   over user iovec, calling pread64/pwrite64 with running offset);
   preadv2/pwritev2 (same but ignore RWF_* flags).
3. **Trivial-but-correct stub**: alarm/getitimer/setitimer (zero
   itimerval, rc=0); membarrier(QUERY)→0; mlock2→0;
   fallocate(mode==0)→0; sync_file_range→DoSync; fchmodat2→
   fchmodat (flags pass-through).
4. **Spec-correct errno over -ENOSYS**: xattr family →
   -EOPNOTSUPP (-95); namespaces → -EINVAL or -ESRCH; LDT →
   -ENOSYS only for non-zero func; cross-process VM → -ESRCH;
   POSIX timer ops on never-created timerids → -EINVAL;
   restart_syscall → -EINTR.

### Why -EOPNOTSUPP, not -ENOSYS, for xattr

Linux's documented behaviour for an FS without xattr storage is
-EOPNOTSUPP, not -ENOSYS. Picking the right errno matters:
libacl/libcap/attr handle -EOPNOTSUPP gracefully (treat the file
as having no attrs and continue); -ENOSYS makes them think the
host kernel is exotic and bail. Same logic applies to
cross-process VM (-ESRCH means "no such pid") and namespaces
(-EINVAL means "not a namespace fd"). The general principle:
return the errno that says "feature recognised, target doesn't
have one" rather than "syscall not recognised at all" wherever
the userspace fallback is documented.

### Pattern: Linux 5.16+ extended futex deserves -ENOSYS

futex_waitv/wake/wait/requeue (449/454/455/456) are 5.16+ extended
ops. glibc/musl probe via /proc/sys/kernel/futex_* (which we don't
expose) and fall back to classic futex(2) (which we DO
implement). Returning -ENOSYS keeps the fallback path alive. This
is a place where -ENOSYS is genuinely correct, not a placeholder.

### When NOT to keep adding handlers

The remaining ~14 ENOSYS-block entries are all genuinely deprecated /
never-released Linux syscalls (afs_syscall, tuxcall, getpmsg/putpmsg,
nfsservctl, security, vserver, ustat, sysfs, sysctl, modify_ldt,
lookup_dcookie, create_module/get_kernel_syms/query_module). Mainline
Linux returns -ENOSYS for these too. Adding handlers would be wrong:
the spec contract IS -ENOSYS.

### Generator gotcha — second pass

After re-running gen-linux-syscall-table.py post-batches, primary
went 51 → 57 → 63 → 70%. The script counts a syscall as
"Implemented" iff a Do<Name> body exists in any syscall*.cpp peer.
That's correct now (after the multi-TU scan fix in slice 4). New
handlers in syscall_aux.cpp pick up automatically.

### Manifest after fifth slice

374 total / 264 primary (70%) / 270 effective (72%) / 110
unimplemented. The remaining 110 unimplemented split into:
- ~14 hand-written ENOSYS-block entries (deprecated)
- ~96 syscalls reachable only via the LinuxGapFill path or whose
  dispatch case calls something other than `Do<Name>` (fall-back
  handlers, cap-gated -EPERM cases, etc.). The manifest counts
  these as "Unimplemented" because no `Do<Name>` body exists, but
  the dispatch DOES handle them — see kSysReboot, kSysIopl,
  kSysIoperm, kSysQuotactl, etc. that return -EPERM directly.

## Sixth-slice findings — synfull exhaustive exerciser + bug hunt

`userland/apps/synfull/synfull.c` — fourth Linux-ABI exerciser.
Issues every spec syscall in 0..462 with all-zero args, prints
`[full] <nr>=<rc>` per call. Atomic-line writes. Spawned with
kCapFsRead + FsWrite + Net + SpawnThread so cap-gated calls
reach their handler.

### Skip-list (15 entries)

Process-destructive (clone/fork/exec/exit/kill/tkill/tgkill/
rt_sigqueueinfo/rt_tgsigqueueinfo) + state-destructive (mmap/
munmap/brk/mremap/arch_prctl/set_tid_address/set_thread_area/
get_thread_area) + module-load (init_module/finit_module/
delete_module/kexec_load/kexec_file_load) + blocking-on-signal
(pause/rt_sigsuspend/rt_sigtimedwait) + ptrace + reboot.

`rt_sigreturn` (15) is also skipped — it terminates the task
when called outside a signal handler (kernel behaviour is
correct; can't issue from a synthetic exerciser).

`wait4` (61) and `waitid` (247) were originally in the
skip-list but the kernel was the bug — now fixed (see below).

### Bugs caught + fixed by synfull

1. **wait4 / waitid blocked when no children exist.** Kernel
   was waiting on linux_wait_wq forever. POSIX rule: no
   children at all -> -ECHILD immediately, regardless of
   WNOHANG. Fix: check sched::SchedCountChildrenOfPid(self)
   after empty exit-queue, return -ECHILD if zero.

2. **fchdir on non-directory fd returned -EINVAL.** POSIX
   says -ENOTDIR. Fix: check `state == 11` (FAT32 dir)
   upfront; anything else (tty/file/pipe/eventfd/socket/
   pidfd) gets -ENOTDIR.

3. **vhangup() returned 0.** Linux requires CAP_SYS_TTY_CONFIG;
   unprivileged callers see -EPERM. We don't model that
   capability so unconditional -EPERM matches Linux's
   user-visible behaviour.

4. **pidfd_open(0, 0) returned -ESRCH.** POSIX rule: pid==0
   (and any negative pid) is invalid input — return -EINVAL
   before the process lookup.

5. **utimensat(AT_FDCWD, NULL, ...) returned 0.** AT_FDCWD with
   NULL path is invalid in Linux (futimens semantics need a
   real fd). Fix: -EFAULT for AT_FDCWD-with-NULL-path,
   -EBADF for invalid dirfd, success only for the actual
   futimens path.

6. **time(NULL) returned 30 (seconds-since-boot).** g_realtime_
   offset_ns started at 0 and was only set by clock_settime
   (which needs CAP_SYS_TIME). Fix: lazy-seed on first
   RealtimeNs() call from time::RealtimeFiletime() (CMOS RTC
   sample, FILETIME epoch). Now `time(NULL) = 1777745989`
   (real May-2026 epoch second).

### Real implementations added in this slice

- **recvmmsg (299)** — vector recvmsg in syscall_socket.cpp.
- **sendmmsg (307)** — vector sendmsg in syscall_socket.cpp.
- **clone3 (435)** — moved out of inline syscall.cpp dispatch
  into syscall_clone.cpp; reads struct clone_args, routes to
  DoClone. (Previous inline impl removed.)

### errno corrections

- **link (86) / symlink (88)** moved from -ENOSYS to
  -EOPNOTSUPP (FS-doesn't-support-this is the right errno;
  glibc/musl handle EOPNOTSUPP by falling back to copy-then-
  rename, ENOSYS makes them think the host is exotic).

### Final synfull matrix (after this slice)

463 calls total. Distribution:
- 139 `-ENOSYS` (-38) — 89 are reserved-range gaps in spec
  (335..423) where no syscall exists; the other 50 are
  documented aux entries (deprecated / no-infra / 5.16+
  fallback).
- 97 success (0) — real handlers running.
- 54 `-EBADF` (-9) — NULL fd rejected (handler ran).
- 52 `-EFAULT` (-14) — NULL ptr rejected (handler ran).
- 35 skip — exerciser skip-list.
- 31 `-EINVAL` (-22) — bad args (handler ran).
- 24 `-EPERM` (-1) — root-cap needed (mknod / chroot /
  mount / settimeofday / clock_settime / etc — correct).
- Long tail: small-positive (real fds / pids / tids /
  msgids / sizes from getpid / gettid / getppid / times /
  msgget / keyctl / dup / fcntl / umask / inotify_init /
  eventfd / timerfd_create / epoll_create / fanotify_init /
  memfd_create), 2 `-ECHILD` (wait4 / waitid after fix),
  2 `-ENOSPC` (shmget / semget — sysv ipc full), 2
  `-ENOTDIR` (getdents / getdents64 on non-dir), 3 `-ESRCH`
  (process_vm_readv / writev — cap not modelled).

### Translation TU clean-up

LinuxGapFill in `kernel/subsystems/translation/translate.cpp`
became dead code once primary dispatch went dense. Removed
the symbol from `translate.h`, `#if 0`'d the function body
plus its four helpers (TranslateUmask / TranslateStatfs /
TranslateDeliberateEnosys / TranslateRseq) in translate.cpp.
NativeGapFill + NtTranslateToLinux still live (used by the
DuetOS-native + Win32-NT dispatchers).

## Cross-references

- `.claude/knowledge/subsystems-status.md` — top-level Linux ABI inventory
  (keep this file's "landed slice" ledger updated when a syscall flips
  from facade to real)
- `kernel/subsystems/linux/syscall_internal.h` — errno constants
- `kernel/subsystems/linux/ring3_smoke.{cpp,h}` — Spawn helpers
- `kernel/test/smoke_profile.cpp` — `SmokeProfileShouldSpawn` gating
  (Linux smokes are TCG-skipped by default; profile=linux opts in)
