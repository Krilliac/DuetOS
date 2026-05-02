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

## Cross-references

- `.claude/knowledge/subsystems-status.md` — top-level Linux ABI inventory
  (keep this file's "landed slice" ledger updated when a syscall flips
  from facade to real)
- `kernel/subsystems/linux/syscall_internal.h` — errno constants
- `kernel/subsystems/linux/ring3_smoke.{cpp,h}` — Spawn helpers
- `kernel/test/smoke_profile.cpp` — `SmokeProfileShouldSpawn` gating
  (Linux smokes are TCG-skipped by default; profile=linux opts in)
