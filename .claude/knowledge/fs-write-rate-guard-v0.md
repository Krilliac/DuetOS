# FS write-rate guard v0 — ransomware defense

**Type:** Decision + Pattern + Observation
**Status:** Active
**Last updated:** 2026-05-03

## What it is

Per-process file-write rate cap, enforced at every successful
file-write syscall site. Closes the
"Ransomware (mass FS encrypt)" gap from
`.claude/knowledge/redteam-coverage-matrix-v0.md` — previously
listed as a ❌ user-mode gap because no FS-write-rate detector
existed and no policy could fire "this process just wrote 1 GiB
in 5 seconds — kill it." The threat model assumes the trusted
process IS the attacker (compromised app, smuggled installer),
so there is **no exemption for trusted caps**.

## Window + threshold

- Window: `kFsWriteWindowTicks` = 100 scheduler ticks = 1 s @
  100 Hz.
- Cap: `kFsWriteWindowByteCap` = 16 MiB per window per process.
- Both constants are `inline constexpr` in
  `kernel/proc/process.h` so retuning is a one-line edit + a
  rebuild.

A process that writes ≤ 16 MiB/s sees zero overhead beyond a
single `TickCount()` read and one add. A process that exceeds the
cap is flagged for kill on the offending syscall via
`FlagCurrentForKill(KillReason::FsWriteRateExceeded)`. The
scheduler converts the flag to a Dead transition on the task's
next re-enqueue (same path the sandbox-denial-threshold and
tick-budget kills use), so the kill is observably "the next
write returns and the task never runs again."

## Plumbing

- `Process` (in `kernel/proc/process.h`) gains three counters:
  `fs_write_bytes_total` (lifetime), `fs_write_window_bytes`
  (current window), `fs_write_window_start_tick`. Zeroed by the
  ProcessCreate `memset` — no extra init.
- `RecordFsWrite(Process*, u64)` is the production syscall-site
  hook. Bumps counters, rolls the window, and on threshold cross
  bumps `MassFsWriteRate` + flags the calling task for kill.
- `RecordFsWriteCheck(Process*, u64)` is the pure-bookkeeping
  variant — same window math, returns true if the call pushed
  the process over cap. No global counter side-effect, no kill.
  Used by `attack_sim` to verify the threshold logic without
  killing the kernel main thread that's running the test.
- `MassFsWriteRate` is the new `HealthIssue` enumerator. Its
  `ResponseFor` policy falls through to `LogOnly` (the default
  branch) — actual kill enforcement happens at the syscall
  site, the checker just provides operator visibility.
- `RuntimeCheckerNoteFsWriteRateExceeded()` is the documented
  global counter hook called by `RecordFsWrite` on threshold
  cross. Routes through `Report` so all the standard logging /
  per-issue counter / last_issue tracking stays consistent.
- `KillReason::FsWriteRateExceeded = 4` (`kernel/sched/sched.h`)
  is the new termination reason; appears as
  `[task-kill] reason=FsWriteRateExceeded` in serial logs.

## Wired-in syscall sites

Every path that lands attacker-controlled bytes on backing
storage routes through `RecordFsWrite`:

- **Win32 `SYS_FILE_WRITE`**: `fs::routing::WriteForProcess` in
  `kernel/fs/file_route.cpp` calls `RecordFsWrite(proc, wrote)`
  after a successful `Fat32WriteInPlace`.
- **Win32 `SYS_FILE_CREATE`**: `fs::routing::CreateForProcess`
  counts the `init_bytes` payload toward the calling process's
  window — encrypt-loops typically follow a "create new file
  with encrypted contents → unlink original" pattern, so the
  create surface matters as much as the in-place write surface.
- **Linux `sys_write`**: `subsystems::linux::DoWrite` in
  `kernel/subsystems/linux/syscall_io.cpp` records `written`
  after the write loop. `DoWritev`/`DoPwrite64`/`DoPwritev*`/
  `DoSendfile` all funnel through `DoWrite`, so they inherit the
  hook automatically.
- **Linux `copy_file_range`**: `extra_syscalls.cpp`
  `DoCopyFileRange` issues `Fat32CreateAtPath` /
  `Fat32AppendAtPath` directly (bypassing `DoWrite` for kernel-
  buffer reasons documented in that file). Records `total` after
  the loop so a kernel-side fd-to-fd attack can't evade the cap.

The ramfs backing path is intentionally unhooked — ramfs is
read-only (`WriteForProcess` returns `u64(-1)` on a ramfs
handle), so no bytes ever land. Pipes, sockets, eventfds, and
the other non-file fd kinds are excluded too: ransomware writes
to *files*, and a flooding socket is a separate threat already
covered by the cap-gate side of the network stack.

## Test wiring (attack_sim)

`AttackRansomwareWriteRate` is a kernel-side test that:

1. Builds a synthetic `Process` on a static buffer. Re-zeros at
   each run so consecutive `AttackSimRun` invocations stay
   clean.
2. Loops `(kFsWriteWindowByteCap / 4096) + 1` calls of
   `RecordFsWriteCheck(p, 4096)`. The last call is guaranteed-
   over-cap; everything before it is within budget.
3. On `RecordFsWriteCheck` returning true, calls
   `RuntimeCheckerNoteFsWriteRateExceeded()` — the same hook
   `RecordFsWrite` (the production path) calls.
4. The standard `RunAttack` harness's before/after compare on
   `MassFsWriteRate` sees the increment and reports PASS.

Synthetic Process (no ProcessCreate, no kheap, no ring 3) is
deliberate: the production path runs `FlagCurrentForKill`,
which would terminate the kernel main task that's running the
suite. Splitting the bookkeeping out into `RecordFsWriteCheck`
gives us a no-side-effect surface to test without that hazard.

## What's intentionally not covered

- Pipes / sockets / eventfds — not the ransomware threat
  surface; their flooding behaviour is a separate concern.
- ramfs writes — ramfs is read-only; no bytes ever land.
- A coordinated attack that spawns many processes each staying
  just under the per-process cap. The cap is per-process by
  design (matches sandbox_denials' per-process discipline); a
  global counter would need its own slice plus a fork-rate
  detector to be useful. Captured here so a future operator
  who notices the gap doesn't have to re-derive it.
- Real ring-3 PE / ELF probe that writes to a real disk file in
  a tight loop. Doable now (the syscall path is wired) but
  needs a per-test FS volume reserved as scratch — otherwise
  the probe would either write to the live kernel image's
  partition (bad) or run out of space if it actually pushed past
  16 MiB. Defer until the install-/scratch-volume work lands.

## Files touched

- `kernel/sched/sched.h` — added `KillReason::FsWriteRateExceeded`
- `kernel/sched/sched.cpp` — added `KillReasonName` case
- `kernel/proc/process.h` — added counters + window constants +
  `RecordFsWrite` / `RecordFsWriteCheck` decls
- `kernel/proc/process.cpp` — implementation of the two
  bookkeeping functions
- `kernel/diag/runtime_checker.h` — added `MassFsWriteRate` enum
  + `RuntimeCheckerNoteFsWriteRateExceeded` decl
- `kernel/diag/runtime_checker.cpp` — `HealthIssueName` case +
  `RuntimeCheckerNoteFsWriteRateExceeded` implementation
- `kernel/fs/file_route.cpp` — hook into `WriteForProcess` +
  `CreateForProcess` (init_bytes payload)
- `kernel/subsystems/linux/syscall_io.cpp` — hook into `DoWrite`
- `kernel/subsystems/linux/extra_syscalls.cpp` — hook into
  `DoCopyFileRange`
- `kernel/security/attack_sim.cpp` — `AttackRansomwareWriteRate`
  + `RestoreRansomwareWriteRate` + spec table entry
