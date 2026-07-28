# DuetOS handoff — 2026-07-28

`main` is at `6289a692`. 52 commits merged (fast-forward, CI was green on
that exact SHA before the merge). Working tree clean.

---

## Paste this into a new session

> Continue DuetOS work. `main` is at `6289a692` — 52 commits just landed
> closing the entire audit backlog (38/38 findings) and the C-series
> sweep items. Read `HANDOFF.md` at the repo root first, then
> `wiki/reference/Roadmap.md`.
>
> **Highest-value next slice: the PE32 game ladder (Roadmap "Run a real
> 32-bit application").** The diagnosis is already done and recorded: the
> exe clears CRT startup and reaches its own code, then settles into a
> quiet loop because `userland/libs/user32_32/user32_32.c` and
> `gdi32_32/gdi32_32.c` are hand-written stubs returning constants with
> **zero syscalls in either file**. The next rung is a real USER32
> surface — window class registration + message loop wired to the
> kernel's window manager — not more import coverage.
>
> **Second candidate: build the WaitQueue detach primitive.** Three
> independent findings (R1-14 AddressSpace `regions_lock`, R1-15 PS/2
> ring, C4 unkillable blocked threads) all block on the same missing
> scheduler ABI — a lock spanning enqueue and detach, i.e.
> `WaitQueueBlockLocked(wq, lock)`. Each is filed in the Roadmap with
> its constraint. Building it once unblocks all three; that is why none
> of them were force-fixed.
>
> Before pushing anything, read the "verification gotchas" section of
> `HANDOFF.md` — the local kernel build does NOT cover host-tests or
> fuzz, and two CI gates broke unnoticed for ~10 pushes last session.

---

## What landed (52 commits)

**All 38 audit findings resolved** — 36 fixed and boot-verified, 2 filed
with design constraints. Highlights, several materially worse than the
audit reported:

- `arch/timer` — every AP was advancing the global tick counter.
  **Measured 617 Hz vs an intended 100 Hz at SMP=8** (6.17x), so every
  tick-derived timeout fired ~6x early. Non-atomic RMW also lost
  updates, making the rate nondeterministic.
- `sched` — AP bring-up ran `SchedStartIdle` (which allocates and locks)
  BEFORE installing the boot sentinel, so a fresh AP ran with
  `current_task == nullptr`. This was the intermittent
  `WaitQueueBlockTimeout on non-Running task` panic the Roadmap had
  carried as "root cause still open" since May. 0 KASSERTs across 3 TCG
  boots after the fix, vs the control panicking at t≈20 s.
- `arch/smp` — TLB shootdown counted CPUs that could not yet service an
  IPI (25 timeouts across 11 control boots -> 0 after).
- `arch/smp` — a timed-out AP's `cpu_id` was reused, so a late-waking AP
  could share one PerCpu, GDT/TSS **and kernel stack** with another CPU.
- `net/tcp` — RST accepted on 4-tuple match alone: a one-packet blind
  reset. Now RFC 5961 with a challenge-ACK, pinned by a boot self-test.
- `net/tcp` — SYN backlog counted only completed handshakes, so
  half-open TCBs were bounded by the GLOBAL Tcb table; a flood against
  one listener starved every socket on the box.
- `core/menu` — `/APPS` shortcuts spawned FAT32-volume binaries with
  `CapSetTrusted()` (every bit, incl. `kCapDebug`). Now
  `CapSetUserLaunch()`, promoted to `proc/process.h` so the two launch
  paths cannot drift apart again.
- `syscall` — FD_CLOEXEC was fully plumbed, observable via `F_GETFD`,
  self-tested, and **never called on a real exec**.
- `linux/signal` — a 1-deep signal-frame slot meant any process able to
  signal a target could KILL it by signalling twice mid-handler.
- `time` — HPET tick->ns overflowed u64 at 5.12 h uptime, reversing
  `MonotonicNs()`. Now host-tested.

**Tooling added:** `tools/qemu/run-whpx-repro.ps1` (repeat-boot under
WHPX with a validity gate), `tests/host/test_hpet_scale.cpp`,
`tests/host/test_damage_bands.cpp`, plus TCP RST / SYN-backlog boot
self-tests.

---

## Still open

| item | why |
|---|---|
| **PE32 ladder** | `user32_32`/`gdi32_32` are stubs with zero syscalls — needs a real USER32 slice |
| **Roadmap (~60 sections)** | ongoing project backlog, not a finishable list |
| **R1-14** AddressSpace `regions_lock` | needs the WaitQueue detach primitive; the obvious fix sleeps under a spinlock |
| **R1-15** PS/2 ring two-writer race | same primitive, or switch ring-full policy to drop-newest |
| **C4** unkillable blocked threads | same primitive. Win32 half already fixed (`NtTerminateThread` now returns `STATUS_PENDING`, not a false SUCCESS) |
| **Branch cleanup** | 19 verified-redundant branches; SHAs in `D:\DuetOS-Snapshots\branch-deletion-manifest.txt`. Bulk `git branch -D` was blocked by the auto-mode classifier — run it yourself |
| **`wip/preserved-worktree-2026-07-27`** | 144 files preserved from the OneDrive checkout. **Do NOT merge** — it measures +10,263/-18,362 vs main and would delete the X.509 extension hardening. Reference only |
| **Defender** | reports real-time protection ON despite intent to disable |

---

## Verification gotchas (these cost real time)

1. **The local kernel build covers neither host-tests nor fuzz.** Both
   broke unnoticed for ~10 pushes. Before pushing, run:
   - `cmake -S tests/host -B /tmp/ht` (~5 s)
   - `cd tests/fuzz && make -j4` (~2 min, 37 targets)
   `tests/fuzz/host_shim/` must mirror kernel APIs **including struct
   field names** (`SpinLock` is a ticket lock: `next_ticket`/
   `now_serving`), because `-I host_shim` precedes `-I kernel`.
2. **CI runs on every `claude/**` push — no PR needed.** It is the only
   place the full 7-smoke signature gate completes (KVM runners). Poll:
   `gh run list --branch <b> --json databaseId,status,conclusion` with
   `GH_TOKEN` from `git credential fill`.
3. **One clean boot proves nothing for intermittent faults.** A WRONG
   fix produced a clean 412 s boot on its first try. Measure a RATE over
   >=3 runs. Intermittent SMP races reproduce under WSL/TCG but often
   NOT under WHPX (fast bring-up narrows the window).
4. **Never set `DUETOS_SERIAL_FILE` when running the smoke driver** — it
   captures run.sh's stdout, so the override makes it grade an empty log
   and report ALL signatures missing. A guard now exits 2 on a missing
   banner.
5. **Kill stray QEMU before any smoke.** A held `nvme0.img` makes the
   next run die pre-boot with a ~550-byte log that reads as zero
   failures.
6. **Do not trust the audit reports' mechanisms.** Of 11 findings
   re-verified by a multi-agent pass, **10 were worse than reported** and
   3 had mechanisms that were simply wrong. Read the current code first;
   "MISFRAMED" is a valid, useful outcome.

Durable notes are in `~/.claude/projects/C--Users-natew-source-repos-DuetOS/memory/`
(`duetos-verification-discipline`, `whpx-boot-repro-workflow`).
