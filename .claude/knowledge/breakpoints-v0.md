# Kernel breakpoint subsystem v0 (phase 1)

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — SW + HW breakpoints land, `bp` shell command
wired, self-test runs at boot. Phases 2 (per-task syscall API) and
3 (static probe macros) planned but not implemented.

## Files

- `kernel/debug/dr.h` — header-only `ReadDrN` / `WriteDrN` inlines
  plus DR6/DR7 bit constants. Follows the MSR-helper idiom from
  `lapic.cpp`.
- `kernel/debug/breakpoints.{h,cpp}` — manager. 16 software slots,
  4 hardware slots (one per DR0..DR3). Internal `SpinLock` guards
  the tables.
- `kernel/arch/x86_64/traps.cpp:320–330` — trap-dispatch hook.
  `#BP` (vec 3) and `#DB` (vec 1) route through the manager
  before the generic `LogAndContinue` log line; the manager's
  return value decides whether the fallback fires.
- `kernel/core/shell.cpp:~2360 / ~6246` — `CmdBp` + dispatch
  entry for `bp` / `breakpoint`.
- `kernel/core/main.cpp:~298` — `BpInit()` + `BpSelfTest()`
  called after `ProtectKernelImage()` and before SMP bring-up.
- `kernel/mm/paging.h / paging.cpp:780` — `SetPteFlags4K`
  promoted from the anonymous namespace to public API so the
  BP subsystem can flip `.text` writable for int3 patching.

## How SW breakpoints work

1. Install: flip the containing 4 KiB page to RW via
   `SetPteFlags4K(page, kPagePresent | kPageWritable)`, save
   the original byte, write `0xCC`, flip the page back to R+X.
2. On `#BP` (vector 3): the CPU pushed rip pointing past the
   `0xCC`. Look up `rip-1`, rewind the frame's rip, restore the
   original byte, OR `RFLAGS.TF` into the frame, record a
   pending-reinsert entry. Return true → iretq resumes at the
   patched address, executes one instruction, takes `#DB`.
3. On `#DB` with `DR6.BS` set + pending reinsert: re-patch the
   `0xCC`, clear pending, clear `RFLAGS.TF` in the frame
   (the CPU does NOT auto-clear TF in the saved image — only in
   the live RFLAGS during the handler), clear `DR6`, return.

The TF-preservation-in-saved-image quirk is the single easiest
mistake to make here. Symptom if you forget: every subsequent
instruction fires another `#DB` forever.

## How HW breakpoints work

1. Install: pick a free DR0..DR3 slot, write the address, OR
   the slot's (R/W, LEN, L-enable, MBS) bits into DR7.
2. On `#DB`: read DR6, scan B0..B3 for which slot fired, log
   the hit, increment per-slot counter, clear DR6.
3. For execute BPs we also OR `RFLAGS.RF` (0x10000) into the
   frame — the Intel SDM says the CPU sets RF automatically on
   instruction-BP delivery so iretq can resume without
   re-triggering the same fetch, but QEMU's TCG doesn't
   propagate that bit reliably. Setting it explicitly is
   defensive; it's a no-op on real hardware where the CPU
   already did it.

## Shell command

```
BP LIST                              — list installed breakpoints
BP SET <hex-addr>                    — software BP at kernel .text address
BP HW <hex-addr> [X|W|RW] [LEN]      — hardware BP (execute/write/read-write)
BP CLEAR <id>                        — remove by id
BP TEST                              — round-trip self-test
```

Output formats for `bp list`:

```
BP: ID KIND   ADDR              HITS
   1  SW     0xffffffff801445a0  0
   2  HW-W   0xffffffff80200000  17
```

## Phase 1 scope cuts (still in effect for SW BPs)

- **Single-CPU only for SW BPs.** Install routines reject
  `SmpCpusOnline() != 1` with `SmpUnsupported` on the SW path.
  Still needed because SW patching writes to shared kernel
  `.text` — another CPU fetching the page mid-patch would see
  a torn instruction. HW BPs dropped this restriction in
  phase 2a (see below).
- **Kernel `.text` only for SW BPs.** Process-image patching
  lands in phase 2b.
- **One-shot reinsertion.** If a second SW BP hit arrives while
  a reinsert is pending (shouldn't happen in phase 1's single-
  CPU no-reentrancy world), we log + drop.
- **No probe macros.** Phase 3 will add a `KBP_PROBE(reason)`
  macro sprinkled at panic paths, sandbox denials, scheduler
  edge cases, etc.

## Phase 2a (2026-04-22) — per-task HW BPs + ring-3 syscall

Adds:

- **Per-task DR0..DR3 + DR7** on `sched::Task` (saved/restored
  around every `ContextSwitch` in `Schedule()` — same pattern
  the Linux `fs_base` save uses). Tasks without any BPs keep
  DR7 = 0, so the save/restore is "zero the slots" on both
  sides and costs a handful of cycles.
- **`kCapDebug` (bit 3)** on `Process::caps`. Gates
  `SYS_BP_INSTALL` / `SYS_BP_REMOVE`. `CapSetTrusted()` now
  includes it by default; sandboxed tasks see `-1` and a
  `[sys] denied syscall=SYS_BP_INSTALL cap=Debug` log line.
- **`SYS_BP_INSTALL = 38`** — rdi=va, rsi=kind (1/2/3),
  rdx=len (1/2/4/8). Returns bp_id on success, `u64(-1)` on
  rejection. **`SYS_BP_REMOVE = 39`** — rdi=id. Returns 0
  on success, `u64(-1)` on unknown-id or cross-owner attempt.
- **Owner-pid stamping.** `BpInstallHardware` now takes an
  `owner_pid` arg. `BpRemove` takes a `requester_pid` and
  rejects the removal if the requester isn't the owner (or
  isn't kernel-privileged via `requester_pid == 0`). Prevents
  a ring-3 debugger from stomping another process's BPs.
- **User-ring BP claim path.** The trap dispatcher now calls
  `BpHandleBreakpoint` / `BpHandleDebug` BEFORE the per-ring
  `TrapResponseFor` policy check. A user-mode #DB that
  matches a per-task BP is handled + resumed cleanly instead
  of being routed to `TrapResponse::IsolateTask` (which would
  kill the task on every BP hit).
- **SMP restriction lifted for HW BPs.** Because DR state now
  rides the task through context switches, a HW BP fires on
  whatever CPU the owning task ran on — no IPI shootdown
  needed. SW BPs still assert single-CPU.

Smoke test: `SpawnBpProbeTask()` in `kernel/core/ring3_smoke.cpp`.
A trusted task issues `SYS_BP_INSTALL` on a `nop` in its own
code page, executes the nop (fires #DB), removes the BP, and
prints `[bp-probe] passed via HW BP`. Expected log sequence:

```
[ring3] queued bp-probe task pid=N code_va=...
[I] debug/bp : HW BP installed   addr=0x46000019   id=0x3
[I] debug/bp : HW BP hit   addr=0x46000019   hits=0x1
[I] debug/bp : HW BP removed id   val=0x3
[bp-probe] passed via HW BP
[I] sys : exit rc val=0x0
[proc] destroy pid=N name="ring3-bp-probe"
```

### Gotchas specific to phase 2a

1. **User-mode #DB is normally IsolateTask.** The existing
   `TrapResponseFor(vector=1, from_user=true)` returns
   `IsolateTask` → kills the task. The BP subsystem has to
   claim the trap BEFORE the policy check runs, not after —
   the phase 1 hook was inside the `LogAndContinue` arm,
   which is only entered for kernel-mode hits.
2. **DR6.BD/BT bits** are CPU-set on kernel-privilege traps
   (setting DR7 with GD=1, task-switch flag). We don't use
   either; the handler masks to just BS + B0..B3, so those
   stray bits never surface as phantom hits.
3. **`ProcessCreate` assigning caps**: `CapSetTrusted()`
   iterates `[1, kCapCount)`, so adding a new cap
   automatically widens the trusted set. Sandboxed tasks
   keep only the caps explicitly named — no phase 2a callsite
   changes were needed for them.

## Phase 3 (2026-04-22) — suspend / inspect / resume / step

Adds the "VS F9 stops a thread" semantics without freezing the
whole OS:

- **`suspend_on_hit` per BP.** Default off; set via
  `bp set --suspend <addr>` / `bp hw --suspend <addr>` from the
  shell, or via `rsi |= 0x10` on `SYS_BP_INSTALL`.
- **When a user-mode hit lands on a suspend-on-hit BP:**
  `BpHandleBreakpoint` / `BpHandleDebug` does the normal
  bookkeeping (reinsert setup for SW, RF for HW exec), then
  calls `MaybeSuspend(bp_id, frame)` which stashes the task's
  `task_id` + `TrapFrame*` + `AddressSpace*` on the BP entry
  and blocks the task on the BP's `sched::WaitQueue`. The
  scheduler moves on to other ready tasks.
- **Safety rail.** Kernel-mode hits with suspend_on_hit set
  get a `[W] debug/bp : suspend-on-hit rejected: kernel-mode
  hit` warning and fall through to log+resume. We can't
  safely park a ring-0 task today because `IrqNestDepthRaw`
  is stubbed (see `kernel/arch/x86_64/traps.cpp:161`) — a
  BP fired while a spinlock is held would deadlock on
  attempted resume. Phase 4 can relax this once that
  telemetry is live.
- **Shell commands (kernel/core/shell.cpp:CmdBp):**
  - `bp stopped` — list tasks currently suspended
  - `bp regs <id>` — dump the stopped task's saved trap frame
  - `bp mem <id> <hex-addr> [len]` — hex+ASCII dump of the
    stopped task's user memory (walks the captured AS)
  - `bp resume <id>` — wake the task with rflags unchanged
  - `bp step <id>` — set RFLAGS.TF, wake, mark this as a
    stepping session; the next `#DB` re-suspends on the
    same BP (one instruction forward)
- **`BpRemove` auto-wake.** Removing a BP with a task parked
  on its wait-queue calls `WaitQueueWakeAll` first so the
  task isn't stranded; the returning task sees the entry's
  id has changed and skips the stopped-state cleanup.

### The stepping dance

The tricky one. When `BpStep` is called:

1. The stopped frame's `rflags |= 0x100` (TF).
2. A single-slot `g_stepping { task_id, bp_id }` records the
   session.
3. `WaitQueueWakeOne` unblocks the task.
4. Task resumes inside its handler, returns up through
   `MaybeSuspend` → `TrapDispatch` → `iretq`.
5. CPU runs one instruction, takes `#DB` with `DR6.BS = 1`.
6. `BpHandleDebug`:
   a. If `g_reinsert.pending` (we were stepping out of a SW
      BP), re-patch `0xCC`, clear TF.
   b. If `g_stepping.task_id` matches the current task, pluck
      `bp_id`, clear the slot, clear TF, and re-enter
      `MaybeSuspend(bp_id)`.
7. Task parks again; operator inspects / steps / resumes.

### Phase 3 syscall extension

`SYS_BP_INSTALL`'s `rsi` now carries flags in the high bits:

```
rsi bits 0..3: kind (1=exec, 2=write, 3=read/write)
rsi bit 4:     suspend_on_hit
```

`SpawnBpProbeTask` still passes `rsi = 1` (no suspend) — the
probe only exercises the log-and-resume path. Suspend-on-hit
is shell-driven today.

### Manual test (no automated suspend smoke yet)

1. Boot. Drop into shell.
2. Identify a ring-3 instruction you can hit. Easiest: run
   `ps` (or equivalent), find a long-running user task, note
   its code VA from `[ring3] task ... rip=...`.
3. `bp hw --suspend <addr> x` — BP armed with suspend.
4. Wait for the task to execute that instruction. Kernel logs
   `task suspended on BP bp_id=N task_id=M`.
5. `bp stopped` — confirm the stop.
6. `bp regs N` — dump frame.
7. `bp mem N <user-va> 64` — dump user memory.
8. `bp step N` — advance one instruction, re-stop.
9. `bp resume N` — let it go.
10. `bp clear N` — remove the BP.

## Next phases (still planned)

- **Phase 2b:** SW breakpoints on user-process `.text` pages.
  Walks target `AddressSpace`, remaps RW briefly, patches.
- **Phase 3b:** automated suspend/resume/step smoke test —
  a kernel driver task that spawns a target, waits for its
  suspend, issues resume, verifies clean exit. Blocked on a
  small amount of orchestration plumbing.
- **Phase 4:** static `KBP_PROBE(event)` macros at panic /
  sandbox-denial / scheduler edge cases (think kprobes).
  Needs the kernel-mode suspend safety question settled
  first (IrqNestDepth live + a "safe-to-block" check).
- **Phase 5:** remote debugger protocol (GDB stub over serial
  or custom TCP). With phase 3's suspend/inspect/step already
  landed, most of the mechanism work is done — the stub is
  mostly packet parsing.

## Gotchas discovered during bring-up

1. **`BpInfo infos[N]{}` compiles to a `memset` call.** The
   kernel has no memset symbol in this TU; the linker fails.
   Fix: declare without the `{}` initialiser; `BpList` only
   populates valid entries so pre-zero isn't needed.
2. **`SetPteFlags4K` was in an anonymous namespace**, preventing
   external linkage. Moved it out (new file-scope definition in
   paging.cpp after the anon-ns close brace, header prototype
   in paging.h).
3. **RF handling on TCG.** Real CPUs auto-set RF on the pushed
   rflags for instruction-BP delivery; TCG apparently doesn't.
   Always OR RF into `frame->rflags` before returning for HW
   execute BPs.
4. **TF is NOT auto-cleared in the saved rflags image** — only
   in the live register while the handler runs. If your `#DB`
   handler forgets to clear it, the caller single-steps forever.

## Self-test at boot

`main.cpp:~298` runs `BpInit()` then `BpSelfTest()` which:

1. Installs a SW BP at the internal `BpSelfTestTarget` function,
   calls it, verifies `hit_count == 1`, removes it.
2. Same round trip with a HW execute BP.

A failure logs a warning and boot continues — we don't want a
subtle debug-subsystem regression to brick the box on every
boot. Health scans still report 0 issues if the test failed
(the BP subsystem doesn't register a health probe yet; phase 2
wiring).
