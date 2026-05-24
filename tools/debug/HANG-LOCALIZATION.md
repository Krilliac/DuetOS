# Localizing an intermittent kernel hang in DuetOS

Use this prompt verbatim when CI or a live boot wedges with a soft-lockup
or silent qemu timeout. Battle-tested 2026-05-24 against the `ps2kbd
KbdSendAndAck` IRQ-race that hung bringup smoke ~50% on GitHub runners and
~75% on the dev WSL host. Found the root cause in 6 instrumentation passes
(~25 minutes of wall time).

---

## How to use

Paste the **PROMPT** section below into a fresh Claude session and supply
two facts in the brief:

1. **Symptom:** the smoke-log tail or CI error message — at minimum the
   line containing `[soft-lockup] task stuck tid=X name="Y" ticks_in_run=N`
   if present, or the last log line the wedged task emitted.
2. **Profile:** which `tools/test/profile-boot-smoke.sh <profile>` is
   failing (`bringup`, `ring3`, `pe-hello`, `pe-winapi`, `pe-winkill`,
   `linux`), or "build-flavor matrix x86_64-debug-fast" / similar.

The session will rebuild the debug preset, repro the hang locally under
WSL+QEMU, bisect by sentinel insertion, identify the wedge function, fix
the root cause (not the symptom), and validate with N consecutive runs.

Helper scripts referenced by the prompt already exist:
- `tools/test/wsl-bringup-repro.sh <max-attempts>` — loops until fail,
  copies log to `/mnt/c/Users/natew/AppData/Local/Temp/bringup-fail.log`.
- `tools/test/wsl-bringup-capture-pass.sh <max-attempts>` — counterpart,
  copies a passing log to `bringup-pass.log`.
- `tools/test/wsl-bringup-smoke.sh [profile]` — single-shot wrapper that
  sets `PATH=/usr/lib/llvm-18/bin:$PATH` so `profile-boot-smoke.sh` finds
  its toolchain.
- `tools/build/wsl-kernel-build-debug.sh` — debug-preset build helper.
  **Critical:** the default `wsl-kernel-build.sh` builds the RELEASE
  preset; smoke loads the DEBUG ELF. Editing source then building only
  release means your new code never executes in the smoke test.

---

## PROMPT (paste this verbatim)

```text
DuetOS is hitting an intermittent boot-time hang. Localize it using the
instrumented-bisect methodology documented in
`tools/debug/HANG-LOCALIZATION.md`.

SYMPTOM:
  <paste the soft-lockup line + last few lines of the smoke log here>

FAILING PROFILE:
  <profile name, e.g. "bringup">

Execute these steps in order. After each, report what you found before
moving to the next.

==========================================================================
STEP 0 — Build the debug preset (smoke uses it, not release):
  bash tools/build/wsl-kernel-build-debug.sh
  Verify the file you intend to edit later was just rebuilt (mtime check
  on .obj > source). If you skip this and only build release, your later
  sentinel inserts will silently not execute.

==========================================================================
STEP 1 — Reproduce locally and capture a failing log:
  bash tools/test/wsl-bringup-repro.sh 20    # or whatever profile
  This loops until a fail; preserves the smoke log to
  /mnt/c/Users/natew/AppData/Local/Temp/bringup-fail.log.

  If 20 attempts pass cleanly: the bug is harder to reproduce locally
  than in CI. Try increasing DUETOS_TIMEOUT, switching to TCG via
  DUETOS_ACCEL=tcg if a helper supports it, or run with the SMP knob
  cranked up. Document and stop if you can't repro — debugging a CI-only
  flake needs a different methodology (re-run the workflow with
  ACTIONS_RUNNER_DEBUG=true).

==========================================================================
STEP 2 — Identify the wedged task and its last log line:
  tail -80 /mnt/c/Users/natew/AppData/Local/Temp/bringup-fail.log

  Look for `[soft-lockup] task stuck tid=X name="<task>" ticks_in_run=N`.

  CLASS-OF-BUG signatures (memory shortcuts to common causes):
    ticks_in_run=101    -> kPollSpinLimit busy-wait (PS/2, PIC, PIT)
                           NOT yielding to scheduler. Check arch::Inb
                           loops in drivers/input, arch/x86_64/pic,
                           arch/x86_64/timer. See memory
                           `guard-prompt-hpet-hang.md` and
                           `serial-log-triage.md`.
    ticks_in_run very large, no Inb -> spinlock held by another task that
                           is itself sleeping/blocked (deadlock).
    no soft-lockup line, qemu killed by timeout -> full system wedge
                           (no task even getting scheduled — IRQ delivery
                           dead, or panic that didn't reach the serial port).

  Identify the LAST log line that came from the wedged task. This is your
  source-tree anchor.

==========================================================================
STEP 3 — Map the anchor log line to source:
  Grep for the EXACT log string (e.g. `selftest pass causal_total`) under
  kernel/ to find its emit site. Then read 50 lines around it to enumerate
  the calls between this emit and the NEXT expected emit (which is missing
  in the fail log). That window contains the wedge.

==========================================================================
STEP 4 — Bracket every call in the suspect window with sentinels:
  Insert `arch::SerialWrite("[<area>] BEFORE foo\n");` and `... AFTER foo\n`
  around each candidate. Pattern matches existing `[bringup-tail] X done`
  lines.

  Why arch::SerialWrite (not KLOG_*):
    Boot-time debug needs UNCONDITIONAL output. KLOG_* respects log-level
    filtering — if the wedge happens before the log floor is configured,
    a KLOG_DEBUG line never fires and you waste an iteration.

  Be aggressive (10+ sentinels is fine). They cost one Inb-or-so each and
  bound the bisect depth.

==========================================================================
STEP 5 — Rebuild debug + re-repro:
  bash tools/build/wsl-kernel-build-debug.sh
  bash tools/test/wsl-bringup-repro.sh 20

  In the failing log, count which sentinels fired. The LAST sentinel that
  fired (without its matching "AFTER" pair) marks the wedge function.

==========================================================================
STEP 6 — Recurse into the wedge function:
  Add sentinels INSIDE the function. If the function has a loop, sentinel
  each iteration (cheaply: emit the loop variable). If the function calls
  several sub-functions, sentinel before/after each.

  Rebuild debug, re-repro. Narrow until you reach a primitive (port I/O,
  spinlock acquire, memory op).

==========================================================================
STEP 7 — Identify the bug class at the primitive:
  Match the primitive against these classes:

  IRQ STEAL (e.g. PS/2 KbdSendAndAck pre-2026-05-24):
    A polled handshake to a device whose IRQ is routed. IRQ handler
    drains the device's data port before the polling code can read it.
    Symptom: bounded spin-loop hits its limit; intermittent because IRQ
    timing varies. Fix: wrap the handshake in CLI/STI (save IF first).
    See drivers/input/ps2mouse.cpp `Ps2MouseInit` for the established
    pattern + comment.

  LOCK ORDER INVERSION:
    Task A acquires lock X then waits on Y; task B acquires Y then waits
    on X. Symptom: ticks_in_run shows growing without bound, and both
    tasks appear in the scheduler stats as live but neither emitting
    serial. Fix: pick a global lock order and enforce it.

  REFCOUNT ASYMMETRY:
    See memory `serial-log-triage.md` class. A path acquires a refcount
    its symmetric release path doesn't drop, pinning a resource. Less
    likely to cause a busy-spin lockup; more likely a slow leak.

  BUSY-WAIT WITHOUT YIELD:
    A polling loop in task context that doesn't call sched::SchedYield()
    or rely on a wait queue. Fix: convert to wait queue or insert
    SchedYield() in the loop body. Per memory `guard-prompt-hpet-hang.md`
    (security/guard.cpp HpetReadCounter busy-wait), this was the fix
    shape for the VBox HPET-absent hang.

==========================================================================
STEP 8 — Fix at the SHARED primitive, not the call site:
  If the wedge is `Ps2KeyboardSetTypematic` and the primitive is
  `KbdSendAndAck`, fix `KbdSendAndAck` — that protects all 5 keyboard
  handshake callers, not just the one your repro exercised.

  Reuse established patterns: if a sibling driver (Ps2MouseInit, e.g.)
  already mitigates the same class, copy its pattern + comment verbatim.

==========================================================================
STEP 9 — Validate with N consecutive runs:
  for i in {1..10}; do
    bash tools/test/wsl-bringup-smoke.sh <profile> 2>&1 | tail -1
  done
  Pre-fix pass rate was P%. Post-fix should be > 95%. If you still see
  failures, recurse: the fix addressed one cause but there's another. Re-run
  the bisect from STEP 1 on the residual failure (often a DIFFERENT
  function — don't assume).

==========================================================================
STEP 10 — Leave the most useful sentinels in:
  CLAUDE.md "Diagnostic Logging — Keep It, Gate It, Probe It" applies.
  Delete the per-iteration noise (e.g. per-key SerialWrite inside a tight
  loop), keep the bracketing ones (`[<area>] X done` for each major step
  in the suspect window). They cost ~one Inb each and pre-localize the next
  regression in the same area.

  At the FIX site, leave a comment explaining the race + the methodology
  that found it. Reference the original soft-lockup signature
  (e.g. `ticks_in_run=101 matches kPollSpinLimit`) so a future reader
  recognises the class shape.

==========================================================================
STEP 11 — Save memory:
  Update or add a `~/.claude/projects/.../memory/` entry capturing:
    - The hang signature (last anchor line, ticks_in_run value)
    - The wedge function
    - The bug class (IRQ steal / lock inversion / etc.)
    - The fix shape (CLI window / SchedYield / lock-order swap)
  This shortcuts STEP 7 for the NEXT instance of the same class.
```

---

## Pre-instrumentation pass (proactive)

If you have spare cycles between live regressions, run THIS prompt once to
identify and instrument every hangable surface BEFORE it bites:

```text
Scan the DuetOS kernel for functions that match the IRQ-race / busy-wait
classes documented in tools/debug/HANG-LOCALIZATION.md. For each match,
either fix it preemptively (preferred) or instrument it with a sentinel
that will localise the next hang to that function in one bisect step
(acceptable for code that's not currently broken).

Search targets:
  - `for (u64 i = 0; i < kPollSpinLimit` patterns — every bounded spin
    loop on `Inb` is a candidate IRQ steal race.
  - `KbdSendAndAck`-shape send-then-wait functions in driver code.
  - Functions in kernel/drivers/{input,storage,net} that call
    `arch::Inb` / `arch::Outb` without a `Cli/Sti` window.
  - `WaitQueueBlock` / `WaitQueueBlockTimeout` callers that don't have
    a matching wake on every exit path of the producer.
  - Spinlock acquire sites in IRQ handlers (held with IRQs off, can't
    sleep, must be released within bounded time).

For each match, evaluate:
  - Is the IRQ for this device routed at the time this function runs?
    (If yes, IRQ steal is plausible. If no — boot before IRQ install —
     it's safe.)
  - Does the function have ANY way to yield? (If not and the spin can
    exceed ~50ms, it's a soft-lockup candidate.)
  - Is there an established fix pattern in a sibling file? (E.g.
    Ps2MouseInit's CLI window for PS/2-class drivers.)

Output a table:
  function | file:line | risk class | sibling pattern | recommended action

Do NOT make speculative fixes for "could plausibly fail" cases —
CLAUDE.md anti-bloat applies. Only fix functions that match an
established failure class with a known repro. For the rest, add ONE
sentinel at the function entry so a future hang in that function
shortcuts to "skip steps 3-6, function name is on the wire".
```

---

## Memory hooks (shortcuts for known signatures)

When the soft-lockup signature matches one of these, jump straight to
the known fix without bisecting:

| Signature | Fix | Memory |
|---|---|---|
| `ticks_in_run=101` near PS/2 handshake | CLI window in KbdSendAndAck / equivalent | this file + Ps2MouseInit comment |
| `ticks_in_run=101` after security guard prompt | swap HpetReadCounter for arch::TimerTicks | `guard-prompt-hpet-hang.md` |
| `[boot] Parsing ACPI tables.` fault loop, VBox only | MapMmio path for phys > low; see ACPI step= sentinels | `acpi-hang-vbox-specific.md` |
| `[mouse] ... 72% serial spam` then soft-lockup | remove per-packet trace (compiled-in debug check is a no-op in release builds) | `serial-log-triage.md` |
| BSOD ~minutes after VBox guest hang | nvlddmkm.sys (NVIDIA), not VBox | `host-bsod-nvlddmkm.md` |
