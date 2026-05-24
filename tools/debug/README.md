# DuetOS debug-localization prompt set

Paste-ready prompts that drive a Claude session through a specific class
of kernel issue. Each is self-contained: signature recognition →
methodology → known-fix shortcuts → save-memory.

Originated 2026-05-24 after the PS/2 KbdSendAndAck IRQ-race investigation
(PR #336). The methodology that found that bug in 6 instrumentation passes
generalises across classes — each prompt below applies it to a different
fault family.

| Class | Prompt | Use when |
|---|---|---|
| Intermittent hang | [HANG-LOCALIZATION.md](HANG-LOCALIZATION.md) | `[soft-lockup] task stuck`, smoke times out on serial silence, `ticks_in_run=N` |
| Memory corruption | [CORRUPTION-LOCALIZATION.md](CORRUPTION-LOCALIZATION.md) | #PF at random RIP, slab integrity panic, "the value read back is garbage" |
| Lock deadlock | [LOCK-DEADLOCK-LOCALIZATION.md](LOCK-DEADLOCK-LOCALIZATION.md) | All tasks alive but boot silent, no soft-lockup, lockdep WARN |
| PE/Win32 failure | [PE-WIN32-FAILURE-LOCALIZATION.md](PE-WIN32-FAILURE-LOCALIZATION.md) | pe-* smoke regressed, PE faults at valid-looking DLL RIP, NT syscall returns wrong status |
| Perf regression | [PERF-REGRESSION-LOCALIZATION.md](PERF-REGRESSION-LOCALIZATION.md) | Boot got slower than before, smoke times out at wall budget but completes given more time |
| Build / toolchain | [BUILD-TOOLCHAIN-LOCALIZATION.md](BUILD-TOOLCHAIN-LOCALIZATION.md) | ninja exit 127, undefined-reference, "release builds but debug doesn't" |
| SMP / cross-CPU | [SMP-BRINGUP-LOCALIZATION.md](SMP-BRINGUP-LOCALIZATION.md) | AP didn't online, IPI lost, "1 vCPU passes, 4 vCPU fails", per-CPU corruption |

## How to use

1. Identify the class from the symptom (the table above). If two
   apply (e.g. corruption + hang), start with the one whose signature
   matches MOST distinctively — corruption with a clean #PF wins over
   hang with an ambiguous soft-lockup.
2. Open the matching `.md` file. The "PROMPT (paste verbatim)" section
   is the prompt — copy it into a fresh Claude session along with the
   two facts the prompt asks for (symptom + repro context).
3. The session drives the methodology end-to-end. Each step reports
   what it found before moving to the next.
4. After landing the fix: save a memory entry per the prompt's STEP-N
   guidance. The "Known signatures → known fixes" table grows; next
   time the same class fires, the table shortcut skips the bisect.

## Helper scripts referenced

| Script | Purpose |
|---|---|
| `tools/test/wsl-bringup-smoke.sh [profile]` | One-shot local smoke run |
| `tools/test/wsl-bringup-repro.sh <max>` | Loop until fail, copy log to /mnt/c/.../bringup-fail.log |
| `tools/test/wsl-bringup-capture-pass.sh <max>` | Counterpart — capture a PASSING log |
| `tools/build/wsl-kernel-build.sh` | Build x86_64-release |
| `tools/build/wsl-kernel-build-debug.sh` | Build x86_64-debug (smoke + lockdep + KASAN-equiv use this) |
| `tools/build/wsl-build-isos.sh` | Build both ISOs for download/exfil |
| `tools/build/wsl-clang-format-check.sh` | Full-tree clang-format dry-run |

## The methodology, in one sentence

**Reduce the search window by inserting cheap, unambiguous sentinels at
each boundary in the suspect area; rebuild the preset the failure
exercises (NOT the default release preset); re-run the repro; the last
sentinel that fires is the new search window; recurse.**

## What ALL the prompts have in common

- **Use raw `arch::SerialWrite` for boot-time diagnostics.** KLOG_* is
  log-level gated; if the wedge happens before log-level configuration
  the KLOG line never fires and you waste an iteration.
- **Rebuild the right preset.** Smoke uses x86_64-debug. Editing source
  then only building release (default helper) means your edits never
  execute in the smoke test — silent failure mode.
- **Fix at the SHARED primitive, not the call site.** If the wedge is in
  caller X but the bug is in helper Y that X uses, fix Y so all of
  X, X', X'' callers benefit at once.
- **Validate with N consecutive runs.** For intermittent bugs, one
  passing run after a fix proves nothing. 10-20 consecutive same-result
  runs is the bar.
- **Leave the most useful diagnostic in.** CLAUDE.md "Diagnostic Logging
  — Keep It, Gate It, Probe It" applies. Trim per-iteration noise,
  keep bracketing sentinels. They pre-localize the next regression
  in the same area.
- **Save memory after every win.** The "Known signatures → known fixes"
  table at the bottom of each prompt is the long-term asset. A future
  session that recognises a signature in the table skips the bisect
  entirely.
