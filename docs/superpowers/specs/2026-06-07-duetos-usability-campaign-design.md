# DuetOS Usability & Robustness Campaign — Design

**Date:** 2026-06-07
**Status:** Approved design → implementation plan
**Goal:** Drive DuetOS through real use under multi-agent orchestration, grade it against a researched bar (peer OSes + documented Win32), then **actually fix what is broken and extend usability toward that bar.** The written report is the record; the OS-level improvements are the deliverable.

---

## 1. Outcome (what "done" means)

Done is **not** a report. Done is:

1. Every reachable usability surface (desktop, ~25 native apps, settings panels, the PE/Win32 path) has been exercised under live boots and graded.
2. Every concretely-broken thing that surfaced and is feasible this session is **fixed and re-verified live** (CLAUDE.md "Fix Anything You Surface").
3. Where the research bar shows DuetOS falls short of a *defined* expectation (a peer OS or documented Win32 behavior), usability is **extended to meet that bar** — disciplined by the bar, never speculative.
4. Items needing a real refactor are filed as concrete `Roadmap.md` rows with rationale, not vague TODOs.
5. A dated evaluation report records findings, severity, evidence (screenshots + log lines), and comparison verdicts.
6. The campaign tooling is committed and re-runnable.

**Anti-bloat guard on "extend":** an extension is in-scope only if a finding cites a concrete bar — "SerenityOS/Haiku/ReactOS/real-Win32 does X here and DuetOS does not, and X is core to the surface's purpose." No future-proofing, no "while I'm here" features.

## 2. Orchestration — six phases (Approach A + grafts)

Driven from the **WSL checkout** (the only place DuetOS builds — `/mnt/c` cannot build). QEMU + OVMF installed on-demand (`wiki/tooling/Dev-Host-Setup.md`).

| Phase | Name | Fan-out | Output |
|-------|------|---------|--------|
| 0 | Bring-up | serial | green build, toolbox installed, 1 golden boot, baseline screenshot set, `boot-log-analyze` clean baseline |
| 1 | Research | web agents (parallel) | the grading rubric: peer-OS usability bar + Win32 fidelity contract, per surface |
| 2 | Exploration | per-app-cluster agents (parallel) | every app/state driven + screenshotted + graded vs rubric |
| 3 | Chaos/stress | per-vector agents → 1 combined run → loop-until-dry | crash/panic/hang/leak findings with repro |
| 4 | Triage & fix | per-root-cause agents (parallel) | fixes applied + re-verified; extensions landed; Roadmap rows for the rest |
| 5 | Synthesis | serial | report + committed tooling + wiki/Roadmap updates |

**Grafts:** Phase 2 uses Approach-B per-app parallelism; Phase 3 uses Approach-C loop-until-dry (≥2 dry rounds) because intermittent bugs are ASLR/scheduling-sensitive — one clean run is not proof.

**Concurrency:** each parallel agent owns an **isolated QEMU instance** (distinct QMP port, serial-log path, screenshot dir, namespaced via `desktop-qmp-session.sh INSTANCE`). Concurrency is **scaled to host capacity, not fixed** — Phase 0 measures `nproc` + free RAM and computes `MAX_VMS = min(nproc-2, floor(free_MiB / per_guest_MiB))` (≈6–8 on the 8c/16t Ryzen 7840HS host). The user has authorized maxing the host, so the orchestrator runs at `MAX_VMS` and gives each guest SMP (up to SMP8) during the extreme-load sweeps. "Multiple boots" = concurrent VMs *and* sequential re-boots.

## 3. The interaction loop (how an agent "uses" the OS)

Per interaction step:

1. **Send input** — `tools/test/qmp-click.sh` / `qmp-sendkey.sh` / `qmp-sendstring.sh` against the VM's QMP socket.
2. **Capture** — `tools/test/qmp-screendump.sh` → PNG into the agent's screenshot dir.
3. **Observe** — the screenshot is read via vision (usability/visual channel); the serial log is scanned with `boot-log-analyze.sh` (correctness/regression channel — the primary truth source, exits non-zero on a non-deliberate failure).
4. **Grade** — compare observed state to the Phase-1 rubric; emit a finding if it diverges.

The serial log is authoritative for "did it break"; the screenshot is authoritative for "is it usable / does it look right."

## 4. Phase 1 — the grading rubric

Two graded axes per surface, produced by web agents (MS Learn for Win32; project docs/source for SerenityOS, Haiku, ReactOS, Wine):

- **Usability bar** (all surfaces): the minimum a competent equivalent does — e.g. *file manager*: navigate dirs, select, open, rename, delete, multi-select; *calculator*: operator precedence, keyboard entry, error states; *settings*: each panel applies and persists. Grade: **meets / partial / missing / broken**.
- **Win32 fidelity** (PE/Win32 surface only): the documented NT/Win32 contract. "Broken" = diverges from documented Windows behavior, cross-checked against ReactOS/Wine. Grade: **matches / diverges / unimplemented**.

The rubric is a single artifact the exploration + chaos phases grade against, so "broken" is defined before grading begins.

## 5. Phase 2 — exploration (exhaustive)

App clusters (each owned by one agent, its own VM):

- **Productivity:** notes, calendar, clock, calculator, charmap
- **System/files:** files, trash, hexview, imageview, devicemgr, sysmon, taskman
- **Settings:** settings + display/datetime/keyboard/mouse/sound panels (every panel state, apply + persist check)
- **Net/sec:** browser, netstatus, firewall
- **Shell/diag:** terminal, dbg, help, about, screenshot, notify_center

Each agent: launch every app in its cluster, drive the primary workflows, screenshot each meaningful state, exercise window ops (move/resize/minimize/close/relaunch), grade against the rubric. Exhaustive = every app and every settings-panel state, not a representative sample.

## 6. Phase 3 — chaos / stress (all four vectors, solo + combined)

Vectors (each a finalized, committed driver):

- **GUI chaos** (`chaos-gui-driver.py`): random + targeted click/keystroke storms across every app and the desktop; rapid launch-cycling; menu mashing; drag/resize fuzz. Hunts WM crashes, compositor freeze, soft-lockup.
- **PE / real .exe** (`chaos-pe-driver.py`): stage real Windows exes on a FAT32 image (`make-gpt-image.py`) and run them (classic-import set first: help.exe, sort, where, timeout, clip + embedded System32). Hunts loader/import/syscall gaps.
- **Syscall / API fuzz** (`fuzz-all.sh` + host-shim, extended with the guest-reachable audit paths): malformed-arg fuzz of the NT/Win32 + native syscall surface. Hunts panic / W^X / OOB.
- **Resource & FS abuse:** memory/handle exhaustion, deep recursion, FAT32 concurrent writes (`fat32-concurrent.sh`), oversized inputs, rapid alloc/free. Hunts OOM handling, leaks, refcount asymmetry, FS corruption.

**Run plan:** each vector solo first (clean attribution), then the **combined max-chaos run** (all four concurrently) plus **extreme-load sweeps** (SMP4/SMP8, mem pressure). Loop-until-dry: repeat the combined run until **2 consecutive rounds** surface nothing new. Confirmed-intermittent findings re-run ≥3×.

**Class-of-bug watch** (from CLAUDE.md): lost-page/slot collisions, refcount asymmetry, whitelist incompleteness, sentinel divergence, stale-comment drift, log-level abuse. When N similar symptoms appear, trace ONE to root cause.

## 7. Phase 4 — triage & fix

- Cluster findings by suspected root cause; one investigation per cluster (systematic-debugging skill).
- **Fix** the broken where feasible; **extend** to the bar where a finding cites a concrete bar; re-verify by re-running the exact signal that produced the finding (and re-scan the others — build, ctest, clang-format, boot log, fuzz).
- Diagnostic log lines added during a fix stay in, gated to the right `KLOG_*` level; add a `KBP_PROBE` on new failure legs.
- Anything not fixable this session → concrete `Roadmap.md` row.

## 8. Phase 5 — synthesis & deliverables

- **Report:** `docs/usability/2026-06-07-evaluation.md` — per-surface grade, findings table (id/surface/repro/evidence/expected/severity/fix-status), comparison verdicts, coverage map, what-was-fixed vs what-was-filed. (Location is immaterial per user; durable findings still flow into Roadmap + subsystem wiki + `Win32-Surface-Status.md`.)
- **Tooling:** commit the three finalized chaos drivers + a master `tools/test/usability-campaign.sh` orchestrator (parameterized paths/timeouts, dependency-light, `bash -n` clean).
- **Wiki:** flip any REAL/STUB/MISSING rows touched; amend owning subsystem pages; append `Design-Decisions.md` where a fix rules out an alternative.

## 9. Findings & severity model

`id · surface · repro-steps · evidence(screenshot path + log line) · expected(rubric/doc ref) · severity · fix-status(fixed|extended|filed)`

Severity: **Critical** (panic / triple-fault / hang / data-loss) · **High** (app crash / unrecoverable state / security-reachable) · **Medium** (wrong behavior / Win32 fidelity divergence) · **Low** (cosmetic / polish).

## 10. Risks & constraints

- **Build path:** WSL only; `/mnt/c` cannot build. Port changed files to the WSL checkout (`wsl-build` skill); after `cp`, touch the TU or ninja won't rebuild.
- **TCG slowness:** no KVM nesting → long boots; bounded re-run counts; budget the combined-load loop.
- **Bare-metal-gated smokes:** several Win32 surface smokes sit behind `if(!emulator)` in `ring3_smoke.cpp` and never run under QEMU — PE findings may need the freestanding-header **hosted-test** path to pin (kernel32_nls pattern).
- **Host disk:** WSL `EIO (os error 5)` = Windows C: full; check free space before long soaks.
- **Determinism:** intermittent ≠ ignorable. ≥3 runs to confirm; then hunt the class-of-bug shape.
- **QMP GUI limits:** HMP can't headlessly open the Start menu in some paths (exit 75 INCONCLUSIVE); use the proven netpanel-hover analog where Start-menu automation is unreliable.

## 11. Out of scope

- Speculative features with no cited bar.
- Bare-metal / VMware / VBox runs (QEMU-on-WSL is the harness; real-HW findings are noted, not chased, unless a fix needs them).
- Rewriting subsystems wholesale — extensions are bar-sized, not redesigns.
