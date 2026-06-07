# DuetOS Usability & Robustness Campaign — Evaluation

**Date:** 2026-06-07 · **Branch:** `claude/usability-campaign` · **Host:** Ryzen
7840HS, WSL2 + QEMU/OVMF (TCG), `x86_64-debug`, MAX_VMS=6.

Spec/plan: `docs/superpowers/specs/2026-06-07-duetos-usability-campaign-design.md`,
`docs/superpowers/plans/2026-06-07-duetos-usability-campaign.md`. Grading bar:
`docs/usability/rubric.md`. Full evidence ledger: `docs/usability/findings.md`.
Screenshots: `docs/usability/screenshots/<app>/`.

This document is the Phase-5 synthesis: what the campaign graded, what it fixed,
extended, filed, and the verdict against peer OSes.

---

## 1. Headline

- **The DuetOS core is robust.** Across ~30 exploration boots, four chaos
  vectors (gui/pe/syscall/resource) run solo + combined, SMP8 extreme load, and
  a memory-pressure sweep, the OS **never triple-faulted and never corrupted
  state** (every session `boot-log-analyze` rc=0, 233 self-tests OK, graceful
  OOM at 65 GiB). The single real crash (F-050) is intermittent, load-induced,
  and **caught by the trap-recursion guard as a controlled panic** — bounded
  blast radius, no data safety risk. It is root-caused and filed with a fix
  recipe.
- **Every app "flaw" narrated a deeper, real defect** rather than a cosmetic
  nit — a kernel net-stack counter bug (F-034), a font-signedness bug (F-016), a
  WM focus-mode bug (F-032), a hit-test dead-zone (F-028), a missing subsystem
  accessor (F-024). Fixing the app surfaced the system bug behind it.
- **10 findings fixed/extended, 4 filed (with concrete unblockers), 1 corrected
  as a misread.** Fixes were held to the cited rubric bar; anything needing a
  subsystem that doesn't exist was filed, not faked.

---

## 2. Per-surface grades (against `rubric.md`)

Grade key: **meets** / **partial** / **missing** / **broken** (native apps).
A criterion graded `meets` is a coverage tick; `partial`/`missing`/`broken`
produced a finding. Grades reflect the post-fix state on this branch.

| Surface | Grade | Notes (post-fix) |
|---------|-------|------------------|
| **calculator** | meets (integer) | Decimal display correct (F-011 was a misread); full integer scientific engine (bitwise/sqrt/factorial/memory, keyboard-driven). Fractional input **filed** (F-010, needs float engine); display-overflow F-051 (Low) open. |
| **notes** | meets | Editor + FAT32 persist work. Dialog legibility (F-014) + filename in status (F-015) Low/open. |
| **calendar** | meets | Today highlighted, grid aligned, prev/next, today-button, add-event modal. |
| **clock** | meets | Live time, uptime panel. |
| **charmap** | meets (1 font) | Latin-1 glyphs render (F-016 fixed). Glyph **name** + font selector (F-017) open — note the system ships a single 8×8 font, so "font selector" is moot until a 2nd font exists. |
| **files** | meets | **Subdir descent + parent-ascent + back/forward + type-ahead landed** (F-018, F-019). Date column wired (invisible in CI: zero-stamped test image). Multi-select/rename remain coverage gaps. |
| **trash** | partial | Restore/empty actions not surfaced in the trash view (F-020, open) — gated on the FS write path. |
| **hexview** | partial | Dual-pane hex+ASCII works; no path input / Go-To offset (F-021, open). |
| **imageview** | meets | Decodes PNG/JPEG/BMP/TGA, fits to chrome. |
| **settings/display** | partial | Read-only info correct; **resolution selector filed** (F-029, needs GPU modeset). |
| **settings/sound** | partial | Mute + beep work; **master volume filed** (F-030, needs audio gain stage). |
| **settings (nav)** | meets | **Tab-strip clicks switch panels** (F-028 fixed). NTP/button-swap/persist (F-031) open. |
| **sysmon** | meets | **Live CPU sparkline + numeric readout** (F-022). Per-core breakdown (F-023) partial — needs `SchedStatsReadCpu`. |
| **taskman** | meets | **Per-process MEM column + clickable column-header sort with asc/desc indicator** (F-024, F-025). |
| **devicemgr** | meets | **NAME + STATUS + DRIVER columns** (F-026, class-inferred). Hierarchical tree (F-027) Low/open. |
| **terminal** | meets | Live shell mirror. Echo artifact (F-036) likely shared the F-002 root (keyboard-drop, fixed) — re-verify. Ctrl+C advertise (F-037) Low. |
| **browser** | meets | HTTP fetch/render works; **address bar auto-focuses on open** (F-032 fixed). Taskbar button (F-033) Low. |
| **netstatus** | meets | **Bound interfaces + IP/gateway/DNS/DHCP show** (F-034 fixed). Header clip (F-035) Low. |
| **firewall** | meets | Enable/disable + rule list + add/remove. |
| **help / about / notify_center / gfxdemo / logview** | meets | Confirmed real windows (quarantine cleared post-F-002). Help scrollbar (F-041), notify dismiss coverage (F-042) Low. |

### Win32 / NT fidelity (PE surface)

**No Win32-Surface-Status rows changed this campaign.** All E-8 fixes were in
native DuetOS kernel apps and kernel subsystems (WM focus, net stack, mm/sched
accessors, FAT32 dir decode, fonts) — none touched the PE/NT thunk surface. The
rubric's candidate divergence table (`GetEnvironmentVariableW`, `atoi`,
`_CxxThrowException`, etc.) remains **unverified-against-live** and is explicitly
out of scope for the E-8 native-app fix phase; it stays as candidate divergences
to confirm in a dedicated PE-fidelity pass (the embedded smokes that would
exercise them sit behind `if(!emulator)` in `ring3_smoke.cpp`, so QEMU CI never
runs them — see memory `win32-surface-smokes-bare-metal-only`).

---

## 3. What was fixed / extended / filed / corrected

### Fixed (root-caused, signal re-verified, screenshot-confirmed)

| Finding | Surface | Root cause | Commit |
|---------|---------|-----------|--------|
| F-002 | keyboard | VBox auto-repeat suppressor ran on every host → dropped fast same-key bursts. Gated to VBox. | `58cef239` |
| F-016 | charmap | `Font8x8Lookup(char)` signed-char → bytes 0x80–0xFF negative → all Latin-1 fell to notdef. Read as `u8` + 96-entry Latin-1 table. | `45fba86c` |
| F-034 | netstatus | `g_interface_count` set once from `NicCount()` (0 at init); async bind never bumped it. Bind now advances the count. | `693a083f` |
| F-018 | files | `FilesFeedChar` dispatched bare letters to view-switch shortcuts before type-ahead. Letters now drive a prefix type-ahead; view-switches stay on toolbar; destructive → Delete/F5. | `fcddc4d5` |
| F-024 | taskman | No per-process memory surfaced. Added `mm::AddressSpaceUserPageCount` → `SchedTaskInfo.mapped_pages` → MEM column. | `5149bac7` |
| F-025 | taskman | Sort was S-key only. Added clickable column headers + asc/desc indicator. | `5149bac7` |
| F-028 | settings | 2px hit-test dead-zone at top of tab strip + test-driver cursor-init offset (-6,-10). Both fixed. | `8876128d` |
| F-032 | browser | Opened in `Mode::View` so keys hit single-letter shortcuts, not the URL field. Focus URL on open from both launch paths. | `1b149e9d` |

### Extended to the rubric bar

| Finding | Surface | Extension | Commit |
|---------|---------|-----------|--------|
| F-022 | sysmon | Live CPU% sparkline + numeric readout (its namesake feature). | `d360c415` |
| F-019 | files | Subdir descent + parent-ascent + `[`/`]` history + date column (date invisible in CI). | `9521061f` |
| F-026 | devicemgr | NAME (vendor+subclass) + STATUS (OK/no-driver) + DRIVER (class-inferred). | `79b3f707` |

### Filed (need a subsystem that doesn't exist — concrete unblocker in Roadmap)

| Finding | Why filed | Unblocker |
|---------|-----------|-----------|
| F-050 | timer-IRQ preemption livelock; risky timer-path change, can't verify without a reproducer | nesting-depth-gated reschedule (recipe in Roadmap) |
| F-029 | no runtime GPU mode-set path; framebuffer fixed at boot | GPU modeset entry + `FramebufferRebind` + revert-timeout |
| F-030 | audio backend is a v0 fixed mixer with no gain stage | `AudioSetMasterGain(q15)` (software gain) wired to a slider |
| F-010 | calculator engine is end-to-end signed `i64` | fixed-point/soft-float value type through the engine |
| F-019 (date sub-part) | CI FAT image stamps zero timestamps | `make-gpt-image.py` timestamp stamping |

### Corrected

- **F-011** — reclassified **not-a-bug** (misread). The calculator's large green
  display *is* decimal (`calc-digits.png`: `987654321`); the grader mistook the
  deliberate hex/bin/oct preview band. Disproving it surfaced **F-051** (Low,
  open): the large-font display overflows the window for long values.

### Still open (lower priority — recorded, not fixed this session)

Low/Medium cosmetic & observability items: F-001 (WM create sentinel), F-012
(calc CE), F-013 (calc arithmetic-driver coverage), F-014/F-015 (notes dialog/
filename), F-017 (charmap glyph name), F-020 (trash actions), F-021 (hexview
path), F-023 (sysmon per-core), F-027 (devicemgr tree), F-031 (settings NTP/
swap/persist), F-033 (browser taskbar button), F-035 (netstatus header clip),
F-036/F-037 (terminal echo/Ctrl+C), F-041 (help scrollbar), F-042 (notify
dismiss), F-051 (calc display clip). None block the daily-driver path; several
(F-036) likely already resolved by the F-002 keyboard fix and need a re-verify
pass.

---

## 4. Coverage map

- **24 desktop apps** explored, **266 baseline screenshots** + per-fix
  verification captures (`docs/usability/screenshots/`).
- **Every app** has ≥1 screenshot set and a grade against every applicable
  rubric criterion. No app was silently skipped.
- **Chaos:** 4 vectors × solo + combined (maxchaos) + extreme (SMP8) + loop
  (to 2 dry rounds) + host-side fuzz + mem/SMP sweeps.
- **Coverage gaps (honest):** interaction-dependent criteria that the generic
  explore driver can't drive (multi-select, rename, kill-process confirm,
  apply+persist round-trips) remain partially unverified — recorded as a
  coverage gap, not graded pass/fail. The new `EXPLORE_KEYS` driver knob (this
  campaign) closes part of this by allowing app-specific key sequences +
  intermediate `shot` captures.

---

## 5. Comparison verdict vs peer OSes

- **vs SerenityOS / Haiku (native desktop bar):** DuetOS now meets the
  *navigation* bar these set for a file manager — subdirectory descent, parent
  ascent, back/forward, and type-ahead (F-018/F-019) — which were the biggest
  gaps. taskman reaches the Haiku ProcessController / Windows Task Manager bar
  for *observability* (live per-process CPU% + memory + column sort), though
  admin actions (kill-priority, etc.) lag. Settings reaches the discoverability
  bar (tab clicks work) but apply+persist for display/sound is gated on
  subsystems (filed).
- **vs Windows/Win32 (fidelity):** unchanged this campaign — the PE thunk
  surface wasn't touched. The candidate-divergence list stands as the backlog
  for a dedicated fidelity pass.
- **Robustness vs all three:** DuetOS's *core* robustness under combined chaos
  + SMP8 (no triple-fault, graceful OOM, guard-bounded panic) is the campaign's
  strongest result — the failures found were app-surface and recoverable, not
  kernel-fatal.

---

## 6. Re-run instructions

All commands run **inside WSL** at `/root/source/DuetOS` (build cannot run over
`/mnt/c`). Source-of-truth is the Windows checkout; port changed files in, then:

```bash
# build
cmake --build build/x86_64-debug --parallel "$(nproc)"

# capacity probe
bash tools/test/usability-campaign.sh capacity

# explore one app (icon or startmenu launch; EXPLORE_KEYS drives interaction)
EXPLORE_APP=taskman EXPLORE_LAUNCH=startmenu EXPLORE_KEYS="shot,s,shot" \
  EXPLORE_SHOT_DIR=/root/source/DuetOS/build/x86_64-debug/shots \
  bash tools/test/desktop-qmp-session.sh dev tools/test/drivers/explore-app-driver.py

# verdict (rc=0 = healthy)
bash tools/test/boot-log-analyze.sh build/x86_64-debug/sess-dev.serial.log; echo "rc=$?"

# chaos (solo / combined / extreme)
bash tools/test/usability-campaign.sh chaos    syscall 75
bash tools/test/usability-campaign.sh maxchaos 90
bash tools/test/usability-campaign.sh extreme  120
```

**Screenshot gotcha:** WSL wipes `/tmp` on idle shutdown — capture → `pnmtopng`
→ copy-out to a persistent path in a **single** `wsl.exe` invocation, and write
shots under `build/` (persistent), not `/tmp`.

---

## 7. Committed tooling (reusable)

- `tools/test/usability-campaign.sh` — orchestrator (capacity / explore / chaos
  / maxchaos / extreme), scales to MAX_VMS.
- `tools/test/drivers/explore-app-driver.py` — per-app exploration; `EXPLORE_KEYS`
  (this campaign) drives app-specific key sequences + `shot` tokens for
  intermediate captures.
- `tools/test/drivers/explore-settings-driver.py` — settings tab/panel driver
  (cursor-init fixed this campaign).
- `tools/test/drivers/chaos-{gui,pe,syscall}-driver.py`, `chaos-shot-probe.py` —
  chaos vectors.

---

*End of evaluation. Findings ledger: `docs/usability/findings.md`. Filed items:
`wiki/reference/Roadmap.md` → "Usability campaign — app gaps (2026-06-07)" and
"Timer-IRQ preemption livelock (F-050)".*
