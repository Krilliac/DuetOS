# DuetOS Usability Campaign — Status & Resume Point

**As of 2026-06-07.** Branch: `claude/usability-campaign`. Spec + plan:
`docs/superpowers/specs/2026-06-07-duetos-usability-campaign-design.md`,
`docs/superpowers/plans/2026-06-07-duetos-usability-campaign.md`.

## Done (committed)

| Phase | Status | Artifact |
|-------|--------|----------|
| T-1 Bring-up | ✅ | golden baseline (`docs/usability/baseline/`), `boot-log-analyze` rc=0, MAX_VMS=6 |
| E-2 Research rubric | ✅ | `docs/usability/rubric.md` (peer-OS bar + Win32 fidelity, 6 web agents) |
| T-3 Chaos drivers | ✅ | `chaos-gui/pe/shot-probe` committed, smoked |
| T-4 Explore+syscall drivers | ✅ | `explore-app-driver.py`, `chaos-syscall-driver.py`; icon map traced |
| E-6 prep launch | ✅ | start-menu nav + `launch-recipes.md`; `explore-settings-driver.py` |
| T-5 Orchestrator | ✅ | `tools/test/usability-campaign.sh` + `DUETOS_SMP` pass-through |
| E-6 Exploration | ✅ | 24 apps, **266 screenshots** (`docs/usability/screenshots/`), findings F-010..F-037 |
| E-8 (pulled fwd) F-002 fix | ✅ | keyboard input-drop fixed (`58cef239`) — the linchpin; unblocks the quarantined apps |

**Headline result so far:** the OS never crashed under ~30 boots of exploration +
input storms (every `boot-log-analyze` rc=0, 0 panics) — robust core. Usability
gaps are in the apps, not stability. One real fix landed (dropped-keystroke bug).

## Remaining (resume here, ideally in fresh sessions — these are large)

1. **Re-run 6 quarantined apps** now that F-002 is fixed: `calendar`, `gfxdemo`,
   `help`, `about`, `notify_center`, `logview`. (3 already re-confirmed: imageview,
   firewall, dbg all open correctly.) Disambiguate whether help/about really open
   Notepad (wiring bug) or were just nav-misses. Use:
   `EXPLORE_APP=<app> EXPLORE_LAUNCH=startmenu ... explore-app-driver.py`, convert
   PPM→PNG, vision-grade vs `rubric.md`, file real findings.
2. **E-7 chaos/stress** (`tools/test/usability-campaign.sh`): vectors solo →
   `maxchaos` → `extreme` (SMP8 + mem pressure) → loop-until-2-dry. File crash/hang
   findings. The drivers + orchestrator are built and smoked; just run the phases.
3. **E-8 fix/extend the real app findings** (one root-cause investigation each;
   fix or extend-to-bar per the rubric, re-verify every signal). High-value targets
   by severity:
   - **High:** F-016 charmap Latin-1 glyphs render as tofu · F-018 files type-ahead
     eaten by single-key shortcuts · F-022 sysmon has no CPU graph (its namesake) ·
     F-028 settings tab-click doesn't switch panels · F-029 display panel read-only
     (no resolution selector) · F-030 sound panel has no volume slider · F-034
     netstatus says "STACK NOT INITIALISED" while the stack is up.
   - **Medium:** F-010/011/012 calculator (no decimal button, opaque display, no CE) ·
     F-017 charmap (no font selector / no glyph name) · F-019 files (no back/fwd, no
     date col, subdir stub) · F-020 trash (no restore/empty) · F-021 hexview (no path
     input) · F-024/025 taskman (no per-proc mem, no col-sort) · F-026 devicemgr (no
     status/driver/names) · F-031 settings (no NTP/button-swap/persist) · F-032
     browser (no address-bar autofocus) · F-036 terminal prompt echo.
   - **Anti-bloat guard:** extend only to a cited rubric bar; file (Roadmap) anything
     needing a real refactor.
4. **E-9 synthesis**: write `docs/usability/2026-06-07-evaluation.md`; flip
   `wiki/reference/Win32-Surface-Status.md` rows; amend subsystem wiki; run the
   Definition-of-Done scan. Then finish the branch (PR + CI green).

## How to resume
Everything is committed on `claude/usability-campaign`. The WSL build checkout
(`/root/source/DuetOS`) is at origin/main + this branch's drivers (port via `/mnt/c`,
rebuild before boot). MAX_VMS=6. Re-read this file + `findings.md` + `rubric.md`.
