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
| E-6 Exploration | ✅ | 24 apps, **266 screenshots** (`docs/usability/screenshots/`), findings F-010..F-042 |
| E-6 re-runs | ✅ | 6 quarantined apps re-graded post-F-002; help/about/notify_center confirmed NOT wiring bugs |
| E-7 Chaos/stress | ✅ | solo + maxchaos + extreme (SMP8) + loop; core robust; found F-050 (timer livelock) + F-040 |
| E-8 fixes (5 done) | ✅/partial | see below |

### E-8 fixes landed (verified by screenshot + boot rc=0 + no self-test regression)
- **F-002** keyboard input-drop — VBox auto-repeat suppressor firing on every host → gated to VBox (`58cef239`)
- **F-022** sysmon CPU graph — added live CPU% sparkline (extend-to-bar) (`d360c415`)
- **F-034** netstatus "STACK NOT INITIALISED" — latent kernel bug: `g_interface_count` never incremented on async bind (`693a083f`)
- **F-016** charmap Latin-1 tofu — latent signedness bug in shared font (`char` vs `u8`) + authored Latin-1 glyphs (`45fba86c`)
- **F-050** timer-IRQ preemption livelock — precisely root-caused, **FILED** (risky timer-path change, 1/4-intermittent, can't verify) → Roadmap + Design-Decisions (`53c4f230`)

**Headline result:** the OS is robust — never crashed under ~30 exploration boots + SMP8
combined chaos (rc=0, 0 panics); graceful OOM. The one real crash (F-050) is
intermittent, load-induced, caught by the recursion guard, and filed with a fix recipe.
Four real usability/correctness fixes landed; each app "flaw" narrated a deeper defect.

## Remaining (resume here)

**E-8 — remaining app fixes** (one root-cause investigation each; fix or extend-to-bar
per the rubric, re-verify every signal; the 5 done above are the pattern to follow):
- **High:** F-018 files type-ahead eaten by single-key shortcuts (note: a design call —
  toolbar buttons already cover the view-switches the letters duplicate) · F-028 settings
  tab-click doesn't switch panels (hit-test; number-keys already work) · F-029 display
  panel read-only / no resolution selector (bigger — needs mode-setting; consider filing) ·
  F-030 sound no volume slider (bigger — needs HDA volume; consider filing).
- **Medium:** F-010/011/012 calculator (no decimal button, hex/binary display, no CE —
  CHECK FIRST whether it's deliberately a programmer's calc before "fixing") · F-017
  charmap (no font selector / no glyph name) · F-019 files (no back/fwd, no date col,
  subdir-descent stub) · F-020 trash (no restore/empty actions) · F-021 hexview (no path
  input) · F-024/025 taskman (no per-proc mem, no col-sort) · F-026 devicemgr (no
  status/driver/names) · F-031 settings (no NTP/button-swap/persist) · F-032 browser
  (no address-bar autofocus) · F-036 terminal prompt-echo artifact.
- **Low:** F-001 wm window-create sentinel · F-014/015 notes dialog/filename · F-023
  sysmon per-core (needs a public `SchedStatsReadCpu` accessor) · F-027 devicemgr tree ·
  F-033 browser taskbar button · F-035 netstatus header clip · F-037 terminal Ctrl+C ·
  F-041 help scrollbar · F-042 notify dismiss.
- **Anti-bloat guard:** extend only to a cited rubric bar; file (Roadmap) anything
  needing a real refactor (like F-050 was).

**E-9 — synthesis:** write `docs/usability/2026-06-07-evaluation.md` (per-surface grade
table + findings + what-fixed/extended/filed + coverage map + comparison verdicts);
flip any `wiki/reference/Win32-Surface-Status.md` rows; amend subsystem wiki; run the
Definition-of-Done scan; finish the branch (PR + CI green).

## How to resume
Everything is committed on `claude/usability-campaign`. The WSL build checkout
(`/root/source/DuetOS`) is at origin/main + this branch's drivers (port via `/mnt/c`,
rebuild before boot). MAX_VMS=6. Re-read this file + `findings.md` + `rubric.md`.
