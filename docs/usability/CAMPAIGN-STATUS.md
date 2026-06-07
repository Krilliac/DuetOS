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
| E-8 fixes | ✅ | 11 fixed/extended + 4 filed + 1 corrected — see below |
| E-9 Synthesis | ✅ | `docs/usability/2026-06-07-evaluation.md` written; Kernel-Apps + Design-Decisions + Roadmap synced; DoD scan clean (no stale refs, final boot rc=0); PR opened |

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

## E-8/E-9 outcome (2026-06-07)

**Fixed/extended (10 this phase + F-002/016/022/034 prior = 11 total apps touched):**
F-018 files type-ahead · F-019 files subdir-descent+back/fwd+date · F-024 taskman
per-proc MEM · F-025 taskman column sort · F-026 devicemgr name/status/driver ·
F-028 settings tab-click · F-032 browser autofocus (+ F-022 sysmon CPU, F-016
charmap, F-034 netstatus, F-002 keyboard from the prior session).

**Filed (need a subsystem that doesn't exist — concrete unblocker in Roadmap):**
F-010 calc decimals (float engine) · F-029 display resolution (GPU modeset) ·
F-030 sound volume (audio gain stage) · F-019-date-subpart (image-builder
timestamps) · F-050 timer livelock (prior).

**Corrected:** F-011 (misread — display IS decimal) → surfaced F-051 (Low, calc
display overflow, open).

**Still open (lower-priority, recorded not fixed):** F-001, F-012, F-013, F-014,
F-015, F-017, F-020, F-021, F-023, F-027, F-031, F-033, F-035, F-036, F-037,
F-041, F-042, F-051 — none block the daily-driver path; see the evaluation §3.

**Report:** `docs/usability/2026-06-07-evaluation.md`. **Win32-Surface-Status:**
no rows flipped (all fixes were native apps / kernel subsystems, not the PE
surface). **DoD scan:** no stale wiki refs, final boot rc=0, STUB/GAP honest
(F-019 removed the descent stub).

## Remaining (if a future session continues)

The open findings above are the backlog (mostly Low cosmetic / observability).
**Anti-bloat guard still applies:** extend only to a cited rubric bar; file
(Roadmap) anything needing a real refactor. F-036 (terminal echo) likely already
resolved by the F-002 keyboard fix — needs a quick re-verify pass.

## How to resume
Everything is committed on `claude/usability-campaign`. The WSL build checkout
(`/root/source/DuetOS`) is at origin/main + this branch's drivers (port via `/mnt/c`,
rebuild before boot). MAX_VMS=6. Re-read this file + `findings.md` + `rubric.md`.
