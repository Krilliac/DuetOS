# DuetOS Usability Findings Ledger

Schema: `id | surface | severity | repro | evidence | expected (rubric ref) | fix-status`

- **Severity:** Critical (panic/triple-fault/hang/data-loss) · High (app crash / unrecoverable / security-reachable) · Medium (wrong behavior / Win32 fidelity divergence) · Low (cosmetic / observability / tooling)
- **fix-status:** open · fixed · extended · filed

| id | surface | severity | repro | evidence | expected | fix-status |
|----|---------|----------|-------|----------|----------|------------|
| F-001 | win32/wm observability | Low | run chaos-pe-driver.py; grep serial log for `[win] create` | 0 occurrences of `[win] create` / `[ui] desktop icon launch`; PE chaos spawn/release tally reads all-zero | WM/desktop launch path should emit a window-create sentinel so spawn/teardown balance is measurable (taskman rubric also wants a live process list) | open |
| F-002 | input/keyboard | Medium | inject keystrokes faster than ~0.18s apart (terminal typing OR start-menu nav) | terminal echo drops/doubles chars (`peek`→`PEK`); start-menu keyboard nav lands one row short (fires wrong app) | **RESOLVED.** Root cause was NOT the compositor lock — it was the kbd-reader's **VirtualBox auto-repeat suppressor** (`KbdReaderTask`, `boot_tasks.cpp:~284`) running on *every* host. Its release→re-press heuristic (eat a same-key press within ~100 ms of its release) cannot tell VBox host auto-repeat from a fast legitimate same-key burst, so it dropped genuine keys everywhere. The 64-byte scancode ring and per-key `DesktopCompose` were NOT the drop site (verified: ring never overflowed for a 6-key burst). **Fix:** gate the suppressor on `HypervisorInfoGet().kind == VirtualBox` (`vbox_auto_repeat`) — the `0xF3` typematic command already kills host auto-repeat on QEMU/KVM/VMware/real-HW. Verified at 0.06 s/key: 6 Down presses all register, correct app opens. | **resolved** |

## E-6 Exploration findings (2026-06-07)

### Root-cause cluster — keyboard input drop (the dominant E-6 issue)

| id | surface | severity | repro | evidence | expected | fix-status |
|----|---------|----------|-------|----------|----------|------------|
| F-003 | start-menu / launch recipe | Low (tooling) | nav SYSTEM submenu via recipe root_steps=2 | landed on UTILITIES (off by one) — `USER APPS` root row is **activatable** because `StartMenuAppsScan` auto-plants `APPS/SAMPLE.MNF` | recipe must count `USER APPS`; OR the auto-planted sample shortcut shouldn't clutter the menu (design Q). | **resolved (was F-002 symptom)** |

**F-002 (the VBox auto-repeat suppressor firing on every host) was the primary root** — it contaminated 9 apps' launches. **F-003 turned out to be a *symptom* of F-002, not a separate nav-table bug:** the "off by one" SYSTEM landing was a *dropped* Down key, not a miscount. Root menu order is `APPS(0) UTILITIES(1) SYSTEM(2) USER APPS(3) … SCREENSHOT POWER` — `USER APPS` sits **after** SYSTEM, so even when it is activatable (the `SAMPLE.MNF` case) SYSTEM stays activatable index **2**. With F-002 fixed, the recipe's `root_steps=2` for SYSTEM apps is correct as-is (verified: firewall + dbg both open correctly). Only the driver's stale root-order *comment* (which omitted `USER APPS`) was corrected; the nav table was already right.

### CONTAMINATED — re-run required after F-002/F-003 fix (NOT defects)

These apps had the wrong window opened by unreliable keyboard nav, so their grades are invalid. Do NOT file them as app defects until re-run:
`imageview` (→Calendar), `calendar` (→Clock), `gfxdemo` (→Clock), `firewall` (→NetStatus), `help` (→Notepad), `about` (→Notepad), `notify_center` (→KernelLog), `dbg` (→DeviceMgr), `logview` (→Terminal). Note: `help`/`about` opening Notepad MIGHT be a real wiring issue OR nav-miss — re-run will disambiguate.

### Trustworthy findings — apps that opened correctly (icon apps + RAISED-confirmed)

Every session below was guest-healthy (boot-log-analyze rc=0, 233 self-tests OK, zero panics — a strong robustness signal: no app crashed the OS).

| id | surface | severity | finding | evidence |
|----|---------|----------|---------|----------|
| F-010 | calculator | Medium | no decimal-point button (grid is 7-9/+ 4-6/- 1-3/* C 0 = /) — can't enter fractions | calculator-open.png |
| F-011 | calculator | Medium | display is opaque hex/binary readout (`0x0 0B0 000`), not a human-readable decimal display | calculator-open.png |
| F-012 | calculator | Medium | no CE (Clear Entry) distinct from C (rubric wants both) | calculator-open.png |
| F-013 | calculator | Low | arithmetic correctness / precedence / divide-by-zero / backspace unverified — generic driver types letters; needs an arithmetic driver | (coverage) |
| F-014 | notes | Low | "UNSAVED CHANGES" dialog body text unreadable (dark-on-near-black); cancel button unlabeled | notes-closed.png |
| F-015 | notes | Low | status bar shows char/word counts but not the filename | notes-enter.png |
| F-016 | charmap | High | Latin-1 Supplement glyphs (U+0080–00FF) all render as notdef/tofu squares — the app's core purpose (browse non-ASCII) is non-functional | charmap-open.png |
| F-017 | charmap | Medium | no font selector; no Unicode name shown for selected glyph (only hex code point) | charmap-open/enter.png |
| F-018 | files | High | type-ahead consumed by single-key global shortcuts — typing 't' jumps to TRASH view instead of filename match; any letter matching a shortcut is destructive | files-typed.png |
| F-019 | files | Medium | no Back/Forward history nav; no modified-date column; subdir descent stubbed ("subdir descent not in v0") despite `[D] SUB` shown | files-open.png |
| F-020 | trash | Medium | trash view (inside Files) has no Restore / Permanently-Delete / Empty-Trash actions exposed | trash-typed.png |
| F-021 | hexview | Medium | file picker is NEXT/PREV blind-scan of `/` only — no path input / no Open dialog; always empty in CI (no files in /) | hexview-open.png |
| F-022 | sysmon | High | "System Monitor" shows only HEAP-USED% + FRAGMENTATION bars — **no CPU graph** (its namesake feature); kernel tracks CPU% (in tray) but the app doesn't surface it | sysmon-open.png |
| F-023 | sysmon | Medium | no per-core breakdown, no scrolling history graph (static bars only) | sysmon-open.png |
| F-024 | taskman | Medium | process list has PID/NAME/STATE/CPU%/TICKS but **no per-process memory** column (only system-total) | taskman-open.png |
| F-025 | taskman | Medium | sort is S-key CPU% only; no clickable column-header sort / asc-desc indicator | taskman-open.png |
| F-026 | devicemgr | Medium | no device status column, no bound-driver name, no human-readable device names (raw VID:DID only) | devicemgr-open.png |
| F-027 | devicemgr | Low | flat list grouped by bus, not a collapsible hierarchical tree | devicemgr-open.png |
| F-028 | settings | High | tab-strip click (GEN/DSP/SND/KBD/MSE/DT) does not reliably switch panels in live use (hit-test/focus issue); number-key switching works but is undiscoverable | settings-tab-dsp.png |
| F-029 | settings/display | High | Display panel is read-only info — no resolution selector / apply / revert-timeout; no wallpaper picker | settings-05-dsp.png |
| F-030 | settings/sound | High | Sound panel only toggles UI-cue mute + PC-speaker beep — no master volume slider, no HDA output volume | settings-08-snd.png |
| F-031 | settings | Medium | no NTP toggle (datetime); no primary/secondary button-swap (mouse); persist-across-reopen unverified for most panels (keyboard typematic is the only one with explicit session-restore hooks) | settings panels |
| F-032 | browser | Medium | address bar does not auto-focus on open — keyboard-first URL entry fails (Enter on launch does nothing); browser self-test confirms FetchUrl works (301→200) | browser-open.png |
| F-033 | browser | Low | browser window has no taskbar button while open (can't click-to-raise/alt-tab from the bar) | browser-open.png |
| F-034 | netstatus | High | shows "NO BOUND INTERFACES — STACK NOT INITIALISED" even though the net stack is operational (arp/wifi/dhcp self-tests pass; e1000 gets SLIRP 10.0.2.15) — GUI not reading the live interface table | netstatus-open.png |
| F-035 | netstatus | Low | column header row clipped at right edge (FW-DRO truncated); no horizontal scroll | netstatus-open.png |
| F-036 | terminal | Medium | typed chars echo the prompt prefix into the line (`TDUETOS>TEDUETOS>...`) — prompt re-render leaks into echo under per-keystroke timing (may share F-002 root) | terminal-typed.png |
| F-037 | terminal | Low | Ctrl+C not advertised as interrupt (only Ctrl+Shift+C copy); shell command set is DuetOS-native, not POSIX (ls/cd/cat/echo unconfirmed) | terminal-open.png |

**Coverage note:** interaction-dependent criteria (multi-select, rename, kill-process, sort, apply+persist) are largely UNVERIFIED because the generic explore driver only types "test"+Enter. These need per-app interaction drivers for full grading — recorded as a coverage gap, not graded pass/fail.

## E-6 re-run results (post-F-002 fix) — quarantine cleared

All 6 quarantined apps re-run with reliable nav. **help/about/notify_center confirmed NOT wiring bugs** — they open real HELP / ABOUT DUETOS / NOTIFICATIONS windows; the earlier Notepad/KernelLog results were pure F-002 nav-contamination. Re-grades:

| app | result | grade |
|-----|--------|-------|
| calendar | RAISED CALENDAR; meets ALL Productivity criteria (today highlighted, grid aligned, prev/next, label, today-button, add-event modal) | meets |
| gfxdemo | RAISED GFX DEMO; plasma renders, mode cycle, live frame counter | clean pass |
| help | RAISED HELP; real quick-reference + type-to-filter | meets (F-041 Low) |
| about | RAISED ABOUT DUETOS; OS name+version+commit+uptime+stats | clean pass |
| notify_center | RAISED NOTIFICATIONS; 11-item history + CLR | meets (F-042 Low) |
| logview | RAISED KERNEL LOG; live log stream | clean pass |

### New findings from re-runs + E-7 chaos

| id | surface | severity | finding | evidence |
|----|---------|----------|---------|----------|
| F-040 | kernel/sched stability | High (intermittent) | hung-task soft-panic during a calendar session (1/2 runs): `selftest-42` stuck ~0x65 ticks → BSOD before window raised. Under load; likely shares a root with F-050. | calendar run-1 serial |
| F-041 | help | Low | overflowing help content has no visible scrollbar (type-to-filter is the only nav) | help-open.png |
| F-042 | notify_center | Low | dismiss (CLR/X) mechanism present but not exercised by generic driver — coverage gap | notify_center-open.png |
| F-050 | kernel/arch traps + mm/slab | **High (intermittent)** | **runaway timer-IRQ trap recursion panic under sustained resource pressure.** LAPIC timer (vec 0x20) nested 9× in `win-timer#43` at `TrapDispatch+0x1453` (traps.cpp:870), preceded by `mm.heap_alloc_fail` in `GrowOneSlab` (slab.cpp:153). Recursion guard caught it → controlled panic (no triple-fault). 1/4 maxchaos runs; 0/3 loop rounds; 0 under SMP8 extreme. Hypothesis: slab-grow-under-pressure leaves IRQs disabled / skips LAPIC EOI so timer IRQ nests. | maxchaos round-1 resource serial |

### E-7 robustness positives (recorded, not findings)

- Solo vectors: pe/syscall/resource rc=0; gui's only task-kill was LINUX.ELF (a deliberate non-Win32 ELF #PF, recovered cleanly).
- maxchaos rounds 2 & 3: all 4 vectors rc=0. Extreme (SMP8 + combined): rc=0.
- Mem stress: KMalloc returned null at 65 GiB and the system kept running (graceful OOM, no crash).
- SMP-sweep "ATTENTION"s were TCG AP-bringup timeouts (test-rig timing), not kernel bugs.
- **Verdict: the core is robust; the one real crash (F-050) is intermittent, load-induced, and caught by the recursion guard.**

## Reference: desktop icon coordinate map (from T-4)

Icon grid (`kernel/drivers/video/desktop_icons.cpp`): origin (20,24), stride 96×92, cell-center +42,+42. Registration order (`kernel/core/boot_bringup.cpp`): index 0..8 = Computer/Files, Browser, Terminal, Calculator, Notepad, Settings, Device Mgr, Trash, Help. So the 9 icon-launchable apps and their click centers:

| app | icon label | ICON_X | ICON_Y |
|-----|-----------|--------|--------|
| files | Computer | 62 | 66 |
| browser | Browser | 62 | 158 |
| terminal | Terminal | 62 | 250 |
| calculator | Calculator | 62 | 342 |
| notes | Notepad | 62 | 434 |
| settings | Settings | 62 | 526 |
| devicemgr | Device Mgr | 62 | 618 |
| trash | Trash | 62 | 710 |
| help | Help | 62 | 24+8*92+42=802 (off-screen at 768h → row wraps to col 2) |

**Gap for E-6:** only these ~9 apps have desktop icons. The remaining apps (calendar, clock, charmap, sysmon, taskman, netstatus, firewall, imageview, hexview, about, screenshot, notify_center, dbg) are NOT icon-launchable — E-6 must add a **Start-menu launch strategy** (click the "DUET" taskbar button, then the app entry) by extending explore-app-driver with a start-menu mode. Help's icon may wrap to a second column (y=802 exceeds 768) — verify its real position.
