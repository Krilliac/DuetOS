# DuetOS Usability Findings Ledger

Schema: `id | surface | severity | repro | evidence | expected (rubric ref) | fix-status`

- **Severity:** Critical (panic/triple-fault/hang/data-loss) · High (app crash / unrecoverable / security-reachable) · Medium (wrong behavior / Win32 fidelity divergence) · Low (cosmetic / observability / tooling)
- **fix-status:** open · fixed · extended · filed

| id | surface | severity | repro | evidence | expected | fix-status |
|----|---------|----------|-------|----------|----------|------------|
| F-001 | win32/wm observability | Low | run chaos-pe-driver.py; grep serial log for `[win] create` | 0 occurrences of `[win] create` / `[ui] desktop icon launch`; PE chaos spawn/release tally reads all-zero | WM/desktop launch path should emit a window-create sentinel so spawn/teardown balance is measurable (taskman rubric also wants a live process list) | open |
| F-002 | input/keyboard | Low (unconfirmed) | rapid `sendkey` storm into terminal (chaos-syscall-driver) | terminal echo occasionally drops/doubles a char (`peek`→`PEK`) under fast keystrokes | every keystroke registers exactly once; needs confirming whether guest-side (PS/2 input ring under rapid input — cf. prior ps2 ring-overflow notes) or QMP harness pacing. Confirm during E-7. | open |

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
