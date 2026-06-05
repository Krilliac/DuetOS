# Start Menu

> **Audience:** Kernel hackers, UI / shell contributors
>
> **Execution context:** Kernel — built and dispatched from the input
> readers in `kernel/core/main.cpp`, runs in process context
>
> **Maturity:** active — root + submenus + `/APPS` manifest shortcuts
> shipped; per-open rebuild keeps dynamic content fresh

The Start menu is the user's primary launcher and the seat of
session-level controls (Lock, Log Out, Reboot, Shut Down). It is
anchored to the START button on the taskbar and built fresh each
time the menu opens, so freshly-dropped `/APPS/*.MNF` shortcuts
appear without a reboot.

## Layout

The root has six rows; submenus are at most ten rows so each
panel fits inside the menu renderer's twelve-item-per-panel cap
(`kMaxItems` in `kernel/drivers/video/menu.cpp`).

```
START
├── APPS ▸          CALCULATOR, NOTEPAD, FILES, CLOCK, CALENDAR,
│                   BROWSER, IMAGE VIEWER, GFX DEMO, ABOUT, HELP
├── SYSTEM ▸        SETTINGS, TASK MANAGER, KERNEL LOG,
│                   NETWORK STATUS, DEVICE MANAGER, FIREWALL,
│                   ───, CYCLE WINDOWS, SWITCH TO TTY
├── USER APPS ▸     /APPS/*.MNF shortcuts (≤ 12, disabled when empty)
├── ───
├── SCREENSHOT      Capture-to-FAT32 trigger (no hotkey required)
└── POWER ▸         LOCK, LOG OUT, ───, REBOOT, SHUT DOWN
```

## Action ID allocation

The dispatch handler is `DispatchMenuAction` in
`kernel/core/main.cpp`; new bands extend the switch.

| Band      | Use                                              |
|-----------|--------------------------------------------------|
| `1..39`   | Misc commands (1=ABOUT, 2=CYCLE, 5=TTY, 6=HELP, 10/11=RAISE/CLOSE, 20-25=system menu, 30-33=Files context). |
| `40..49`  | Power / session: 40=REBOOT, 41=SHUT DOWN, 42=LOCK, 43=LOG OUT. |
| `50..59`  | System shortcuts: 50=SCREENSHOT.                 |
| `60..69`  | Bespoke viewer windows (no ThemeRole today): 60=NETWORK STATUS, 61=DEVICE MANAGER, 62=FIREWALL. |
| `100..199`| Open app by ThemeRole (id = 100 + role index).   |
| `200..255`| `/APPS` shortcut slots resolved through `StartMenuAppsResolveLaunch`. |

## Constraints

- **12 items per panel.** The menu renderer silently drops rows
  past index 11. Any flat list longer than 12 entries must be
  split into a submenu before it lands.
- **4-level nesting cap.** `kMenuMaxStack` in `menu.h` allows
  the root plus up to three submenus. Keep submenus shallow.
- **No icons, no native section headers.** Visual grouping is
  separators (`kMenuItemFlagSeparator`) and disabled rows.
- **Per-open rebuild.** The kernel rebuilds `kStartItems` every
  time the user clicks START, so dynamic content (USER APPS) is
  always fresh.

## Known Limits / GAPs

- **Hard 12-item panel cap.** Rows past index 11 are silently
  dropped by the renderer (`kMaxItems`), not scrolled — a panel that
  overflows loses entries with no warning. Split into a submenu.
- **No icons or native section headers.** Grouping is limited to
  separators and disabled rows; there is no glyph/icon column.
- **No search / type-to-filter.** The launcher is click-to-navigate
  only.
- **USER APPS capped at 12 shortcuts.** `/APPS/*.MNF` entries beyond
  the 12th are not shown.

## Relevant files

- `kernel/core/main.cpp` — root + submenu tables, dispatch.
- `kernel/drivers/video/menu.{h,cpp}` — renderer + hit-test.
- `kernel/drivers/video/start_menu_apps.{h,cpp}` — `/APPS`
  manifest scanner.
- `kernel/apps/{netstatus,devicemgr,firewall}.{h,cpp}` — the
  bespoke viewers backing actions 60/61/62.
- `kernel/security/login.{h,cpp}` — `LoginLock` (action 42)
  and `LoginReopen` (action 43).
- `kernel/power/reboot.{h,cpp}` — `KernelReboot` (action 40)
  and `KernelHalt` (action 41).
