# DuetOS Usability Campaign — Per-App Launch Recipes

This is the launch recipe the Phase 2 exploration fan-out follows. Every
desktop app is reachable by one of two mechanisms, both driven by
`tools/test/drivers/explore-app-driver.py` (env `EXPLORE_LAUNCH`):

- **`icon`** — double-click the app's desktop icon at
  `(EXPLORE_ICON_X, EXPLORE_ICON_Y)`. Only the 9 registered desktop
  icons have this path.
- **`startmenu`** — keyboard-navigate the built-in Start menu. Works for
  **every** registered app. The driver looks the app up in its
  `LAUNCH_NAV` table and emits the sendkey sequence below.

## Start-menu mechanism (why it's the most reliable)

The built-in Start menu (`kernel/core/boot_tasks.cpp`, opened by the
taskbar **DUET** button or **Ctrl+Esc**) is a nested submenu structure.
Keyboard navigation is fully wired (`kernel/drivers/video/menu.cpp`
`MenuFeedKey` → dispatch in `boot_tasks.cpp` L486-507):

- **Ctrl+Esc** toggles the menu; on open the kernel **auto-hovers the
  first activatable row** (root row 0 = APPS).
- **Down/Up** move the highlight, **wrapping** and **skipping separators
  and disabled rows** (`MenuMoveHover`). So step counts are measured in
  *activatable rows only* and stay stable regardless of separator
  placement.
- **Right** opens the highlighted submenu; the submenu also auto-hovers
  its first activatable row (row 0).
- **Enter** activates the highlighted row → `DispatchMenuAction`.

Pure `sendkey` — no pixel-targeting of menu geometry — which makes it far
more robust than clicking menu rows. The driver now uses **0.09 s per
keypress** (only to let QEMU's HMP flush each `sendkey` before the next).

> **F-002 fixed.** The original driver needed **0.18 s** because the
> kbd-reader's VirtualBox auto-repeat suppressor ran on *every* host and
> ate any same-key re-press inside ~100 ms of its release. A faster burst
> (0.06–0.08 s) landed one row short and opened the WRONG app (e.g. fired
> CLOCK instead of IMAGE VIEWER). That suppressor is now gated to
> VirtualBox only (`kernel/core/boot_tasks.cpp` `KbdReaderTask`,
> `vbox_auto_repeat`), so on QEMU / KVM / VMware / real hardware fast
> keystrokes are delivered verbatim — the 0xF3 typematic command already
> disables host auto-repeat there. Verified: 6 fast Down presses at
> 0.06 s/key now all register and IMAGE VIEWER opens correctly.

### Sequence

```
ctrl-esc                 # open menu, root auto-hovers row 0 (APPS)
down  × root_steps       # highlight the target submenu
right                    # open it, submenu auto-hovers row 0
down  × sub_steps        # highlight the target app
ret                      # activate
```

### Root menu order (activatable rows)

`USER APPS` is disabled+skipped on a normal boot (no `/APPS` shortcuts),
so it is **not** counted in `root_steps`:

| root_steps | submenu      |
|-----------:|--------------|
| 0          | APPS         |
| 1          | UTILITIES    |
| 2          | SYSTEM       |
| 3          | SCREENSHOT (leaf action, not a window) |
| 4          | POWER        |

## Per-app recipe table

`icon X Y` = `EXPLORE_LAUNCH=icon EXPLORE_ICON_X=X EXPLORE_ICON_Y=Y`.
`startmenu` rows give `(root_steps, sub_steps)` — the driver's `LAUNCH_NAV`
key is the `EXPLORE_APP` value.

Icon centres derive from the grid in
`kernel/drivers/video/desktop_icons.cpp` (origin 20,24; col stride 96; row
pitch 92; tile centre +42,+42; 7 icons/column) and the registration order
in `kernel/core/boot_bringup.cpp` L3641-3649.

| App (EXPLORE_APP) | ThemeRole / action | Icon recipe | Start-menu recipe (root→sub) |
|-------------------|--------------------|-------------|------------------------------|
| files             | Files (Computer icon) | `icon 62 66`   | startmenu APPS→FILES (0,2) |
| browser           | Browser            | `icon 62 158`  | startmenu APPS→BROWSER (0,5) |
| terminal          | Terminal           | `icon 62 250`  | startmenu UTILITIES→TERMINAL (1,2) |
| calculator        | Calculator         | `icon 62 342`  | startmenu APPS→CALCULATOR (0,0) |
| notes / notepad   | Notes              | `icon 62 434`  | startmenu APPS→NOTEPAD (0,1) |
| settings          | Settings           | `icon 62 526`  | startmenu SYSTEM→SETTINGS (2,0) |
| devicemgr         | DeviceMgr win (act 61) | `icon 62 618` | startmenu SYSTEM→DEVICE MANAGER (2,6) |
| trash             | Files/Trash view (Trash icon) | `icon 158 66` | (no menu entry — opens Files) |
| help              | Help               | `icon 158 158` | startmenu APPS→HELP (0,9) |
| clock             | Clock              | — (no icon)    | startmenu APPS→CLOCK (0,3) |
| calendar          | Calendar           | — (no icon)    | startmenu APPS→CALENDAR (0,4) |
| imageview         | ImageView          | — (no icon)    | startmenu APPS→IMAGE VIEWER (0,6) |
| gfxdemo           | GfxDemo            | — (no icon)    | startmenu APPS→GFX DEMO (0,7) |
| about             | About              | — (no icon)    | startmenu APPS→ABOUT (0,8) |
| hexview           | HexView            | — (no icon)    | startmenu UTILITIES→HEX VIEWER (1,0) |
| charmap           | CharMap            | — (no icon)    | startmenu UTILITIES→CHARACTER MAP (1,1) |
| taskman           | TaskManager        | — (no icon)    | startmenu SYSTEM→TASK MANAGER (2,1) |
| sysmon            | Sysmon             | — (no icon)    | startmenu SYSTEM→SYSTEM MONITOR (2,2) |
| logview           | LogView            | — (no icon)    | startmenu SYSTEM→KERNEL LOG (2,3) |
| notify_center     | NotifyCenter       | — (no icon)    | startmenu SYSTEM→NOTIFICATIONS (2,4) |
| netstatus         | NetStatus win (act 60) | — (no icon) | startmenu SYSTEM→NETWORK STATUS (2,5) |
| firewall          | Firewall win (act 62)  | — (no icon) | startmenu SYSTEM→FIREWALL (2,7) |
| dbg / debugger    | Dbg win (act 63)   | — (no icon)    | startmenu SYSTEM→DEBUGGER (2,8) |

### Apps with no GUI window (intentionally excluded from the fan-out)

- **screenshot** — root `SCREENSHOT` (action 50) is a one-shot capture, not
  a window. It is not an "openable app"; the exploration grader should
  treat it as an action, not a launch target.

## Validation evidence (2026-06-07)

Three non-icon apps launched via `EXPLORE_LAUNCH=startmenu` and
vision-confirmed open from the post-launch screendump:

| App     | Serial confirmation        | Window seen on screen |
|---------|----------------------------|-----------------------|
| clock   | `RAISED CLOCK` (action 0x69)| digital clock 11:52:43 + CLOCK/STOP/ALRM/TIMR tabs |
| charmap | `RAISED CHARACTER MAP` (0x74)| full glyph grid + RNGE/COPY + "U+FE (254)" |
| sysmon  | `RAISED SYSTEM MONITOR` (0x72)| UPTIME/POOL header + HEAP%/FRAGMENTATION graphs |

The icon path was regression-checked: `EXPLORE_LAUNCH=icon EXPLORE_APP=files`
still opens the FILES window (Computer icon double-click → DISK:/ listing).
