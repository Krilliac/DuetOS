# End-user onboarding & launcher v0

_Type: Observation + Decision._
_Last updated: 2026-05-01._

## Why

Until this slice the kernel booted, the user logged in (defaults
admin/admin or guest/empty are printed on the login panel), and
landed on a desktop with seven pre-registered windows visible —
but with no discoverable way to launch / re-raise an app, no
visible record of the global keyboard shortcuts (which had grown
to a dozen+), and no orientation banner past the first compose.

The Start menu existed but only carried four diagnostic items
(`ABOUT / CYCLE / LIST / PING`); none of them launched anything.

## What landed

Four small wires that turn the existing chrome into something a
fresh user can actually *use* without reading the source:

### 1. `ThemeRoleWindow(role)` getter — `kernel/drivers/video/theme.{h,cpp}`

Public lookup that hands back the `WindowHandle` previously
registered for a `ThemeRole` (Calculator / Notes / TaskManager /
LogView / Files / Clock / GfxDemo). Returns `kWindowInvalid` if
the role was never registered or the handle is no longer alive.

The boot sequence already calls `ThemeRegisterWindow(role, h)`
for every native app it spawns; the new getter is the
read-side of the same table. Caller is the Start-menu launcher
dispatch — kept intentionally narrow so this isn't a generic
service registry.

### 2. Start menu = launcher

`kStartItems[]` rewritten to expose every native boot app plus a
HELP item, an existing CYCLE WINDOWS item, and ABOUT (10 entries
total — well under the bumped `kMaxItems = 12`). Each launcher
item carries `action_id = 100 + role_index`; the dispatch handler
recognises the `100..199` band, calls `ThemeRoleWindow(role)`,
and on a hit walks `WindowSetVisible(h, true)` +
`WindowRaise(h)` so even apps hidden by Show Desktop or a
min-button click come back to the front.

The desktop right-click menu got a HELP item too (id 6, same
target as the Start menu's HELP).

`kMaxItems` in `menu.cpp` bumped from 8 to 12 to fit the launcher
list. Static-storage `MenuItem[]` are still file-local; the cap
only governs how many copies the menu stores when open.

### 3. Help / shortcuts overlay = `PrintShortcutHelp()`

File-local helper in `main.cpp`'s anon namespace dumps a
formatted block into the framebuffer console covering:

  - **Getting started** (Start, taskbar tabs, drag, close, shell help)
  - **Windows** (Alt+Tab, Ctrl+Alt+arrow snap, Ctrl+Alt+Shift+arrow
    resize, Ctrl+Alt+,/. opacity)
  - **Desktop / system** (F1, Ctrl+Alt+T tty, Ctrl+Alt+B dock,
    Ctrl+Alt+L lock, Ctrl+Alt+Y / 1..9 themes, Ctrl+Alt+F1/F2,
    Ctrl+C interrupt)

Two callers fan into it:

  - **F1 (no modifiers)** — new branch in the kbd reader,
    tested *before* the existing `Ctrl+Alt+F1` console-flip so
    bare F1 doesn't also flip the render target.
  - **Start menu HELP item** (action id 6) — same payload, and
    the post-dispatch recompose makes the text appear immediately
    rather than waiting on the 1 Hz ui-ticker.

### 4. Post-login orientation banner + immediate recompose

  - When the login gate deactivates, a single line lands in the
    console pointing at the discovery surfaces:
    `WELCOME TO DUETOS. CLICK [START] OR PRESS F1 FOR A SHORTCUT REFERENCE.`
  - After `MenuClose()` the dispatch path now issues a
    `CursorHide` / `DesktopCompose` / `CursorShow` triple so any
    output the action wrote (HELP, `-> RAISED Calculator`, etc.)
    is visible inside one frame instead of the up-to-1-second
    ui-ticker latency.

## Action-id band convention

A shared band keeps the launcher table additive: future native
apps allocate the next role slot in `ThemeRole`, and the menu
just gets a new label entry — no per-app `case` in the dispatch
switch.

| Range  | Meaning                                |
|--------|----------------------------------------|
| 1..99  | Existing system actions (ABOUT=1, CYCLE=2, LIST=3, PING=4, TTY=5, HELP=6, RAISE=10, CLOSE=11) |
| 100..199 | "Raise window for ThemeRole(action - 100)" |
| 200+   | Reserved for future bands (per-window context, etc.) |

## Files touched

- `kernel/drivers/video/theme.h` — `ThemeRoleWindow` decl
- `kernel/drivers/video/theme.cpp` — getter impl (alive-check guarded)
- `kernel/drivers/video/menu.cpp` — `kMaxItems` 8 -> 12
- `kernel/core/main.cpp` — `PrintShortcutHelp()`, F1 handler,
  rewritten `kStartItems` + `kDesktopMenuItems`, `case 6` + the
  100..199 launcher band in the action switch, post-dispatch
  recompose, post-login orientation banner.

## Non-goals

- No new syscall. ABI is unchanged — this is all kernel-internal
  chrome wiring.
- No "first-run wizard." The orientation banner is one line, not
  a multi-step splash. If the user dismisses it (any console
  scroll), F1 still works.
- No localisation; the help text is hardcoded ASCII. Aligns with
  the rest of the kernel's user-facing strings.
- No app-window position memory beyond what `WindowRaise` /
  `WindowSetVisible` already give. Closing windows is still a
  one-way operation (no respawn from the launcher) — the Start
  menu raises, doesn't re-instantiate.

## Verification

- `cmake --preset x86_64-release && cmake --build build/x86_64-release`
  links cleanly with `-Werror`.
- `clang-format --dry-run --Werror` passes for all four touched
  files.
- No live-boot smoke run — the changes only add new dispatch
  branches and a console writer; no new IRQ paths, no new syscall
  numbers, no new boot-time state. Visual verification deferred
  to next QEMU smoke.
