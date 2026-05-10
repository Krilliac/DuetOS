# Compositor and Window Manager

> **Audience:** Compositor / WM authors, GDI thunk authors
>
> **Execution context:** Kernel — compositor runs in the focused-window's draw pass
>
> **Maturity:** v0 painting + windowing; popup menus shipped, modal dialogs deferred

## Overview

The compositor and window manager live in `kernel/drivers/video/`
(`widget.cpp`, `theme.cpp`, framebuffer primitives). They are
**in-kernel** for hot-path latency. Userland reaches them via
`SYS_WIN_*` (window lifecycle) and `SYS_GDI_*` (pixel primitives).

`kMaxWindows = 16`.

## What Paints Today

Native DuetOS apps and Win32 PE windows compose into the same
framebuffer:

- **Native apps** (`kernel/apps/`): Calculator, Notepad, Files, Task
  Manager, Kernel Log, Clock, GFX Demo, About / System Info, Help,
  Calendar, Image Viewer, Browser (HTTP only), Trash. Each is an
  in-kernel native app, registered via a `ThemeRole` enum entry +
  per-theme palette extension; the compositor scans the role table
  on every recompose and the Start menu's `/APPS/*.MNF` enumerator
  raises the matching window when a manifest specifies
  `target=<role>`.
- **Win32 PE windows**: `windowed_hello` paints with `Rectangle` /
  `Ellipse` / `DrawTextW` / `FillRect`, dispatches `WM_PAINT` /
  `WM_TIMER` / `WM_LBUTTONDOWN` through a user-registered `WndProc`,
  round-trips `SendMessage`, queries focus / styles / sys palette,
  exits cleanly.

The compositor renders into a virtio-gpu scanout (kernel framebuffer)
and the present hook flushes per compose. See
[Graphics Drivers](../drivers/Graphics-Drivers.md).

## Window Manager Surface

`SYS_WIN_*` syscall family (numbers ~58..61):

- `SYS_WIN_CREATE` — `user32!CreateWindowExA/W`
- `SYS_WIN_SHOW` — `user32!ShowWindow`
- `SYS_WIN_MSGBOX` — `user32!MessageBoxA/W`
- `SYS_WIN_DESTROY` — `user32!DestroyWindow`

The kernel-side handlers route into the compositor in
`kernel/drivers/video/widget.cpp`. The blue-titled "WINDOWED HELLO"
window in the screenshots comes from a real PE issuing
`SYS_WIN_CREATE` / `SYS_WIN_SHOW`.

## GDI Surface

`SYS_GDI_*` syscall family for pixel primitives:

- Filled-ellipse compositor prim (parity between window-HDC and
  memDC).
- Window-DC `SetTextColor` honors explicit-black.
- `BitBlt` for blitting back buffers (used by the DirectX v0 path).

## Themes

`kernel/drivers/video/theme.cpp` is a flat token table sampled by the
window registry, taskbar, console, and cursor backing on every
recompose. See [Graphics Drivers > Themes](../drivers/Graphics-Drivers.md#themes)
and [Duet Theme Spec](../specifications/Duet-Theme-Spec.md).

`Ctrl+Alt+Y` (or `theme=<name>` on the kernel cmdline / `theme <name>`
in the kernel shell) hot-swaps every chrome colour.

## Mouse Wheel

`MousePacket::dz` is captured by the PS/2 driver
(`ps2mouse.cpp`) and the xHCI HID decode
(`xhci_input.cpp`) and surfaced to consumers via
`WindowDispatchWheel(hwnd, client_x, client_y, dz, screen_x, screen_y, mk_buttons)`
in `widget.{h,cpp}`. The dispatcher fans out:

- **PE owners** — posts `WM_MOUSEWHEEL` (`0x020A`) with the
  Win32-canonical `wparam = (i16(dz * 120) << 16) | mk_buttons`,
  `lparam = (screen_y << 16) | screen_x`. Standard Win32
  message-pump handling applies.
- **Native owners** — calls the per-window `WindowWheelFn`
  registered via `WindowSetWheelHandler`. v1 consumers: Files
  (selection step), Notes (cursor step), Browser (body /
  selection scroll), ImageView (next/prev image).

The kernel's mouse loop clamps `|dz| <= 8` per packet to defang
fast-wheel runaway and recomposes after each dispatch.

## Double-Click

Press-edge double-click detection lives in
`kernel/core/main.cpp` mouse loop. Fires on two press edges
within `kDblClickTicks` (50 ticks @ 100 Hz ≈ 500 ms) at the
same pixel on the same HWND. Three independent detectors:

- **PE client area** — posts `WM_LBUTTONDBLCLK` (`0x0203`).
- **Native client area** — calls per-app `OnDoubleClick(cx, cy)`
  (`FilesOnDoubleClick` opens row by extension;
  `BrowserOnDoubleClick` follows a bookmark; others are no-ops).
- **Title bar (any window)** — toggles
  `WindowMaximize` / `WindowRestore`. The detector lives in the
  chrome branch so it short-circuits the drag-start.

## Cursor Shapes

`cursor.{h,cpp}` carries eight 12×20 sprite tables — `Arrow`,
`IBeam`, `Hand`, `Wait`, `ResizeNS`, `ResizeEW`, `ResizeNESW`,
`ResizeNWSE` — selectable via `CursorSetShape(s)`. The mouse
loop runs a hit-test on every packet:

- Within `kWindowResizeBorderPx` (4 px) of a window corner →
  `ResizeNWSE` (top-left / bottom-right) or `ResizeNESW`
  (top-right / bottom-left)
- Within 4 px of a window edge → `ResizeNS` (top/bottom) or
  `ResizeEW` (left/right)
- Over a button widget → `Hand`
- Over Notes / Browser client area → `IBeam`
- Otherwise → `Arrow`

The change-gate (`if (new != current)`) keeps the per-packet
test cheap when the shape doesn't change. `CursorPushWait()` /
`CursorPopWait()` are refcounted hooks for long-running
operations (used by `screenshot.cpp` around the FAT32 streaming
write); the pre-Wait shape is restored on the last balance.

## Modal Dialogs

`dialog.{h,cpp}` carries a single-instance `MessageBox` /
`InputBox` primitive. The API is fire-and-forget: callers pass
a `DialogResultFn` callback that fires from the kbd-reader
thread once the user resolves the dialog. Synchronous spin
would deadlock the readers themselves, so the design avoids
blocking entirely.

- `MessageBoxOpen(title, body, cb, user)` — OK/Cancel.
- `InputBoxOpen(title, prompt, default_text, cb, user)` —
  single-line edit field, `kDialogInputMax = 64` bytes.
- `DialogIsActive()` — lets the kbd / mouse routers redirect
  input. While a dialog is up: every keystroke goes to
  `DialogFeedKey` / `DialogFeedChar`; every press_edge goes
  to `DialogOnPress`. Menus, app shortcuts, app routing all
  skipped.
- `DialogCompose()` — paints a 50% theme-coloured dim over the
  desktop + a centred 400×140 panel + OK/Cancel buttons. Drawn
  from `DesktopCompose` after every other surface so it lands
  above chrome and tooltips.

Consumers in v1: Files rename (`InputBox` → `Fat32RenameAtPath`);
Notes dirty-close (`MessageBox` "Discard unsaved changes?"
replaces the prior two-step Alt+F4 prompt).

## Scrollbar

`scrollbar.{h,cpp}` is a pure visual indicator. Apps call
`ScrollbarPaint(x, y, w, h, {total, visible, first})` from
their `DrawFn`; the painter draws a track + proportional
thumb. v1 doesn't implement drag-the-thumb interactivity —
wheel dispatch covers the common scroll case; click-on-track
jump-to is deferred. Files (FAT32 list) and Browser (body
view) integrate today; Notes / Help skipped because their
content fits the typical render area.

## Tooltips

Hover a button widget for ≥ 1 second (100 ticks at 100 Hz)
and the next compose paints the widget's label in a small
pale-yellow panel near the cursor. State lives in `widget.cpp`
(`g_tooltip_widget`, `g_tooltip_arm_tick`); the mouse loop
calls `WidgetTooltipTrack(cx, cy, now_tick)` every packet,
and `DesktopCompose` calls `WidgetTooltipRender()` after
chrome but before modal dialogs.

## Window Edge + Corner Resize

A 4-px hit band along each window border flips the cursor to
the matching shape (`ResizeEW` / `ResizeNS` for edges,
`ResizeNESW` / `ResizeNWSE` for corners) on hover and starts a
resize-drag on press. Corner zones win over single-edge zones
in the hit-test. The drag preserves the press-time anchor
bounds and feeds cursor deltas through `WindowResizeFromEdge`
(which composes `apply_top` / `apply_bottom` /
`apply_left` / `apply_right` so corner edges resize on both
axes simultaneously). Clamps to a minimum 80 × 60 size and the
framebuffer extents. The title bar takes priority over the
top edge — clicks in the title still drag-to-move, not
drag-to-resize.

## Notification History

`notify.{h,cpp}` retains the last 16 distinct toasts displayed
via `NotifyShowFor` / `NotifyShowKindFor`. Duplicate
`(text, kind)` pushes coalesce so a service that fires the
same toast every second doesn't burn through the ring; a
different-kind push of the same text DOES land so an operator
sees an Info→Warning→Error transition. The history is exposed
via `NotifyHistoryCount()` + `NotifyHistoryGet(idx, out, cap)`
+ `NotifyHistoryGetKind(idx)` + `NotifyHistoryClear()`.
Consumers:

- `Ctrl+Shift+N` in `kernel/core/main.cpp` — dumps the ring to
  the framebuffer console between two banner lines.
- **Notification Center** (`kernel/apps/notify_center.cpp`) —
  windowed reader. Bindings: J/K Up/Down navigate, PageUp /
  PageDown step by 8, Home / End jump to newest / oldest, X /
  Del clears the ring (MessageBox confirm). A 3-px coloured
  stripe at each row's left edge encodes the severity:
  blue (Info), green (Success), amber (Warning), red (Error).

### Toast Severity (`NotifyKind`)

`NotifyKind::Info` (default) paints with the theme's taskbar
accent so the toast reads as system chrome. `Success` uses a
dark green, `Warning` a dark amber, `Error` a dark red — all
paired with a 1-px theme-coloured border. Callers pick the
kind through `NotifyShowKind(text, kind)` /
`NotifyShowKindFor(text, kind, ttl)`. `NotifyShow` and
`NotifyShowFor` continue to default to `Info` so existing call
sites are unchanged. Failure paths (screenshot write, file
load / rename, trash move, calendar / notes save) ship with
`NotifyKind::Error`; the matching success arm uses
`NotifyKind::Success`.

## First-Run Welcome

After login completes (post-greeter, post-banner-Console
write), main.cpp fires a one-shot `NotifyShowFor("Welcome to
DuetOS - press F1 for shortcuts", 8)` with extended TTL. The
static gate (`s_welcome_shown`) makes it strictly per-boot;
TTY mode skips the toast since toasts don't paint there.

## Chrome Polish

Recent compositor work:

- Window gradient title bars
- X-glyph close button
- Taskbar gradient strip
- Rounded START button + tabs
- Active-tab accent
- Drop shadow primitive
- Round-rect outline primitive
- Filled circle primitive

## Network Flyout

Bottom-right Wi-Fi-style popup with hover preview, exposing the
network state from `kernel/net/`. The flyout reads the live `netifs`
list and per-NIC TX/RX byte counters; a single tick polls each path
state and refreshes the per-row tooltip without blocking the main
compose pass.

## Popup Menus

The compositor owns a single global popup menu primitive
(`kernel/drivers/video/menu.{h,cpp}`) used by:

- **Native menus**: Start menu, desktop right-click,
  per-window right-click, title-bar (NC) right-click system
  menu, and the Files-app per-row context menu.
- **PE TrackPopupMenu**: USER32's `TrackPopupMenu` /
  `TrackPopupMenuEx` marshal the userland HMENU into a fixed
  request struct and issue `SYS_WIN_TRACK_POPUP` (173). The
  syscall opens the same kernel menu primitive with a sentinel
  context value, blocks the calling task on a Mutex+Condvar,
  and returns the chosen `action_id` (or 0 = cancel) to userland.

Capabilities of the primitive:

- Up to `kMenuMaxStack = 4` nested panels (root + 3 submenus).
- Hover highlight tracked via `MenuTrackHoverAt(cx, cy)` from
  the mouse-reader on every packet; a recompose is forced when
  the cursor moves while a menu is open.
- Keyboard navigation via `MenuFeedKey(vk)` from the
  kbd-reader: Up / Down move the highlight, Enter activates
  the hovered item, Esc closes the whole menu, Right opens a
  submenu, Left pops one panel (or closes at root).
- Per-item flags: `kMenuItemFlagDisabled`, `kMenuItemFlagChecked`,
  `kMenuItemFlagSubmenu`, `kMenuItemFlagSeparator`.

Right-click dispatch in the mouse-reader (`kernel/core/main.cpp`):

| Cursor target | Menu opened |
|---|---|
| Title bar of any window | System menu (Restore / Move / Size / Min / Max / Close) |
| Body of a kernel-app window | Enriched window menu (Raise + Min/Max/Restore/Close) |
| Body of a PE window | No kernel menu — `WM_CONTEXTMENU` (0x007B) is posted to the PE |
| Body of the Files app | Per-row context menu (Open / Rename(GAP) / Delete / Properties) |
| Desktop background | Desktop menu (Help / About / Cycle / List / TTY) |

PE apps process `WM_CONTEXTMENU` in their `WndProc` — `wparam` is
the receiving HWND, `lparam` packs screen X/Y. They typically
reply by calling `TrackPopupMenu(TPM_RETURNCMD, x, y, 0, hwnd, NULL)`
and acting on the returned id.

Action-id allocation:

| Range | Owner |
|---|---|
| 1–6 | Desktop menu |
| 10–11 | Window menu (Raise / Close legacy) |
| 20–25 | System menu (NC) — Restore / Move / Size / Min / Max / Close |
| 30–33 | Files app row menu |
| 100–199 | ThemeRole launchers (Calculator, Notes, …) |
| 200+ | `/APPS/*.MNF` shortcuts |
| ≥ 0x10000 | PE-app dynamic ids (opaque to kernel) |

## Known Limits / GAPs

- **No GDI paint inside the client area for unfiled Win32 PEs** —
  `BitBlt` / `TextOut` / `Rectangle` work in the right context but
  the client area defaults to a no-op fill.
- **Per-window message queues**: `GetMessage` / `PeekMessage` return
  `WM_QUIT` for unhandled paths so event-driven programs exit their
  pump immediately.
- **Keyboard / mouse routing to the focused window**: input still
  goes to the native console even when a Win32 PE is focused.
- **Submenu marshaling across `SYS_WIN_TRACK_POPUP`**: GAP. PE
  apps that need nested menus call `TrackPopupMenu` recursively
  from their `WM_COMMAND` handler.
- **Concurrent `TrackPopupMenu` from two PE processes**: serialise
  on the single-instance kernel menu — the second caller cancels
  with action_id = 0 and returns immediately.
- **PE `SetCursor`**: GAP. Native windows can change cursor
  shape via `CursorSetShape`, but PE apps have no
  `SYS_GDI_SETCURSOR` to request a shape change. Cursor shape
  is owned entirely by the kernel hit-test today.
- **ImageView zoom**: Ctrl+wheel and `+` / `-` keys zoom by
  resizing the window; `FitThumbnail` reflows the image into
  the new content area on next decode. No independent
  zoom-without-resize state — pan is implicit through window
  position.
- **Drag-and-drop between windows**: not in scope. Needs a
  per-window drop-target registry, a `kDraggingItem` global,
  and ghost-image rendering during drag — more invasive than
  any single-app feature.
- **Audio feedback / system sounds**: gated on HDA codec
  programming (Roadmap.md). PC speaker exists but is not
  wired to any UI event.
- **PE `SetCursor` ABI**: gated on a new `SYS_GDI_*` syscall.
  Native windows can change cursor shape via `CursorSetShape`,
  but PE apps have no equivalent.
- **Settings GUIs (Display / Sound / Keyboard / Mouse /
  Date-Time)**: each is its own slice per CLAUDE.md.
- **Trash / ramfs mode in Files**: only FAT32 mode has a v0
  context menu; other modes fall through to the kernel-window menu.
- **Win32 common controls, outline fonts, multi-threaded
  message queues**: still on the windowing track's deferred
  list. (Native modal dialogs ship via `dialog.{h,cpp}` —
  `MessageBox` / `InputBox`; native scrollbars ship via
  `scrollbar.{h,cpp}` with full hit-test + drag-the-thumb
  wiring in the kernel mouse loop.)

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md)
- [Win32 DLLs](Win32-DLLs.md) — `user32`, `gdi32`
- [Graphics Drivers](../drivers/Graphics-Drivers.md)
- [DirectX v0 Path](DirectX.md)
- [Duet Theme Spec](../specifications/Duet-Theme-Spec.md)
