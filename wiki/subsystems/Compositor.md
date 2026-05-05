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

`cursor.{h,cpp}` carries four 12×20 sprite tables — `Arrow`,
`IBeam`, `Hand`, `Wait` — selectable via `CursorSetShape(s)`.
The mouse loop runs a hit-test on every packet:

- Over a button widget → `Hand`
- Over Notes / Browser client area → `IBeam`
- Otherwise → `Arrow`

The change-gate (`if (new != current)`) keeps the per-packet
test cheap when the shape doesn't change. `CursorPushWait()` /
`CursorPopWait()` are refcounted hooks for long-running
operations (used by `screenshot.cpp` around the FAT32 streaming
write); the pre-Wait shape is restored on the last balance.

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
- **Interactive Move / Size from the system menu**: GAP. Win32's
  Move / Size enter a modal-input state that follows the cursor
  until the next click; we don't have modal input. Move
  one-shot-recenters the window under the cursor as a degraded
  stand-in; Size is shown disabled.
- **Submenu marshaling across `SYS_WIN_TRACK_POPUP`**: GAP. PE
  apps that need nested menus call `TrackPopupMenu` recursively
  from their `WM_COMMAND` handler.
- **Concurrent `TrackPopupMenu` from two PE processes**: serialise
  on the single-instance kernel menu — the second caller cancels
  with action_id = 0 and returns immediately.
- **Files-app rename**: GAP. No text-input modal exists yet; the
  RENAME row notifies "rename: not in v0 UI". A modal-text-input
  primitive replaces the notify when it lands.
  `Fat32RenameAtPath` is already in tree (`kernel/fs/fat32.h`);
  only the dialog half is missing.
- **Common dialogs (MessageBox / InputBox)**: GAP. The "discard
  unsaved changes?" prompt for Notes is a two-step Alt+F4
  pattern (notify on first press, close on second within 3 s).
  A real synchronous modal dialog primitive would replace this
  in a follow-up slice.
- **PE `SetCursor`**: GAP. Native windows can change cursor
  shape via `CursorSetShape`, but PE apps have no
  `SYS_GDI_SETCURSOR` to request a shape change. Cursor shape
  is owned entirely by the kernel hit-test today.
- **Resize cursors + edge-drag-to-resize**: not in scope for
  v1. The cursor enum has slots for `IBeam` / `Hand` / `Wait`
  but no resize variants because no consumer would set them
  (windows still rely on `Ctrl+Alt+Shift+Arrow` for resize).
- **Notes wheel = cursor step, not viewport scroll**: a viewport
  scroll requires tracking visible-row offset state in the draw
  loop; v1 maps wheel ticks to `MoveUp`/`MoveDown` calls. Works
  for a typical 4 KiB Notes buffer; a longer document would
  need real viewport tracking.
- **ImageView wheel = next/prev only**: zoom is deferred until
  ImageView grows zoom state.
- **Trash / ramfs mode in Files**: only FAT32 mode has a v0
  context menu; other modes fall through to the kernel-window menu.
- **Modal dialogs, common controls, scroll bars, outline fonts,
  multi-threaded message queues**: all on the windowing track's
  deferred list.

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md)
- [Win32 DLLs](Win32-DLLs.md) — `user32`, `gdi32`
- [Graphics Drivers](../drivers/Graphics-Drivers.md)
- [DirectX v0 Path](DirectX.md)
- [Duet Theme Spec](../specifications/Duet-Theme-Spec.md)
