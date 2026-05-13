# UI Toolkit

> **Audience:** UI / app contributors, theme authors, kernel-app authors
>
> **Execution context:** Kernel — compositor runs as a kernel task; widget
> ops are called from the compositor thread
>
> **Maturity:** v0 — windows + buttons + dialogs + taskbar + notify +
> drag-drop functional; TTF text + accessibility primitives wired

## Overview

The DuetOS UI toolkit lives mostly under
[`kernel/drivers/video/`](../../kernel/drivers/video/). Despite the
"drivers" path, only the framebuffer and console TUs are real drivers —
the rest are toolkit widgets that paint into the framebuffer the
driver exposes. Keeping them next to the driver is intentional: every
widget consumes the framebuffer, the cursor, and the input router, so
they live one `cd` from their dependencies.

The architecture:

```
   kernel apps   PE app (via Win32)   native ELF apps (via Win32 thunks)
        |               |                       |
        +---------------+-----------------------+
                        |
                  Compositor               <-- DesktopCompose() orchestrator
                        |
   chrome + taskbar + tray + menu + dialog + drag-drop + tooltips + notify + cursor
                        |
                    Framebuffer driver
                        |
                  Live pixels on screen
```

The compositor is the single owner of pixel writes. Apps never touch
the framebuffer directly; they paint into chrome-owned client rects,
and the compositor flushes through damage rects.

## File Layout

### Drivers

| File | Purpose |
|------|---------|
| [`framebuffer.h`](../../kernel/drivers/video/framebuffer.h) / `.cpp` | Linear framebuffer (32-bpp A:R:G:B). Primitives: `Clear`, `FillRect`, `PutPixel`. Damage-rect tracking. |
| [`console.h`](../../kernel/drivers/video/console.h) / `.cpp` | 80×40 character grid, bitmap font, auto-scroll. Kernel log mirror. |
| [`cursor.h`](../../kernel/drivers/video/cursor.h) / `.cpp` | 12×20 mouse sprite; per-theme colours; show/hide/move. |
| [`display_info.h`](../../kernel/drivers/video/display_info.h) / `.cpp` | Screen metrics + compose state flag. |

### Window Chrome and Compositor

| File | Purpose |
|------|---------|
| [`widget.h`](../../kernel/drivers/video/widget.h) / `.cpp` | Window registry (16 windows max), button registry, Z-order, hit-test, drag handles. `WindowChrome` struct. |
| `widget.h`/`DesktopCompose()` | The master paint orchestrator — desktop → wallpaper → taskbar → calendar → menus → console → widgets → dialog → tooltips → DnD → cursor. |
| [`taskbar.h`](../../kernel/drivers/video/taskbar.h) / `.cpp` | App tabs + clock + tray. |
| [`tray_flyout.h`](../../kernel/drivers/video/tray_flyout.h) / `.cpp` | System tray expanded panel. |
| [`netpanel.h`](../../kernel/drivers/video/netpanel.h) / `.cpp` | Tray network indicator. |

### Panels and Overlays

| File | Purpose |
|------|---------|
| [`menu.h`](../../kernel/drivers/video/menu.h) / `.cpp` | Context / start menu. |
| [`dialog.h`](../../kernel/drivers/video/dialog.h) / `.cpp` | Modal dialogs — OK/Cancel, text input. |
| [`modal_input.h`](../../kernel/drivers/video/modal_input.h) / `.cpp` | Focus + input routing for modal panes. |
| [`notify.h`](../../kernel/drivers/video/notify.h) / `.cpp` | Toast notifications with TTL (default 3 sec at 1 Hz compose). |
| [`scrollbar.h`](../../kernel/drivers/video/scrollbar.h) / `.cpp` | Generic scroll bar widget. |
| [`dnd.h`](../../kernel/drivers/video/dnd.h) / `.cpp` | Drag-and-drop with per-window drop targets and preview. |
| [`magnifier.h`](../../kernel/drivers/video/magnifier.h) / `.cpp` | Zoom-and-pan accessibility overlay. |
| [`calendar.h`](../../kernel/drivers/video/calendar.h) / `.cpp` | Calendar tray widget. |
| [`render_stats.h`](../../kernel/drivers/video/render_stats.h) / `.cpp` | Debug overlay — frame time, damage rect size, allocations per frame. |

### Text and Assets

| File | Purpose |
|------|---------|
| [`font8x8.h`](../../kernel/drivers/video/font8x8.h) / `.cpp` | 8×8 bitmap ASCII font (case-folded lowercase → uppercase). |
| [`ttf.h`](../../kernel/drivers/video/ttf.h) / `.cpp` | TrueType parser. |
| [`ttf_raster.h`](../../kernel/drivers/video/ttf_raster.h) / `.cpp` | TrueType outline rasteriser. |
| [`svg.h`](../../kernel/drivers/video/svg.h) / `.cpp` | Static SVG parser for icons + the device theme spec. |
| [`wallpaper.h`](../../kernel/drivers/video/wallpaper.h) / `.cpp` | Desktop wallpaper renderer. |
| [`theme.h`](../../kernel/drivers/video/theme.h) / `.cpp` | Theme engine — colour palettes, chrome look, cursor colours. |
| [`sound_cue.h`](../../kernel/drivers/video/sound_cue.h) / `.cpp` | Audio cue player tied to UI events (click / error / notify). |

### Start-Menu Integration

| File | Purpose |
|------|---------|
| [`start_menu_apps.h`](../../kernel/drivers/video/start_menu_apps.h) / `.cpp` | App registry the start menu reads — each entry is `{name, icon, launch_callback}`. |

The Start menu itself is documented at
[Start Menu](../kernel/Start-Menu.md). Kernel apps register themselves
into this table at init time; the Start menu paints the list.

## Window Chrome

`WindowChrome` is the per-window state:

```cpp
struct WindowChrome {
    i32       x, y, w, h;
    u32       border, title_color, client_color, close_btn_color;
    u8        title_height;
    bool      visible, active;
    char      title[64];
    void*     owner;          // app handle
};
```

Registry operations:

```cpp
WindowHandle WindowRegister(WindowChrome);     // returns opaque ID
bool         WindowMoveTo(WindowHandle, x, y);
WindowHandle WindowTopmostAt(x, y);            // hit-test, Z-walk top-down
void         WindowRaise(WindowHandle);
WindowResizeEdge WindowPointInResizeEdge(WindowHandle, x, y);  // 8 zones, 4px bands
```

The 16-window cap is intentional. The desktop is not a tiled window
manager; it's an everyday workspace. Increase when we have a use case
for more.

## Compositor (DesktopCompose)

`DesktopCompose(desktop_rgb, banner)` is the entry point the UI ticker
calls each tick. Paint order is fixed:

1. Desktop fill (solid RGB)
2. Wallpaper (if loaded)
3. Taskbar (app tabs + tray)
4. Calendar tray widget (when expanded)
5. Menu panels (start menu / context menu)
6. Console (if docked — debug mode)
7. App windows (Z-order, bottom-up)
8. Per-window buttons (the widget registry's drawables)
9. Dialog (modal — drawn over everything else app-side)
10. Tooltips
11. Drag-drop preview
12. Cursor (last — always on top)

The order is **fixed**: changing it requires a corresponding update
to every documented hit-test assumption. The compositor flushes the
union of every damage rect at the end of the pass.

## Input Routing

A mouse event coming out of [`kernel/drivers/input/`](../../kernel/drivers/input/)
flows:

```
   PS/2 / USB-HID input event
            |
            v
       (cursor moves)
            |
       WindowTopmostAt(x, y)
            |
   +--------+--------+--------+--------+
   v        v        v        v        v
 Window  Widget   Taskbar   Menu    Dialog
                                     (modal — eats everything if shown)
```

Hit-test precedence: dialog > tooltip > drag-drop preview > cursor >
widget > taskbar > window. A click that does not hit any chrome is
delivered to the topmost window as a client-area event.

Keyboard events route through `modal_input.h` — the modal dialog
gets first-look; if none is showing, the active window's WndProc
runs.

## Theming

`theme.h` exposes a small palette per theme:

- `desktop_rgb` (background)
- `chrome_border`, `chrome_title_active`, `chrome_title_inactive`,
  `chrome_client_active`, `chrome_client_inactive`
- `cursor_primary`, `cursor_secondary`
- `taskbar_bg`, `taskbar_active_bg`
- `dialog_bg`, `dialog_button_bg`, `dialog_button_text`

A theme change calls back into each window to update its `WindowChrome`
colours; the next compose pass picks them up.

See [Duet Theme Spec](../specifications/Duet-Theme-Spec.md) for the
on-disk theme format (SVG-derived).

## Text Rendering

Two rasterisers ship side by side:

- **`font8x8`** — the original bitmap font; one pass through a per-glyph
  bitmap; fastest path; used by the console and the early-boot panel
  before the TTF rasteriser is online.
- **`ttf_raster`** — TrueType outline rasteriser; used by every chrome
  caption, menu item, dialog text. Cached glyph atlas per (face, size,
  style).

The TTF rasteriser is single-threaded — only the compositor calls it.
That keeps the cache lock-free.

## Drag and Drop

`dnd.h` supports per-window drop-target registration:

```cpp
DndRegisterDropTarget(WindowHandle, DropAccepts predicate, DropCallback cb);

DndBegin(WindowHandle from, DragItem item);  // starts a drag; preview painted
```

The preview is rendered by the compositor after windows, before
tooltips, so it visually stays "above" everything except the cursor.

## Threading and Locking

- **Compositor runs on a kernel task** that wakes at 60 Hz (configurable).
- All widget registry mutations happen on that task. Apps never mutate
  widgets directly — they call into the API which posts a message to
  the compositor.
- The framebuffer driver's `FillRect` / `PutPixel` are protected by
  the compositor's single-thread ownership; there is no internal
  framebuffer lock.
- Damage rect accumulation is per-tick; no concurrent writers.

## Capability Gates

The toolkit itself doesn't gate at the API level — it runs in kernel
context. Userland apps reach it through the Win32 syscall surface
(`SYS_WINDOW_*`), which carries the user-level cap checks.

## Known Limits / GAPs

- **16-window cap.** Increase when the workload demands it.
- **No GPU-accelerated chrome.** Every pixel comes from the CPU
  through framebuffer writes. Once Vulkan ICD ships real submission,
  the compositor will optionally route through `vkCmdClearColorImage`
  + a small textured-quad pipeline.
- **No multi-monitor.** Single scanout.
- **No window animation framework.** Window moves are direct, not
  tweened.
- **TTF rasteriser is bitmap-quality.** No subpixel-AA yet. Visible
  on high-DPI scanouts.
- **Drag-and-drop within-process only.** Cross-process drag via
  clipboard payloads is on the Roadmap.

## Related Pages

- [Start Menu](../kernel/Start-Menu.md) — app registration
- [Kernel Apps](../kernel/Kernel-Apps.md) — consumers
- [Compositor and Window Manager](Compositor.md) — broader window
  manager story (this page is the toolkit; Compositor is the WM)
- [DirectX](DirectX.md) / [Vulkan ICD](Vulkan-ICD.md) — for the GPU
  acceleration story
- [Duet Theme Spec](../specifications/Duet-Theme-Spec.md) — theme
  on-disk format
- [Driver Overview](../drivers/Driver-Overview.md) — input + framebuffer
  drivers
