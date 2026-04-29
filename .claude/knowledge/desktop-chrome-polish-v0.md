# Desktop chrome polish — v0

_Type: Observation + Decision._
_Last updated: 2026-04-28._

## What landed

Five concrete additions to make the framebuffer-backed desktop +
window chrome look less "flat coloured rectangles", without adding
a real compositor or anti-aliasing path:

### 1. New framebuffer primitives (`drivers/video/framebuffer.{h,cpp}`)

| Primitive | Notes |
|-----------|-------|
| `FramebufferDrawLine(x0, y0, x1, y1, rgb)` | Bresenham, all-octant, signed coords; per-pixel surface clip; bounded by `kFbMaxLinePixels = 8192`. |
| `FramebufferDrawCircle(cx, cy, r, rgb)` | Midpoint algorithm, 8-symmetric plot; signed center; degenerate `r == 0` → single pixel. |
| `FramebufferFillCircle(cx, cy, r, rgb)` | Per-row span via integer test `dx² + dy² ≤ r²`; clipped against surface. |
| `FramebufferDrawRoundRect(x, y, w, h, radius, rgb)` | Outline sibling of `FramebufferFillRoundRect`. Reuses the same midpoint indent walk; plots only the boundary pixel per row. `radius == 0` falls through to a 1-px `FramebufferDrawRect`. |
| `FramebufferDropShadow(x, y, w, h, depth, start_alpha)` | Soft alpha-blended L-shape on the right + bottom edges. Linear alpha ramp from `start_alpha` at the inner band to 0 at the outer band. Lives entirely outside the source rect. |

All five primitives are no-ops when `!FramebufferAvailable()` and
clip per-pixel against the surface.

### 2. Window chrome (`drivers/video/widget.cpp::WindowDraw`)

- **Title bar gradient**: `FramebufferFillRectGradient(top = LightenRgb(colour_title, 24), bot = colour_title)` — preserves the theme's `colour_title` as the bottom shade so the registered hue still dominates, with a subtle lifted band on top.
- **Top highlight ridge**: 1-px `LightenRgb(colour_title, 56)` strip at `y + 1`, inset 2 px from each side. Reads as a discrete "pane edge" cue.
- **Inner client highlight**: 1-px `LightenRgb(colour_client, 16)` line just inside the border at the top of the client area.
- **Close button**: now renders an "X" glyph via two doubled diagonal `FramebufferDrawLine` calls inside the existing coloured square. Removes the "what does this mean?" ambiguity of the v0 flat-coloured square.
- **Drop shadow**: every window gets `FramebufferDropShadow(..., depth = 4, start_alpha = 0x60)`. Active and inactive windows both shadowed — `WindowDrawAllOrdered` walks bottom-to-top in z-order, so each window's shadow lands beneath any window above it (correct stacking).

`LightenRgb` / `DarkenRgb` are file-local saturating per-channel
helpers — file-scope anonymous namespace inside `widget.cpp`.

### 3. Desktop background (`drivers/video/widget.cpp::DesktopCompose`)

- Replaces the `FramebufferClear(desktop_rgb)` first paint with a vertical `FramebufferFillRectGradient(top = LightenRgb(desktop_rgb, 18), bot = DarkenRgb(desktop_rgb, 22))`.
- A pure-black `desktop_rgb` (used by the login / TTY-flip path) skips the gradient and falls through to the original `FramebufferClear(0)` — both `LightenRgb(0, 18)` and `DarkenRgb(0, 22)` would produce the same fail-safe shade, but the explicit fast path saves a per-row interpolation.

### 4. Taskbar (`drivers/video/taskbar.cpp::TaskbarRedraw`)

- **Gradient strip**: `FramebufferFillRectGradient(top = LightenRgb(g_bg, 12), bot = g_bg)` over the strip's full footprint. Top accent line preserved.
- **START button**: now `FramebufferFillRoundRect` + `FramebufferDrawRoundRect` (radius 4) with a 1-px `LightenRgb(g_accent, 40)` highlight on the top edge, inset by the radius.
- **Per-window tabs**: `FramebufferFillRoundRect` + `FramebufferDrawRoundRect` (radius 3). Active tab gets a 2-px `LightenRgb(g_accent, 48)` strip at the bottom — the Win10 / macOS-style "selected" indicator. Reads even on themes where `g_accent` is close to the strip bg (e.g. Slate10).

## Why this shape

- **All themes get the polish for free**. Lighten / Darken derive their highlight shades from the theme's existing `colour_title` / `colour_client` / `desktop_bg` / `taskbar_bg` / `taskbar_accent`, so Classic / Slate10 / Amber / Duet all benefit without per-theme hand-tuning. Amber's monochrome aesthetic is preserved (a `+24` lift on a near-black amber bg is still a near-black amber bg with a hint of warmth).
- **No anti-aliasing dependency**. Every primitive is pixel-aligned. Anti-aliased text + chrome is a follow-on once the compositor has an off-screen mask — at that point the round-rect outline + drop shadow get an obvious upgrade path (subpixel coverage masks).
- **Drop shadow lives outside the window rect**. The painting order is `WindowDrawAllOrdered` (bottom-up z-order), so each window's shadow lands on whatever was painted before it. For the bottom window, that's the desktop gradient. For higher windows, the shadow falls onto the windows below — exactly the visual stacking a user expects.
- **Z-order overpaint cleans up shadow artifacts**. The bottom band of a shadow could land where a higher window is about to paint; the higher window's chrome paint is unconditional (not alpha-blended), so any stray shadow pixel under a higher window's footprint gets overwritten by the chrome of that window.

## Non-goals

- No new APIs reach ring 3. The new primitives are kernel-side only; `SYS_GDI_*` doesn't change.
- No anti-aliasing, no subpixel rendering, no font hinting. The 8×8 bitmap font is unchanged.
- No invalidation tracking. Every `DesktopCompose` still re-paints the whole framebuffer; the gradients + drop shadows add a constant per-pixel cost (~2× the prior fill bandwidth, still well under any plausible budget on commodity hardware).
- No icons. Tabs and the START button stay text-only.

## Verification

- `cmake --preset x86_64-release` + `cmake --build build/x86_64-release` linked the kernel ELF cleanly with `-Werror`.
- `clang-format --dry-run --Werror` is clean for all four touched files.
- No live-boot smoke run in this slice — the changes only affect what
  pixels get painted (no new boot-time state, no new syscalls, no new
  IRQ paths). Visual verification deferred to next QEMU smoke (or to
  the next theme-screenshot refresh).

## Files

- `kernel/drivers/video/framebuffer.h`
- `kernel/drivers/video/framebuffer.cpp`
- `kernel/drivers/video/widget.cpp`
- `kernel/drivers/video/taskbar.cpp`
