# Desktop chrome polish — v0

_Type: Observation + Decision._
_Last updated: 2026-04-29._

## Update 2026-04-29 (Duet-theme follow-on slice)

Five additional changes layered on top of the v0 chrome polish to
close out more items from `docs/duet-theme-spec.md`:

1. **Subtitle paint**: `WindowDrawAllOrdered` now reads
   `WindowGetSubtitle` and paints it right of the title in dim
   ink (`LightenRgb(colour_title, 96)`) with a `|` separator,
   capped at the close-button's left edge. The `WindowSetSubtitle`
   storage existed since the chrome polish slice; this is the
   missing paint pass.

2. **Inactive-window dim**: when more than one window is visible,
   each inactive window gets a `0x18000000` alpha overlay over its
   whole rect, painted last in its per-window pass. Matches the
   spec's "3% dim on unfocused windows" — the slightly heavier
   ~10% alpha compensates for 8-bit framebuffer quantization.

3. **Theme-aware menu**: `MenuSetColours(body, border, ink, accent)`
   now flows from `ThemeApplyToAll`. The menu paints with the
   theme's `taskbar_tab_inactive` (recess body), `taskbar_border`,
   `taskbar_fg`, and `taskbar_accent`. Adds a left-edge accent
   strip, top highlight ridge, vertical body gradient, drop
   shadow, and per-row separators — same chrome language as
   windows + taskbar.

4. **Boot-time theme publish**: `kernel/core/main.cpp` now calls
   `ThemeApplyToAll()` after `ConsoleInit` so the start menu (and
   any future theme-listener) gets the boot-time palette without
   waiting for the first `Ctrl+Alt+Y`. Console + taskbar were
   already initialised with `theme0` directly; the duplicate
   publish is harmless (idempotent state writes).

5. **DuetMark on Start (Duet only)**: when `ThemeCurrentId() ==
   ThemeId::Duet`, `TaskbarRedraw` paints two outlined circles
   (teal + amber, 2-px stroke via doubled `FramebufferDrawCircle`)
   followed by "DUET" instead of the plain "START" label. This
   ships the simplified form of the spec's DuetMark; the
   partial-arc stroke form remains deferred until a path-stroker
   primitive lands.

### Files touched in this slice

- `kernel/drivers/video/widget.cpp` — subtitle paint, inactive dim
- `kernel/drivers/video/menu.h` — `MenuSetColours` declaration
- `kernel/drivers/video/menu.cpp` — palette state + theme-aware paint
- `kernel/drivers/video/theme.cpp` — call `MenuSetColours` from `ThemeApplyToAll`
- `kernel/drivers/video/taskbar.cpp` — DuetMark in START button
- `kernel/core/main.cpp` — boot-time `ThemeApplyToAll`
- `docs/duet-theme-spec.md` — flipped shipping flags for the items above

## Update 2026-04-29 (wallpaper + focus-dot slice)

Two more items off `docs/duet-theme-spec.md`:

1. **Wallpaper subsystem v0** — new TU
   `kernel/drivers/video/wallpaper.{h,cpp}` exposes
   `WallpaperPaint(desktop_rgb)`. Theme-dispatched: Classic /
   Slate10 / Amber are intentional no-ops (preserves existing
   flat / gradient look bit-for-bit); Duet paints `PaintDuetArcs`
   — two interlocking outlined circles (teal-tinted left,
   amber-tinted right) at ~28% of the shorter framebuffer
   dimension, anchored at ~38% of the height. 2-pixel stroke
   via doubled `FramebufferDrawCircle`. Tints are derived from
   `LightenRgb(desktop_rgb, 22)` plus a per-channel bias toward
   teal / amber, so the rings read as ambient texture, not
   chrome. Cost is O(diameter) pixel writes per frame.

   `DesktopCompose` calls `WallpaperPaint` after the gradient
   fill and before the console / window paint, so windows
   correctly occlude the wallpaper. Skipped in TTY mode (early
   return before WallpaperPaint).

2. **Active-tab focus dot** — `taskbar.cpp` replaced the
   full-tab-width 2-px strip introduced in the previous slice
   with a centred 14-px × 2-px dot at the bottom of the active
   tab (matches the spec's "running-app" indicator size). 8-px
   "pinned" form is deferred until the kernel taskbar tracks a
   pinned-vs-running distinction.

3. **Paint-stack comment** updated in `widget.cpp::DesktopCompose`
   to reflect the new layer order: gradient → wallpaper → console
   → windows (+ inactive dim) → freestanding widgets → banner →
   taskbar → menu.

### New files

- `kernel/drivers/video/wallpaper.h`
- `kernel/drivers/video/wallpaper.cpp`

## Update 2026-04-29 (window controls + pinned tabs)

### Batch A: window minimize / maximize / restore

`WindowDraw` now paints three control buttons in the title
bar (right-to-left: min, max, close) sized off `title_bar_height`.
Min is a horizontal "_" bar near the bottom; max is a 1-px
outlined square; close is the existing doubled-X. Min + max
share the title fill; close keeps its theme-distinct red.

`widget.h` gains:
- `WindowPointInMaxBox` / `WindowPointInMinBox` hit-tests
- `WindowMinimize` (SW_HIDE-style; promotes next visible
  window to active)
- `WindowMaximize` (snapshots `saved_x/y/w/h`, fills
  framebuffer minus 28-px taskbar reserve; idempotent)
- `WindowRestore` / `WindowIsMaximized`

`RegisteredWindow` gained `saved_x/y/w/h + maximized`.
`main.cpp`'s mouse press dispatcher routes clicks to the new
hit-tests; max click toggles between maximize and restore;
min hides (taskbar tab click restores via WindowRaise).

### Batch B: pinned-vs-running tab distinction

`widget.h` gains `WindowSetPinned` / `WindowIsPinned`. The
flag is a UI hint — kernel taskbar paints an 8-px active-tab
focus dot when the active window is pinned, 14-px when it's
not. `ThemeRegisterWindow` automatically pins any role-
tracked window (Calculator / Notes / TaskManager / LogView /
Files / Clock / GfxDemo — the boot apps), so ring-3 PE
windows registered via SYS_WIN_CREATE land unpinned and get
the larger dot.

## Update 2026-04-29 (login + button + banner polish, accent variants, Show Desktop)

Two big batches:

### Batch A: chrome polish for login / banner / buttons

1. **Login screen polish** — `login.cpp::DrawBackground` swaps
   the two-stripe BG approximation for `FillRectGradient` (now
   that the framebuffer ships gradient primitives). `DrawPanel`
   gains drop shadow (depth 5, alpha 0x70), gradient title bar,
   1-px ridge highlight along the title's top, 1-px outer
   border (was 2-px slab), 1-px divider where the title meets
   the body. Login → desktop transition is now visually
   continuous.

2. **Welcome banner drop shadow** — `DesktopCompose` paints a
   black 1-pixel offset shadow before the white banner ink
   so the text reads on every theme's gradient bg without a
   hard background-fill rectangle.

3. **Widget button gradient + ridge** — `PaintButton` swaps
   the flat fill for a vertical gradient (Lighten +22) plus a
   1-px ridge highlight along the inside top. Pressed buttons
   skip the gradient + ridge so the press transition reads as
   a clear "settled" state. Forward-declares the existing
   `LightenRgb` helper so PaintButton can use it.

### Batch B: accent variants + Show Desktop

4. **Three Duet accent variants** — `ThemeId::DuetBlue /
   DuetViolet / DuetGreen` (kCount: 5 → 8). Each duplicates the
   slate Duet palette and swaps the primary accent for the
   variant's brand hue (Win10 blue / tailwind violet-500 /
   mint green). The amber accent for document-style apps
   stays — preserves the dual-accent identity. Rounded corners
   + DuetMark START + duet-arcs wallpaper extend to all three
   automatically. The DuetMark's primary ring colour now reads
   from the live `g_accent` taskbar state so it picks up the
   variant's accent without per-theme code.

5. **Real Show Desktop click** — `WindowShowDesktopToggle()` /
   `WindowShowDesktopActive()` in widget.h. The toggle
   snapshots a `g_show_desktop_mask` bitmask of which alive
   windows were `visible` at activation time, hides them all,
   and the next click restores only those — windows the user
   closed mid-toggle drop off the mask. Mouse reader in
   main.cpp dispatches clicks on `TaskbarShowDesktopBounds`
   into the toggle, then re-composes. The taskbar paint reads
   `WindowShowDesktopActive()` and shifts the rail's body
   alpha 0x60 → 0xC0 so the user has a visible "armed" cue.

## Update 2026-04-29 (theme-aware popups + Light Duet)

Three more chrome polish slices:

1. **Theme-aware calendar popup** — `CalendarSetColours(body,
   border, header, ink)` replaces the hardcoded slate-blue
   palette. `CalendarRedraw` now paints with drop shadow,
   vertical body gradient, top highlight ridge, and a 1-px
   theme-border outline (was 2-px slab). Semantic indicators
   ("today" green, "other-month" dim) stay hardcoded.
   `ThemeApplyToAll` flows the palette through.

2. **Theme-aware network flyout** — same treatment as the
   calendar: `NetPanelSetColours(body, border, header, ink,
   button)` + drop shadow + gradient + ridge + 1-px border on
   both Preview and Full layouts. Online-green / pending-amber
   / dim-slate stay hardcoded since they encode link state.
   The RENEW button now uses the taskbar accent so it reads as
   a callable affordance.

3. **Light Duet palette** — `ThemeId::DuetLight` (kCount bumped
   from 4 to 5). Light-mode sibling of Duet sourced from the
   prototype's `light` tokens — near-white canvas (#EDEFF2),
   the same dual-accent (teal/amber) vocabulary, with darker
   per-role title hues so they read against the off-white
   client fills. Cursor flips to slate-ink-on-teal.
   Wallpaper module gains `AmbientStrokeRgb(bg, amount)` that
   picks lighten vs darken by the bg's mid-luminance — both
   `PaintTopo` and `PaintDuetArcs` use it now, so the same
   paint paths render correctly on the dark and light Duet
   variants. Rounded corners + DuetMark START button extend
   to DuetLight automatically.

## Update 2026-04-29 (rounded corners + per-theme wallpapers + theme-aware cursor)

Three more chrome polish slices, each its own commit:

1. **Rounded window corners on Duet** — new primitive
   `FramebufferPunchCorners(x, y, w, h, radius, punch_rgb)` walks
   each of the four corner-quadrant `radius × radius` squares
   and overpaints every pixel OUTSIDE the rounded curve with
   `punch_rgb`. `WindowDrawAllOrdered` calls it after
   `WindowDraw` when `ThemeCurrentId() == ThemeId::Duet`,
   passing the desktop fill colour (= the gradient mid-tone)
   captured into a file-static `g_compose_desktop_rgb` by
   `DesktopCompose`. The chrome itself is still painted as a
   rectangle; the punch shapes the visible silhouette.
   Other themes keep rectangular chrome to preserve their
   original v0 look bit-for-bit.

2. **Per-theme wallpapers for Classic / Slate10 / Amber** —
   `wallpaper.cpp` gains three more programmatic patterns:
   `PaintClassicBubbles` (12 deterministic outlined circles
   scattered via LCG-ish positions, skipping the taskbar zone),
   `PaintSlate10Grid` (sparse 32-px grid of single-pixel dots
   blended toward Win10 blue), `PaintAmberScanlines` (every 3rd
   row gets a 1-px brightness lift evoking CRT phosphor
   interlace). All three skip the bottom 80 px so the taskbar
   stays clean. `WallpaperPaint` now dispatches to one of the
   four patterns per theme; Duet keeps its topo + duet-arcs
   stack.

3. **Theme-aware cursor** — new `CursorSetColours(outline, fill)`
   replaces the cursor's hardcoded black-on-white sprite. The
   `Theme` struct gained two new fields (`cursor_outline`,
   `cursor_fill`) and `ThemeApplyToAll` flows them through.
   Per-theme choices: Classic = white-on-black (preserves the
   original look), Slate10 = bright slate ink on near-black,
   Amber = bright phosphor on deep-CRT-brown, Duet = `--ink` on
   `desktop_bg` (slate ink on near-charcoal). Cursor is
   repainted at its current position when colours change so
   the new look appears without waiting for motion.

## Update 2026-04-29 (Show Desktop sliver + topo backdrop)

Two more chrome additions:

1. **Show Desktop sliver** — `taskbar.cpp` paints a 4-px-wide
   theme-accent rail at the very right edge of the strip,
   inset 1 px so the framebuffer's outer column stays on the
   bg gradient. Body is alpha-blended (`0x60` over the accent)
   for a soft accent feel; a 1-px brighter highlight runs down
   the inside edge so the rail has visible structure. New
   `TaskbarShowDesktopBounds(x*, y*, w*, h*)` exposes the rect
   for a future click dispatcher. Click logic is **STUB** —
   the spec's restore-on-toggle behaviour needs a "minimize-
   all + restore" backing map that's its own slice.

2. **Topo backdrop layer for Duet wallpaper** — `WallpaperPaint`
   on the Duet theme now paints a topo concentric-circle stack
   FIRST, then the duet-arcs over the top. Stroke contrast is
   half the duet-arcs lift so the topo reads as a base layer
   rather than competing with the foreground rings. Gives the
   Duet desktop a layered look matching the prototype's
   multi-layer SVG composition.



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
