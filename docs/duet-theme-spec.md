# Duet theme — design spec (v0)

This spec translates the React/Babel prototype under
`docs/duet-theme/prototype/` into terms the existing DuetOS
framebuffer compositor and `kernel/drivers/video/theme.h` `Theme`
struct can express. It is the source of truth that
`kernel/drivers/video/theme.cpp`'s `kDuet` palette, future
chrome work, and the eventual user-mode shell port will all be
measured against.

## Status (2026-04-29)

| Area              | State |
|-------------------|-------|
| Slate Duet palette + per-role title hues | **Yes** |
| Duet variants (Light, Blue, Violet, Green, Classic) | **Yes** — 6 Duet-family themes ship |
| Window chrome (gradient title, ridge, drop shadow, X-glyph close, min/max/restore controls, subtitle, dim-on-blur, rounded corners on Duet family) | **Yes** |
| Per-theme `title_bar_height` (22 / 26 px) | **Yes** |
| Per-theme `taskbar_height` (28 / 36 px) | **Yes** |
| Taskbar polish (gradient strip, rounded START + tabs, focus dot 8/14 px for pinned/running, theme-tinted Show Desktop sliver with click toggle) | **Yes** |
| Wallpapers (duet-arcs + topo on Duet family; Classic bubbles, Slate10 grid, Amber scanlines on others) | **Yes** |
| DuetMark on START | **Yes** — partial-arc form (189° sweeps, primary at -30° and amber at 150°) backed by `FramebufferStrokeArc` |
| Login screen + start menu + calendar + netpanel chrome polish | **Yes** |
| Theme-aware cursor | **Yes** |
| Per-window alpha (real compositor mask, 30-px titlebar, taskbar height/position) | **Deferred** — needs a real compositor / dimensions pass |
| TTF/OTF rasterizer | **Deferred** — 8×8 bitmap font remains |
| `FramebufferStrokePath` + partial-arc DuetMark / topo SVG / syscalls SVG wallpaper | **Deferred** — needs path stroker primitive |
| Userland shell + TOML reader + `~/.config/duet/shell.toml` | **Deferred** — needs userland process |
| procfs entries (`/proc/cpuhist`, `/sys/inspect`, `/proc/abi/*`, `/sys/syscalls`, `/proc/boottrace`) | **Deferred** — separate slice each |

## Personality (short form)

> Refined, confident, calm. Two interlocking arcs as the
> logomark; **two** accent colours (teal = native DuetOS,
> amber = Win32 PE peer) that visually distinguish ABIs throughout
> the UI. Win7/10 grammar (bottom taskbar with Start | search |
> pinned | tray | clock) rendered in DuetOS's own visual language —
> no Microsoft chrome lifted verbatim.

Where the prototype offers three modes (`slate` / `light` /
`classic`), v0 of the kernel-side Duet palette ships **slate**
only. Slate is the default mode in the prototype, the only one
needed to hit "land Duet alongside Classic / Slate10 / Amber",
and the only one whose contrast story works with the existing
single-buffer framebuffer (no compositor backdrop blur, no
alpha). Light + Classic Duet variants are deferred to a later
slice (see "Deferred to follow-on slices" below).

## Palette translation — slate (default)

The prototype defines its surfaces as CSS custom properties
(`--bg-1`, `--chrome`, `--ink`, `--accent`, …) inside
`docs/duet-theme/prototype/desktop.html`. The kernel `Theme`
struct (see `kernel/drivers/video/theme.h`) is flat: one 32-bit
ARGB value per role. The mapping below picks a single
representative shade for each prototype token, prioritising the
surface the role paints most often.

| Role (`Theme` field)         | Source token (slate)            | Hex (ARGB) | Notes |
|------------------------------|---------------------------------|------------|-------|
| `desktop_bg`                 | `--bg-1` deep canvas            | `0x000B0E13` | Same as prototype `:root[data-theme="slate"]` |
| `banner_fg`                  | `--ink`                         | `0x00E8EDF2` | Slate ink — also taskbar fg |
| `taskbar_bg`                 | `--chrome-2`                    | `0x001C222B` | Prototype taskbar surface |
| `taskbar_fg`                 | `--ink-2`                       | `0x00AEB7C2` | Secondary ink for inactive labels |
| `taskbar_accent`             | `--accent` (teal)               | `0x002DD4BF` | Start + active-tab indicator |
| `taskbar_tab_inactive`       | `--chrome-3`                    | `0x000F1319` | Recess panel |
| `taskbar_border`             | `--line-2`                      | `0x001E2530` | Approx of `rgba(255,255,255,.12)` flattened over chrome |
| `window_border`              | `--line-2` flattened            | `0x002A323C` | Slightly brighter to read against chrome |
| `window_close`               | red-hover close                 | `0x00E3413C` | Prototype `TitleBtn` close hover |
| `console_fg`                 | `--ink` (mono)                  | `0x00E8EDF2` | JetBrains-Mono ink in code views |
| `console_bg`                 | `--chrome-3`                    | `0x000F1319` | "Slate panel — log view ground" |

### Per-role title + client

The prototype distinguishes apps by **icon hue** (teal for
native, amber for Win32) and chrome consistency, not by title
hue. To preserve the existing DuetOS "title-hue carries app
identity" invariant inside the new palette without breaking it,
each role gets a Duet-specific title hue derived from
`--accent` / `--accent-2` / a near-neutral chrome.

| Role        | Title hue (rationale)                         | Title hex   | Client hex (`--chrome-3`-ish) |
|-------------|-----------------------------------------------|-------------|-------------------------------|
| Calculator  | Teal-tinted chrome (utility, native primary)  | `0x00207A6F` | `0x00141A22` |
| Notes       | Amber-tinted chrome (paper analogue)          | `0x00805E20` | `0x00F3F0E6` cream |
| TaskManager | Deeper teal (telemetry, primary)              | `0x00164D45` | `0x00141A22` |
| LogView     | Slate panel (mono content, no hue)            | `0x00161B23` | `0x000F1319` |
| Files       | Amber-tinted chrome (document storage)        | `0x00604818` | `0x00141A22` |
| Clock       | Slate panel (passive widget)                  | `0x00141822` | `0x000B0E13` near-black ground |
| GfxDemo     | Magenta accent (overpaint marker)             | `0x00702070` | `0x00000000` black |

The two-accent "duet" story remains visible: native (teal-tint)
apps cluster on the cool side, Win32-flavoured apps (Notes ≈
"document", Files ≈ "documents") on the warm side. The
distinction matches the prototype's icon palette.

## Type stack — addressed for v0

The prototype calls for **Inter** (UI) and **JetBrains Mono**
(kernel/inspect/log) at sizes `10 / 10.5 / 11 / 11.5 / 12 / 14
/ 18`.

Today the kernel renderer ships a single 8×8 bitmap font
(`kernel/drivers/video/font8x8.h`). No TTF rasterizer, no
sub-pixel sizes. That gap is a Phase 6 prerequisite, not a
blocker for the palette landing — the existing themes draw with
the same font and look correct in their own terms.

For the v0 Duet palette: `console_fg` / `console_bg` are
verified against the 8×8 font's contrast budget, identical to
how Slate10 and Amber were tuned. When a TTF rasterizer lands,
the Duet `Theme` does not change — the font stack is per-app
state, not theme state.

## Window chrome — what the prototype wants vs. what we ship

| Prototype spec                                         | Ships in v0 Duet palette? | Notes |
|--------------------------------------------------------|---------------------------|-------|
| 30-px titlebar (26-px in compact)                      | Partial — `Theme.title_bar_height` is now per-theme. Duet family (Duet / DuetLight / DuetBlue / DuetViolet / DuetGreen) ships 26 px; non-Duet themes + DuetClassic stay at 22 px. The full 30-px target awaits a chrome-side pass that gives content rooms more vertical breathing room. |
| 1-px border                                            | Yes — `window_border` is sampled by the existing border-draw path |
| 6-px corner radius (0 when maximized)                  | Yes (Duet only) — `FramebufferPunchCorners(x, y, w, h, 6, desktop_rgb)` overpaints the four corner-quadrant pixels OUTSIDE the curve so the silhouette reads as rounded. Other themes keep rectangular chrome. Compositor mask is still the proper fix, but the punch is good enough as a v0 approximation. |
| Vertical gradient on focus titlebar                    | Yes — `WindowDraw` paints `LightenRgb(colour_title, 24) → colour_title` with a 1-px highlight ridge on top |
| Square title buttons, 46-px wide                       | Partial — chrome now paints a min / max / close trio sized off `title_bar_height` rather than a fixed 46-px width. Pixel-perfect fixed widths await a per-theme dimensions slice. |
| Red-on-hover close button                              | Yes — `window_close = 0x00E3413C` matches the prototype's `TitleBtn` close hover; chrome now also draws an "X" glyph inside the close box |
| 3% dim on unfocused windows                            | Yes — `WindowDrawAllOrdered` alpha-blends `0x18000000` over the whole inactive-window rect when more than one window is visible |
| Drop shadow on every window                            | Yes — `FramebufferDropShadow(depth=4, alpha=0x60)` from `WindowDraw` |
| Subtitle / context-tag rendering                        | Yes — `WindowDrawAllOrdered` paints `WindowGetSubtitle` in dim ink right of the title (separator: `\|`) |

## Taskbar — same delta

| Prototype spec                                         | Ships in v0 Duet palette? | Notes |
|--------------------------------------------------------|---------------------------|-------|
| 44-px (compact 38-px) bar                              | Partial — `Theme.taskbar_height` per palette (Duet family ships 36 px, others 28 px). The full 44-px bar awaits a content-density pass on the strip itself. `WindowMaximize` reads the live value via `TaskbarHeight()` so the maximize reserve adapts. |
| 4 positions (bottom/top/left/right)                    | No — taskbar position fixed |
| Accent-rail "Show desktop" sliver                      | Yes — paints a 4-px theme-accent rail at the right edge of the strip; clicking the rail snapshots visibility of every alive window via `WindowShowDesktopToggle`, hides them all, and a second click restores the snapshot. Rail body alpha shifts (0x60 → 0xC0) when the toggle is active so the user has a visible "armed" cue. |
| 2-px tall focus dot under running apps (8 / 14 px)     | Yes — active-tab dot is 8 px when the window is pinned (kernel boot apps marked via `ThemeRegisterWindow` → `WindowSetPinned(true)`) and 14 px otherwise (ring-3 PE windows + any unpinned). Per-window `WindowIsPinned` / `WindowSetPinned` accessors back the distinction. |
| Rounded START + tabs                                    | Yes — `FramebufferFillRoundRect` + `FramebufferDrawRoundRect` (radius 4 / 3) |
| Vertical gradient on the strip                          | Yes — `LightenRgb(g_bg, 12) → g_bg` |
| Bottom-default w/ Start | search | pinned | tray | clock | Already shipping in this layout — colours sampled from Duet palette transparently |

## Start menu — unchanged

The kernel side has a `menu.cpp` (start-menu equivalent). It
already samples `taskbar_accent` and `taskbar_fg`. Duet's
palette flows through it without code change: the menu paints
teal accents on a slate panel.

A 520×540 modeless panel with a 3-col pinned grid, recommended
column, recents column, and user/power footer is a Phase 5
deliverable, not a palette deliverable.

## DuetMark — geometry

Two counter-rotating arcs forming a "D":

```
arc A: circle( cx = c - size*0.08, cy = c, r = size*0.34 )
       stroke = accent (teal)
       stroke-dasharray = (r*PI*1.05, r*PI*2)   // shows ~52% of the circle
       rotate(-30deg) about its own centre

arc B: circle( cx = c + size*0.08, cy = c, r = size*0.34 )
       stroke = accent-2 (amber)
       stroke-dasharray = (r*PI*1.05, r*PI*2)
       rotate(150deg) about its own centre

stroke-width = max(1.6, size * 0.11)
stroke-linecap = round
```

Reproduced in `kernel/drivers/video/menu.cpp` would require
either a parametric arc rasterizer or a bake-to-bitmap pass at
build time. The existing renderer can already draw a filled or
outlined ellipse (`WindowClientFillEllipse` /
`WindowClientDrawEllipse`); a "draw partial-arc stroke" call
would be a small extension.

For v0 the Start button paints the existing 3-letter "D u e"
glyph in `taskbar_fg` over `taskbar_accent`, matching how
Classic / Slate10 / Amber draw it today.

The DuetMark now ships in its prototype-faithful partial-arc
form. `FramebufferStrokeArc(cx, cy, r, start_deg, sweep_deg,
thickness, rgb)` (backed by a 91-entry Q16.16 sin table) walks
the arc in 1° steps and plots concentric pixels for thickness.
The START button paints two 189° arcs (~52% sweep, matching
the prototype's `dasharray = (r·π·1.05, r·π·2)`) — primary
arc rotated -30° in the variant accent, amber arc rotated
150°. Two-pixel stroke survives the active-tab gradient and
inactive-window dim overlay.

The full `FramebufferStrokePath` (cubic-Bézier flattener, etc.)
is still a Phase 3+ item; the partial-arc primitive that
landed here is sufficient for circular-arc work without a
full path stroker.

## Wallpaper — same approach

The prototype offers `duet-arcs`, `topo`, `syscalls` SVG-based
wallpapers. v0 ships a **duet-arcs + topo**-style backdrop on the Duet
theme: `kernel/drivers/video/wallpaper.{h,cpp}` paints two
layers — a `topo` concentric-circle stack as the base layer
and two interlocking outlined circles (teal-tinted left,
amber-tinted right) over the top. The arcs sit at ~28% of the
shorter framebuffer dimension, anchored at ~38% of the height
so the taskbar doesn't crop them. Stroke is a low-contrast
lift over the gradient bg so the rings read as ambient
texture, not chrome.

The other three themes now ship their own programmatic
patterns: Classic gets `PaintClassicBubbles` (12 deterministic
outlined circles scattered with an LCG-ish position table,
skipping the taskbar zone), Slate10 gets `PaintSlate10Grid`
(sparse 32-px grid of single-pixel dots, blended toward the
theme's Win10-blue accent), Amber gets `PaintAmberScanlines`
(every-3rd-row 1-px lift in brightness — CRT phosphor
interlace). A real SVG loader for the prototype's `topo` /
`syscalls` files remains deferred.

## Scope inside this slice

Phase 2 lands strictly:

1. The `kDuet` palette literal, mirroring `kSlate10` and
   `kClassic` in shape, in `kernel/drivers/video/theme.cpp`.
2. `ThemeId::Duet` after `Amber` in the enum, with `kCount`
   bumped.
3. The new entry registered in `kThemes[]`.
4. `ThemeSelfTest` extended to cover the new id (its loop
   already iterates `kCount`, so it picks Duet up automatically;
   the only check is that the palette literal is non-default).
5. No changes to `Ctrl+Alt+Y` handler logic — `ThemeCycle`
   already wraps over `kCount` and now visits Duet as the
   fourth entry.

## Phase 3+ prerequisites (what greenlights look like)

These are the new framebuffer primitives, kernel APIs, and
userland surfaces that the prototype assumes but DuetOS doesn't
ship yet. Each is its own slice — none are inside this commit.

- **Framebuffer primitives**
  - `FramebufferFillRectAlpha(x, y, w, h, argb)` — pre-multiplied
    alpha-over composite, needed for all the prototype's
    `color-mix` accent washes.
  - `FramebufferFillRectGradient(x, y, w, h, top_rgb, bot_rgb)` —
    vertical gradient, needed for focus titlebars and Start
    menu header.
  - `FramebufferFillRoundRect(x, y, w, h, radius, rgb)` — needed
    for 6-px window corners and pill widgets.
  - `FramebufferStrokePath(...)` — vector path stroking for the
    DuetMark arcs and the `duet-arcs` wallpaper. May land as a
    cubic-Bézier flattener.
- **Font subsystem**
  - TTF/OTF rasterizer (FreeType-style) so Inter and JetBrains
    Mono can render at the prototype's seven sizes. Existing
    8×8 bitmap stays as the kernel-console fallback.
- **Compositor**
  - Per-window alpha so unfocused windows can dim 3%.
  - Per-window rounded-corner mask.
  - Optional decoration "subtitle" slot on the titlebar
    (additive `WindowSetSubtitle(handle, str)`).
- **Userland**
  - A user-mode shell process (today the Start menu / taskbar
    are kernel widgets). Until that lands, "Duet shell" is
    additive paint policy on the existing kernel taskbar.
  - `~/.config/duet/shell.toml` reader. Requires a TOML parser
    in userland (or in the shell, with parsing bounded to a
    sub-process).
- **New procfs / sysfs entries (proposals — wait for greenlight)**
  - `/proc/cpuhist` — 60-sample ring of per-core utilisation
    percent, sampled at the scheduler tick. Needed by Task
    Manager Performance.
  - `/sys/inspect/<pid_or_path>` — exposes the existing PE
    parser's section table, import descriptors, and disasm
    iterator over a fd interface. Needed by Inspect.
  - `/proc/abi/native` and `/proc/abi/win32` — the syscall and
    DLL/export tables, already enumerated in-kernel; needs an
    fd surface.
  - `/sys/syscalls` — string-table view of the syscall numbers
    so the Start menu's search bar can resolve `58` or
    `WIN_CREATE` to the real syscall.
- **Boot trace**
  - The kernel already records a boot trace; expose it as
    `/proc/boottrace` so Task Manager → Startup can read it.

## Deferred to follow-on slices

- ~~Light + Classic-mode Duet palettes~~ — both ship.
  `ThemeId::DuetLight` carries the prototype's light tokens
  (near-white canvas, dual-accent teal/amber, dark per-role
  titles); `ThemeId::DuetClassic` carries Win9x panel grey
  (#C0C0C0) with the same dual-accent identity in role
  titles, plus a 4-px corner radius that matches the era's
  chunkier chrome proportions.
- ~~All of the prototype's accent variants beyond
  teal-amber~~ — DuetBlue / DuetViolet / DuetGreen ship as
  additional `ThemeId` entries. Each duplicates the slate Duet
  palette and swaps the cool accent for a different brand hue
  (Win10 blue / Tailwind violet / mint green). The amber accent
  for document-style apps stays so the dual-accent identity is
  preserved. The DuetMark START glyph picks up the variant's
  primary accent automatically; the wallpaper falls through to
  the same duet-arcs paint path.
- DuetMark-as-Start-glyph in the kernel taskbar — _v0 simplified
  form lands (two interlocking outlined circles); partial-arc
  stroke form deferred to the path-stroker slice._
- Three Duet wallpapers in the framebuffer — _duet-arcs lands as
  a programmatic two-ring backdrop; topo + syscalls + an actual
  SVG loader remain deferred._
- All Phase 4–9 chrome / shell / app / widget / cleanup work
  (each is its own slice; this spec only commits to the Phase
  1 + Phase 2 deliverables).

## Files this spec touches in v0

- `docs/duet-theme-spec.md` (this file).
- `kernel/drivers/video/theme.h`: extends `ThemeId` with
  `Duet`, bumps `kCount`. ABI-additive — existing
  `Classic/Slate10/Amber` numeric values unchanged.
- `kernel/drivers/video/theme.cpp`: adds the `kDuet` palette
  literal and registers it in `kThemes[]`. `ThemeSelfTest` is
  unchanged in code (its loop already covers `kCount`); the
  test is exercised against the new id at boot.

That's it. No widget changes, no compositor changes, no
userland changes. Cycle order on `Ctrl+Alt+Y` becomes:

> Classic → Slate10 → Amber → **Duet** → (wraps)
