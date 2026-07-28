# Implementation plan — Aurora shell in the DuetOS kernel

Everything below refers to real files at `Krilliac/DuetOS@main`. Read the file
before you change it; the notes call out the specific functions involved.

## 0. Suggested phase order

1. Tokens + theme struct (§1) — no visual change yet, just new fields.
2. Window chrome (§2) — 44 px titlebar, gloss, focus ring, control trio.
3. Taskbar island (§3) — the biggest layout change; all tray anchors move.
4. Glass / blur in the compositor (§4) — behind a per-theme flag so it can ship dark.
5. Accent personalisation + persistence (§5).
6. Fonts (§6).
7. Per-app panels (§8) once the chrome is settled.

Each phase is independently shippable and each maps to a `theme=` cmdline flag or
an existing hotkey, so nothing needs a flag day.

## 1. Theme tokens — `kernel/drivers/video/theme.h` / `theme.cpp`

The `Theme` struct already carries per-theme chrome metrics and the tactility
bytes; the Aurora look needs a handful of additions. Keep the flat-token shape.

Existing fields to change for the Duet family:
- `title_bar_height` 30 → **44**
- `taskbar_height` 36 → **68** (plus the new inset, below)
- `title_button_width` 46 → **46** (close is **52**; see §2)
- `focus_glow_colour` → the theme's primary accent, alpha comes from §2
- `shadow_intensity_active` 255, `shadow_intensity_inactive` 160,
  `hover_lift_alpha` 96, `press_alpha` 128, `motion_intensity` 220
- `font_kind` → `Ttf` (§6)

New fields (extend the per-theme tables in `theme.cpp` in lock-step, and the
`ThemeSelfTest` walker):
```cpp
u32  window_radius;        // 14 for Duet family, 0 for Classic/DuetClassic
u32  surface_radius;       // 20 — floating panels (start, flyouts, island)
u8   glass_alpha;          // 148 ≈ rgba(11,16,22,.58) window body
u8   panel_glass_alpha;    // 118 ≈ rgba(19,26,35,.46) floating panels
u8   sheen_alpha;          // 87  ≈ rgba(255,255,255,.34) top hairline + inset
u8   gloss_alpha;          // 28  ≈ .11 top of the gloss ramp
u32  accent_native;        // user-set; defaults #31e0c0
u32  accent_peer;          // user-set; defaults #ffc046
bool taskbar_island;       // true for Duet family
u32  taskbar_inset;        // 22 px gap from the screen edge when island
u8   blur_radius;          // 0 = no backdrop blur (Amber/HighContrast), else px
```
`ThemeApplyToAll()` already republishes chrome into the window registry, taskbar,
console and cursor — extend it to publish the new fields too, then let the caller
`DesktopCompose()`.

`role_title` / `role_client` stay per-role, but the Aurora chrome derives the
titlebar glyph colour from ABI rather than role: native apps use `accent_native`,
Win32-hosted windows use `accent_peer`. `ThemeRoleForWindow` already gives you the
role; `window_syscall.cpp` knows which windows came from a PE.

## 2. Window chrome — `kernel/drivers/video/widget.cpp` (+ `widget.h`)

- **Titlebar 44 px.** Paint order per window: drop shadow → body fill (§4) →
  gloss ramp → titlebar gradient → 1 px sheen hairline on the top edge → glyph →
  title (TTF, `title_text_scale`) → mono subtitle → control trio.
- **Gloss ramp** is a vertical alpha ramp over the body fill:
  `.11 → .03 @34% → 0 @46% → .02 @100%` white. Two `FramebufferFillRect` bands
  plus a per-row alpha loop is enough; there is no need for a gradient primitive.
- **Titlebar gradient**: specular `.15 → .04 @50% → 0 @51%` white over
  `bg_3 @70% → transparent`. The hard terminator at 50% is what reads as Aero.
- **Controls**: minimise 46 × 44, maximise 46 × 44, close **52** × 44. Hover fill
  `--hover` (white 7%); close hover solid `#ff5f57` with a white glyph. Reuse the
  existing hover-lift/press alphas from the tactility pass.
- **Focus**: 1 px inner stroke in `focus_glow_colour` at 30% + an outer glow.
  `RenderSoftShadowWithStroke` already exists for this — feed it the accent and the
  active/inactive shadow intensities.
- **Radius**: `window_radius` 14. If rounded corners are expensive, the cheap
  version is corner masking on the four 14 × 14 blocks only.

## 3. Taskbar island — `kernel/drivers/video/taskbar.cpp` / `taskbar.h`

This is the invasive part: the strip becomes a centred, inset, rounded island, so
every published anchor moves.

- `TaskbarInit(y, height, …)` keeps its signature, but when `taskbar_island` is
  set the painted rect is `x = (fb_w - island_w)/2`, `y = fb_h - height - inset`,
  `w = island_w` (content-derived), `h = height`.
- `TaskbarReanchor()` must recompute the island rect (it already re-derives y from
  the dock edge — extend it for x/w).
- Recompute and re-publish: `TaskbarStartBounds`, `TaskbarClockBounds`,
  `TaskbarNetCellBounds`, `TaskbarVolumeBounds`, `TaskbarChevronBounds`,
  `TaskbarShowDesktopBounds`. `TaskbarContains` / `TaskbarTabAt` must hit-test the
  island rect only, so clicks in the desktop margin either side fall through to
  the wallpaper.
- Content order and metrics are in `README.md` §10. Tabs become fixed 52 × 52
  icon buttons rather than title-text tabs — keep `TaskbarTabAt` returning the
  `WindowHandle` so the existing click dispatch keeps working, and paint the
  per-role glyph `ThemeRoleForWindow` already resolves.
- Indicator pills replace the old tab fills: 3 px tall, 10 px wide when running,
  22 px + glow when focused, `--ink-3` when minimised.
- `WindowMaximize` reserves `TaskbarHeight()`; with an island it must reserve
  `height + 2 * inset` (968 px of usable height at 1080) or windows will tuck
  under the island's shadow.
- Dock edges: island layout is defined for Bottom and Top only. `TaskbarSetDock`
  for left/right should fall back to the full-width strip (already the deferred
  case in `taskbar.h`).

## 4. Glass — the compositor

The design's translucency is the one thing the current renderer cannot express:
`DesktopCompose` paints opaque ARGB fills in a single pass and the framebuffer
driver discards alpha.

Minimum viable version (**do this first**):
- Composite windows back-to-front (the compositor already walks in z order) and
  blend each window's body fill over what is already in the backbuffer:
  `dst = src*a + dst*(1-a)` with `a = glass_alpha/255`. No blur — just tint. This
  alone gets ~80% of the look because the wallpaper's aurora glow shows through.

Full version (`blur_radius > 0`):
- Before painting a window, box-blur the backbuffer region under it (two passes,
  separable, radius ≈ 12 px at 1080p — 36 px CSS blur ≈ σ 18, so a 2-pass box of
  radius 12 is close), then blend the tint + gloss over the blurred copy.
- Cache the blurred region per window and invalidate on move/resize/z-change or
  when anything below it repaints; otherwise a full-screen blur per frame at 60 Hz
  will not hold cadence.
- Gate on `blur_radius`: Amber and HighContrast set 0 and keep flat fills, which
  matches their existing `tactility_enabled = false` posture.
- `mask-image` on the wallpaper hex band and grid is just a per-row alpha ramp in
  the wallpaper painter — no new primitive needed.

## 5. Accent personalisation + persistence

The prototype stores `{accents, presets, activePreset}` in `localStorage`. In the
shell this is registry work (the hive is already Win32-shaped and there is a
working query path):

```
HKCU\Software\DuetOS\Personalization\AccentNative   REG_DWORD  0x0031e0c0
HKCU\Software\DuetOS\Personalization\AccentPeer     REG_DWORD  0x00ffc046
HKCU\Software\DuetOS\Personalization\ActivePreset   REG_SZ     "duet"
HKCU\Software\DuetOS\Personalization\Presets        REG_SZ     "name:aaaaaa:bbbbbb;…"
```

- Read at boot in `main.cpp` right after `ThemeSet`, before `ThemeApplyToAll`.
- Write on change, debounced — the editor's sliders fire continuously; a 500 ms
  settle timer (as in the prototype) keeps hive writes down to one per gesture.
- Surface it three ways: the Settings panel (§8), a shell command
  (`theme accent native #31e0c0` / `theme accent peer #ffc046` /
  `theme preset save <name>` / `theme preset use <name>`), and the existing
  `Ctrl+Alt+Y` cycle for whole themes.
- HSL ↔ RGB helpers: the prototype's `hex2hsl` / `hsl2hex` are 20 lines of integer
  math each; port them into `kernel/util/` rather than pulling in floats if that
  matters on your target.
- **Keep the two channels distinguishable.** The pair helpers exist for this
  reason: when a user sets one channel, offer complement/split/triad/analogue for
  the other. If both channels land within ~20° of hue and similar L, the ABI
  distinction in Task Manager / Files / badges stops reading — consider a soft
  warning in Settings.

## 6. Fonts — TTF chrome path

`Theme::font_kind = Ttf` already dispatches through the TTF rasteriser when a font
is registered with `TtfChromeFontSet`, falling back to the 8 × 8 ROM font.

- Vendor **Instrument Sans** (UI) and **JetBrains Mono** (data) as TTF into the
  ISO's font directory; both are SIL OFL 1.1, which is compatible.
- Register both at boot; the chrome needs the sans for titles/labels and the mono
  for every value, timestamp and address.
- `title_text_scale` 2 stays meaningful only on the bitmap fallback path; with TTF
  use real point sizes from the scale in `README.md` (13 px titles, 11.5 px mono
  subtitles).
- The bitmap fallback must still be legible: at 8 × 8 the design's 10–11 px
  uppercase labels should render as plain 8 px caps rather than being scaled.

## 7. 1024 × 768 metric table

The design canvas is 1920 × 1080. For the shipping framebuffer, scale the chrome
(not the type) by ≈ 0.53 and round to even pixels:

| Element | 1920 | 1024 |
|---|---|---|
| Titlebar height | 44 | 30 |
| Control button (min/max) | 46 × 44 | 32 × 30 |
| Close button | 52 × 44 | 36 × 30 |
| Status bar | 30 | 22 |
| Taskbar island height | 68 | 44 |
| Island inset | 22 | 12 |
| App button | 52 | 36 |
| Desktop icon tile | 52 | 40 |
| Window radius | 14 | 8 |
| Surface radius | 20 | 12 |
| Gadget column width | 300 | 220 |

Type does **not** scale below 11 px; drop the mono subtitle before shrinking type.

## 8. Per-app panels — `kernel/apps/*`

The app windows in the design map onto existing apps; the work is panel layout,
not new features.

| Design surface | Existing source |
|---|---|
| Task Manager (4 tabs) | `kernel/apps/taskman.*` (+ sysmon counters) |
| Kernel Log | `kernel/apps/logview.*` |
| Inspect / disassembler | new app; PE data comes from `kernel/subsystems/win32/` |
| Files | `kernel/apps/files.*` |
| Settings → Personalization | `kernel/apps/settings.*` (theme cycle already wired) |
| Terminal | `kernel/apps/terminal.*` (+ `kernel/net/drsh/`) |
| Notepad | `kernel/apps/notes.*` |
| Calculator | `kernel/apps/calculator.*` |
| GFX Demo | `kernel/apps/gfxdemo*.cpp` |
| Notification centre | `kernel/apps/notify_center.*` |

Shared panel primitives worth extracting first (they repeat across every app):
uppercase section label, pill button (3 states), pill toggle, segmented control,
sticky table header, zebra row, badge pill, sparkline, status bar, sidebar rail
with a 2 px selection rail, slider with gradient track. `app_widgets/widget.h` +
`widget_group.h` is the natural home; there are already host tests for bounds,
paint and events to extend.

## 9. Data shown in the design

All sample data is lifted from the repo so nothing is invented: kernel log lines,
process table, disassembly, syscall sites and PE sections come from
`docs/duet-theme/prototype/desktop-data.jsx`; the PE inventory, `windows-kill.exe`
output, DLL/export counts and security posture come from `README.md`; the theme
family and tactility fields come from `kernel/drivers/video/theme.h`.

## 10. Definition of done

- `theme=duet` boots into the island taskbar with 44 px glass titlebars and the
  accent pair from the hive.
- `Ctrl+Alt+Y` still cycles all ten themes; Amber/HighContrast stay flat with no
  blur and no gloss.
- `Ctrl+Alt+B` (dock cycle) and `Ctrl+Alt+L` (lock) still work; island layout
  re-anchors correctly and `WindowMaximize` respects the reserve.
- Accent changes repaint every surface in one compose pass and survive a reboot.
- `ThemeSelfTest` passes with the new fields; the tactility self-test aggregator
  still emits its single PASS line.
