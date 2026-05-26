# Compositor and Window Manager

> **Audience:** Compositor / WM authors, GDI thunk authors
>
> **Execution context:** Kernel — compositor runs in the focused-window's draw pass
>
> **Maturity:** v0 painting + windowing; popup menus + modal dialogs shipped

## Overview

The compositor and window manager live in `kernel/drivers/video/`
(`widget.cpp`, `theme.cpp`, framebuffer primitives). They are
**in-kernel** for hot-path latency. Userland reaches them via
`SYS_WIN_*` (window lifecycle) and `SYS_GDI_*` (pixel primitives).

`kMaxWindows = 40` (21 system + debugger + headroom for ring-3 PE
windows; see `kernel/drivers/video/widget.h` for the breakdown).

## What Paints Today

Native DuetOS apps and Win32 PE windows compose into the same
framebuffer:

- **Native apps** (`kernel/apps/`): Calculator, Notepad, Files, Task
  Manager, Kernel Log, Clock, GFX Demo, About / System Info, Help,
  Calendar, Image Viewer, Browser (HTTP only), Trash, Notification
  Center, **System Monitor (Sysmon)**, **Hex Viewer**, **Character
  Map**. Each is an in-kernel native app, registered via a
  `ThemeRole` enum entry + per-theme palette extension; the
  compositor scans the role table on every recompose and the Start
  menu's `/APPS/*.MNF` enumerator raises the matching window when a
  manifest specifies `target=<role>`.

  - **Sysmon** — rolling 64-sample chart of heap-used % and
    free-list fragmentation, sampled by the 1 Hz ui-ticker. About
    answers "what's the heap right now"; Sysmon answers "is the
    heap leaking" by surfacing the trend.
  - **Hex Viewer** — read-only hex / ASCII inspector for FAT32
    root files (capped at 1 MiB per file). Classic 16-bytes-per-row
    layout with offset / hex / ASCII gutter. Wired into the kernel
    scrollbar drag-the-thumb path.
  - **Character Map** — codepoint grid over the bitmap font's
    printable range (0x20..0x7E ASCII; Tab toggles to the full
    0x20..0xFF range that includes the font8x8 extended glyphs).
    Enter / Space copies the selected glyph as UTF-8 to the
    clipboard so it pastes into Notes / Calculator / Browser via
    the standard Ctrl+V path.
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

## Window Chrome Interactions

The kernel mouse-reader (`kernel/core/main.cpp`) owns every
non-client-area gesture; PE and native windows go through the same
path. On a press inside a window:

- **Close glyph hit** → `WindowClose(h)` (with the Notes
  dirty-close prompt routed through `MessageBoxOpen` for the
  Notes role).
- **Maximise glyph hit** → toggles `WindowMaximize` ↔
  `WindowRestore`. The pre-maximize bounds are snapshotted into
  `g_windows[h].saved_*` so Restore returns to the exact
  press-time geometry.
- **Minimise glyph hit** → `WindowMinimize(h)` (the window stops
  composing; the taskbar tile shows the minimised state and a
  tile-click restores).
- **Title-bar press (no glyph hit)** → arms the move-drag with
  `(grab_offset_x, grab_offset_y) = (cx − wx, cy − wy)`; subsequent
  motion packets call `WindowMoveTo(h, cx − grab_x, cy − grab_y)`.
  Title-bar **double-click** (within `WindowDoubleClickTicks()`,
  same hwnd) toggles maximise ↔ restore and consumes the second
  click so a fast triple-click doesn't fire a third toggle.
- **Resize-band press (4 px from any edge / corner)** → see
  [Window Edge + Corner Resize](#window-edge--corner-resize).

Keyboard shortcuts for the same operations:

| Shortcut | Effect |
|---|---|
| `Alt+F4` | Close active (Notes prompts on dirty buffer) |
| `Ctrl+Alt+Left` | Snap-left half (`WindowSnapLeft`) |
| `Ctrl+Alt+Right` | Snap-right half (`WindowSnapRight`) |
| `Ctrl+Alt+Up` | Maximise active |
| `Ctrl+Alt+Down` | Restore (if maximised) or minimise |

The system menu (NC right-click on the title bar) routes Move /
Size through `ModalInputBegin` so the cursor follows the press
delta until the next click commits or Esc cancels (`drivers/video/
modal_input.{h,cpp}`). Min / Max / Restore / Close items in the
system menu and the enriched window menu (right-click on a kernel-
app body) all reach `WindowMinimize` / `WindowMaximize` /
`WindowRestore` / `WindowClose` directly.

A click anywhere inside an inactive window calls `WindowRaise`
before the press is dispatched so Z-order tracks the click in
addition to explicit `BringWindowToTop` / `SetForegroundWindow`
syscalls.

## Window Transition Animations

`WindowMaximize`, `WindowMinimize`, `WindowRestore`, and the
`WindowSnap*` family (Left / Right / Top / Bottom + four corners)
route their rect change through the `WindowAnimate` primitive in
`widget.{h,cpp}` instead of jumping in a single frame. Default
tween: 10 ticks of ease-out (`t' = 1 - (1 - t)^2`) at the 100 Hz
`WinTimerTicker` cadence ≈ 100 ms. Math is integer fixed-point
(q10) — no FPU in kernel context.

State (`anim_active`, `anim_start_*`, `anim_target_*`,
`anim_remaining_ticks`, `anim_ease`, `anim_post_action`) lives on
the per-window struct; no dynamic allocation. The animator only
walks `chrome.x/y/w/h` — flags (`maximized`, `visible`, focus)
are set immediately by the calling op so observers
(`WindowIsMaximized`, hit-testing, the chrome max / restore
glyph) see the new state before the tween finishes. The Restore
target is still `saved_*` so Restore returns to the exact
pre-maximize bounds.

Skip rules: identical source / target rect, in-flight animation
for the same window (the in-flight one wins; the new request is
dropped). `WindowMinimize` carries a `hide-on-complete`
post-action — the window stays visible through the tween then
rolls back to its pre-anim rect and clears `visible`, so the next
`SW_SHOW` lands where the user left it. Drag-move
(`WindowMoveTo` per motion packet) deliberately bypasses the
animator — animating live input would lag the cursor.

## Snap Zones

While dragging a window the mouse loop hit-tests the cursor
against 32-px screen-edge bands and 32×32-px corner boxes
(`SnapPreviewHitTest` in `widget.cpp`). When the cursor enters
a zone, `SnapPreviewArm` records the target and `DesktopCompose`
paints a translucent `taskbar_accent` rect (~25 % alpha) at the
exact rect the snap would commit — read as "preview" not real
chrome. Releasing inside a zone commits the matching
`WindowSnap*` / `WindowMaximize`; releasing outside leaves the
window at the cursor position.

| Zone | Snap | Primitive |
|---|---|---|
| Top edge | Maximise | `WindowMaximize` |
| Left / right edge | Half | `WindowSnapLeft` / `WindowSnapRight` |
| Top-left / top-right corner | Quarter | `WindowSnapTopLeft` / `WindowSnapTopRight` |
| Bottom-left / bottom-right corner | Quarter | `WindowSnapBottomLeft` / `WindowSnapBottomRight` |
| Bare bottom edge | none — owned by taskbar drag-snap | — |

Corners take precedence over edges (a cursor 8 px from the
top-left resolves to `TopLeft`, not `Maximize`). Esc during the
drag clears the preview without aborting the move; the rest of
the drag behaves normally.

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

`scrollbar.{h,cpp}` paints a track + thumb and provides pure-function
hit-test / drag math (`ScrollbarHitTest`, `ScrollbarDragTo`,
`ScrollbarThumbY`, `ScrollbarThumbH`). Apps call `ScrollbarPaint(x, y,
w, h, {total, visible, first})` from their `DrawFn` and register the
same geometry with the widget system via `WindowSetScrollbar(handle,
WindowScrollbarSurface{...})`. Apps also register a scroll callback
via `WindowSetScrollHandler(handle, fn)` to receive the new `first`
value.

The kernel mouse loop in `boot_tasks.cpp` consults the per-window
scrollbar surface on every press-edge: track click pages by `visible`
and fires the callback via `WindowDispatchScroll`; thumb click arms an
`sb_drag` that follows the cursor through subsequent motion via
`ScrollbarDragTo` + `WindowDispatchScroll`. Wheel dispatch remains the
incremental fast path. v1 consumers: Files (FAT32 list), Browser
(body), HexView (grid), Notification Center. Notes / Help skip the
scrollbar because their content fits the typical render area.

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
- Drop shadow primitive (strip-based — fallback for tactility=off themes)
- Round-rect outline primitive
- Filled circle primitive

## Chrome Tactility (Pass A)

The chrome tactility lift (Pass A of a 4-pass UX initiative) adds
depth + materiality to the surface: soft drop shadows on windows
+ modals + menu panels, hover lift on taskbar tabs, accent halo on
snap previews, and an opt-in focus-glow ring helper for focused
controls. The work spans Phases 1 - 5 of the implementation plan
(`docs/superpowers/plans/2026-05-24-duetos-chrome-tactility.md`).

**Per-pixel math** lives in `kernel/drivers/video/blend_math.h` -
constexpr `BlendOver(dst_rgb, src_rgb, src_a)` Porter-Duff "src
over dst" + `ScaleAlpha(argb, scale)` modulator. Pure - no kernel
deps - so `tests/host/test_blend.cpp` exercises the rounding +
fast-path math without a QEMU boot.

**Atlas-based shadow renderer** lives in
`kernel/drivers/video/shadow.{h,cpp}`. Reads the 32 x 32
quadratic-falloff atlas baked at configure time
(`tools/build/gen_shadow_atlas.py` -> `generated_shadow_atlas.h`)
and paints a 9-slice soft shadow OUTSIDE the rect.
`RenderSoftShadow(x, y, w, h, radius, opacity, colour)` for the
basic case; `RenderSoftShadowWithStroke(...)` adds the 1-px inner
accent stroke for focus glow. Radius clamps to [8, 48]; opacity
== 0 is a no-op.

**Framebuffer alpha primitives** in
`kernel/drivers/video/framebuffer.{h,cpp}` route Porter-Duff blends
through the same `BlendOver` math: `FramebufferBlendFill`
(rect with one ARGB), `FramebufferBlendPixel` (single pixel),
`FramebufferBlendRgba` (bitmap blit, sparse-atlas fast-path skips
alpha=0 pixels). Inline forwarders `FramebufferBlendFill` /
`FramebufferBlendPixel` give the chrome-tactility plan its naming
convention without duplicating implementation.

**Theme integration**: the `Theme` struct
(`kernel/drivers/video/theme.h`) carries 7 new tactility fields -
`tactility_enabled` master switch, `shadow_intensity_active` /
`_inactive` (separate so focus state can dim sibling shadows),
`hover_lift_alpha`, `press_alpha`, `focus_glow_colour` (0 = no
glow opt-out for DuetClassic), and `cursor_microshadow_enabled`.
The per-theme matrix in `theme.cpp` lights up the Duet family
aggressively (255 active / 128 inactive shadow), keeps Classic
moderate (80 / 40), and opts out HighContrast + Amber (the
high-contrast use case can't afford the legibility hit, the
amber-CRT aesthetic breaks with soft shadows).

**Runtime override**: `ThemeTactilityOverride()` is `-1`
("follow theme default"), `0` ("force off"), or `1` ("force on").
Set via `tactility=on/off` kernel cmdline at boot or the
`tactility on|off|default` shell command at runtime.
`ThemeTactilityEffective()` is the single read accessor every
tactility-aware paint path consults.

**Chrome paint integration sites** (Phase 3):

- `WindowDrawAllOrdered` (widget.cpp): swap from strip-based
  `FramebufferDropShadow` to atlas-based `RenderSoftShadow` when
  tactility is effective. Radius 24 active / 16 inactive, opacity
  from theme intensity bytes. Strip shadow remains as fallback
  for tactility=off themes so HighContrast / Amber chrome is
  bit-for-bit identical to pre-spec.
- `DialogCompose` (dialog.cpp): 40-px soft shadow + 75% intensity
  around modal panel, on top of the existing 40% dim scrim. Modal
  reads as floating ON the scrim instead of painted INTO it.
- `SnapPreviewCompose` (widget.cpp): accent-coloured 16-px halo
  added under the existing 25% translucent fill so the snap target
  reads as "the window will hover here".
- `TaskbarRedraw` (taskbar.cpp): 6-px shadow bleeds upward from
  the strip's top edge (the bar floats above the desktop, not
  pasted onto it); per-tab hover wash + 8-px soft shadow under
  the hovered tab via `CursorPosition()` hit-test.
- `MenuRedraw` (menu.cpp): swap from strip-shadow to atlas-shadow
  for the menu panel itself (radius 12 — proportional to the
  smaller surface).
- `WindowPaintFocusGlow(x, y, w, h, is_pe_window)`: available for
  focused-input + button paint paths; Win32-role windows force
  the accent to amber so the dual-accent identity reads
  consistently across themes. Not yet wired into a caller — the
  call site lands with whichever focus-aware widget needs it
  first.

**Self-tests** run from `boot_bringup.cpp` after the existing
ThemeSelfTest:
- `BlendSelfTest` exercises the alpha-blend primitives'
  round-trip math.
- `ShadowSelfTest` exercises four atlas invariants: size=32,
  origin=255, opacity-linearity within +/-2 LSB, rotational
  symmetry within +/-1 LSB.
- `ThemeSelfTest` (extended): tactility-matrix invariant guards -
  every `tactility_enabled` theme must have
  `shadow_intensity_active > 0` and `active >= inactive`,
  HighContrast + Amber must stay opted out.
- Umbrella aggregator emits `[tactility-selftest] PASS` only
  when every sub-test passed. Each FAIL fires its own probe
  (`kBlendRangeOob` / `kShadowAtlasInvalid` /
  `kTactilityThemeMismatch`) so an attached GDB can break at
  `duetos::debug::ProbeFire`.

**Tooling**: `tools/test/tactility-soak.sh` (per-theme
render_stats soak + probe-fire gate), `tactility-screenshot-
matrix.sh` (per-theme PPM via QMP screendump + optional
ImageMagick montage), and the `TACTILITY` section in
`tools/test/boot-log-analyze.sh` (counts the 4 PASS sentinels +
3 probe fires).

**Deferred from Pass A** (intentionally — visual verification
needed first):
- Per-row hover wash in menu rows (existing solid accent fill
  is already strong; wash on top would compound).
- Menu scale-pop open animation (needs animation system
  extension).
- Cursor micro-shadow (plan-marked stretch; per-frame cost
  weighed against a small visual lift).
- Press overlay on taskbar tabs (per-tab pressed state isn't
  surfaced at paint time; needs an input-state refactor).
- Damage-rect halo inflation across every dirty-emit site - the
  codebase's per-pixel `MarkDamage` in the paint primitives
  already covers shadow regions, since each shadow pixel marks
  itself dirty as it paints. The plan's `MarkDirty(window.bounds)`
  pattern doesn't exist in this codebase.

## First-Impression Moments (Pass B)

Pass B is the four scenes a user sees before any app opens: boot
splash, login welcome, idle/lock, and the desktop wallpaper itself.

**Continuous backdrop.** `WallpaperPaint(rgb)` paints the active
theme's wallpaper at the same coordinates in every scene. Splash,
login, lock, and the desktop all share that same backdrop layer.
Overlays (phase ticker, login card, desktop chrome) paint on top
without recomposing the backdrop — the arcs centroid at (512, 384)
never moves between scenes.

**Ambient motion** (~15 FPS via WinTimerTickerTask): arcs rotate ±5° / 60s
(via `FramebufferStrokeArcFloat` for sub-degree smoothness), soft pulse
glow (8s breath via smoothstep), topo curves drift 1 px/s horizontally
(theme-tinted via the new `SvgRender(..., tint_argb)` parameter), login
clock refreshes on minute roll. Gated by `Theme::motion_intensity` (new
field) and the existing `tactility_enabled` master gate — HighContrast
opts out entirely; Classic runs at 30% intensity; others run full.
Runtime override via `motion=on|off|auto` cmdline (mirrors Pass A's
`tactility=` pattern, with `tactility_enabled` as the unbypassable
master gate).

**Files:**

- `kernel/drivers/video/splash.{h,cpp}` (new) — boot splash module
- `kernel/drivers/video/wallpaper.cpp` — adds `WallpaperTick()`, three
  motion math helpers, motion threading into arcs + topo paint
- `kernel/drivers/video/framebuffer.{h,cpp}` — `FramebufferStrokeArcFloat`
  variant for sub-degree rotation
- `kernel/drivers/video/svg.{h,cpp}` — optional `tint_argb` parameter
  on `SvgRender` for topo pulse-breath
- `kernel/drivers/video/theme.{h,cpp}` — `motion_intensity` field +
  per-theme matrix + `motion=` cmdline override
- `kernel/security/login.cpp` — corner-card GUI layout (clock left,
  atlas-shadow card bottom-right, avatar + monogram + name + focus-glow
  password + sign-in button), per-minute clock refresh, GUI self-test

**Self-tests:** `SplashSelfTest`, `WallpaperMotionSelfTest`,
`LoginGuiSelfTest` — each emits `[*-selftest] PASS` on success.
Umbrella line emitted by `boot_bringup.cpp`:
`[pass-b-selftest] PASS (splash=ok, wallpaper-motion=ok, login-gui=ok)`.
`boot-log-analyze.sh` recognises the new sentinels and a
`[pass-b]` umbrella status line.

See [`docs/superpowers/specs/2026-05-24-duetos-pass-b-design.md`](../../docs/superpowers/specs/2026-05-24-duetos-pass-b-design.md)
for the full design + acceptance criteria.

## Typography Hierarchy (Pass C)

Pass C wires a four-tier type role (Display / Title / Body / Caption)
through a single dispatcher (`kernel/drivers/video/chrome_text.{h,cpp}`).
Every chrome paint site uses
`ChromeTextDraw(role, x, y, text, fg, bg, weight)` instead of calling
`TtfDrawString` or `FramebufferDrawStringScaled` directly. The mono
path (terminal, kernel shell, hex viewer) intentionally does NOT route
through `ChromeTextDraw` — those surfaces call `FramebufferDrawString`
directly to keep cell width predictable.

### Type Roles

| Role | TTF px | Bitmap scale | Surfaces |
|---|---|---|---|
| Display | 72 | 8 (64 px) | Login clock, hero numerals |
| Title | 16 | 2 (16 px) | Window titlebars, dialog titles, login card name, taskbar clock |
| Body | 13 | 1 (8 px) | Menu rows, button labels, dialog body, tile labels, password echo |
| Caption | 11 | 1 (8 px) | Hints, status, date, splash phase ticker, settings hints, taskbar date |

Weights: **Regular** (default) and **Bold**. Bitmap themes synthesize
bold via double-paint with 1 px x-offset; TTF themes load Liberation
Sans Bold and dispatch to it when present (falling back to Regular if
the bold font failed to load).

### Per-Theme Dispatch

`Theme::font_kind` determines path:

- **TTF themes** (`Duet`, `DuetLight`, `DuetSoft`, `DuetDeep`,
  `DuetMono`): all roles use Liberation Sans Regular + Bold companion.
- **Bitmap themes** (`Classic`, `Slate10`, `Amber`, `HighContrast`,
  `DuetClassic`): roles map to integer-scaled 8×8.

### Self-Test + Sentinels

`ChromeTextSelfTest()` runs at the boot umbrella stage and emits:

```
[chrome-text-selftest] PASS
[pass-c-selftest] PASS (chrome-text=ok)
```

The bold-font load is announced at boot via
`[boot] chrome font bold (Liberation Sans Bold) loaded + registered`.

Verify via:

- `tools/test/boot-log-analyze.sh <log>` — Pass C section reports
  `chrome-text=N umbrella=N` + bold-font status.
- `tools/test/tactility-screenshot-matrix.sh --typography` — 10 themes
  × 3 surfaces reference set.
- `tools/test/pass-c-soak.sh` — 30 s sustained-load regression guard.

### API Summary

```cpp
ChromeTextDraw(role, x, y, text, fg, bg, weight);   // paint
u32 w = ChromeTextMeasure(role, text);              // pixel width
u32 h = ChromeTextRoleHeight(role);                 // pixel height
```

See `kernel/drivers/video/chrome_text.h` for the full declaration set.

## App Widgets (Pass D)

Pass D collapses the imperative paint + click ladder every kernel
app used to hand-roll into a small set of value-typed widget
structs composed into a per-app `WidgetGroup<…>`. The library
lives under `kernel/drivers/video/app_widgets/` and ships eight
widgets (`AppPanel`, `AppLabel`, `AppDivider`, `AppButton`,
`AppListRow`, `AppToolbar`, `AppInput`, `AppScrollbar`) layered
on a CRTP `Widget<Self>` base — zero virtual dispatch, zero RTTI,
zero heap, every widget a plain value struct.

28 of 33 in-tree apps migrated; the 5 carve-outs (debug overlays,
gfx-demo content modes, notes persistence backend, trash facade)
stay on raw paint by design. Apps marked "chrome only" (Terminal,
Hexview, Gfxdemo, Dbg_render) migrated their toolbar / status bar
to widgets and kept the content region raw. Files and Calendar
carve out raw paint regions inside otherwise-migrated apps for
their grid surfaces.

The umbrella sentinel
`[pass-d-selftest] PASS (widgets=ok, apps=28/28)` fires at boot
when both `AppWidgetsSelfTest()` and every per-app self-test pass.
`boot-log-analyze.sh` keys its Pass D section off this line and
`tools/test/pass-d-soak.sh` is the 60 s regression rig.

See [AppWidgets](AppWidgets.md) for the full library reference
(CRTP design, widget table, event model, carve-out rationale,
acceptance criteria).

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
| Body of the Files app | Per-row context menu tuned to the active mode (FAT32: Open / Rename / Delete / Properties / Refresh / New File / New Folder; DuetFS: Open / Properties / Refresh; Trash: Open / Restore / Delete Forever / Properties / Refresh; Ramfs: Open / Delete (disabled) / Properties / Refresh) |
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
| 30–39 | Files app FAT32 + non-FAT generic menus (30–33 OPEN / RENAME / DELETE / PROPERTIES, 34 REFRESH, 35–36 NEW FILE / FOLDER, 37–39 generic OPEN / PROPERTIES / REFRESH reused by DuetFS + ramfs) |
| 40–43 | Power / session (REBOOT / SHUTDOWN / LOCK / LOGOUT) |
| 44–47 | Files app Trash + ramfs row menus (44 OPEN trash / 45 RESTORE / 46 DELETE FOREVER / 47 ramfs DELETE — disabled placeholder) |
| 50–59 | System shortcuts (50 SCREENSHOT, …) |
| 60–69 | Bespoke viewer windows (Net Status / Device Manager / Firewall) |
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
- **Submenu marshaling across `SYS_WIN_TRACK_POPUP`**: live. The
  userland `TrackPopupMenu` thunk walks the HMENU tree depth-first
  and packs it into a single flat array (`TpItemWire[32]`); each
  submenu-flagged row carries `child_index` / `child_count`
  back-pointers into the same array, and `child_index == -1` marks
  a leaf row. The kernel rejects negative-index-with-children,
  out-of-bounds ranges, non-forward references (which also kills
  cycles), per-panel overflow, orphan slots, and any tree deeper
  than `kMenuMaxStack = 4` panels. Patching submenu pointers
  happens in a second pass after every slot is populated so the
  menu primitive's `MenuItem::submenu` pointers land on stable
  storage.
- **Concurrent `TrackPopupMenu` from two PE processes**: serialise
  on the single-instance kernel menu — the second caller cancels
  with action_id = 0 and returns immediately.
- **PE `SetCursor`**: live. Win32 PEs request a cursor shape via
  `user32!SetCursor(LoadCursor(NULL, IDC_*))`, which marshals
  through `SYS_GDI_SET_CURSOR` (174). The handler stamps the
  requested `GdiCursorShape` on every alive window owned by the
  caller's pid (`requested_cursor` slot on `RegisteredWindow`).
  The mouse-loop hit-test consults that slot after its
  kernel-priority rules (resize bands, Hand-on-button widgets,
  native IBeam over Notes / Browser) and uses it in place of the
  unconditional Arrow fallback when the cursor is over a
  client-area pixel of one of those windows. Title-bar hits keep
  the Arrow fallback so window chrome stays predictable. Custom
  sprite registration (`SYS_GDI_CREATE_CURSOR`, 175) accepts a
  12×20 PE-supplied mask + hotspot and returns a sentinel HCURSOR
  ≥ 256 the PE then hands to `SetCursor`; custom shapes bypass
  the per-window slot and stamp the global cursor directly. Known
  limits: shape is per-process, not per-thread (Win32 spec is
  per-thread), and a shape request from a process that owns no
  windows only takes effect via the global path while no PE
  window is under the cursor.
- **ImageView zoom + pan**: independent of window size. Ctrl+wheel
  and `+` / `-` / `=` / `_` step `zoom_percent` by 25 percentage
  points each (clamped to [25, 400]); `0` resets to fit-to-window.
  Arrow keys pan by 32 px when zoomed past 100% (Left/Right at
  100% fall back to prev/next image, Up/Down become no-ops). The
  decoded thumbnail buffer is sized to the content rect once;
  zoom is applied at blit time by nearest-neighbour-scaling that
  buffer, so changing zoom doesn't trigger a re-decode. Resizing
  the window changes how much of the image is visible at 100% but
  does NOT change `zoom_percent`.
- **Drag-and-drop between windows**: shipped via
  `kernel/drivers/video/dnd.{h,cpp}`. Single in-flight payload
  (`DndPayload { kind, text[31] }`) with `DndKind::FileEntry` /
  `Bookmark` / `Text`. Sources call `DndBegin` from a press-edge;
  targets register via `DndRegisterDropTarget(hwnd, cb,
  accepted_mask)`. The mouse loop feeds motion into
  `DndUpdateCursor`; release calls `DndResolveAt(cx, cy)` which
  walks alive targets top-down. `DndCompose` paints the ghost
  image after chrome but before tooltips. v1 consumers: Files
  (source), Notes / ImageView (targets). Future gap: full
  OLE/IDataObject COM marshalling for Win32 PE source apps
  (`userland/libs/ole32/ole32.c` ships the loader-resolvable
  surface but `DoDragDrop` is a stub).
- **Audio feedback / system sounds**: gated on HDA codec
  programming (Roadmap.md). PC speaker exists but is not
  wired to any UI event.
- **Settings GUI**: shipped as a unified windowed app
  (`kernel/apps/settings.{h,cpp}`) with sub-panels for General
  (theme + active-window opacity + clock + version banner), Display,
  Sound, Keyboard, Mouse, and DateTime
  (`kernel/apps/settings_<panel>.cpp`). Number keys 0..5 switch
  panels; the General panel includes the theme picker that
  `Ctrl+Alt+Y` also drives.
- **Trash / ramfs mode in Files**: every Files mode now ships its
  own per-row right-click menu tuned to what the backing store
  supports. FAT32 keeps the rich 30..36 surface (Open / Rename /
  Delete / Properties / Refresh / New File / New Folder). DuetFS
  (read-only browse mount) shows Open / Properties / Refresh
  (action ids 37/38/39). Trash shows Open / Restore / Delete
  Forever / Properties / Refresh (Open is action 44 and notifies
  "restore to open" — the FAT32 openers look up by name in root,
  so opening a binned file in-place is a GAP pending an opener
  refactor; Delete Forever shares the same Y-confirm prompt the
  X keybind triggers). Ramfs shows Open / Delete / Properties /
  Refresh, with Delete flagged disabled because the trusted
  ramfs is constinit `.rodata` and there is no unlink primitive
  to route through.
- **Win32 common controls, outline fonts, multi-threaded
  message queues**: still on the windowing track's deferred
  list. (Native modal dialogs ship via `dialog.{h,cpp}` —
  `MessageBox` / `InputBox`; native scrollbars ship via
  `scrollbar.{h,cpp}` with full hit-test + drag-the-thumb
  wiring in the kernel mouse loop.)
- **Pass C typography — bitmap Caption collapses to Body scale**:
  both render at 8 px on bitmap themes because the bitmap font is
  single-size. Acceptable v0.
- **Pass C typography — Bold-TTF degrades to Regular when
  `LiberationSans-Bold.ttf` fails to load**: surfaced at boot via
  `chrome font bold load FAILED — Bold weight will degrade to
  Regular` (non-fatal advisory).
- **Pass C typography — no italic, no Thin/Medium/Heavy weights**.
  Extend via the `ChromeTextWeight` enum when a real caller needs
  it.

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md)
- [Win32 DLLs](Win32-DLLs.md) — `user32`, `gdi32`
- [Graphics Drivers](../drivers/Graphics-Drivers.md)
- [DirectX v0 Path](DirectX.md)
- [Duet Theme Spec](../specifications/Duet-Theme-Spec.md)
