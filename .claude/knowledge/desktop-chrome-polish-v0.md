# Desktop chrome polish — v0

_Type: Observation + Decision._
_Last updated: 2026-04-29._

## Update 2026-04-29 (title-text scale, usershell v2, HighContrast theme)

Three more slices closing out adjacent items now that the
big-ticket deferred items are fully scoped (TTF rasterizer
needs a font file + glyf walker; real compositor needs a
shadow framebuffer + per-window backing allocator; real
userland shell needs a freestanding userland libc — each is
a multi-week effort, not a single batch).

1. **`Theme.title_text_scale`** (commit `f79407f`). New
   per-theme field 1..8 (0 collapses to 1). Duet family at 2,
   compact at 1. Chrome paint in widget.cpp's title +
   subtitle path now routes through
   `FramebufferDrawStringScaled` and centres the (also-scaled)
   text in the title bar. Subtitle separator + clipped
   subtitle text scale together so the layout reads as a
   unit. Subtitle hit-zone calculation also picks up the
   per-theme `title_button_width` (was still using the
   pre-spec btn_side from before commit `4eb06c2` —
   incidental fix).

2. **Userland shell ELF v2** (commit `f00cdf5`). Extends the
   hand-built ELF from a single SYS_WRITE+SYS_EXIT to a
   three-syscall sequence:
   `SYS_WRITE("Hello from usershell\n", 21);`
   `pid = SYS_GETPID();`
   `SYS_EXIT(pid);`
   The exit-code-as-pid trick lets the kernel reaper log the
   userland shell's PID via the existing "task <pid> exited
   with code <N>" path — confirms the round-trip without
   needing decimal-to-ASCII conversion in the stub. ELF
   layout updated: 40-byte code (was 33), 21-byte msg, 181
   bytes total.

3. **HighContrast accessibility theme** (commit `077c418`).
   `ThemeId::HighContrast` (idx 9, 10th theme). WCAG-AAA
   palette: pure black bg, pure white ink, bright yellow
   accents (start, close, every role title). Per-role hue
   is uniform yellow; differentiation falls back to title
   text content so users with colour-blindness aren't
   relying on hue. Cursor white outline + yellow fill.
   Compact 22 / 28 px chrome.

Spec status table picks up:
- "Per-theme `title_text_scale`" -> Yes (with chrome wiring).
- "Accessibility theme" -> Yes (HighContrast).
- Userland shell row updated to v2 details.

Substantively deferred (each genuinely needs infrastructure
that doesn't exist yet, not just more chrome work):
- Real TTF/OTF rasterizer — needs glyf walker + scanline
  fill + a real font file.
- Real compositor — needs shadow framebuffer +
  per-window backing allocator for true alpha-blend toward
  the underlying surface; also needs an SVG loader for the
  prototype's topo / syscalls SVGs.
- Real prompt-driven userland shell — needs a freestanding
  userland libc + an ELF build rule for compiling shell.c.

## Update 2026-04-29 (deferred-items batch — chrome dims, /sys/inspect, opacity, usershell ELF, scaled font)

Eight commits closing out almost every remaining row in the
spec status table. The deferred list went from "infrastructure
projects, multi-slice each" to "one row remains substantively
deferred (full TTF rasterizer)".

1. **Duet chrome 30/44 px** (commit `25892f2`). Bumps the
   five Duet-family themes (Duet, DuetLight, DuetBlue,
   DuetViolet, DuetGreen) from the v0 26/36 intermediate to
   the prototype's full 30-px title bar + 44-px taskbar.
   Compact themes stay at 22/28. The
   `EffectiveTitleHeight()` / `TaskbarHeight()` accessors
   are the single sources of truth so chrome paint, hit-test,
   and `WindowMaximize` all picked it up automatically.

2. **Per-theme `title_button_width`** (commit `4eb06c2`).
   New `Theme.title_button_width` field — 46 across the Duet
   family (the prototype's spec value), 0 ("derive from
   height" = historical square button) elsewhere. New
   `EffectiveButtonWidth()` helper. Chrome paint +
   `WindowPointInClose/Max/MinBox` all read btn_w / btn_h
   through it instead of the previous square btn_side. Glyph
   dimensions use min(btn_w, btn_h) so the inner mark stays
   centred and symmetric whether the box is square or
   wider-than-tall (Duet 46x22).

3. **`/sys/inspect/<basename>`** (commit `d5bb248`). Closes
   the last deferred procfs/sysfs row. New
   `PeQuickSummaryTo(writer, file, len)` public API in
   `pe_loader.h` mirrors PeReport's first ~10 lines (image
   base, entry RVA, image size, section count, exports
   status) but emits via a callback. New
   `RamfsInspectSnapshot()` walks an `InspectSlot[]` table
   keyed by basename and renders 1 KiB per PE into a per-PE
   buffer. `g_sys_inspect_children[]` is fixed up at init
   time because RamfsNode addresses inside an InspectSlot[]
   aren't constant-expressible.

4. **Multi-source topo wallpaper** (commit `cc8a200`).
   Replaces the single concentric-stack `PaintTopo()` with
   four independent peaks at fixed `(x%, y%)` anchors.
   Each peak carries its own `ring_step` / `ring_count`.
   Stroke is the same `AmbientStrokeRgb(9)` lift the previous
   single-source paint used. Reads as a real topographic
   map with overlapping contours instead of a target.

5. **Per-window opacity** (commit `fb43a6b`). New
   `u8 opacity` field per window (default 0xFF). Post-paint
   alpha overlay at `alpha = (0xFF - opacity)` over black
   fades the window. Hotkeys: Ctrl+Alt+, decrement,
   Ctrl+Alt+. increment (32-step, floored at 64 so chrome
   stays readable). Public APIs: `WindowSetOpacity` /
   `WindowGetOpacity`. Fake-transparency cue without a
   per-window backbuffer; the real compositor mask remains
   the long-tail item.

6. **Userland shell stub ELF** (commit `a923c14`).
   Hand-built 184-byte ELF64 (`kBinUsershellElfBytes`,
   clang-format-off-bracketed in ramfs.cpp). Code is the
   smallest useful userland stub:
   `SYS_WRITE(1, "Hello from userland shell stub\n", 31);
   SYS_EXIT(0);`. Encoded directly with RIP-relative
   addressing for the message so the ELF doesn't need
   relocations. Two new public ramfs accessors
   (`RamfsUsershellElfBytes` / `RamfsUsershellElfSize`)
   lift it out of the anonymous namespace; main.cpp's
   pre-login init block spawns via `SpawnElfFile` with
   `CapSetTrusted()` so the SYS_WRITE survives the
   `kCapSerialConsole` gate. End-to-end ring-3 proof
   without a freestanding userland libc.

7. **Integer-scaled bitmap font** (commit `5db88b6`).
   New `FramebufferDrawStringScaled` + `StringPixelWidthScaled`
   render each 8x8 source pixel as a `scale × scale`
   filled rect (capped at scale=8). Wired into the
   "WELCOME TO DUETOS  BOOT OK" desktop banner: themes
   with `title_bar_height >= 30` (the Duet family) render
   the banner at scale=2 so the text matches the bigger
   chrome. NOT a TTF rasterizer — that remains a
   multi-slice project — but a real path to bigger text
   without a fixed second bitmap font.

Spec status table now flips:
- Per-theme `title_bar_height` row → 22 / **30** (Duet
  spec target).
- Per-theme `taskbar_height` row → 28 / **44**.
- New row "Per-theme `title_button_width`" → **Yes**.
- Per-window alpha + 30/44 px → **Yes** (with caveat: real
  compositor backbuffer alpha-blend toward the underlying
  surface remains the long-tail item; the post-paint
  overlay is the v0 stand-in).
- TTF rasterizer → **Partial** (integer-scaled bitmap font).
- Userland shell → **Partial** (hand-built stub ELF
  spawns + runs ring-3 + makes a syscall + exits cleanly).
- procfs row → all six files including
  `/sys/inspect/<basename>`.

Remaining substantively deferred:
- Real TTF / OTF rasterizer (Inter at 7 sizes).
- Real compositor (per-window backbuffers + true alpha
  blend toward underlying surface; SVG loader for the
  prototype's `topo` / `syscalls` SVGs).
- A real prompt-driven userland shell with TOML reader.

## Update 2026-04-29 (StrokePath + window resize + procfs/sysfs surface)

Six more slices closing out almost every remaining row of the
spec status table. Theme not "chrome polish" anymore in the
narrow sense — these are the path-stroker primitive + the
keyboard tiling layer + the procfs/sysfs surface the spec's
deferred list called out.

1. **`FramebufferStrokePath`** (commit `164eb50`). New
   primitive in `framebuffer.{h,cpp}` accepting a flat
   `PathSegment[]` array of `PathOp { Move, Line, Cubic,
   Close }` ops. Lines walk Bresenham with a `thickness ×
   thickness` square stamp at each pixel; cubics flatten via
   adaptive de Casteljau (depth-cap 8, chord-deviation ≤ 1 px
   squared) and stroke each leaf as a thick line. Two
   file-local helpers — `StampThick` (clip-to-fb, FillRect)
   and `StrokeThickLine` (Bresenham-walk + stamp). Cubic
   uses a midpoint subdivision; chord-distance test uses the
   2A triangle formula, denominator-aware so degenerate
   chords don't divide by zero. Wired into the wallpaper:
   `PaintDuetArcs` now traces a single cubic-Bezier ribbon
   over the two interlocking rings in the teal/amber
   midpoint colour, thickness 2.

2. **Window resize hotkeys** (commit `8fb2d4a`).
   `Ctrl+Alt+Shift+Arrow` grows / shrinks the active window
   from its bottom-right corner in 32-px steps. Floor at 96
   px so the chrome stays usable. Tested BEFORE the bare
   `Ctrl+Alt+Arrow` snap handler — more specific modifier
   mask wins. Picks `shift` up from
   `ev.modifiers & kKeyModShift` alongside `ctrl`/`alt`. No
   new widget API; uses the existing `WindowResizeTo` +
   `WindowGetBounds`.

3. **`/proc/boottrace`** (commit `1559e27`). New /proc
   directory in the trusted ramfs tree with one file
   `boottrace`. Backed by a 16 KiB `.bss` buffer that
   `RamfsBoottraceSnapshot()` fills by routing
   `core::DumpLogRingTo` into a local writer. After
   snapshot, `file_size` is updated and the file is a normal
   static-bytes ramfs entry — no callback machinery in the
   rest of the VFS. Snapshot runs at the end of boot, just
   before the login gate. Sandbox tree intentionally not
   given /proc — sandbox processes still see only
   `/welcome.txt`.

4. **`/sys/syscalls`** (commit `43b5971`). Companion to
   `/proc/boottrace`: a `/sys` directory with one file
   `syscalls`. Backed by an 8 KiB `.bss` buffer that
   `RamfsSyscallsSnapshot()` fills with one line per
   `kSyscallNames` entry, formatted as
   `<dec_nr>  SYS_FOO\n`. Two file-local helpers —
   `SyscallsAppend` (NUL-terminated string) and
   `SyscallsAppendDec` (u64 → ASCII decimal, "0" for zero,
   no leading zeros, max 24 chars). Both truncate at the
   buffer end without a separate error path.

5. **`/proc/abi/native` + `/proc/abi/win32`** (commit
   `cb2625a`). New `/proc/abi` directory with two files:
   - `native`: header line plus `<dec_nr>  SYS_FOO\n` per
     `kSyscallNames` entry. Same payload shape as
     `/sys/syscalls` plus a `#`-prefixed header so consumers
     that key off path layout (Task Manager → ABI tab)
     don't have to special-case.
   - `win32`: header line plus every (DLL, function) the
     Win32 thunks table knows, formatted as `<dll>!<func>\n`
     in table order.
   Win32 dump is sourced from a new
   `Win32ThunksDumpTo(ThunksDumpFn)` public API in
   `subsystems/win32/thunks.h`: walks `kThunksTable` and
   emits 4 chunks per row (dll, "!", func, "\n"). The
   constexpr table is the single source of truth so the
   dump can never drift. Generic `AppendInto` /
   `AppendDecInto` helpers parameterized over target buffer
   so each ABI dump's cursor stays independent.

6. **`/proc/cpuhist`** (commit `c4a6e97`). 60-sample ring of
   `CpuhistSample {t_total, t_idle, busy_percent}`. Each
   call to `RamfsCpuhistSnapshot()` reads
   `sched::SchedStatsRead()` and computes busy% as
   `1 - (delta_idle / delta_total)` against the previous
   sample's cumulative ticks (first sample is 0 by
   construction since it has no predecessor). Then
   re-renders the buffer from the ring oldest-first, with
   a `#`-prefixed header that calls out the gap: no
   timer-driven sampler is wired up yet, so the ring fills
   only at explicit `RamfsCpuhistSnapshot()` calls. Future
   slice can hang it off a 1 Hz timer thread.

`main.cpp`'s pre-login snapshot block now runs all four
snapshots in sequence: `RamfsBoottraceSnapshot`,
`RamfsSyscallsSnapshot`, `RamfsAbiSnapshot`,
`RamfsCpuhistSnapshot`. All five materialised files behave
like normal static-bytes ramfs entries from that point on.

Spec status table now flips:
- `FramebufferStrokePath` row → **Yes** (with cubic flattener +
  wallpaper consumer; topo / syscalls SVG wallpapers still
  deferred since they need an SVG loader, not a stroker).
- procfs row → **Yes** for all five files; only
  `/sys/inspect/<pid_or_path>` remains deferred (needs
  per-path fanout, not a static buffer — would require a
  callback node type the rest of the VFS doesn't have yet).

The remaining "No"s in the spec table are the structural
ones: real per-window alpha compositor, TTF rasterizer,
userland shell. Each is a multi-slice project of its own.

## Update 2026-04-29 (window snap + direct theme select hotkeys)

Two more chrome / UX slices:

1. **Window snap halves (Ctrl+Alt+Arrow)** — new `WindowSnapLeft`
   / `WindowSnapRight` APIs sit `h` against the left / right half
   of the work area (framebuffer minus taskbar). Both clear the
   maximized flag. New file-local `WorkArea()` helper is the
   single source of truth for "framebuffer minus taskbar
   reserve" — same calculation `WindowMaximize` already uses.
   Keyboard shortcuts: `Ctrl+Alt+Left/Right` snap halves,
   `Ctrl+Alt+Up` maximizes, `Ctrl+Alt+Down` restores (or
   minimizes if not maximized). Mirrors Win10's Win+Arrow tiling
   (Win key isn't tracked separately; Ctrl+Alt is the standard
   "system" modifier in this session).

2. **Direct theme select** — `Ctrl+Alt+1..9` now picks a specific
   theme (idx 1..9 maps to `ThemeId` 0..8). Saves repeat presses
   of Ctrl+Alt+Y (cycle) when there are 9 themes registered.
   Out-of-range digits (idx ≥ kCount) silently no-op.

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

## Update 2026-04-29 (per-theme taskbar height + StrokeArc + partial-arc DuetMark)

Three more chrome polish slices:

1. **Per-theme `taskbar_height`** — `Theme` struct gained the
   field. Duet family ships 36 px; non-Duet themes + DuetClassic
   stay at 28. main.cpp's boot path samples `theme0.taskbar_height`
   instead of the prior hardcoded 28. New `TaskbarHeight()`
   accessor exposes the live value; `WindowMaximize` uses it for
   the bottom-edge reserve so maximize on Duet correctly preserves
   the larger strip. Live re-init on theme cycle still deferred
   (would shift the console anchor mid-session).

2. **`FramebufferStrokeArc(cx, cy, r, start_deg, sweep_deg,
   thickness, rgb)`** — partial-arc rasterizer backed by a
   91-entry Q16.16 sin table covering [0°, 90°] (mirrored for
   the other quadrants). Walks the sweep in 1° steps; for each
   step plots concentric pixels at `r-half .. r+half`. Negative
   sweep flips direction; sweep > 360° caps to 360°. Coordinate-
   clipped, no AA.

3. **Partial-arc DuetMark on START** — the START button's
   two-circle DuetMark is replaced with two 189° arcs (matches
   the prototype's `dasharray = (r·π·1.05, r·π·2)` =
   ~52% of the circle), thickness 2: primary arc rotated -30°
   in the variant accent, amber arc rotated 150°. Each 189°
   sweep × 2 thickness × 2 arcs = ~756 pixel writes per frame —
   trivial.

## Update 2026-04-29 (per-theme dimensions + DuetClassic palette)

`Theme` struct gained a `title_bar_height` field. Duet family
(Duet / DuetLight / DuetBlue / DuetViolet / DuetGreen) ships
26 px; non-Duet themes + DuetClassic stay at 22 px. New
`EffectiveTitleHeight(WindowChrome&)` helper in widget.cpp is
the single source of truth — explicit per-window
`title_height` wins, otherwise the active theme's value, else
the historical 22-px default. Six call sites that hardcoded
`(c.title_height == 0) ? 22 : c.title_height` now route
through the helper, so paint + hit-test can't desync after a
theme cycle.

`ThemeId` gained `DuetClassic` (kCount: 8 → 9). Win9x panel
grey (#C0C0C0) carrying Duet's dual-accent teal/amber title
hues. Uses a 4-px corner-punch radius (vs 6-px for the modern
Duet variants) so the chrome proportions match the era's
chunkier feel. Cursor returns to classic black-on-white.
DuetMark, rounded corners, duet-arcs wallpaper extend to
DuetClassic transparently.

`docs/duet-theme-spec.md` gained a "Status (2026-04-29)" table
at the top — single-glance shipping summary, sorted by area.
Six rows are **Yes** (slate Duet, variants, window chrome,
taskbar polish, wallpapers, popup polish + cursor); five
remain **Deferred** (real compositor, TTF rasterizer, path
stroker, userland shell, procfs entries).

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
