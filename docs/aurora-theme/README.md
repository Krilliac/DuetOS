# Handoff: DuetOS "Aurora" shell redesign

## Overview

A full visual + interaction redesign of the DuetOS desktop shell — window chrome,
taskbar, Start, quick settings, notification centre, sign-in, boot, and nine app
surfaces. It replaces the current Duet theme's flat-fill chrome with a glossy
glass system in the Windows 7 Aero lineage crossed with modern Fluent-era layout
(centred island taskbar, rounded surfaces, superbar-style pinned icons) and an
"ethereal" translucency pass.

The design keeps DuetOS's own identity rather than importing Microsoft chrome:
the two interlocking arcs stay the logomark, and the dual accent keeps its
meaning — **teal = native ABI, amber = Win32 PE peer** — refined to
`#31e0c0` / `#ffc046` and now fully user-customisable.

## About the design files

The files in this bundle are **design references created in HTML** (Design
Components — a single streaming `.dc.html` file each). They are prototypes that
show intended look and behaviour. They are **not** production code to port
verbatim.

DuetOS's shell is C++ in the kernel (`kernel/drivers/video/*`), so the task is to
**re-express these designs in that renderer**: theme tokens in `theme.h` /
`theme.cpp`, layout in `taskbar.cpp`, chrome in `widget.cpp`, per-app panels in
`kernel/apps/*`. `IMPLEMENTATION.md` in this folder maps every part of the design
onto the real files and calls out what the compositor needs in order to paint it.

## Fidelity

**High-fidelity.** Exact colours, type sizes, spacing, radii, shadows, and
interaction states are specified. Recreate pixel-for-pixel where the framebuffer
allows; `IMPLEMENTATION.md` lists the graceful degradations for the parts that
need new compositor capability (real backdrop blur, per-pixel alpha).

Design canvas: **1920 × 1080**, 60 Hz. The shipped QEMU framebuffer is 1024 × 768 —
`IMPLEMENTATION.md` §7 gives the scaled-down metric table.

## Screens / views

### 1. Desktop
- **Purpose:** the composited shell — wallpaper, desktop icons, gadgets, windows, taskbar.
- **Layout:** full-bleed 1920 × 1080. Desktop icons: 2-column grid of 104 px cells at
  `left:44 top:44`, `gap:10`. Gadget column: `right:44 top:44`, width 300, `gap:14`.
  Taskbar island: centred horizontally, `bottom:22`, height 68.
- **Wallpaper (4 layers, bottom → top):**
  1. `linear-gradient(158deg, --bg-2 0%, --bg-1 52%, --bg-0 100%)`
  2. Aurora blobs, `inset:-10%`, `filter:blur(10px)`, 34 s drift animation:
     `radial-gradient(46% 44% at 74% 20%, accent 34%)`,
     `radial-gradient(42% 40% at 16% 86%, accent-2 22%)`,
     `radial-gradient(34% 32% at 22% 14%, accent 14%)`
  3. 60 px grid of `--line` hairlines, opacity .5, radial mask `80% 70% at 50% 45%`
  4. Hex-dump band — JetBrains Mono 12/26, letter-spacing 2, opacity .13, masked
     `linear-gradient(105deg, #000 0%, transparent 46%)`; rows are
     `<offset 8 hex>: <40 bytes>` from `((r*40+c)*1103515245+12345) & 0xff`
  5. Arcs watermark: 1240 px SVG at `56%/46%`, six counter-rotating circles
     (r 470/360/250, stroke 2/1.4/1, opacity .22→.09), 46 s drift
  6. Vignette `radial-gradient(120% 100% at 50% 50%, transparent 40%, --vignette)`
- **Desktop icon:** 52 × 52 tile, radius 14, gloss dome
  (`linear-gradient(180deg, rgba(255,255,255,.3), rgba(255,255,255,.06) 44%, transparent 52%)`
  over `linear-gradient(160deg, accent 30%, accent 8%)`), border `accent 38%`,
  `box-shadow: 0 12px 24px -12px rgba(0,0,0,.75), inset 0 1px 0 rgba(255,255,255,.5),
  inset 0 -6px 12px rgba(0,0,0,.18)`; 24 px stroke glyph in `--accent`.
  Label 12 px/500, centred, `text-shadow: var(--label-shadow)`.
  Hover: background `--glass-3`, border `--line`.
- **Gadgets:** clock (44 px mono time + weekday/date + 66 px analogue dial with
  accent second hand and glowing hub), kernel (arcs mark, "healthy", 46 px CPU
  sparkline, 5 mono stat rows), ABI peers (3 glowing dots + counts).
  All: radius 18, `--gloss-strong` over `--glass`, blur 32 px / saturate 190%,
  border `--line-2`, `--shadow-float`, `inset 0 1px 0 --sheen`.

### 2. Window chrome (all nine apps)
- Radius 14, `--gloss` over `--glass-2`, backdrop blur 36 px saturate 185%,
  1 px `--line-2` border, `--shadow-win`, plus
  `inset 0 1px 0 --sheen, inset 0 -1px 0 rgba(255,255,255,.05)`.
- **Titlebar:** 44 px. Two stacked gradients — specular
  `linear-gradient(180deg, rgba(255,255,255,.15), rgba(255,255,255,.04) 50%, transparent 51%)`
  over `linear-gradient(180deg, --bg-3 70%, transparent)`; a 1 px sheen hairline
  along the very top edge (`linear-gradient(90deg, transparent, --sheen, transparent)`);
  16 px app glyph in the accent (amber for PE-adjacent apps), 13 px/600 title,
  11.5 px mono subtitle in `--ink-3`.
- **Controls:** minimise 46 × 44, maximise 46 × 44, close 52 × 44. Hover: `--hover`;
  close hover `--danger #ff5f57` with white glyph. Icons 12–14 px, stroke 1.5.
- **Focus:** overlay ring `inset 0 0 0 1px accent 30%` + `0 0 60px -10px accent 22%`.
  Unfocused windows lose the ring and the titlebar specular.
- **Status bar:** 30 px, 11 px mono `--ink-3`, `|` separators in `--line-2`,
  right-aligned accent value.

### 3. Task Manager (800 × 560 default)
Tabs: Processes · Performance · ABI peers · Startup — 12.5 px, active 600 weight
with a 2 px `--accent` underline; right side carries a `live · 1 s` pill.
- **Processes:** table, 11 px uppercase `--ink-3` headers, rows 10 px/18 px padding,
  zebra `--glass-3`, hover `--hover`; glowing 7 px ABI dot; pill badges
  (`NATIVE` teal 18% / `WIN32 PE` amber 18% / `LINUX` grey); CPU > 5% turns amber;
  state column running/sleeping/zombie in accent/`--ink-3`/`--danger`.
- **Performance:** 264 px rail (CPU, Memory, NVMe0, e1000 — amber warn, Compositor)
  each with a 60 × 26 sparkline; selected row gets `--glass-3` + 2 px accent rail.
  Right pane: title + mono spec line + 24 px accent utilisation, 2 × 2 core cards
  (radius 12, 52 px filled sparkline), then a 4-up stat strip above a `--line` rule.
- **ABI peers:** three cards (native / Win32 PE peer / Linux) each with a glowing
  dot, mono subtitle, scrolling process list, and a count footer.
- **Startup:** mono boot-time line, then a bordered list — name, impact pill
  (HIGH amber / MED accent / LOW grey), and `+N ms` right-aligned.

### 4. Kernel Log (800 × 266 default)
Filter row: pill search field (live filter over tag + message) plus I/W/E toggle
pills that tint to accent / amber / `--danger` when active. Log pane: `--recess`,
11.5 px/20 px mono, columns `[ts 92px] [level 12px] [tag 62px] [message flex]`,
messages wrap (`pre-wrap`), timestamp `(i*0.027+0.184).toFixed(6)` zero-padded to 11.
Warnings colour the whole message amber. Tail caret: `▸` plus a 7 px accent block
blinking at 1.05 s, 2-step.

### 5. Inspect (1160 × 660)
Toolbar: amber PE glyph, path, mono meta, then `Decode` / `Trace` pills and a
filled accent `Run in sandbox` pill. Body grid `212px 1fr 268px`:
sections rail (selected = accent 14% + 2 px rail) over an imports block;
disassembly (12 px/21 px mono — address `--ink-3` 100 px, bytes amber 80% 168 px,
mnemonic coloured by class: call = accent, ret = danger, jump = amber, else `--ink`,
syscall rows tinted accent 12% with a `⟶ SYS_*` annotation); syscall-site rail
over hashes.

### 6. Files (690 × 578)
Toolbar: back/forward 28 px squares, breadcrumb pill (`duetos / bin`), search pill.
Body `172px 1fr`: quick-access rail (selected = accent 16% + rail) + devices list;
list columns `minmax(0,1fr) 68px 96px` with sticky uppercase headers; each row has a
16 px glyph coloured by ABI, name 12.5 px/500 with ellipsis, an ABI pill, mono size
and modified. Selected row = accent 14%. Footer: item count, selection, amber
"4 Win32 PE".

### 7. Settings → Personalization (1060 × 700)
Nav 248 px: avatar + build, then System / Personalization / Display / Sound /
Network / ABI peers / Security / About; selected = accent 16% + 2 px rail.
Content: heading + hint, then
- **Theme family** — 5 × 2 cards, one per `ThemeId` (Duet, DuetLight, DuetBlue,
  DuetViolet, DuetGreen, DuetClassic, Slate10, Amber, Classic, HighContrast), each a
  58 px mini-chrome preview (title bar, accent bar, taskbar strip) + name + note;
  active card gets an accent border and an "active" tag.
- **Accent** — see §8 below.
- **Wallpaper** — 4 thumbnails (aurora / duet-arcs / topo / syscalls), 2 px accent
  border when selected.
- **Taskbar** — Island | Full width, Compact 38 | Regular 68 segmented pairs.
- **Chrome tactility** — five labelled 0–255 sliders mirroring the `Theme` struct
  (`shadow_intensity_active` 255, `shadow_intensity_inactive` 160,
  `hover_lift_alpha` 96, `press_alpha` 128, `motion_intensity` 220) plus an
  "enabled" pill and a mono summary block (`tactility=on · motion=auto`,
  `title_bar_height 44 · taskbar_height 68`, `font_kind Ttf · title_text_scale 2`).

### 8. Accent editor (inside Settings → Personalization)
Fully open-ended, not a preset list:
- Two channel cards — **Native ABI** and **Win32 PE peer** — each with a 52 px
  gloss swatch, role caption, a native colour picker and an editable hex field.
  Clicking a card selects it for editing (border `--ink-2` + 2 px colour ring).
- Three HSL sliders for the selected channel, tracks painted live: hue = full
  spectrum, saturation = grey→pure at current L, lightness = black→hue→white.
  Thumb: 16 px white circle, dark ring, drop shadow.
- Shade ramp: five swatches at L = 88/74/60/46/32 of the current H/S — click to apply.
- Pair helpers: complement / split / triad / analogue — each writes the *other*
  channel, so the ABI pair stays legibly distinct.
- Presets: 6 built-ins (Duet, Cobalt, Violet, Forest, Ember, Ice) + unlimited
  custom. Each card is a two-tone swatch + name + `built-in`/`custom` tag;
  custom cards carry `set` (overwrite with current pair) and `×` (delete).
  Name field + **Save preset**; **Reset all** restores Duet.
- Everything applies live to every surface; the pair and the preset list persist.

### 9. Terminal (820 × 440), Notepad (760 × 520), Calculator (350 × 520), GFX Demo (720 × 520)
- **Terminal:** `--recess` pane, 12.5 px/22 px mono; prompt lines accent 600,
  output `--ink-2`, warnings amber, kernel lines `--ink-3`; 9 × 15 blinking block caret.
  Status: `ring 3 | 80×24 | utf-8` + `Ctrl+Shift+C copy`.
- **Notepad:** menu strip (File Edit Format View Help, 12 px, 34 px tall), mono body
  on `--recess`, amber caret, status `Ln 12, Col 1 … UTF-8 | LF | 100%`.
- **Calculator:** mono expression line, 34 px result, DEC/HEX/BIN row (HEX in accent),
  then a 4-column keypad — function keys `--glass-3`/`--ink-3`, digits `--recess`,
  `=` accent-filled. Press state `translateY(1px) scale(.985)`.
- **GFX Demo:** client area of layered accent/amber/violet/blue radial blobs,
  `blur(2px) saturate(150%)`, 12 s drift, over a 3 px scanline+column grid
  (`repeating-linear-gradient`) to read as framebuffer pixels; mono overlay
  ("FramebufferPutPixel · 720×430 client", "present 60.00 fps · 0 dropped",
  amber "d3d11 ClearRenderTargetView → Present") and "press E for next mode".

### 10. Taskbar island
Centred, `bottom:22`, height 68, padding 8/12, radius 20, `--gloss-strong` over
`--glass`, blur 38 px saturate 200%, `0 26px 60px -20px rgba(0,0,0,.7)`,
`inset 0 1px 0 --sheen`, `inset 0 -1px 0 rgba(255,255,255,.07)`.
Order: Start (56 × 52, radius 14, 26 px arcs mark; open = accent 22% + accent 44%
border) · search pill (250 × 40) · divider · nine app buttons (52 × 52, radius 14,
22 px glyph; focused = accent 18% bg + accent 34% border + accent glyph) each with a
3 px indicator pill under it (running 10 px `--ink-3`/accent, focused 22 px accent
with `0 0 10px accent 80%`) · divider · stats pill (CPU % + 52 px sparkline + fps) ·
tray button (net/vol/battery, 15 px) · clock button (13 px mono time + 10.5 px date,
opens the notification centre) · 4 × 44 show-desktop rail with an accent→amber
gradient at 70% opacity.

### 11. Start menu (760 wide, centred, `bottom:112`)
Search pill (40 px) with a `Ctrl Esc` key hint · "Pinned" label + "All apps →" ·
6 × 2 grid of 44 px domed tiles (PE Sandbox tile uses amber) · "Recommended"
2 × 2 cards (30 px glyph, 12.5 px title, mono subtitle) · 64 px footer with the
user chip (34 px gradient avatar, name, `uid=1000 · ring 3`), a Settings pill and
an amber Power pill. Radius 20, blur 40 px saturate 200%.

### 12. Quick settings (400 wide, `right:44 bottom:112`)
2 × 2 toggle chips (Network off / Audio on / Night light off / Tactility on — on =
accent 20% bg, accent 42% border, accent text) · volume and brightness sliders
(6 px track, gradient fill, 14 px knob) · "Personalization" label · Slate | Light
segmented · accent strip: 6 preset swatches, two inline colour pickers, and a
`Customise…` button that opens Settings.

### 13. Notification centre (420 wide, `right:44 bottom:112`)
Header ("Notifications", accent "3 new", "Clear all") · three cards (uppercase
source in the source colour, 12.5 px body, mono meta); warnings get an amber 12%
wash and amber 32% border · a `--line` rule · month calendar with mono weekday
letters and today filled accent with `--bg-0` text.

### 14. Sign in
Big mono clock (96 px, letter-spacing −4) + long date at `left:72 top:64`.
Centred card 420 wide, radius 24, blur 38 px: 104 px gradient avatar with an accent
outer glow, 21 px name, mono `uid=1000 · ring 3 · capability set: full`, a 46 px
password pill (dots + accent caret + 34 px accent arrow button → desktop), then
"Sign-in options · Reset via recovery hive". Bottom-left mono build lines;
bottom-right net / accessibility / power glyphs.

### 15. Boot
Always dark (`#04060a`) regardless of mode. 150 px arcs mark inside a breathing
accent radial glow (2.6 s), 34 px `DUETOS` at letter-spacing 10, mono build line,
then a 320 × 3 track with an accent→amber sweep (1.5 s linear), six mono boot lines
(`✓` accent, `win32` line amber, final `▸ comp starting compositor …`), and a
bottom strip: `4-LEVEL PAGING · SMP 4 CORES · W^X SMEP SMAP ASLR RETPOLINE`.

## Interactions & behaviour

- **Windows:** drag by titlebar (pointer delta ÷ scale), click anywhere to focus
  (raises z), minimise (hides, taskbar pill dims to `--ink-3`), maximise
  (0,0 → 1920 × 968, i.e. full height minus the island reserve; double-click the
  titlebar toggles), close (returns to minimised in the prototype).
- **Taskbar app button:** not running → launch; minimised or unfocused → focus;
  focused → minimise. Exactly the current prototype's rule.
- **Start / quick settings / notification centre:** mutually exclusive; a full-screen
  transparent scrim at z-index 1000 closes them on outside click.
- **Task Manager tabs / Inspect sections / Files places:** simple selection state.
- **Kernel Log:** live text filter (case-insensitive over tag + message) and three
  level toggles; the count in the status bar updates.
- **Accent editor:** every change repaints instantly by rewriting `--accent` /
  `--accent-2` on the document root; writes to storage are debounced 500 ms so a
  slider drag doesn't thrash persistence.
- **Motion:** wallpaper drift 34 s / 46 s, GFX plasma 12 s, boot glow 2.6 s, boot
  sweep 1.5 s, carets 1.05 s 2-step. Chrome transitions are short and non-elastic
  (press 90 ms, hover 160 ms, panel open 320 ms) per the existing tactility spec.

## State management

`screen` (desktop | login | boot) · `mode` (dark | light) · `accents {a,b}` ·
`presets[]` · `activePreset` · `editing` (a | b) · `presetName` ·
`startOpen` · `qsOpen` · `ncOpen` · `focus` (window id) · `tab` (Task Manager) ·
`filter` + `levels {I,W,E}` (Kernel Log) · `wins{id: {x,y,w,h,z,min,max}}` for
tm, files, kl, ins, set, term, note, calc, gfx · `vw` (fit-to-viewport scale).

Persisted: `localStorage["duetos-aurora-accents"] = {accents, presets, activePreset}`.
In the real shell this belongs in the registry hive — see `IMPLEMENTATION.md` §5.

## Design tokens

**Dark (default)**
```
--bg-0 #04060a   --bg-1 #080c12   --bg-2 #0e141d   --bg-3 #131b25
--glass rgba(19,26,35,.46)        --glass-2 rgba(11,16,22,.58)
--glass-3 rgba(255,255,255,.06)   --recess rgba(4,7,11,.42)
--line rgba(255,255,255,.1)       --line-2 rgba(255,255,255,.2)
--sheen rgba(255,255,255,.34)
--ink #eef3f9    --ink-2 #a7b3c2  --ink-3 #68737f
--accent #31e0c0 --accent-2 #ffc046 --danger #ff5f57
--hover rgba(255,255,255,.07)     --press rgba(255,255,255,.12)
--shadow-win 0 44px 90px -28px rgba(0,0,0,.78)
--shadow-float 0 24px 60px -20px rgba(0,0,0,.6)
--vignette rgba(0,0,0,.35)        --label-shadow 0 1px 3px rgba(0,0,0,.5)
--gloss        linear-gradient(180deg, rgba(255,255,255,.11), rgba(255,255,255,.03) 34%, rgba(255,255,255,0) 46%, rgba(255,255,255,.02) 100%)
--gloss-strong linear-gradient(180deg, rgba(255,255,255,.2), rgba(255,255,255,.05) 40%, rgba(255,255,255,0) 60%, rgba(255,255,255,.03) 100%)
```

**Light**
```
--bg-0 #dfe5ee   --bg-1 #eaeef4   --bg-2 #f2f5f9   --bg-3 #ffffff
--glass rgba(255,255,255,.56)     --glass-2 rgba(255,255,255,.68)
--glass-3 rgba(9,20,38,.03)       --recess rgba(9,20,38,.045)
--line rgba(9,20,38,.1)           --line-2 rgba(9,20,38,.14)
--sheen #ffffff
--ink #111a24    --ink-2 #4b5765  --ink-3 #7b8794
--accent #0aa58f --accent-2 #b6791a (light-mode pair for the built-in Duet preset)
--shadow-win 0 34px 70px -26px rgba(16,28,48,.34)
--shadow-float 0 20px 44px -18px rgba(16,28,48,.28)
--vignette rgba(24,44,80,.12)     --label-shadow 0 1px 2px rgba(255,255,255,.7)
```

**Preset pairs** `Duet #31e0c0/#ffc046 · Cobalt #4da3ff/#ffc046 · Violet #a78bfa/#f0abfc ·
Forest #3fd68a/#e2c66b · Ember #ff7a4d/#ffd166 · Ice #7fd7ff/#c9b8ff`

**Geometry** radius: 8 (small) / 10–12 (controls, cards) / 14 (windows, tiles) /
18–20 (floating surfaces) / 99 (pills). Spacing steps 2/4/6/8/10/12/14/16/18/22/26.
Chrome: titlebar 44, status bar 30, taskbar island 68 (+22 inset), tab strip 44.

**Typography** UI = **Instrument Sans** 400/500/600/700; data/system =
**JetBrains Mono** 400/500/600/700 (both Google Fonts, SIL OFL).
Scale: 9.5 / 10 / 10.5 / 11 / 11.5 / 12 / 12.5 / 13 / 14 / 17 / 19 / 21 / 24 / 34 / 44 / 96.
Uppercase section labels: 10–11 px, 700, letter-spacing .7–.9.
Tabular numbers everywhere a value updates.

## Assets

No binary assets are required. Every glyph is an inline stroke SVG (24 × 24 box,
stroke-width 1.6–1.7, round caps/joins) taken from
`docs/duet-theme/prototype/desktop-icons.jsx`, and the arcs logomark is the same
two-counter-rotating-circle construction used there. Fonts load from Google Fonts;
for the kernel build they need to be vendored as TTF (see `IMPLEMENTATION.md` §6).

## Files

| File | What it is |
|---|---|
| `DuetOS Aurora.dc.html` | The new design. Toolbar at the top switches Desktop / Sign in / Boot and dark ↔ light; everything else is the shell itself. Open in a browser. |
| `DuetOS Current.dc.html` | Pixel recreation of today's Duet theme (from `docs/duet-theme/prototype/`), for before/after comparison. |
| `IMPLEMENTATION.md` | File-by-file plan for landing this in the kernel, including the compositor work the glass needs. |
| `BRANCH.md` | Exact git commands to put this bundle on a new branch. |
| `github.md` | Source association + screen → repo-file map. |
