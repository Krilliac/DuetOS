# DuetOS Chrome Tactility — Design Spec

**Status:** Approved, pending implementation plan
**Date:** 2026-05-24
**Branch context:** `claude/desktop-functional-audit`
**Companion docs:** `docs/duet-theme/prototype/` (design source of truth — interactive HTML prototype with Tweaks panel for live theme/accent/wallpaper cycling)
**Sequencing:** This is **pass A** of four. Follow-ups (B = first-impression moments, C = typography + hierarchy, D = app-level redesigns) sequence after this lands.

---

## 1. Summary

Lift the visual quality of DuetOS system chrome by adding **depth + materiality** — drop shadows, hover lift, press depression, focus glow, snap-zone preview, menu pop, and modal dim — anchored on the Duet Slate palette. Built on three new framebuffer primitives (alpha-blend rect, alpha-blend fill, soft-shadow renderer) and gated through the existing theme system so HighContrast / Amber opt out and other themes tune intensity.

Engineering target: ~570 LOC across ~10 files, no new subsystems, no new syscalls, no compositor rewrite. Sits on top of existing infra (damage diffing `d77478e3`, banded present `0d2c5db9`, window-animate tween `3e6e1586`, snap-zone preview `3681f5fe`, modal lockdep-safe callback `eb84a824`).

## 2. Goals

- **Every visible chrome surface gains depth** — windows cast shadows, taskbar tabs lift on hover, inputs glow when focused, modals dim their parents. The visual ceiling of the screenshots, not just the text.
- **The dual-accent identity (teal = native ABI, amber = Win32 PE peer) stays load-bearing** — focus glow on a Win32-role window is amber, on a native-role window is teal, regardless of the active theme's primary accent.
- **Zero impact on opt-out themes** — HighContrast and Amber render bit-for-bit identical to pre-spec.
- **Tooling reusable for passes B/C/D** — the alpha-blend primitives are general infrastructure, not chrome-specific.

## 3. Non-goals

- **No layered/offscreen surfaces.** Per-window backing surfaces (the "option 3" engine-rewrite from the approach exploration) are explicitly deferred. We add primitives that let us approximate depth via Porter-Duff *over* on a single shared framebuffer; we do not rearchitect the compositor.
- **No SIMD/SSE2 in the blend inner loop yet.** The unrolled scalar path is within budget. Adding compile-flag-gated SIMD is a separate optimisation slice.
- **No premultiplied alpha sprite pipeline.** Sprites stay unpremultiplied, blended at draw time. Cheap enough at chrome rect sizes.
- **No user-mode syscall.** Tactility state is kernel-internal chrome state, consistent with the theme system. PE / ELF binaries see no new ABI surface.
- **No new app redesigns or boot-splash work in this spec.** Those are passes B and D.

## 4. Visual vocabulary (9 effects)

| # | Effect | Where it lives |
|---|---|---|
| 1 | Window drop shadow | `widget.cpp::WindowPaint` — `radius=24, opacity=120` active / `radius=16, opacity=60` inactive. Renders over wallpaper and over other windows. |
| 2 | Drag-lift shadow | While `WindowFlag::Dragging`, scale to `radius=32, opacity=160`. Eases back via existing `WindowAnimate` tween on release. |
| 3 | Active / inactive contrast | Inactive loses shadow strength AND titlebar gradient flattens. Focus reads at a glance across many windows. |
| 4 | Hover lift | Taskbar tabs, menu rows, start-menu tiles, file rows, button hover: 1px Y-translate + 6% additive white overlay + 4px ambient shadow. Single shared primitive. |
| 5 | Press depression | Inverse of hover: 1px Y+ translate, ambient shadow flattens, slight darken (20% over black). Visible on mouse-down before release. |
| 6 | Focus accent glow | `RenderSoftShadowWithStroke` at `radius=4, opacity=120` in the theme's `focus_glow_colour` (teal for native role, amber for Win32 role — dual-accent semantics). Replaces 1px border. |
| 7 | Snap-zone preview | Existing snap-hover preview (commit `3681f5fe`) → translucent accent fill (20% alpha) + window silhouette shadow behind. Reads "the window will sit here, hovering." |
| 8 | Menu pop scale | Dropdowns and context menus: 6-tick scale-in (95% → 100%, cubic ease-out) via extended `WindowAnimate::AnimKind::ScalePop`. Shadow fades in. Esc / outside-click reverses. |
| 9 | Modal dim + lift | Modal dialogs: 40%-darkened scrim over parent rect on open + 50% larger shadow than a normal window. Pairs with existing `sound_cue` + lockdep-safe modal callback (commit `eb84a824`). |

### 4.1 Control glyphs (titlebar buttons)

- `−` minimize · `□` maximize → toggles to `❐` restore · `×` close.
- 28×22 cells, 2px gutter. Drawn via existing 8×8 bitmap font (no TTF dependency).
- Hover: 6% white overlay. Close hover: full `#D24A4A` red fill.
- Maximize glyph toggles at WM level via existing `WindowFlag::Maximized` bit.

## 5. Primitives API

### 5.1 File layout

```
kernel/drivers/video/
├── framebuffer.h        (+3 declarations)
├── framebuffer.cpp      (+3 implementations, ~120 LOC)
├── shadow.h             (NEW — ~40 LOC)
└── shadow.cpp           (NEW — ~180 LOC + sprite table)
```

### 5.2 Framebuffer alpha primitives

```cpp
namespace duetos::drivers::video {

// Per-pixel alpha-blend source bitmap onto the live framebuffer.
// src_rgba is 0xAARRGGBB row-major; src_pitch_px is row stride in PIXELS.
// Clips to fb bounds. Skips alpha-zero pixels (important for shadow corners).
// Returns dirty-pixel count (caller charges to render_stats).
size_t FramebufferBlendRgba(u32 x, u32 y, u32 w, u32 h,
                            const u32* src_rgba, u32 src_pitch_px);

// Fill rect with one ARGB colour, blended over existing fb contents.
// Cheaper than BlendRgba (no source-buffer fetch). Used for hover/press
// overlays, snap preview fill, modal dim scrim.
size_t FramebufferBlendFill(u32 x, u32 y, u32 w, u32 h, u32 argb);

// Single-pixel blend, inlined.
inline void FramebufferBlendPixel(u32 x, u32 y, u32 argb);

}
```

- Blend: straight Porter-Duff *over*, per-channel, unpremultiplied: `dst = (src.rgb * src.a + dst.rgb * (255 - src.a)) / 255`.
- Inner loop unrolled 4-wide. SIMD deferred.
- All callers hold the compositor lock (same contract as `FramebufferFillRect`).

### 5.3 Soft-shadow renderer

```cpp
namespace duetos::drivers::video {

// 9-slice composed from a single 32×32 quarter-circle quadratic-falloff
// corner sprite + edge extrusion. Shadow renders OUTSIDE (x,y,w,h) —
// the rect is the window edge; the shadow blooms outward. Charges
// itself to render_stats via FramebufferBlendRgba.
//
// radius: 8..48 (clamped). opacity: 0..255. colour: 0x00RRGGBB.
void RenderSoftShadow(s32 x, s32 y, u32 w, u32 h,
                      u32 radius, u8 opacity, u32 colour);

// Variant: shadow + a 1px-wide accent stroke at the inner edge.
// Used for focus glow (saves a separate FillRect call).
void RenderSoftShadowWithStroke(s32 x, s32 y, u32 w, u32 h,
                                u32 radius, u8 opacity, u32 colour,
                                u32 stroke_colour);

}
```

- Atlas: single 32×32 RGBA bitmap baked at build time by `tools/build/gen_shadow_atlas.py` → `generated_shadow_atlas.h`. Same pattern as `generated_svg_*.h`. ~4 KB constexpr in `.rodata`.
- Falloff: `alpha(d) = 255 * pow(1 - d/32, 2)` (quadratic — softer than linear, cheaper than gaussian, indistinguishable at chrome scale).
- `shadow.cpp` exports `ShadowSelfTest()` and `BlendSelfTest()`, called from the boot self-test list immediately after `ThemeSelfTest()` (`kernel/core/boot_bringup.cpp`).

### 5.4 Result<T,E> shape

These primitives never fail recoverably — bad rects clip to nothing; null src pointers are a programmer bug (debug-build assert via `KBP_PROBE(kBlendRangeOob, …)`). Return `size_t` / `void` matching existing `FramebufferFillRect`. No `Result<T,E>` ceremony.

## 6. Compositor integration

### 6.1 Paint order

Per window: shadow first, body second. Bottom-to-top z-order preserved. No new z-order machinery.

```
wallpaper
  ├─ window[bottom].shadow      (blended over wallpaper)
  ├─ window[bottom].body        (solid)
  ├─ window[mid].shadow         (blended over wallpaper + bottom.body)
  ├─ window[mid].body
  ├─ window[top/active].shadow  (blended over everything below)
  ├─ window[top/active].body
  └─ cursor                     (solid + optional micro-shadow)
```

### 6.2 Paint-path changes

| File | Function | Change |
|---|---|---|
| `widget.cpp` | `WindowPaint` | Pre-body: `RenderSoftShadow` with theme-scaled active/inactive intensity. Dragging → scale up. |
| `widget.cpp` | `WindowPaintTitlebar` | New glyph spec for `− □ ×` controls. Hover via `BlendFill`. Close-hover via red `FillRect`. |
| `widget.cpp` | `WindowPaintFocusGlow` *(new)* | On `WidgetFlag::Focused`, `RenderSoftShadowWithStroke` in `focus_glow_colour` (amber if Win32 role override). |
| `taskbar.cpp` | `PaintTab` | Hover: `BlendFill(0x1AFFFFFF)` + 4px ambient shadow + 1px Y-translate. Press: `BlendFill(0x33000000)`. |
| `taskbar.cpp` | `PaintStrip` | 6×18 ambient drop shadow above the strip — covered by banded present row. |
| `start_menu_apps.cpp` | `PaintTile` | Same hover/press treatment. Tile shadow `radius=4 → 8` on hover. |
| `menu.cpp` | `MenuOpen` | `WindowAnimate::ScalePop` (6-tick, 95% → 100%, cubic ease-out) + shadow fade-in. |
| `menu.cpp` | `PaintRow` | Hover/press via `BlendFill`. |
| `dialog.cpp` | `DialogPaint` | Open: `BlendFill(parent_rect, 0x66000000)` scrim once, then `RenderSoftShadow(modal, radius=40, opacity=180)`. |
| `widget.cpp` | `SnapPreviewCompose` (existing, ~L1808) | Replace solid `FillRect` with `BlendFill(accent | 0x33000000)` + `RenderSoftShadow` in accent. |
| `cursor.cpp` | `CursorPaint` | **Stretch:** 2px micro-shadow under cursor. Gated by `cursor_microshadow_enabled`. Defer if budget tight. |

### 6.3 Damage tracking — inflate by shadow halo

Every `DirtyRect` emit in chrome paint paths inflates by the active shadow radius so moved windows don't leave shadow ghosts:

```cpp
DirtyRect r = window.bounds;
r.inflate(window.shadow_radius);
```

One-line change per call site. Audit via `git grep -nE "DirtyRect|InvalidateRect"`.

### 6.4 Content-diff frame elision interaction

The frame-elision path (commit `d77478e3` — `[UNVALIDATED]` per memory `compositor-damage-diff-validation.md`) hashes pixel rects. Real risk: elision could fail to defeat when a hover-bit flips and the un-paint should happen but the cached hash matches. Audit task: every `WidgetFlag::Hovered / Pressed / Focused` flip force-dirties the widget rect.

### 6.5 What does NOT change

- Compositor lock contract.
- Banded multi-rect present (`0d2c5db9`) — alpha-blended rects ride the same banding.
- Existing `WindowAnimate` 10-tick tween — extended with `ScalePop`, not replaced.
- `ThemeApplyToAll` publish flow.

### 6.6 LOC estimate

+120 (framebuffer.cpp), +220 (shadow.cpp+h), +60 (widget.cpp), +40 (taskbar.cpp), +30 (menu.cpp), +25 (dialog.cpp), +30 (start_menu_apps.cpp), +15 (snap preview), +10 (cursor.cpp stretch), +20 (damage halo audit). **~570 LOC across ~10 files.** No file exceeds the ~500-LOC threshold from CLAUDE.md.

## 7. Theme integration

### 7.1 New `Theme` struct fields

```cpp
struct Theme {
    /* ... existing fields ... */

    bool tactility_enabled;        // master switch
    u8   shadow_intensity_active;
    u8   shadow_intensity_inactive;
    u8   hover_lift_alpha;
    u8   press_alpha;
    u32  focus_glow_colour;
    bool cursor_microshadow_enabled;
};
```

### 7.2 Per-theme matrix

| Theme | tactility | shadow act/in | hover/press | focus glow | μ-shadow | Why |
|---|---|---|---|---|---|---|
| Classic | on | 80 / 40 | 100 / 100 | accent | off | Half intensity; era. |
| Slate10 | on | 200 / 100 | 255 / 255 | Win10 blue | on | Flat-dark base; full tactility appropriate. |
| **Amber** | **off** | — | — | — | off | 1980s CRT — shadows anachronistic. **Hard opt-out.** |
| **Duet (anchor)** | on | 255 / 128 | 255 / 255 | teal | on | Design target — all 9 effects at spec. |
| DuetLight | on | 100 / 50 | 200 / 200 | teal | on | Shadows softer on light bg. |
| DuetBlue | on | 255 / 128 | 255 / 255 | Win10 blue | on | Duet with accent swapped. |
| DuetViolet | on | 255 / 128 | 255 / 255 | violet | on | Duet with accent swapped. |
| DuetGreen | on | 255 / 128 | 255 / 255 | amber (sec) | on | Green-on-green glow reads poorly — route to amber secondary. |
| DuetClassic | on | 160 / 80 | 200 / 200 | **off** | off | Win9x grey — glow conflicts with dashed-rect focus convention. |
| **HighContrast** | **off** | — | — | — | off | Accessibility — intentionally flat. **Hard opt-out.** |

### 7.3 Runtime controls

- `tactility=on|off|auto` kernel cmdline override (default `auto` respects theme).
- `tactility` shell command — print state / `on` / `off` / `default`.
- No syscall (consistent with theme system).

### 7.4 ThemeSelfTest extension

Existing `ThemeSelfTest()` extended to assert:
- Every `tactility_enabled == true` theme: `shadow_intensity_active > 0` (no silent-nop themes — porting mistake guard).
- Every `tactility_enabled == true` theme: `shadow_intensity_active >= shadow_intensity_inactive` (contrast invariant — active never dimmer than inactive).
- HighContrast + Amber: `tactility_enabled == false` (regression guard — these MUST stay opt-out).
- Emits `[theme-selftest] tactility-matrix PASS (10/10)` on success; fires `kTactilityThemeMismatch` probe on any failure.

## 8. Performance + testing

### 8.1 Per-frame dirty-pixel budget

| Workload | Pre-spec | Post-spec target | Headroom |
|---|---|---|---|
| Idle desktop | ~0 | ~0 | unchanged |
| Cursor over wallpaper | ~256 | ~512 | 2× |
| Tab hover lift | ~3.2 K | ~6.4 K | 2× |
| Window drag | ~80 K | ~120 K | 1.5× |
| Modal open + scrim | ~50 K | ~600 K (one frame) | **12×** — concentrated, decays |
| Theme cycle (×10) | ~3 M total | ~3.5 M total | 1.2× |

Modal-scrim mitigations:
- Scrim paints once on open, not per frame.
- 6-tick scale-pop animation does not re-blend scrim each tick.
- Soft-lockup heuristic already rate-limited via `b79b8f59`.

Inner-loop budget for `FramebufferBlendRgba`: ~3 cycles/px on the unrolled-4 path. 1080p full-screen blend ~7 ms at 1 GHz. Acceptable for one-frame events (modal open); avoided for every-frame events (window body stays solid).

### 8.2 Self-test PASS lines (boot-log-analyze sentinels)

```
[shadow-selftest] PASS (atlas=32x32, corners=4, edges=4, opacity-linear=ok)
[blend-selftest] PASS (blendrgba, blendfill, alpha-zero-skip)
[theme-selftest] tactility-matrix PASS (10/10, hc-amber-opt-out=verified)
[tactility-selftest] PASS (per-effect: shadow=ok, hover=ok, press=ok, glow=ok)
```

Each fires a kernel probe on mismatch — added to `kernel/debug/probes.h`:

- `kShadowAtlasInvalid` — atlas integrity
- `kBlendRangeOob` — BlendRgba/BlendFill OOB rect (debug only; release clips silently)
- `kTactilityThemeMismatch` — theme advertises enabled but all intensity fields zero (porting mistake)

### 8.3 Live-boot smoke gates

`tools/test/boot-log-analyze.sh` checks:

- All four `*-selftest PASS` lines present.
- No `tactility-probe-fire` warn during the 30-second canonical smoke (`DUETOS_TIMEOUT=20 tools/qemu/run.sh`).
- `render_stats` end-of-smoke dirty-px total ≤ 1.5× pre-spec baseline.

### 8.4 Reusable measurement tooling

Committed alongside implementation:

- `tools/test/tactility-soak.sh` — opens N windows, cycles themes, drags, opens modals; captures `render_stats` per phase to TSV. Populates the "post-spec target" column above.
- `tools/test/tactility-screenshot-matrix.sh` — boots once per theme, captures via `apps/screenshot.cpp`, lays out 5×2 contact sheet. Catches visual regressions self-tests can't see.

### 8.5 Verification checklist (gate to "shipped")

- [ ] Build clean on `x86_64-release`, zero new warnings.
- [ ] All four self-test PASS lines in `tools/qemu/run.sh` boot log.
- [ ] `tactility-soak.sh` final dirty-px ≤ 1.5× baseline, no probe fires.
- [ ] `tactility-screenshot-matrix.sh` 10/10 themes render — visual inspection passes.
- [ ] VBox boot passes (per memory `vbox-bringup-pr266.md`).
- [ ] HighContrast: empirical pixel-diff vs pre-spec confirms zero chrome change.
- [ ] `git grep -nE "// (STUB|GAP):"` count for `drivers/video/` did not increase.
- [ ] Wiki `wiki/graphics/Compositor.md` (or equivalent) updated — one sentence per primitive, link to this spec.

## 9. Sequencing — what comes after

This spec covers **pass A** of four. The remaining passes inherit the alpha-blend primitives from this one and need them landed first:

- **Pass B — First-impression moments.** Boot splash (animated Duet arcs), login/welcome screen, idle/lock, wallpaper polish. Uses Section 5 primitives for the splash fade + arcs glow.
- **Pass C — Typography + hierarchy.** Wire the existing TTF infra (`TtfChromeFontSet` already called at boot) across chrome text. Introduce display/body/mono hierarchy. Largely independent of A but better-anchored after the chrome lift.
- **Pass D — App-level redesigns.** Pick 3 apps (Settings / About / Files / Sysmon candidates) and reimagine internal layout. Uses Section 5 primitives for hover lift and focus glow inside app bodies.

Each gets its own design spec → plan → implementation cycle.
