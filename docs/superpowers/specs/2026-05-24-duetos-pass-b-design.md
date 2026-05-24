# DuetOS Pass B — First-Impression Moments — Design Spec

**Status:** Approved, pending implementation plan
**Date:** 2026-05-24
**Branch context:** `claude/desktop-functional-audit`
**Companion docs:** `docs/duet-theme/prototype/` (design source of truth for the desktop), `docs/superpowers/specs/2026-05-24-duetos-chrome-tactility-design.md` (Pass A — primitives this spec consumes)
**Sequencing:** This is **pass B** of four. Pass A (chrome tactility) is merged in `main` via PR #338. Pass C (typography hierarchy) and Pass D (app-level redesigns) sequence after this lands.

---

## 1. Summary

Make the moments *before* an app is open — boot, login, lock, and the wallpaper itself — feel like one continuous, characterful surface. The Duet identity (interlocking arcs + teal/amber dual-accent) carries through unbroken from cold boot to desktop. The arcs are painted to the **same screen coordinates** in every scene; overlays (phase ticker, login card, desktop chrome) appear and disappear on top without the backdrop ever recomposing.

This is the first pass to introduce **motion** into DuetOS. Ambient, subtle, theme-gated: slow arc rotation + soft pulse glow + topo drift + per-minute clock. ~15 FPS, ~3–8% CPU avg on the surfaces where motion is active, with surgical dirty-rect declarations so Pass A's compositor-damage-diff frame elision continues to elide every static chrome region.

Engineering target: one new module (`splash.{h,cpp}`, ~300 LOC) + in-place extensions to `wallpaper.cpp`, `login.cpp`, `theme.{h,cpp}`, and `boot_bringup.cpp`. No new subsystems. No new syscalls. No compositor rewrite.

## 2. Goals

- **One continuous backdrop, four moments.** The arcs centroid at `(512, 384)` is painted by the same `WallpaperPaint(rgb)` call in splash, login, lock, and desktop. Overlays change; the backdrop does not.
- **Motion as a verb, not noise.** Slow rotation (±5° / 60 s), soft pulse (8 s breath), topo drift (1 px/s). 15 FPS ceiling. Always-on while a moment is active; gated off on opt-out themes; occlusion-aware on the desktop so a window covering the arcs pauses the per-frame work.
- **Pass A primitives carry forward.** The atlas-shadow 9-slice renderer underwrites the login card halo. Blend* underwrites the arc pulse alpha. The theme tactility matrix underwrites the per-theme motion intensity.
- **Zero impact on opt-out themes.** HighContrast renders bit-for-bit identical to pre-spec (no motion, no glow, no pulse, no drift) — same invariant Pass A's `hc-invariant-check.sh` verifies, extended to cover the new motion code paths.
- **Lock screen is free.** The lock screen IS the login screen with session-aware state; no new layout, no new paint path.

## 3. Non-goals

- **No new app chrome, no new typography, no app redesigns.** Those are Passes C and D.
- **No GPU acceleration.** Pure software framebuffer, same as Pass A.
- **No new themes.** The existing five (Classic, Slate10, Amber, Duet, HighContrast) cover the surface.
- **No login bypass / autologin.** Existing default seed (`admin/admin`) and credential flow unchanged.
- **No wallpaper image loading.** Patterns stay programmatic (the Phase 7+ image loader is unaffected).
- **No cursor micro-shadow.** That's a Pass A residual; stays deferred per the soak-headroom gate.
- **No TTY ASCII-art splash.** GUI is the new design language; TTY mode skips the splash entirely (existing text banner persists).
- **No GIF/video wallpaper.** Programmatic SVG patterns only.
- **No sound cues on splash/login.** Audio subsystem exists but adds another lifecycle; deferred.
- **No app-level animation primitives.** Pass D will decide if a shared tween helper is justified by two consumers; Pass B inlines motion math in each TU.

## 4. The four moments

### 4.1 Boot splash

**Today.** Pre-FB boot prints `[boot] phase=…` lines to serial. After `FramebufferInit()` lands, the kernel paints a flat desktop fill and proceeds straight to login. There is no splash screen.

**Pass B.** A new `kernel/drivers/video/splash.{h,cpp}` module owns the boot splash:

- **Composition.** `WallpaperPaint(rgb)` fills the full screen with the active theme's wallpaper pattern (arcs + topo for Duet/Slate10/Amber, flat for Classic/HighContrast). A phase ticker mono-text line paints bottom-left (`duetos · bringing up scheduler · cpu 0/4`).
- **Motion.** Arcs rotate ±5° linearly over 60 s. Pulse glow breathes over 8 s (sine, peak alpha +0.08 above base). Topo curves drift 1 px/s horizontally. Phase ticker text snaps on each `SplashAdvancePhase()` call (no fade).
- **Lifecycle.** `SplashInit()` paints the initial backdrop + first ticker line. Each boot phase calls `SplashAdvancePhase(name)`. `SplashDismiss()` clears the ticker rect (backdrop continues unchanged) and returns; the next call is `LoginStart(LoginMode::Gui)`, which paints the clock + corner card on top of the same backdrop.
- **No splash-dismissed cut.** The backdrop is the same pixels through the transition; only overlays change.

### 4.2 Login welcome

**Today.** `LoginMode::Gui` paints a centered "winlogon-flavour" box (avatar + username + password + button) over the theme's desktop background.

**Pass B.** Corner-card layout:

- **Big clock left.** `04:18` at 84 px weight-200; date below at 20 px weight-300. Anchored bottom-left, ~80 px from edge.
- **Corner card bottom-right.** ~280×160 panel with atlas-shadow halo (Pass A primitive). Inside: avatar circle (40 px diameter, accent stroke, single-letter monogram derived from the first character of `username` — falls back to `?` if username is empty) + username + role + password field (accent-stroked, single line) + accent sign-in button.
- **Backdrop.** Same arcs + topo painted by `WallpaperPaint(rgb)`. Motion continues from splash.
- **Focus glow.** Password field uses Pass A's `WindowPaintFocusGlow` helper for the accent ring on focus.
- **Wordmark.** Bottom-center small uppercase `DUETOS · v0` at low alpha; optional, theme-gated.

### 4.3 Idle / lock

**Today.** `LoginLock()` re-engages the login gate without clearing the auth session; `LoginIsLocked()` flips true; the same Gui paint path runs. `Ctrl+Alt+S` triggers "switch user" (existing affordance).

**Pass B.** Identical layout to login. Session-locked state is implicit (no UI difference). The reasons to keep them identical:

- Lowest implementation cost — one paint path covers both
- Simplest mental model for the operator — one screen, two reasons to be on it
- The kernel already differentiates state via `LoginIsLocked()` and `Ctrl+Alt+S` is unchanged, so existing affordances continue to work without UI revisions

The clock animates the same way (per-minute roll-over). Motion continues unchanged from the login moment.

### 4.4 Wallpaper polish

**Today.** `kernel/drivers/video/wallpaper.cpp` (365 LOC) paints three theme-dispatched patterns: `duet-arcs` (Duet theme), `topo` (alt), `syscalls-grid` (alt). No motion, no glow, no theme-aware tinting beyond the existing accent passthrough.

**Pass B.** All three patterns get polish:

- **duet-arcs (load-bearing).** Cleaner SVG; soft pulse glow on the arc strokes (uses Pass A Blend*); theme-aware accent tinting via existing `Theme::accent_*` fields. Motion: slow rotation + pulse (as above). This is the hero pattern — it's painted in every scene from splash through desktop.
- **topo (concentric curves).** Cleaner curve density; soft drift motion (full pattern translates 1 px/s horizontally, wraps at screen width); theme-aware stroke tinting. Used as alternative wallpaper; not on the splash/login canonical path but enabled when the operator picks it.
- **syscalls-grid (debug aesthetic).** Static (no motion — the dense grid reads as noise under motion); per-cell tactility shadow via Pass A's atlas-shadow renderer; theme-aware text tint. Niche but earns its polish to match the others.

## 5. The continuous backdrop

The arcs are painted by `WallpaperPaint(rgb)` at the same coordinates in every scene:

| Element | Coordinates | Coverage |
|---|---|---|
| Teal arc centroid | `(512 - 90, 384)` = `(422, 384)` | radius 160, stroke 2.5 px |
| Amber arc centroid | `(512 + 90, 384)` = `(602, 384)` | radius 160, stroke 2.5 px |
| Topo curve band | y ∈ `[200, 600]` | full screen width, 5 curves, opacity 0.18 |
| Phase ticker | `(40, 730)` | mono text, splash only |
| Clock | `(80, 640)` baseline | 84-px digits, login + lock only |
| Date | `(80, 680)` baseline | 20-px text, login + lock only |
| Corner login card | `(694, 540)`, `280×160` | atlas-shadow halo, login + lock only |

**The compositor never repaints the backdrop layer when only overlays change.** A `LoginRepaint()` paints the clock + corner card on top of the existing backdrop pixels. A desktop `DesktopCompose()` paints icons + windows + taskbar on top of the existing backdrop pixels. The wallpaper layer is touched only by `WallpaperTick()`, which mutates only the regions it actually animates (arcs bbox, topo strip).

## 6. Motion design

### 6.1 Motion budget (per element)

| Element | Cadence | Bounding rect | Active during |
|---|---|---|---|
| Arc rotation | ±5° / 60 s linear | arcs bbox (~340×340 around centroid) | always-on while backdrop visible |
| Arc pulse glow | 8 s breath (sine), peak alpha +0.08 | arcs bbox | always-on while backdrop visible |
| Topo drift | 1 px/s horizontal | full-width strip y ∈ `[200, 600]` | always-on while backdrop visible |
| Phase ticker text | snaps on `SplashAdvancePhase()` | bottom-left text rect | splash only |
| Clock minute roll | 1× per minute | clock text rect | login + lock |
| syscalls-grid | static | n/a | never |

**Frame rate ceiling:** 15 FPS for ambient motion (~67 ms tick period). Not 30 — slow enough for the design intent (the arcs should feel like breath, not a screensaver), half the CPU.

### 6.2 Coexistence with Pass A frame elision

Pass A's compositor-damage-diff (see `wiki/subsystems/Compositor.md`) elides chrome regions that didn't change between frames. Pass B motion preserves that win by declaring narrow dirty rects:

- Arc rotation/pulse → `WallpaperTick()` marks the arcs bbox dirty per frame
- Topo drift → marks the horizontal topo strip dirty per frame
- Clock minute roll → `LoginRepaint()` of clock rect when the minute changes (1× per minute, not per frame)
- **Everything else** — icons, windows, taskbar, login card body, password field — stays in the compositor-elided fast path

### 6.3 Occlusion gating

On the desktop, a window covering the arcs region pauses arc motion for that frame (no visible benefit, full cost). Implementation: each `WallpaperTick()` checks `Compositor::AnyOpaqueRectIntersects(arcs_bbox)`; if true, skip motion math AND skip the dirty-rect mark. Free for splash (no windows yet) and login/lock (no windows shown).

### 6.4 Motion discipline summary

| Surface | Default motion state | Pause condition |
|---|---|---|
| Splash | always-on | never (splash is bounded — typically < 5 s) |
| Login | always-on | never (operator-attention moment) |
| Lock | always-on | never |
| Desktop | always-on | any opaque window overlaps the motion bbox |

## 7. Theme integration

Pass A landed `Theme::tactility_enabled` (bool, opts out HighContrast). Pass B adds **one new field** to `kernel/drivers/video/theme.h`:

```cpp
struct Theme {
    // ... existing fields ...
    float motion_intensity;   // 0.0..1.0 — scales rotation speed, pulse amplitude, drift speed
};
```

| Theme | `tactility_enabled` | `motion_intensity` | Behavior |
|---|---|---|---|
| Duet | true | 1.0 | Full motion as specified in §6 |
| Slate10 | true | 1.0 | Full motion; blue accent instead of teal on arcs |
| Amber | true | 1.0 | Full motion; amber/teal swapped (amber primary) |
| Classic | true | 0.3 | Subdued — rotation period 120 s (slower), pulse amplitude halved, topo drift halved |
| HighContrast | false | 0.0 | No motion, no glow, no pulse, no drift. Bit-for-bit identical to pre-spec |

`tactility_enabled = false` is the master gate — motion is always disabled when tactility is disabled, regardless of `motion_intensity` or any cmdline override. This preserves the Pass A HighContrast invariant verified in commit `1bfab2e5`.

**Runtime override.** Pass A introduced `tactility=on|off|auto` on the kernel cmdline. Pass B extends with `motion=on|off|auto`:

- `motion=auto` (default) — honors the active theme's `motion_intensity`
- `motion=off` — forces all motion off (useful for the screenshot matrix and the HighContrast invariant test's no-motion control boot)
- `motion=on` — forces `motion_intensity = 1.0` regardless of theme defaults, but **does not bypass `tactility_enabled`**. Under HighContrast, `motion=on` still produces no motion because the master gate wins. This is intentional: the HighContrast invariant test (§9.2) boots HighContrast with `motion=on` vs `motion=off` and confirms pixel-identity, which catches any regression where a future motion code path accidentally bypasses the master gate.

## 8. Module layout

| File | New / Edit | Role | Size delta |
|---|---|---|---|
| `kernel/drivers/video/splash.h` | **new** | Splash API: Init / AdvancePhase / Tick / Dismiss / SelfTest | ~40 LOC |
| `kernel/drivers/video/splash.cpp` | **new** | Splash backdrop paint (delegates to WallpaperPaint), phase ticker render, motion tick dispatch, self-test | ~280 LOC |
| `kernel/drivers/video/wallpaper.h` | edit | Declare `WallpaperTick()` + `WallpaperMotionSelfTest()` | +5 LOC |
| `kernel/drivers/video/wallpaper.cpp` | edit | Arc rotation/pulse math; topo drift offset; theme-aware tint; per-tick dirty-rect marking | +150 LOC (currently 365 → ~515, slightly over the 500-LOC soft threshold from `CLAUDE.md`; revisit a split into `wallpaper_paint.cpp` + `wallpaper_motion.cpp` only if it grows further in implementation) |
| `kernel/security/login.h` | edit | Declare `LoginGuiSelfTest()` | +2 LOC |
| `kernel/security/login.cpp` | edit | Replace centered-box paint with corner-card layout; big clock; atlas-shadow card; clock-minute tick path | +250 LOC (currently 935) |
| `kernel/drivers/video/theme.h` | edit | Add `Theme::motion_intensity` field | +2 LOC |
| `kernel/drivers/video/theme.cpp` | edit | Per-theme intensity values; cmdline parsing for `motion=...` | +20 LOC |
| `kernel/core/boot_bringup.cpp` | edit | Call `SplashInit()` after `FramebufferInit()`; `SplashAdvancePhase()` from each boot step; `SplashDismiss()` before `LoginStart()` | +30 LOC |

**Total:** ~780 LOC across 9 files, 1 new module. No new subsystems.

### 8.1 Splash module API

```cpp
namespace duetos::drivers::video {

/// Paint the initial backdrop + first phase ticker line. Must be called
/// after FramebufferInit() and before any SplashAdvancePhase() call.
/// Caller holds compositor lock.
void SplashInit();

/// Update the phase ticker text. Called from boot_bringup.cpp for each
/// completed phase. Re-renders only the phase-ticker rect (backdrop
/// continues unchanged). Caller holds compositor lock.
void SplashAdvancePhase(const char* name);

/// Per-frame motion tick (15 FPS target). Dispatches to WallpaperTick()
/// for the backdrop motion and re-renders the phase ticker if its
/// dirty-rect needs refreshing. Caller holds compositor lock.
void SplashTick();

/// Clear the phase ticker rect; backdrop continues unchanged. The next
/// call is typically LoginStart(LoginMode::Gui), which paints the clock
/// + corner card on top of the same backdrop pixels. Caller holds
/// compositor lock.
void SplashDismiss();

/// Boot-time self-test: paint → advance → dismiss invariants. Emits
/// `[splash-selftest] PASS` on success. No-op if framebuffer is not
/// available (caught by SplashInit's own guard).
void SplashSelfTest();

} // namespace duetos::drivers::video
```

### 8.2 Boot sequencing

1. **Pre-FB boot.** Unchanged. Text to serial, `[boot] phase=…` per phase.
2. **`FramebufferInit()` lands.** Compositor lock available.
3. **`SplashInit()` called from boot_bringup.cpp.** Paints initial backdrop + first ticker. Schedules `SplashTick()` to fire at 15 FPS via the existing compositor tick scheduler.
4. **Each boot phase calls `SplashAdvancePhase("scheduler")`, `SplashAdvancePhase("vfs")`, etc.** Phase ticker text updates in-place.
5. **Final phase → `SplashDismiss()` then `LoginStart(LoginMode::Gui)`.** Splash stops emitting ticker; login draws clock + card on the unchanged backdrop. The compositor tick scheduler swaps the per-frame tick callback from `SplashTick` to `WallpaperTick` — `WallpaperTick` becomes the single backdrop-motion source for login, lock, and desktop. Login's clock-minute roll is a separate concern: `LoginStart` records the wall-clock minute at paint time, and `WallpaperTick` checks at each tick whether the minute has advanced (cheap — 15 comparisons per second); if yes, it re-paints the clock rect via a small `LoginRefreshClock()` helper before returning.
6. **Auth success → existing `LoginEnd()` path.** Compositor reveals desktop chrome on top of the unchanged backdrop. `WallpaperTick()` continues running (with occlusion gating) for the desktop motion.
7. **Idle timeout → `LoginLock()`.** Same paint path as login; same motion.

### 8.3 TTY fallback

`LoginMode::Tty` (no framebuffer, or operator selected via cmdline) skips Pass B entirely:
- `SplashInit()` is not called
- Pre-FB boot text continues to serial through the whole boot
- Login uses existing TTY prompt unchanged
- No ASCII-art splash, no TTY-mode motion

Rationale: GUI is the new design language. TTY mode is for debugging / embedded / serial-console use where the visual investment doesn't earn its lines. The existing `LoginMode` bifurcation cleanly separates the two surfaces.

## 9. Testing + verification

### 9.1 Self-tests

| Test | What it asserts | Sentinel |
|---|---|---|
| `SplashSelfTest()` | Paint → AdvancePhase → Dismiss cycle is no-op safe; backdrop pixels survive Dismiss; framebuffer-unavailable guard works | `[splash-selftest] PASS` |
| `WallpaperMotionSelfTest()` | Arc rotation phase increments correctly over 240 ticks (16 s @ 15 FPS); pulse alpha bounded `[0, 0.08]`; topo drift offset wraps at screen width | `[wallpaper-motion-selftest] PASS` |
| `LoginGuiSelfTest()` | Corner-card layout coords stable; clock rect dirty-rect math correct on minute roll; atlas-shadow halo paints at expected position | `[login-gui-selftest] PASS` |
| `boot-log-analyze.sh` Pass B umbrella | All three above plus the existing Pass A self-tests fired | `[pass-b] splash=1 login=1 lock=1 wallpaper=1 motion=1 probe fires=0` |

Self-tests run silently on PASS (one `[<n>-selftest] PASS` line each); FAIL emits a verbose `[<n>-selftest] FAIL <reason>` line and fires a gated probe (see `kernel/debug/probes.h`).

### 9.2 HighContrast invariant

Extend `tools/test/hc-invariant-check.sh` (landed in Pass A, commit `be07b482`) to cover motion:

1. Boot HighContrast with cmdline `motion=on` — capture screenshot at T+5s, T+10s
2. Boot HighContrast with cmdline `motion=off` — capture screenshot at T+5s, T+10s
3. Pixel-diff (1) vs (2) must be below the **same 333-px noise floor** measured for tactility in Pass A

If the diff exceeds the noise floor, some motion code path is mutating pixels under HighContrast — that's a violation of `tactility_enabled = false → no motion`. The structural argument is that `motion_intensity` is multiplicatively zero under HighContrast (`tactility_enabled` is the master gate), so this is a regression guard, not a correctness check.

### 9.3 Screenshot matrix

Extend `tools/test/tactility-screenshot-matrix.sh` (landed Pass A, commit `71a61447`) with new surface flags:

```bash
tools/test/tactility-screenshot-matrix.sh --splash      # capture splash mid-boot
tools/test/tactility-screenshot-matrix.sh --login       # capture login GUI at first paint
tools/test/tactility-screenshot-matrix.sh --lock        # boot, wait for idle, capture lock
tools/test/tactility-screenshot-matrix.sh --wallpaper   # boot to desktop, dismiss any auto-window, capture
```

Each flag produces one PPM per theme × surface combination at `build/shots/<surface>-<theme>-debug-fast.ppm`. Adds 4 × 5 = 20 new screenshots to the matrix on a full sweep.

### 9.4 Soak harness

New: `tools/test/pass-b-soak.sh`:

```bash
# Boot to login, hold for 30 s, capture compositor frame timings.
# Asserts: avg CPU < 8% over the soak window, no compositor missed-tick warnings,
# no soft-lockup warnings, no [E] lines from wallpaper/splash/login.
DUETOS_TIMEOUT=60 DUETOS_PROFILE=login-soak tools/qemu/run.sh \
    | tee /tmp/pass-b-soak.log
tools/test/boot-log-analyze.sh /tmp/pass-b-soak.log
```

Pairs with the existing `boot-log-analyze.sh` analyzer (no new analyzer logic — extends the existing sentinel set).

### 9.5 VBox boot verification

Pairs with Pass A's residual VBox verification (see `wiki/reference/Roadmap.md` "Chrome tactility (Pass A) — residual polish"). Same approach: boot the matrix under VirtualBox after QEMU verification lands; LAPIC / GS-base differences from QEMU sometimes catch what QEMU doesn't. Tracked in the same Roadmap entry, gated on Pass A's VBox verification being run first.

## 10. Acceptance criteria

Observable success — every one must hold before Pass B is considered landed:

1. **Cold boot** in `x86_64-debug-fast` produces splash → login → desktop with arcs visibly continuous (verified via `tactility-screenshot-matrix.sh --splash --login --wallpaper`).
2. **All three new `*-selftest` PASS sentinels fire** on boot, in addition to the four Pass A sentinels.
3. **`boot-log-analyze.sh` reports** `[pass-b] splash=1 login=1 lock=1 wallpaper=1 motion=1 probe fires=0`.
4. **HighContrast pixel-diff** (motion=on vs motion=off) below the 333-px noise floor measured in Pass A.
5. **`pass-b-soak.sh` reports** avg CPU < 8 % over a 30 s ambient-motion window with no compositor missed-tick warnings.
6. **No regressions in Pass A self-tests** (`blend`, `shadow`, `theme-matrix`, `tactility-umbrella`).
7. **If residuals surface during implementation** (deferred items, visual verification follow-ups, or edge cases not caught by the self-tests above), they are appended to `wiki/reference/Roadmap.md` in the same commit that lands the code — modelled on the existing "Chrome tactility (Pass A) — residual polish" entry. A clean landing produces no new Roadmap entry.

## 11. Sequencing — what comes after

Pass B unlocks two follow-on streams:

- **Pass C (typography + hierarchy).** Wire the existing TTF infra (`TtfChromeFontSet` already called at boot) across chrome text. Introduce display/body/mono hierarchy. The Pass B clock at 84 px display-weight is the first non-chrome typography moment in the system; Pass C extends that language to chrome text (titlebars, menu items, button labels).
- **Pass D (app-level redesigns).** Pick 3 apps (Settings / About / Files / Sysmon candidates) and reimagine internal layout. Uses Pass A primitives for hover lift and focus glow inside app bodies; uses the Pass B clock as the model for app-level display typography. Will likely justify the shared animation primitive that Pass B deliberately did not extract.

Per the Roadmap policy, the residuals that surface from Pass B implementation become a new "Pass B residual polish" entry in `wiki/reference/Roadmap.md` (modelled on the existing "Chrome tactility (Pass A) — residual polish" entry). Items landed in this slice get **deleted from the Roadmap in the same commit**, not added as "shipped" paragraphs.
