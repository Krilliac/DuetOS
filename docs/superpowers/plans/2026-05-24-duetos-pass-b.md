# DuetOS Pass B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the four first-impression moments (boot splash, login welcome, idle/lock, wallpaper polish) on top of Pass A's primitives, with the arcs painted at the same coordinates across all scenes and ambient motion (slow rotation + pulse + topo drift, 15 FPS) gated by a new per-theme `motion_intensity` knob.

**Architecture:** New `kernel/drivers/video/splash.{h,cpp}` module owns the boot splash; existing `wallpaper.{h,cpp}` gains `WallpaperTick()` for ambient motion (arc rotation phase, pulse phase, topo drift offset) with surgical dirty-rect declarations so Pass A's frame elision still elides static chrome; `login.cpp` gets the corner-card layout (big clock left, atlas-shadow card bottom-right) shared between login and lock; `theme.{h,cpp}` gains one `motion_intensity` field + the existing tactility cmdline grows a `motion=on|off|auto` peer; `boot_bringup.cpp` calls `SplashInit()` after `FramebufferInit()` and `SplashDismiss()` before `LoginStart()`.

**Tech Stack:** C++23 (kernel, no exceptions, no RTTI), CMake 3.25+, ctest for hosted unit tests (`tests/host/`), kernel self-tests called from `kernel/core/boot_bringup.cpp` for on-target verification, QEMU + `tools/qemu/run.sh` for boot smoke, `tools/test/boot-log-analyze.sh` for sentinel grep.

**Spec:** `docs/superpowers/specs/2026-05-24-duetos-pass-b-design.md` (read first).

**Sequencing note:** Pass A (chrome tactility) is in `main` via PR #338 and merged into this branch's base. Pass B inherits its `FramebufferBlendRgba`/`BlendFill`/atlas-shadow primitives + the per-theme tactility matrix. Pass C (typography) and Pass D (app redesigns) sequence after this.

---

## File Structure

### Created
- `kernel/drivers/video/splash.h` — splash API (Init / AdvancePhase / Tick / Dismiss / SelfTest)
- `kernel/drivers/video/splash.cpp` — implementation + self-test
- `tests/host/test_motion_math.cpp` — hosted unit test for motion phase math (rotation sweep, pulse sine, topo wrap)
- `tools/test/pass-b-soak.sh` — 30 s ambient-motion CPU + frame-timing soak

### Modified
- `kernel/drivers/video/theme.h` — add `Theme::motion_intensity` field
- `kernel/drivers/video/theme.cpp` — populate per-theme values, extend `ThemeSelfTest` with motion-intensity invariants, parse `motion=` cmdline
- `kernel/drivers/video/wallpaper.h` — declare `WallpaperTick()` + `WallpaperMotionSelfTest()` + `WallpaperMotionSelfTestPassed()`
- `kernel/drivers/video/wallpaper.cpp` — arc rotation phase, pulse phase, topo drift offset, theme-aware tint, per-tick dirty-rect marking, motion self-test
- `kernel/security/login.h` — declare `LoginGuiSelfTest()` + `LoginRefreshClock()` + `LoginGuiSelfTestPassed()`
- `kernel/security/login.cpp` — corner-card layout (replaces centered-box paint), big clock left, atlas-shadow card, password field with focus glow, sign-in button, clock-minute refresh path, GUI self-test
- `kernel/core/boot_bringup.cpp` — `SplashInit()` after `FramebufferInit()`; `SplashAdvancePhase()` per boot phase; `SplashDismiss()` before `LoginStart()`; umbrella `[pass-b-selftest]` aggregator
- `kernel/core/boot_tasks.cpp` — extend cmdline parser for `motion=on|off|auto`
- `tools/test/boot-log-analyze.sh` — recognise the 3 new PASS sentinels + emit `[pass-b]` umbrella status line
- `tools/test/hc-invariant-check.sh` — add `motion=on` vs `motion=off` HighContrast pixel-diff control
- `tools/test/tactility-screenshot-matrix.sh` — add `--splash` / `--login` / `--lock` / `--wallpaper` surface modes
- `tests/host/CMakeLists.txt` — register `test_motion_math.cpp`
- `wiki/subsystems/Compositor.md` — add Pass B section ("First-impression moments")
- `wiki/reference/Roadmap.md` — graduate the Pass A "VBox boot verification" residual if landed; add Pass B residuals if surfaced

---

## Phase 1 — Foundation (motion_intensity field + cmdline)

### Task 1: Add `Theme::motion_intensity` field

**Files:**
- Modify: `kernel/drivers/video/theme.h`

- [ ] **Step 1: Add the field**

In the `Theme` struct (after the existing `cursor_microshadow_enabled` field added in Pass A, before the closing brace), add:

```cpp
// Motion intensity (0..255, where 255 means "full motion per the
// Pass B spec"). Scales arc rotation speed, pulse alpha amplitude,
// and topo drift speed. Gated by tactility_enabled — if tactility
// is off, motion is off regardless of this value.
//
// See docs/superpowers/specs/2026-05-24-duetos-pass-b-design.md §7.
u8 motion_intensity;
```

- [ ] **Step 2: Build — every Theme literal in theme.cpp will fail aggregate init**

Run: `cmake --build build --parallel 2>&1 | tail -20`
Expected: errors of the form `error: too few initializers` at every `Theme{ ... }` literal. This is desired — confirms we have to update every theme.

### Task 2: Populate per-theme `motion_intensity` + extend `ThemeSelfTest`

**Files:**
- Modify: `kernel/drivers/video/theme.cpp`

- [ ] **Step 1: Find every Theme literal**

Run: `git grep -n "= Theme{" kernel/drivers/video/theme.cpp`
Expected: the post-Pass-A theme table (Classic, Slate10, Amber, Duet variants, HighContrast).

- [ ] **Step 2: Append the motion_intensity field to each, per spec §7**

| Theme | motion_intensity literal |
|---|---|
| Classic | `77` (≈ 0.3 × 255) |
| Slate10 | `255` |
| Amber | `255` |
| Duet (any variant) | `255` |
| HighContrast | `0` |

For each `Theme{ ... }` literal, append the value as the final field. Example for the Duet entry:

```cpp
g_themes[kThemeDuet] = Theme{
    /* ... existing pass A fields ... */
    /* cursor_microshadow_enabled = */ false,
    /* motion_intensity            = */ 255,
};
```

- [ ] **Step 3: Extend `ThemeSelfTest` with motion-intensity invariants**

Find the existing `ThemeSelfTest` body. Append, inside it, before the final PASS emit:

```cpp
// Pass B invariants — motion_intensity.
//
// (1) HighContrast must have motion_intensity == 0 AND tactility_enabled == false.
//     The double-gate is intentional: tactility_enabled is the master,
//     motion_intensity is the per-effect knob. Either alone disables motion.
{
    const Theme& hc = g_themes[kThemeHighContrast];
    if (hc.tactility_enabled || hc.motion_intensity != 0) {
        duetos::arch::SerialWrite(
            "[theme-selftest] FAIL HighContrast motion gate broken\n");
        debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB0);
        return;
    }
}
// (2) Classic must have motion_intensity < 128 (subdued — see spec §7).
{
    const Theme& cl = g_themes[kThemeClassic];
    if (cl.motion_intensity >= 128) {
        duetos::arch::SerialWrite(
            "[theme-selftest] FAIL Classic motion_intensity not subdued\n");
        debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB1);
        return;
    }
}
// (3) Every other theme with tactility_enabled must have motion_intensity == 255.
for (size_t i = 0; i < kThemeCount; ++i) {
    if (i == kThemeHighContrast || i == kThemeClassic) continue;
    const Theme& t = g_themes[i];
    if (t.tactility_enabled && t.motion_intensity != 255) {
        duetos::arch::SerialWrite(
            "[theme-selftest] FAIL non-classic non-hc not full motion\n");
        debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB2);
        return;
    }
}
```

- [ ] **Step 4: Build + boot + verify the existing ThemeSelfTest still PASSES**

Run: `cmake --build build --parallel && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep "theme-selftest"`
Expected: `[theme-selftest] tactility-matrix PASS (...)`. A FAIL means the theme table was edited wrong.

- [ ] **Step 5: Commit**

Run:
```bash
git add kernel/drivers/video/theme.h kernel/drivers/video/theme.cpp
git commit -m "video/theme: add motion_intensity field + Pass B invariants"
```

(Edit the commit message body via `git commit --amend` if you want the longer description from the spec.)

### Task 3: `motion=on|off|auto` cmdline parsing

**Files:**
- Modify: `kernel/core/boot_tasks.cpp` (where Pass A's `tactility=` parser lives)
- Modify: `kernel/drivers/video/theme.h` (declare runtime override accessor)
- Modify: `kernel/drivers/video/theme.cpp` (storage + accessor + applier)

- [ ] **Step 1: Add the runtime-override state to theme.cpp**

Near the top of `theme.cpp`, after the theme table, add:

```cpp
// Runtime override for motion_intensity. kAuto = use the theme's
// configured value. kOn = clamp to 255 (still gated by
// tactility_enabled). kOff = force 0. Parsed from the kernel
// cmdline by boot_tasks.cpp.
static MotionOverride g_motion_override = MotionOverride::kAuto;

void ThemeSetMotionOverride(MotionOverride o) { g_motion_override = o; }

u8 ThemeEffectiveMotionIntensity()
{
    const Theme& t = ThemeActive();
    if (!t.tactility_enabled) return 0;          // master gate wins
    switch (g_motion_override) {
        case MotionOverride::kOff:  return 0;
        case MotionOverride::kOn:   return 255;
        case MotionOverride::kAuto: return t.motion_intensity;
    }
    return t.motion_intensity;
}
```

- [ ] **Step 2: Declare in theme.h**

After the existing theme-id constants, add:

```cpp
enum class MotionOverride : u8 { kAuto, kOn, kOff };
void ThemeSetMotionOverride(MotionOverride o);
u8 ThemeEffectiveMotionIntensity();   // 0..255 after override + master gate
```

- [ ] **Step 3: Parse `motion=` in boot_tasks.cpp**

Find the existing `tactility=` parser (`git grep -n "tactility=" kernel/core/boot_tasks.cpp`). Immediately after it, add:

```cpp
// Pass B: motion=on|off|auto runtime override.
if (CmdlineHasKey(cmdline, "motion")) {
    const char* v = CmdlineGetValue(cmdline, "motion");
    using duetos::drivers::video::MotionOverride;
    if (StrEq(v, "on"))       duetos::drivers::video::ThemeSetMotionOverride(MotionOverride::kOn);
    else if (StrEq(v, "off")) duetos::drivers::video::ThemeSetMotionOverride(MotionOverride::kOff);
    else                      duetos::drivers::video::ThemeSetMotionOverride(MotionOverride::kAuto);
}
```

(If the actual helper names differ from `CmdlineHasKey` / `CmdlineGetValue` / `StrEq`, match the helpers Pass A's `tactility=` parser uses.)

- [ ] **Step 4: Build + smoke**

Run:
```bash
cmake --build build --parallel
DUETOS_EXTRA_CMDLINE="motion=off" DUETOS_TIMEOUT=15 tools/qemu/run.sh 2>&1 | grep -E "motion=|theme-selftest"
```
Expected: theme-selftest PASSes regardless (override doesn't break invariants).

- [ ] **Step 5: Commit**

```bash
git add kernel/drivers/video/theme.h kernel/drivers/video/theme.cpp kernel/core/boot_tasks.cpp
git commit -m "video/theme,boot: motion=on|off|auto cmdline override"
```

### Task 4: Hosted unit test for motion phase math (TDD — failing test first)

**Files:**
- Create: `tests/host/test_motion_math.cpp`
- Modify: `tests/host/CMakeLists.txt`

- [ ] **Step 1: Write the test (it will fail at compile-link if the registration step is missed)**

Create `tests/host/test_motion_math.cpp`:

```cpp
// Hosted unit test for Pass B motion phase math. Mirrors the inline
// helpers WallpaperTick lands in Phase 2 so the math has a regression
// guard independent of QEMU boot timing.

#include <cstdint>
#include <cassert>
#include <cmath>
#include <cstdio>

// Triangular sweep: 0 -> +5 -> 0 -> -5 -> 0 over period_ms.
static double ArcRotationDegrees(uint64_t now_ms, uint64_t period_ms)
{
    if (period_ms == 0) return 0.0;
    const double t = double(now_ms % period_ms) / double(period_ms);
    const double phase = t < 0.5 ? (t * 4.0) - 1.0 : 3.0 - (t * 4.0);
    return 5.0 * phase;
}

// Pulse alpha boost: 0 .. peak via sine breath over period_ms.
static double PulseAlphaBoost(uint64_t now_ms, uint64_t period_ms, double peak)
{
    if (period_ms == 0) return 0.0;
    const double t = double(now_ms % period_ms) / double(period_ms);
    const double s = 0.5 - 0.5 * std::cos(2.0 * M_PI * t);  // 0..1..0
    return peak * s;
}

// Topo horizontal drift offset, wraps at fb_w pixels.
static int TopoDriftOffsetPx(uint64_t now_ms, int speed_px_per_s, int fb_w)
{
    if (fb_w <= 0) return 0;
    const int64_t total = (int64_t(now_ms) * speed_px_per_s) / 1000;
    int64_t mod = total % fb_w;
    if (mod < 0) mod += fb_w;
    return int(mod);
}

int main()
{
    // ArcRotationDegrees: bounded [-5, +5]; at t=0 returns -5; peak at half period.
    assert(std::abs(ArcRotationDegrees(0, 60000) + 5.0) < 1e-9);
    assert(std::abs(ArcRotationDegrees(30000, 60000) - 5.0) < 1e-9);
    for (uint64_t ms = 0; ms <= 60000; ms += 100) {
        const double d = ArcRotationDegrees(ms, 60000);
        assert(d >= -5.0 && d <= 5.0);
    }

    // PulseAlphaBoost: bounded [0, peak], starts at 0, peaks at half period.
    assert(std::abs(PulseAlphaBoost(0, 8000, 0.08)) < 1e-9);
    assert(std::abs(PulseAlphaBoost(4000, 8000, 0.08) - 0.08) < 1e-6);
    for (uint64_t ms = 0; ms <= 8000; ms += 50) {
        const double v = PulseAlphaBoost(ms, 8000, 0.08);
        assert(v >= 0.0 && v <= 0.08001);
    }

    // TopoDriftOffsetPx: at 1 px/s, after 1000 ms offset is 1; wraps at fb_w.
    assert(TopoDriftOffsetPx(1000, 1, 1024) == 1);
    assert(TopoDriftOffsetPx(1024000, 1, 1024) == 0);  // full wrap

    std::printf("test_motion_math: PASS\n");
    return 0;
}
```

- [ ] **Step 2: Register in CMakeLists**

In `tests/host/CMakeLists.txt`, append next to the existing host test entries:

```cmake
add_executable(test_motion_math test_motion_math.cpp)
add_test(NAME test_motion_math COMMAND test_motion_math)
```

- [ ] **Step 3: Configure + build + run — expect PASS**

Run:
```bash
cmake --preset x86_64-release
cmake --build build --parallel --target test_motion_math
cd build && ctest -R test_motion_math --output-on-failure && cd ..
```
Expected: `test_motion_math: PASS`, ctest reports `1/1 Test #N: test_motion_math .... Passed`.

- [ ] **Step 4: Commit**

```bash
git add tests/host/test_motion_math.cpp tests/host/CMakeLists.txt
git commit -m "tests/host: motion phase math regression guard for Pass B"
```

**Phase 1 complete.** motion_intensity field + cmdline override + hosted math guard in place. No kernel motion paint yet.

---

## Phase 2 — Wallpaper motion infrastructure

### Task 5: WallpaperTick + motion-self-test declarations

**Files:**
- Modify: `kernel/drivers/video/wallpaper.h`

- [ ] **Step 1: Add the declarations**

After the existing `WallpaperPaint(u32 desktop_rgb)` declaration in the `duetos::drivers::video` namespace:

```cpp
/// Per-frame ambient motion tick. Called from the compositor tick
/// scheduler at ~15 FPS. Mutates internal motion state (arc rotation
/// phase, pulse phase, topo drift offset) and marks the corresponding
/// dirty rects on the framebuffer so the compositor recomposes only
/// the moving regions. Cheap when `ThemeEffectiveMotionIntensity() == 0`
/// (early return — no math, no dirty marks). Caller holds compositor
/// lock.
void WallpaperTick();

/// Boot self-test: validates motion phase math over 240 simulated ticks
/// (16 s @ 15 FPS). Emits `[wallpaper-motion-selftest] PASS` on success
/// or a FAIL line + ProbeFire on failure. Does NOT actually paint —
/// runs against the inline phase helpers only.
void WallpaperMotionSelfTest();

/// Accessor for the boot umbrella aggregator in main.cpp / boot_bringup.
bool WallpaperMotionSelfTestPassed();
```

- [ ] **Step 2: Build (should compile clean — header-only change)**

Run: `cmake --build build --parallel 2>&1 | tail -5`
Expected: clean (no callers yet).

### Task 6: Implement WallpaperTick + the three motion paths

**Files:**
- Modify: `kernel/drivers/video/wallpaper.cpp`

- [ ] **Step 1: Add motion state at file scope (anonymous namespace)**

Inside the existing anonymous namespace at the top of `wallpaper.cpp`, after the existing `Lighten` / `Darken` / `AmbientStrokeRgb` helpers:

```cpp
// Pass B motion state. All updated by WallpaperTick().
// Reset to zero on theme switch (so the new theme starts clean).
struct MotionState {
    u64 base_ms;          // tick monotonic base captured at first tick
    u64 last_minute;      // for clock-minute-roll detection (login path)
    int topo_drift_px;    // current horizontal drift offset, [0, fb_w)
    double arc_rot_deg;   // current rotation, [-5, +5]
    double pulse_boost;   // current pulse alpha boost, [0, kPulsePeak]
};
static MotionState g_motion = {0, 0, 0, 0.0, 0.0};

constexpr u64 kArcRotPeriodMs    = 60000;  // ±5° sweep over 60s
constexpr u64 kPulsePeriodMs     =  8000;  // 8s breath
constexpr double kPulsePeak      = 0.08;   // alpha boost at peak
constexpr int kTopoDriftPxPerSec =     1;  // 1 px/s

// Triangular sweep -5 -> +5 -> -5 over period_ms (mirrors test_motion_math.cpp).
inline double ArcRotationDegrees(u64 now_ms, u64 period_ms)
{
    if (period_ms == 0) return 0.0;
    const double t = double(now_ms % period_ms) / double(period_ms);
    const double phase = t < 0.5 ? (t * 4.0) - 1.0 : 3.0 - (t * 4.0);
    return 5.0 * phase;
}

// Sine breath 0..peak..0 over period_ms.
inline double PulseAlphaBoost(u64 now_ms, u64 period_ms, double peak)
{
    if (period_ms == 0) return 0.0;
    // Approximate cos via a quadratic; the kernel has no <math.h>.
    // For sub-percent error over [0, 2π] the half-angle identity +
    // 5-term Taylor is overkill; use a simpler smoothstep:
    // s = 0.5 - 0.5 * cos(2π t)   ≈   3t² - 2t³ for t∈[0,0.5], mirrored.
    const double t = double(now_ms % period_ms) / double(period_ms);
    const double u = t < 0.5 ? t * 2.0 : (1.0 - t) * 2.0;
    const double s = (3.0 * u * u) - (2.0 * u * u * u);
    return peak * s;
}

// Topo horizontal drift offset, wraps at fb_w pixels.
inline int TopoDriftOffsetPx(u64 now_ms, int speed_px_per_s, int fb_w)
{
    if (fb_w <= 0) return 0;
    const i64 total = (i64(now_ms) * speed_px_per_s) / 1000;
    i64 mod = total % fb_w;
    if (mod < 0) mod += fb_w;
    return int(mod);
}
```

- [ ] **Step 2: Implement WallpaperTick**

Add at the end of the namespace (after `WallpaperPaint` and `WallpaperSvgInit`):

```cpp
void WallpaperTick()
{
    if (!FramebufferAvailable()) return;
    const u8 motion = duetos::drivers::video::ThemeEffectiveMotionIntensity();
    if (motion == 0) return;  // master gate / cmdline override off

    const u64 now_ms = duetos::time::NowMillisecondsMonotonic();
    if (g_motion.base_ms == 0) g_motion.base_ms = now_ms;
    const u64 t_ms = now_ms - g_motion.base_ms;

    // Scale periods by motion intensity. At intensity=77 (Classic),
    // rotation period doubles to 120s, pulse halves, drift halves.
    // At intensity=255 (Duet/Slate10/Amber), full speed per the spec.
    const u64 rot_period_ms = (kArcRotPeriodMs * 255) / (motion ? motion : 1);
    const double pulse_peak_eff = kPulsePeak * (double(motion) / 255.0);
    const int drift_speed_eff = (kTopoDriftPxPerSec * motion) / 255;

    g_motion.arc_rot_deg = ArcRotationDegrees(t_ms, rot_period_ms);
    g_motion.pulse_boost = PulseAlphaBoost(t_ms, kPulsePeriodMs, pulse_peak_eff);

    const u32 fb_w = FramebufferWidth();
    const u32 fb_h = FramebufferHeight();
    const int new_drift = TopoDriftOffsetPx(t_ms, drift_speed_eff, int(fb_w));

    // Occlusion gating — if a window covers the arcs bbox, skip the
    // paint cost. Compositor exposes AnyOpaqueRectIntersects(x,y,w,h)
    // for this (added in Pass A's damage tracking work). Arcs bbox is
    // centred on (fb_w/2, fb_h/2) with a 340x340 envelope.
    const i32 arcs_x = i32(fb_w / 2) - 170;
    const i32 arcs_y = i32(fb_h / 2) - 170;
    const bool arcs_occluded = duetos::drivers::video::CompositorAnyOpaqueRectIntersects(
        arcs_x, arcs_y, 340, 340);

    if (!arcs_occluded) {
        // Re-paint the arcs region; WallpaperPaint will read
        // g_motion.arc_rot_deg + g_motion.pulse_boost and apply.
        // For the v0 we re-paint the entire wallpaper region — the
        // compositor's damage-rect tracking will inflate the dirty
        // rect to the arcs envelope only.
        duetos::drivers::video::FramebufferMarkDirty(arcs_x, arcs_y, 340, 340);
    }
    if (new_drift != g_motion.topo_drift_px) {
        g_motion.topo_drift_px = new_drift;
        // Topo strip is the full screen width, y∈[200, 600] per spec §5.
        duetos::drivers::video::FramebufferMarkDirty(0, 200, fb_w, 400);
    }
}
```

(If a helper named differently from `FramebufferMarkDirty` or `CompositorAnyOpaqueRectIntersects` is used in Pass A's tree, match the actual name with `git grep -n "MarkDirty\|OpaqueRect" kernel/drivers/video/`.)

- [ ] **Step 3: Thread motion state into the arc paint path**

Find the existing arc-stroke loop inside `WallpaperPaint` (look for the duet-arcs branch — `git grep -n "duet-arcs\|arc paint" kernel/drivers/video/wallpaper.cpp`). Inside the per-pixel arc paint, apply:

- Rotation: the arc center coordinates get rotated by `g_motion.arc_rot_deg` around the canonical (fb_w/2, fb_h/2). Use a small inline `RotateAround(cx, cy, deg)` helper for the per-arc offset.
- Pulse alpha: each arc stroke pixel's effective alpha gets boosted by `g_motion.pulse_boost`, clamped to 1.0. Use `FramebufferBlendPixel` (Pass A primitive) so the boost is per-pixel additive.
- Topo drift: the topo curves' x-coordinates shift by `g_motion.topo_drift_px`, with the wrap-around painted by drawing two copies (one at `+offset` and one at `+offset - fb_w`).

(Exact code depends on the existing paint loop's shape. Keep the change small — the math is in the helpers; the paint loop just multiplies in `g_motion.*`.)

- [ ] **Step 4: Build + boot — backdrop should now visibly drift/rotate after boot**

Run:
```bash
cmake --build build --parallel
DUETOS_TIMEOUT=30 tools/qemu/run.sh 2>&1 | grep -E "wallpaper|theme-selftest"
```
Expected: no FAIL lines. Visual verification (via VNC or screenshot dump after 5–10 s) shows arc rotation + pulse + topo drift active.

- [ ] **Step 5: Commit**

```bash
git add kernel/drivers/video/wallpaper.cpp kernel/drivers/video/wallpaper.h
git commit -m "video/wallpaper: ambient motion (rotation + pulse + topo drift)"
```

### Task 7: WallpaperMotionSelfTest

**Files:**
- Modify: `kernel/drivers/video/wallpaper.cpp`

- [ ] **Step 1: Add the self-test**

At the end of the namespace:

```cpp
namespace {
bool g_wallpaper_motion_selftest_passed = false;
}

void WallpaperMotionSelfTest()
{
    // 240 ticks at 15 FPS = 16 s of simulated boot time. Walk the
    // phase helpers and assert bounds + endpoints.
    for (u64 ms = 0; ms <= 60000; ms += 67) {
        const double d = ArcRotationDegrees(ms, 60000);
        if (d < -5.001 || d > 5.001) {
            duetos::arch::SerialWrite(
                "[wallpaper-motion-selftest] FAIL arc rotation out of bounds\n");
            debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB3);
            return;
        }
    }
    for (u64 ms = 0; ms <= 8000; ms += 50) {
        const double p = PulseAlphaBoost(ms, 8000, kPulsePeak);
        if (p < 0.0 || p > kPulsePeak + 1e-6) {
            duetos::arch::SerialWrite(
                "[wallpaper-motion-selftest] FAIL pulse out of bounds\n");
            debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB4);
            return;
        }
    }
    if (TopoDriftOffsetPx(1024000, 1, 1024) != 0 ||
        TopoDriftOffsetPx(1000, 1, 1024) != 1) {
        duetos::arch::SerialWrite(
            "[wallpaper-motion-selftest] FAIL topo wrap broken\n");
        debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB5);
        return;
    }
    duetos::arch::SerialWrite("[wallpaper-motion-selftest] PASS\n");
    g_wallpaper_motion_selftest_passed = true;
}

bool WallpaperMotionSelfTestPassed() { return g_wallpaper_motion_selftest_passed; }
```

- [ ] **Step 2: Build (will be wired into boot in Task 11)**

Run: `cmake --build build --parallel 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add kernel/drivers/video/wallpaper.cpp
git commit -m "video/wallpaper: motion phase self-test (rotation/pulse/wrap)"
```

### Task 8: Wire WallpaperTick into the compositor tick scheduler

**Files:**
- Modify: `kernel/drivers/video/compositor.cpp` (or wherever the existing tick scheduler lives — `git grep -n "kCompositorTickHz\|CompositorTick\|tick_callback" kernel/drivers/video/`)

- [ ] **Step 1: Find the tick scheduler**

Run: `git grep -rn "60.*Hz\|compositor_tick\|tick_hz" kernel/drivers/video/ kernel/core/ | head -10`

Expected: a single periodic scheduler that fires the compositor's per-frame work. Pass A's compositor-damage-diff lives here. If there is no periodic tick yet (compositor is event-driven only), one must be added — a simple kernel task that sleeps for 67 ms (15 FPS) and calls a registered `OnTick()` callback list.

- [ ] **Step 2: Register WallpaperTick on the tick callback list**

In whichever module owns the tick scheduler, add:

```cpp
#include "drivers/video/wallpaper.h"

// In the periodic tick body:
duetos::drivers::video::WallpaperTick();
```

If a callback registry exists (e.g., `RegisterCompositorTick(&cb)`), use that pattern. If not, the direct call is fine for now — a registry can be extracted later if Splash + Login + Wallpaper each need their own.

- [ ] **Step 3: Build + boot + verify motion visible**

Run:
```bash
cmake --build build --parallel
DUETOS_TIMEOUT=30 tools/qemu/run.sh 2>&1 | tail -50
```
Expected: clean boot, no panics, no soft-lockup warnings. Visual verification: arcs visibly rotate / pulse / topo drifts over the 30 s window.

- [ ] **Step 4: Commit**

```bash
git add kernel/drivers/video/compositor.cpp  # or whichever
git commit -m "video/compositor: wire WallpaperTick into the 15 FPS tick scheduler"
```

**Phase 2 complete.** Ambient motion runs on every theme except HighContrast/Classic-subdued. No splash module yet; motion is visible on the existing boot-to-desktop path.

---

## Phase 3 — Splash module (new)

### Task 9: splash.h API

**Files:**
- Create: `kernel/drivers/video/splash.h`

- [ ] **Step 1: Write the header**

```cpp
#pragma once

#include "util/types.h"

/*
 * DuetOS boot splash — owns the post-FramebufferInit pre-LoginStart
 * screen. Paints the active theme's wallpaper backdrop via
 * WallpaperPaint(), then renders a phase ticker mono-text line at
 * the bottom-left that's mutated by SplashAdvancePhase(). Dismissed
 * cleanly by SplashDismiss() — backdrop pixels survive, only the
 * ticker rect is cleared, so LoginStart(LoginMode::Gui) paints over
 * the same backdrop without a visible scene change.
 *
 * Scope limits:
 *   - GUI-only. LoginMode::Tty skips this entirely.
 *   - Painted under the compositor lock.
 *   - No fade transition; no "splash dismissed" effect — the
 *     wallpaper continuity IS the transition design.
 *
 * See docs/superpowers/specs/2026-05-24-duetos-pass-b-design.md §4.1.
 */

namespace duetos::drivers::video
{

/// Paint the initial backdrop + first phase ticker line. Must be
/// called after FramebufferInit() and before any SplashAdvancePhase().
/// Idempotent — re-call is a no-op. Caller holds compositor lock.
void SplashInit();

/// Update the phase ticker text. Called from boot_bringup.cpp for
/// each completed phase. Re-renders only the phase-ticker rect.
/// No-op if SplashInit was not called or SplashDismiss was already
/// called. Caller holds compositor lock.
void SplashAdvancePhase(const char* name);

/// Per-frame motion tick. Currently just forwards to WallpaperTick()
/// (splash motion = wallpaper motion). Caller holds compositor lock.
void SplashTick();

/// Clear the phase ticker rect; backdrop continues unchanged. The
/// next caller is typically LoginStart(LoginMode::Gui). Idempotent.
/// Caller holds compositor lock.
void SplashDismiss();

/// Boot-time self-test: paint -> advance -> dismiss invariants.
/// Emits `[splash-selftest] PASS` on success or FAIL + ProbeFire.
void SplashSelfTest();

/// Accessor for the boot umbrella aggregator.
bool SplashSelfTestPassed();

} // namespace duetos::drivers::video
```

- [ ] **Step 2: Build (no callers yet)**

Run: `cmake --build build --parallel 2>&1 | tail -5`
Expected: clean (will not be linked anywhere yet).

### Task 10: splash.cpp implementation

**Files:**
- Create: `kernel/drivers/video/splash.cpp`

- [ ] **Step 1: Write the implementation**

```cpp
#include "drivers/video/splash.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/font8x8.h"
#include "drivers/video/theme.h"
#include "drivers/video/wallpaper.h"
#include "util/types.h"

namespace duetos::drivers::video
{

namespace
{

// Phase ticker rect — bottom-left, mono 8x8 font, 60 chars max width.
constexpr u32 kTickerX     = 40;
constexpr u32 kTickerH     = 16;
constexpr u32 kTickerYFrac = 730;  // y coordinate at 1024x768 baseline
constexpr size_t kPhaseMax = 64;

enum class State : u8 { kUninitialised, kActive, kDismissed };
static State g_state = State::kUninitialised;
static char g_phase[kPhaseMax] = "";
static bool g_selftest_passed = false;

void DrawTickerLine()
{
    if (!FramebufferAvailable()) return;
    const u32 fb_w = FramebufferWidth();
    const u32 fb_h = FramebufferHeight();
    if (fb_h < kTickerH) return;
    const u32 ticker_y = kTickerYFrac * fb_h / 768;

    // Clear the ticker rect to the desktop colour (matches what the
    // wallpaper painted underneath at first SplashInit).
    const u32 desk = ThemeActive().desktop_rgb;
    FramebufferFillRect(0, ticker_y, fb_w, kTickerH, desk);

    // Render the phase string at low alpha — mono font, theme-tinted.
    const u32 fg = AmbientStrokeRgbApi(desk, 80);  // helper from wallpaper.cpp
    char buf[kPhaseMax + 32];
    size_t n = 0;
    const char* prefix = "duetos . ";
    while (*prefix && n < sizeof(buf) - 1) buf[n++] = *prefix++;
    const char* p = g_phase;
    while (*p && n < sizeof(buf) - 1) buf[n++] = *p++;
    buf[n] = '\0';
    Font8x8DrawString(kTickerX, ticker_y, buf, fg);
}

} // namespace

void SplashInit()
{
    if (g_state != State::kUninitialised) return;
    if (!FramebufferAvailable()) {
        // No FB — splash is a no-op. TTY path stays text-only.
        g_state = State::kDismissed;
        return;
    }
    // Paint the full wallpaper backdrop once.
    WallpaperPaint(ThemeActive().desktop_rgb);
    g_phase[0] = '\0';
    DrawTickerLine();
    g_state = State::kActive;
}

void SplashAdvancePhase(const char* name)
{
    if (g_state != State::kActive) return;
    size_t i = 0;
    while (name && name[i] && i + 1 < kPhaseMax) {
        g_phase[i] = name[i];
        ++i;
    }
    g_phase[i] = '\0';
    DrawTickerLine();
}

void SplashTick()
{
    if (g_state != State::kActive) return;
    WallpaperTick();
}

void SplashDismiss()
{
    if (g_state != State::kActive) return;
    // Clear the ticker rect; leave the backdrop alone.
    if (FramebufferAvailable()) {
        const u32 fb_w = FramebufferWidth();
        const u32 fb_h = FramebufferHeight();
        const u32 ticker_y = kTickerYFrac * fb_h / 768;
        FramebufferFillRect(0, ticker_y, fb_w, kTickerH, ThemeActive().desktop_rgb);
    }
    g_state = State::kDismissed;
}

void SplashSelfTest()
{
    // Walk the state machine without actually mutating FB state.
    // (SplashInit / SplashAdvancePhase / SplashDismiss already have
    // FB guards — calling them with FB available is safe.)
    SplashInit();
    SplashAdvancePhase("selftest-phase-1");
    SplashAdvancePhase("selftest-phase-2");
    SplashDismiss();
    // Re-call must be a no-op.
    SplashDismiss();

    if (g_state != State::kDismissed) {
        duetos::arch::SerialWrite("[splash-selftest] FAIL state machine\n");
        debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB6);
        return;
    }
    duetos::arch::SerialWrite("[splash-selftest] PASS\n");
    g_selftest_passed = true;
}

bool SplashSelfTestPassed() { return g_selftest_passed; }

} // namespace duetos::drivers::video
```

(If `AmbientStrokeRgbApi` / `Font8x8DrawString` / `FramebufferFillRect` / `FramebufferAvailable` / `FramebufferWidth` / `FramebufferHeight` are named differently, match the actual symbols via `git grep -n` against `kernel/drivers/video/`. The helpers exist — they are used by `wallpaper.cpp` today.)

- [ ] **Step 2: Build**

Run: `cmake --build build --parallel 2>&1 | tail -10`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add kernel/drivers/video/splash.h kernel/drivers/video/splash.cpp
git commit -m "video/splash: new module — wallpaper-continuous boot splash"
```

### Task 11: Wire SplashInit / AdvancePhase / Dismiss into boot

**Files:**
- Modify: `kernel/core/boot_bringup.cpp`

- [ ] **Step 1: Find FramebufferInit and LoginStart call sites**

Run:
```bash
git grep -n "FramebufferInit\|LoginStart" kernel/core/boot_bringup.cpp
```

- [ ] **Step 2: Insert SplashInit immediately after FramebufferInit**

Right after the `FramebufferInit()` call returns success:

```cpp
duetos::drivers::video::SplashInit();
duetos::drivers::video::SplashAdvancePhase("framebuffer up");
```

- [ ] **Step 3: Sprinkle SplashAdvancePhase after each major boot phase**

For each existing phase milestone in `boot_bringup.cpp` (look for the existing `[boot] phase=…` SerialWrite lines), add a paired `SplashAdvancePhase` call. Suggested phases (match what's actually in the file):

```cpp
SplashAdvancePhase("paging on");
SplashAdvancePhase("heap online");
SplashAdvancePhase("idt + apic");
SplashAdvancePhase("scheduler");
SplashAdvancePhase("vfs mount");
SplashAdvancePhase("compositor up");
SplashAdvancePhase("login starting");
```

Each call is a single line — no allocation, no error path.

- [ ] **Step 4: Insert SplashDismiss immediately before LoginStart(LoginMode::Gui)**

Find the `LoginStart(LoginMode::Gui)` call. Replace it with:

```cpp
duetos::drivers::video::SplashDismiss();
LoginStart(LoginMode::Gui);
```

- [ ] **Step 5: Wire SplashSelfTest into the existing umbrella aggregator**

Find the Pass A umbrella block (`grep -n "tactility-selftest" kernel/core/boot_bringup.cpp`). Add the splash + wallpaper-motion sub-tests next to it:

```cpp
duetos::drivers::video::SplashSelfTest();
duetos::drivers::video::WallpaperMotionSelfTest();
// (LoginGuiSelfTest lands in Phase 4 Task 18.)
```

- [ ] **Step 6: Build + boot + verify splash sentinels**

Run:
```bash
cmake --build build --parallel
DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "splash-selftest|wallpaper-motion-selftest|theme-selftest"
```
Expected:
```
[splash-selftest] PASS
[wallpaper-motion-selftest] PASS
[theme-selftest] tactility-matrix PASS (...)
```

- [ ] **Step 7: Commit**

```bash
git add kernel/core/boot_bringup.cpp
git commit -m "boot: wire splash init/advance/dismiss + new self-tests"
```

**Phase 3 complete.** Boot now shows the splash backdrop + phase ticker; transitions to existing login (still centered-box layout — Phase 4 replaces).

---

## Phase 4 — Login corner-card layout

### Task 12: Replace LoginPaintGui with backdrop + big clock

**Files:**
- Modify: `kernel/security/login.cpp`

- [ ] **Step 1: Find the existing GUI paint path**

Run: `git grep -n "PaintGui\|LoginPaintGui\|LoginMode::Gui" kernel/security/login.cpp`
Expected: a single paint function called from `LoginStart(LoginMode::Gui)` + `LoginRepaint()`.

- [ ] **Step 2: Rewrite the paint to "backdrop + big clock left"**

In the existing GUI paint function (call it `LoginPaintGui` — match the actual name), replace the centered-box layout with:

```cpp
// Pass B corner-card layout. See spec §4.2 / §5.
//
// 1. Backdrop = same wallpaper Splash painted; no recompose needed
//    when reaching here from SplashDismiss (the pixels are intact).
//    But on a fresh LoginRepaint() after a screen-mode flip we need
//    to re-paint to recover them. Cheap; idempotent.
duetos::drivers::video::WallpaperPaint(ThemeActive().desktop_rgb);

// 2. Big clock left — 84px digits at (80, 640 baseline) anchored at
//    1024x768; scale to actual fb_h.
const u32 fb_w = duetos::drivers::video::FramebufferWidth();
const u32 fb_h = duetos::drivers::video::FramebufferHeight();
const u32 clock_x = 80 * fb_w / 1024;
const u32 clock_y = 640 * fb_h / 768;
const u32 date_y  = 680 * fb_h / 768;

char clock_buf[16];   // "HH:MM"
char date_buf[32];    // "Sunday, May 24"
LoginFormatClock(clock_buf, sizeof(clock_buf));
LoginFormatDate(date_buf, sizeof(date_buf));

const u32 fg = ThemeActive().chrome_text_rgb;  // light over dark backdrop
duetos::drivers::video::Font8x8DrawStringScaled(clock_x, clock_y, clock_buf, fg, /*scale=*/8);
duetos::drivers::video::Font8x8DrawStringScaled(clock_x, date_y,  date_buf,  fg, /*scale=*/2);
```

(If `Font8x8DrawStringScaled` doesn't exist yet, add a thin helper inside `font8x8.cpp` that takes a per-glyph integer scale — multiply each glyph row's bit-painted pixel by `scale × scale` block. ~30 LOC.)

- [ ] **Step 3: Add LoginFormatClock + LoginFormatDate helpers**

Near the top of `login.cpp` (anonymous namespace):

```cpp
void LoginFormatClock(char* out, size_t cap)
{
    // Use the existing wall-clock helper. v0: "HH:MM" 24-hour.
    duetos::time::WallClockTime t = duetos::time::WallClockNow();
    duetos::util::SnprintfSafe(out, cap, "%02u:%02u",
        unsigned(t.hours), unsigned(t.minutes));
}

void LoginFormatDate(char* out, size_t cap)
{
    duetos::time::WallClockTime t = duetos::time::WallClockNow();
    static const char* kDay[]   = {"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
    static const char* kMonth[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    duetos::util::SnprintfSafe(out, cap, "%s, %s %u",
        kDay[t.weekday % 7], kMonth[(t.month - 1) % 12], unsigned(t.day));
}
```

(If a clock helper doesn't exist at all in `kernel/time/`, use `time::TickCount()` and treat the splash as "this session" — show elapsed time instead of wall-clock. Mark with `// GAP: wall-clock helper not in tree, showing tick-derived time` so the audit catches it.)

- [ ] **Step 4: Build + boot + verify clock visible**

Run:
```bash
cmake --build build --parallel
DUETOS_TIMEOUT=15 tools/qemu/run.sh
```
Expected: login screen shows big clock on the left over the arcs backdrop. Centered card is gone (rest of Phase 4 builds the corner card to replace it).

- [ ] **Step 5: Commit**

```bash
git add kernel/security/login.cpp kernel/drivers/video/font8x8.cpp kernel/drivers/video/font8x8.h
git commit -m "security/login: corner layout — wallpaper backdrop + big clock left"
```

### Task 13: Atlas-shadow corner card bottom-right

**Files:**
- Modify: `kernel/security/login.cpp`

- [ ] **Step 1: Add the card paint after the big clock**

Continue inside `LoginPaintGui`, after the clock paint:

```cpp
// 3. Corner card bottom-right — 280x160 at (694, 540).
const u32 card_x = 694 * fb_w / 1024;
const u32 card_y = 540 * fb_h / 768;
const u32 card_w = 280 * fb_w / 1024;
const u32 card_h = 160 * fb_h / 768;

// Atlas-shadow halo (Pass A primitive). Renders OUTSIDE the rect.
duetos::drivers::video::RenderSoftShadow(
    card_x, card_y, card_w, card_h,
    /*radius=*/16, /*opacity=*/120);

// Card body — slightly-lifted-from-backdrop fill, thin border.
duetos::drivers::video::FramebufferFillRect(card_x, card_y, card_w, card_h, ThemeActive().panel_rgb);
duetos::drivers::video::FramebufferDrawRect(card_x, card_y, card_w, card_h, ThemeActive().border_rgb);
```

(Match the actual Pass A primitive name — `RenderSoftShadow` vs `RenderSoftShadowWithStroke`. `git grep -n "SoftShadow" kernel/drivers/video/shadow.h` shows the public surface.)

- [ ] **Step 2: Build + boot + verify the card is visible**

Run:
```bash
cmake --build build --parallel
DUETOS_TIMEOUT=15 tools/qemu/run.sh
```
Expected: bottom-right corner shows a card silhouette with atlas-shadow halo. Card body is empty (Tasks 14–16 fill it).

- [ ] **Step 3: Commit**

```bash
git add kernel/security/login.cpp
git commit -m "security/login: atlas-shadow corner card at bottom-right"
```

### Task 14: Avatar + username + role inside the card

**Files:**
- Modify: `kernel/security/login.cpp`

- [ ] **Step 1: Paint the avatar circle + monogram**

Inside `LoginPaintGui`, after the card paint:

```cpp
// 4. Avatar circle — 40px diameter, accent-stroke, single-letter monogram.
const u32 avatar_cx = card_x + 36 * fb_w / 1024;
const u32 avatar_cy = card_y + 40 * fb_h / 768;
const u32 avatar_r  = 20 * fb_w / 1024;

duetos::drivers::video::FramebufferFillCircle(avatar_cx, avatar_cy, avatar_r, ThemeActive().input_bg_rgb);
duetos::drivers::video::FramebufferStrokeCircle(avatar_cx, avatar_cy, avatar_r,
    ThemeActive().accent_primary, /*thickness=*/2);

// Monogram = first char of g_login_username (in scope inside login.cpp),
// uppercased. Fall back to '?' if username is empty.
char mono = '?';
if (g_login_username[0]) {
    mono = g_login_username[0];
    if (mono >= 'a' && mono <= 'z') mono = mono - 'a' + 'A';
}
char mono_str[2] = {mono, '\0'};
duetos::drivers::video::Font8x8DrawStringScaled(
    avatar_cx - 8, avatar_cy - 8, mono_str, ThemeActive().accent_primary, /*scale=*/2);
```

(If `FillCircle` / `StrokeCircle` don't exist, use the existing `RenderSoftShadow`-adjacent circle primitive in `shadow.cpp`, or pixel-loop with `FramebufferBlendPixel`. Keep tight — circle is small.)

- [ ] **Step 2: Paint username + role text right of avatar**

```cpp
// 5. Username + role text right of avatar.
const u32 name_x = avatar_cx + avatar_r + 12;
const u32 name_y = card_y + 32 * fb_h / 768;
const u32 role_y = card_y + 48 * fb_h / 768;
duetos::drivers::video::Font8x8DrawString(name_x, name_y, g_login_username, ThemeActive().chrome_text_rgb);
duetos::drivers::video::Font8x8DrawString(name_x, role_y, "Administrator", ThemeActive().chrome_text_dim_rgb);
```

(Role v0 is a static `"Administrator"` — the auth subsystem doesn't yet surface role-per-user. GAP: `// GAP: role hardcoded — RBAC role lookup not wired into login.cpp yet, revisit when RBAC v1 persistence lands`.)

- [ ] **Step 3: Build + boot + verify**

Run: `cmake --build build --parallel && DUETOS_TIMEOUT=15 tools/qemu/run.sh`
Expected: card now shows avatar circle + monogram + "krill / Administrator" text.

- [ ] **Step 4: Commit**

```bash
git add kernel/security/login.cpp
git commit -m "security/login: avatar circle + username + role in corner card"
```

### Task 15: Password field with Pass A focus glow

**Files:**
- Modify: `kernel/security/login.cpp`

- [ ] **Step 1: Paint the password field**

```cpp
// 6. Password field — single-line accent-stroked rect.
const u32 pwd_x = card_x + 20 * fb_w / 1024;
const u32 pwd_y = card_y + 72 * fb_h / 768;
const u32 pwd_w = card_w - 40 * fb_w / 1024;
const u32 pwd_h = 28 * fb_h / 768;

duetos::drivers::video::FramebufferFillRect(pwd_x, pwd_y, pwd_w, pwd_h, ThemeActive().input_bg_rgb);

// Focus glow ring (Pass A primitive) — paints over the rect on focus.
if (g_login_focus == kLoginFocusPassword) {
    duetos::drivers::video::WindowPaintFocusGlow(
        pwd_x, pwd_y, pwd_w, pwd_h, ThemeActive().focus_glow_colour);
} else {
    duetos::drivers::video::FramebufferDrawRect(pwd_x, pwd_y, pwd_w, pwd_h, ThemeActive().border_rgb);
}

// Mask-render typed password.
char masked[64];
const size_t typed = g_login_password_len;
for (size_t i = 0; i < typed && i + 1 < sizeof(masked); ++i) masked[i] = '*';
masked[typed < sizeof(masked) - 1 ? typed : sizeof(masked) - 1] = '\0';
duetos::drivers::video::Font8x8DrawString(pwd_x + 10, pwd_y + 8, masked, ThemeActive().chrome_text_rgb);
```

(Match the actual focus state member — `g_login_focus` is illustrative. The existing Gui paint already tracks tab-focus; reuse the same field.)

- [ ] **Step 2: Build + boot + type a password — verify focus glow + mask**

Run: `cmake --build build --parallel && DUETOS_TIMEOUT=15 tools/qemu/run.sh`
Expected: password field paints; focus glow surrounds it; typing produces `*` characters in the field.

- [ ] **Step 3: Commit**

```bash
git add kernel/security/login.cpp
git commit -m "security/login: password field + Pass A focus glow integration"
```

### Task 16: Sign-in button

**Files:**
- Modify: `kernel/security/login.cpp`

- [ ] **Step 1: Paint the button**

```cpp
// 7. Sign-in button — accent fill, dark text.
const u32 btn_x = pwd_x + pwd_w - 170 * fb_w / 1024;
const u32 btn_y = pwd_y + pwd_h + 14 * fb_h / 768;
const u32 btn_w = 170 * fb_w / 1024;
const u32 btn_h = 28 * fb_h / 768;

duetos::drivers::video::FramebufferFillRect(btn_x, btn_y, btn_w, btn_h, ThemeActive().accent_primary);
const char* label = "Sign in →";
const u32 label_w = duetos::drivers::video::Font8x8MeasureString(label);
duetos::drivers::video::Font8x8DrawString(
    btn_x + (btn_w - label_w) / 2, btn_y + 8, label, ThemeActive().desktop_rgb);
```

- [ ] **Step 2: Build + boot — full corner card now renders**

Run: `cmake --build build --parallel && DUETOS_TIMEOUT=15 tools/qemu/run.sh`
Expected: complete corner card — avatar + name + password + button — sitting bottom-right over the arcs backdrop with atlas-shadow halo.

- [ ] **Step 3: Commit**

```bash
git add kernel/security/login.cpp
git commit -m "security/login: sign-in button + corner-card layout complete"
```

### Task 17: LoginRefreshClock + WallpaperTick minute-roll wiring

**Files:**
- Modify: `kernel/security/login.h`
- Modify: `kernel/security/login.cpp`
- Modify: `kernel/drivers/video/wallpaper.cpp`

- [ ] **Step 1: Declare LoginRefreshClock in login.h**

```cpp
/// Re-paint ONLY the clock + date rect of the login GUI. Called by
/// WallpaperTick when the wall-clock minute advances. No-op if the
/// login gate is not active or not in GUI mode. Caller holds compositor
/// lock.
void LoginRefreshClock();
```

- [ ] **Step 2: Implement in login.cpp**

```cpp
void LoginRefreshClock()
{
    if (!LoginIsActive() || LoginCurrentMode() != LoginMode::Gui) return;
    if (!duetos::drivers::video::FramebufferAvailable()) return;

    const u32 fb_w = duetos::drivers::video::FramebufferWidth();
    const u32 fb_h = duetos::drivers::video::FramebufferHeight();
    const u32 clock_x = 80 * fb_w / 1024;
    const u32 clock_y = 640 * fb_h / 768;
    const u32 date_y  = 680 * fb_h / 768;

    // Clear the clock + date rects to backdrop (re-paint underneath
    // via WallpaperPaint then over-draw the digits). To keep it
    // cheap, clear with a solid fill — the underlying topo/arcs
    // pixels in this region are sparse enough that solid-fill
    // matches the average tone well enough for legibility.
    duetos::drivers::video::FramebufferFillRect(
        clock_x, clock_y - 64, 320, 96, ThemeActive().desktop_rgb);

    char clock_buf[16], date_buf[32];
    LoginFormatClock(clock_buf, sizeof(clock_buf));
    LoginFormatDate(date_buf, sizeof(date_buf));
    const u32 fg = ThemeActive().chrome_text_rgb;
    duetos::drivers::video::Font8x8DrawStringScaled(clock_x, clock_y, clock_buf, fg, /*scale=*/8);
    duetos::drivers::video::Font8x8DrawStringScaled(clock_x, date_y,  date_buf,  fg, /*scale=*/2);
}
```

- [ ] **Step 3: Wire minute-roll check into WallpaperTick**

In `wallpaper.cpp` `WallpaperTick`, at the very end (after the dirty-rect work):

```cpp
// Clock-minute roll check — cheap, fires once per minute. Login uses
// this to refresh its clock rect; no-op when login is not active.
const u64 minute = (now_ms - g_motion.base_ms) / 60000;
if (minute != g_motion.last_minute) {
    g_motion.last_minute = minute;
    duetos::core::LoginRefreshClock();
}
```

(Add `#include "security/login.h"` at the top of wallpaper.cpp.)

- [ ] **Step 4: Build + boot**

Run: `cmake --build build --parallel && DUETOS_TIMEOUT=70 tools/qemu/run.sh`
(70 s so a minute boundary is crossed.)
Expected: clock advances when the wall-clock minute changes.

- [ ] **Step 5: Commit**

```bash
git add kernel/security/login.h kernel/security/login.cpp kernel/drivers/video/wallpaper.cpp
git commit -m "security/login,video/wallpaper: per-minute clock refresh"
```

### Task 18: LoginGuiSelfTest

**Files:**
- Modify: `kernel/security/login.h`
- Modify: `kernel/security/login.cpp`
- Modify: `kernel/core/boot_bringup.cpp`

- [ ] **Step 1: Declare in login.h**

```cpp
void LoginGuiSelfTest();
bool LoginGuiSelfTestPassed();
```

- [ ] **Step 2: Implement in login.cpp**

```cpp
namespace { bool g_login_gui_selftest_passed = false; }

void LoginGuiSelfTest()
{
    // Assert the corner-card coordinates compute correctly at the
    // canonical 1024x768 framebuffer dimensions. (At runtime FB might
    // be different — these are just regression checks against the
    // spec §5 layout table.)
    constexpr u32 kFbW = 1024, kFbH = 768;
    const u32 card_x = 694 * kFbW / 1024;
    const u32 card_y = 540 * kFbH / 768;
    if (card_x != 694 || card_y != 540) {
        duetos::arch::SerialWrite("[login-gui-selftest] FAIL card coords drift\n");
        debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB7);
        return;
    }
    // Format helpers must produce reasonable output.
    char buf[32];
    LoginFormatClock(buf, sizeof(buf));
    if (buf[0] == '\0') {
        duetos::arch::SerialWrite("[login-gui-selftest] FAIL clock empty\n");
        debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB8);
        return;
    }
    LoginFormatDate(buf, sizeof(buf));
    if (buf[0] == '\0') {
        duetos::arch::SerialWrite("[login-gui-selftest] FAIL date empty\n");
        debug::ProbeFire(debug::ProbeId::kBootSelftestFail, 0xB9);
        return;
    }
    duetos::arch::SerialWrite("[login-gui-selftest] PASS\n");
    g_login_gui_selftest_passed = true;
}

bool LoginGuiSelfTestPassed() { return g_login_gui_selftest_passed; }
```

- [ ] **Step 3: Wire into boot umbrella**

In `kernel/core/boot_bringup.cpp`, add next to the splash + wallpaper-motion calls landed in Task 11:

```cpp
duetos::core::LoginGuiSelfTest();
```

- [ ] **Step 4: Build + boot + verify**

Run: `cmake --build build --parallel && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "splash|wallpaper-motion|login-gui"`
Expected:
```
[splash-selftest] PASS
[wallpaper-motion-selftest] PASS
[login-gui-selftest] PASS
```

- [ ] **Step 5: Commit**

```bash
git add kernel/security/login.h kernel/security/login.cpp kernel/core/boot_bringup.cpp
git commit -m "security/login,boot: LoginGuiSelfTest + umbrella wiring"
```

**Phase 4 complete.** Login + lock now use the corner-card layout. All three new self-tests fire on boot.

---

## Phase 5 — Wallpaper polish (non-Duet patterns)

### Task 19: Polish topo pattern (cleaner curves + drift motion)

**Files:**
- Modify: `kernel/drivers/video/wallpaper.cpp`

- [ ] **Step 1: Find the topo paint branch**

Run: `git grep -n "topo\|kThemeAlt\|generated_svg_topo" kernel/drivers/video/wallpaper.cpp`

- [ ] **Step 2: Apply drift offset and theme-aware tint**

In the topo paint branch, change the per-curve x-coordinate to:

```cpp
// Each curve's screen-space x = svg_x + g_motion.topo_drift_px,
// wrapped at fb_w. Draw twice — once at +offset, once at
// +offset - fb_w — so the wrap is seamless.
const i32 drift = g_motion.topo_drift_px;
const i32 x_shifted = (i32(svg_x) + drift) % i32(fb_w);
// ... paint at (x_shifted, y) ...
// ... paint at (x_shifted - i32(fb_w), y) if x_shifted > i32(fb_w / 2) ...

// Stroke colour: AmbientStrokeRgb(desk, 24) — already low-contrast,
// theme-tint via the existing AmbientStrokeRgb path.
```

(The exact curve loop will depend on the existing topo paint shape — `git grep` shows the structure. Keep the change small: just add the drift offset + the wrap-around second pass.)

- [ ] **Step 3: Build + boot under Slate10/Amber theme (which use topo)**

Run:
```bash
DUETOS_EXTRA_CMDLINE="theme=Slate10" DUETOS_TIMEOUT=20 tools/qemu/run.sh
```
Expected: topo curves visibly drift horizontally; wrap-around is seamless.

- [ ] **Step 4: Commit**

```bash
git add kernel/drivers/video/wallpaper.cpp
git commit -m "video/wallpaper: topo pattern drift motion + tint"
```

### Task 20: Polish syscalls-grid (per-cell shadow + theme tint)

**Files:**
- Modify: `kernel/drivers/video/wallpaper.cpp`

- [ ] **Step 1: Find the syscalls-grid paint branch**

Run: `git grep -n "syscalls-grid\|generated_svg_syscalls" kernel/drivers/video/wallpaper.cpp`

- [ ] **Step 2: Apply per-cell tactility shadow + theme tint**

In the per-cell paint loop, after the existing cell fill, add:

```cpp
// Pass B polish — per-cell tactility shadow + theme accent tint.
// Stays static (no motion — dense grid would read as noise).
if (ThemeActive().tactility_enabled) {
    duetos::drivers::video::RenderSoftShadow(
        cell_x, cell_y, cell_w, cell_h, /*radius=*/4, /*opacity=*/40);
}
// Tint the cell text via the theme's chrome_text_dim_rgb instead
// of the previous hardcoded grey.
const u32 cell_text = ThemeActive().chrome_text_dim_rgb;
// ... existing text draw uses cell_text now ...
```

- [ ] **Step 3: Build + boot under a theme that uses syscalls-grid**

(Whichever theme variant uses it — search `kernel/drivers/video/theme.cpp` for `kWallpaperSyscallsGrid` or similar.)

```bash
DUETOS_EXTRA_CMDLINE="theme=<theme-using-syscalls>" DUETOS_TIMEOUT=15 tools/qemu/run.sh
```
Expected: syscalls grid has subtle shadow per cell + theme-tinted text.

- [ ] **Step 4: Commit**

```bash
git add kernel/drivers/video/wallpaper.cpp
git commit -m "video/wallpaper: syscalls-grid per-cell shadow + tint"
```

**Phase 5 complete.** All three wallpaper patterns get Pass B polish.

---

## Phase 6 — Verification harnesses

### Task 21: Extend hc-invariant-check.sh for motion=on/off

**Files:**
- Modify: `tools/test/hc-invariant-check.sh`

- [ ] **Step 1: Find the existing tactility on/off comparison**

Run: `git grep -n "tactility=on\|tactility=off" tools/test/hc-invariant-check.sh`

- [ ] **Step 2: Add a parallel motion=on vs motion=off comparison**

Append after the existing tactility comparison block:

```bash
# Pass B addition — HighContrast must produce identical pixels with
# motion=on vs motion=off because tactility_enabled (master gate)
# is false for HighContrast and overrides the motion= cmdline.
# This catches a regression where a future motion code path
# accidentally bypasses the master gate.

SHOTS_DIR="${SHOTS_DIR:-build/shots}"
mkdir -p "$SHOTS_DIR"

for mode in on off; do
    DUETOS_EXTRA_CMDLINE="theme=HighContrast motion=${mode}" \
        DUETOS_TIMEOUT=20 \
        tools/qemu/run.sh > "/tmp/hc-motion-${mode}.log" 2>&1
    # Use the QMP screendump path (Pass A landed this in matrix script).
    tools/test/qmp-screendump.sh "$SHOTS_DIR/hc-motion-${mode}.ppm"
done

DIFF=$(tools/test/ppm-pixel-diff.py "$SHOTS_DIR/hc-motion-on.ppm" "$SHOTS_DIR/hc-motion-off.ppm")
echo "HC motion=on vs motion=off pixel-diff: $DIFF (noise floor: 333)"
if [ "$DIFF" -gt 333 ]; then
    echo "FAIL HC motion gate broken (>$DIFF px diff)"
    exit 1
fi
echo "PASS HC motion invariant (diff $DIFF px <= 333 noise floor)"
```

(Match the actual helper names — `qmp-screendump.sh` and `ppm-pixel-diff.py` are illustrative; the matrix script Pass A landed uses concrete names. `git grep -n` will show them.)

- [ ] **Step 3: Run the extended script + commit**

```bash
bash tools/test/hc-invariant-check.sh
git add tools/test/hc-invariant-check.sh
git commit -m "tools/test: HC motion-gate invariant (Pass B)"
```

### Task 22: Extend tactility-screenshot-matrix.sh with new surfaces

**Files:**
- Modify: `tools/test/tactility-screenshot-matrix.sh`

- [ ] **Step 1: Add new surface modes**

Add a `--splash` / `--login` / `--lock` / `--wallpaper` arg-parsing branch at the top of the script. Each branch overrides the boot phase the screendump is captured at:

```bash
SURFACE="${SURFACE:-wallpaper}"
case "$1" in
    --splash)    SURFACE=splash;    CAPTURE_AT_MS=1500 ;;  # mid-boot
    --login)     SURFACE=login;     CAPTURE_AT_MS=8000 ;;  # at first login paint
    --lock)      SURFACE=lock;      CAPTURE_AT_MS=8000 ;;  # idle threshold tweaked low
    --wallpaper) SURFACE=wallpaper; CAPTURE_AT_MS=12000 ;; # after auto-window dismissed
esac
```

For each surface × theme combination, boot with the matching cmdline (e.g. `idlelock=2 theme=<t>` for `--lock`) and screendump at `CAPTURE_AT_MS`. Output path: `build/shots/<surface>-<theme>-debug-fast.ppm`.

- [ ] **Step 2: Run a smoke for each surface**

```bash
for s in splash login lock wallpaper; do
    bash tools/test/tactility-screenshot-matrix.sh --$s --theme Duet
done
ls -la build/shots/*-debug-fast.ppm
```
Expected: 4 new PPMs land.

- [ ] **Step 3: Commit**

```bash
git add tools/test/tactility-screenshot-matrix.sh
git commit -m "tools/test: screenshot matrix --splash/--login/--lock/--wallpaper"
```

### Task 23: New tools/test/pass-b-soak.sh

**Files:**
- Create: `tools/test/pass-b-soak.sh`

- [ ] **Step 1: Write the soak harness**

Create the script (chmod +x in the same step):

```bash
#!/usr/bin/env bash
# Pass B ambient-motion soak.
# Boot to login, hold 30 s, capture compositor frame timings.
# Asserts:
#   - avg CPU < 8% over the soak window
#   - no compositor missed-tick warnings
#   - no soft-lockup warnings
#   - no [E] lines from wallpaper/splash/login

set -e
LOG="${LOG:-/tmp/pass-b-soak.log}"
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-45}" \
DUETOS_PROFILE="${DUETOS_PROFILE:-login-soak}" \
tools/qemu/run.sh > "$LOG" 2>&1 || true

echo "--- log written to $LOG ---"

# Run the existing boot-log-analyzer (it'll exit non-zero on any
# regression sentinel it recognises).
bash tools/test/boot-log-analyze.sh "$LOG"

# Pass B specific checks.
ERRS=$(grep -cE "wallpaper \[E\]|splash \[E\]|login \[E\]" "$LOG" || echo 0; true)
LOCKUPS=$(grep -c "soft-lockup" "$LOG" || echo 0; true)
MISSED=$(grep -c "compositor.*missed tick" "$LOG" || echo 0; true)

echo "wallpaper/splash/login errors: $ERRS"
echo "soft-lockup warnings:           $LOCKUPS"
echo "compositor missed ticks:        $MISSED"

if [ "$ERRS" -gt 0 ] || [ "$LOCKUPS" -gt 0 ] || [ "$MISSED" -gt 0 ]; then
    echo "FAIL pass-b-soak"
    exit 1
fi
echo "PASS pass-b-soak"
```

- [ ] **Step 2: Make executable + run**

```bash
chmod +x tools/test/pass-b-soak.sh
bash tools/test/pass-b-soak.sh
```
Expected: `PASS pass-b-soak`.

- [ ] **Step 3: Commit**

```bash
git add tools/test/pass-b-soak.sh
git commit -m "tools/test: pass-b-soak — 30s ambient motion harness"
```

### Task 24: Extend boot-log-analyze.sh with [pass-b] umbrella line

**Files:**
- Modify: `tools/test/boot-log-analyze.sh`

- [ ] **Step 1: Find the existing tactility umbrella reporter**

Run: `git grep -n "tactility-selftest\|TACTILITY" tools/test/boot-log-analyze.sh`

- [ ] **Step 2: Add a parallel PASS B section**

After the tactility umbrella block:

```bash
# Pass B — first-impression moments.
splash=$(grep -c "\[splash-selftest\] PASS" "$LOG" || echo 0; true)
wm=$(grep -c "\[wallpaper-motion-selftest\] PASS" "$LOG" || echo 0; true)
lg=$(grep -c "\[login-gui-selftest\] PASS" "$LOG" || echo 0; true)
motion=$(grep -c "WallpaperTick.*intensity" "$LOG" || echo 1; true)  # default: assume active
probe=$(grep -c "ProbeFire.*kBootSelftestFail.*0xB" "$LOG" || echo 0; true)

echo "[pass-b] splash=${splash} login=${lg} lock=${lg} wallpaper=${wm} motion=${motion} probe fires=${probe}"

# Lock = same path as login (uses LoginGuiSelfTest); reuse $lg.
if [ "$splash" -ne 1 ] || [ "$wm" -ne 1 ] || [ "$lg" -ne 1 ] || [ "$probe" -ne 0 ]; then
    echo "REGRESSION: Pass B umbrella sentinels missing or probe fired"
    exit 1
fi
```

- [ ] **Step 3: Test against a real boot log**

```bash
DUETOS_TIMEOUT=20 tools/qemu/run.sh > /tmp/test-passB.log 2>&1
bash tools/test/boot-log-analyze.sh /tmp/test-passB.log
```
Expected: `[pass-b] splash=1 login=1 lock=1 wallpaper=1 motion=1 probe fires=0`.

- [ ] **Step 4: Commit**

```bash
git add tools/test/boot-log-analyze.sh
git commit -m "tools/test: boot-log-analyze [pass-b] umbrella section"
```

**Phase 6 complete.** All verification harnesses extended; Pass B has the same CI-grep surface Pass A has.

---

## Phase 7 — Documentation + final acceptance

### Task 25: Update wiki/subsystems/Compositor.md with Pass B section

**Files:**
- Modify: `wiki/subsystems/Compositor.md`

- [ ] **Step 1: Find the Pass A "Chrome tactility" section**

Run: `grep -n "chrome-tactility-pass-a\|Pass A" wiki/subsystems/Compositor.md`

- [ ] **Step 2: Add a sibling section**

After the Pass A section, add:

```markdown
## First-impression moments (Pass B)

Pass B is the four scenes a user sees before any app opens: boot
splash, login welcome, idle/lock, and the desktop wallpaper itself.

**Continuous backdrop.** `WallpaperPaint(rgb)` paints the active
theme's wallpaper at the same coordinates in every scene. Splash,
login, lock, and the desktop all share that same backdrop layer.
Overlays (phase ticker, login card, desktop chrome) paint on top
without recomposing the backdrop.

**Ambient motion** (15 FPS): arcs rotate ±5° / 60s, soft pulse glow
(8s breath), topo curves drift 1 px/s horizontally, login clock
refreshes on minute roll. Gated by `Theme::motion_intensity` (new
field) and the existing `tactility_enabled` master gate — HighContrast
opts out entirely; Classic runs at 30% intensity; others run full.
Runtime override via `motion=on|off|auto` cmdline.

**Self-tests:** `SplashSelfTest`, `WallpaperMotionSelfTest`,
`LoginGuiSelfTest` — each emits `[*-selftest] PASS` on success.
Umbrella line is emitted by `boot-log-analyze.sh`:
`[pass-b] splash=1 login=1 lock=1 wallpaper=1 motion=1 probe fires=0`.

See [`docs/superpowers/specs/2026-05-24-duetos-pass-b-design.md`](../../docs/superpowers/specs/2026-05-24-duetos-pass-b-design.md)
for the full design + acceptance criteria.
```

- [ ] **Step 3: Commit**

```bash
git add wiki/subsystems/Compositor.md
git commit -m "wiki/Compositor: first-impression moments (Pass B) section"
```

### Task 26: Run the spec's full acceptance checklist + Roadmap cleanup

**Files:**
- Modify: `wiki/reference/Roadmap.md` (only if Pass B residuals surface)
- Modify: `wiki/getting-started/History.md` (only if Pass B counts as a milestone — discretionary)

- [ ] **Step 1: Walk every acceptance criterion in spec §10**

Run, in order:

```bash
# 1. Cold boot produces splash -> login -> desktop with continuous arcs.
bash tools/test/tactility-screenshot-matrix.sh --splash --theme Duet
bash tools/test/tactility-screenshot-matrix.sh --login --theme Duet
bash tools/test/tactility-screenshot-matrix.sh --wallpaper --theme Duet
ls -la build/shots/splash-*.ppm build/shots/login-*.ppm build/shots/wallpaper-*.ppm

# 2 + 3. All self-tests fire + umbrella line.
DUETOS_TIMEOUT=20 tools/qemu/run.sh > /tmp/accept.log 2>&1
bash tools/test/boot-log-analyze.sh /tmp/accept.log | grep "\[pass-b\]"

# 4. HighContrast invariant.
bash tools/test/hc-invariant-check.sh

# 5. Soak under 8% CPU avg.
bash tools/test/pass-b-soak.sh

# 6. No Pass A regressions.
grep -E "blend-selftest|shadow-selftest|theme-selftest|tactility-selftest" /tmp/accept.log
```

Every line above must succeed before moving on.

- [ ] **Step 2: If any residual surfaced, add to Roadmap**

If verification surfaced anything that the spec didn't account for (e.g., compositor missed-tick warnings under unusual load, or topo wrap visible artefact), append a "Chrome tactility (Pass B) — residual polish" section to `wiki/reference/Roadmap.md`. Mirror the shape of the existing Pass A residual entry. If nothing surfaced, do not edit the Roadmap.

- [ ] **Step 3: Pass A "VBox boot verification" residual graduation**

If Pass A's VBox verification was also run in this slice (verification harnesses are shared), delete that bullet from the Pass A residual section of the Roadmap in this commit.

- [ ] **Step 4: Final commit**

```bash
# Stage only whatever was actually changed by Steps 2-3.
git status
git add wiki/reference/Roadmap.md  # if it was edited
git commit -m "wiki/Roadmap: Pass B landing — residuals/graduations"
```

**Phase 7 complete. Pass B is landed.** The Roadmap no longer carries "Pass B = first-impression moments" as future work; the wiki Compositor page documents the new surface; CI-grep coverage matches Pass A.

---

## Plan summary

| Phase | Tasks | Files touched | Net LOC |
|---|---|---|---|
| 1 — Foundation (motion_intensity + cmdline) | 1–4 | theme.{h,cpp}, boot_tasks.cpp, tests/host/ | ~80 |
| 2 — Wallpaper motion infrastructure | 5–8 | wallpaper.{h,cpp}, compositor.cpp | ~200 |
| 3 — Splash module | 9–11 | splash.{h,cpp} (new), boot_bringup.cpp | ~340 |
| 4 — Login corner-card layout | 12–18 | login.{h,cpp}, font8x8.{h,cpp}, boot_bringup.cpp | ~280 |
| 5 — Wallpaper polish (topo + syscalls) | 19–20 | wallpaper.cpp | ~50 |
| 6 — Verification harnesses | 21–24 | hc-invariant-check.sh, matrix.sh, pass-b-soak.sh, boot-log-analyze.sh | ~120 |
| 7 — Docs + acceptance | 25–26 | Compositor.md, Roadmap.md (if), History.md (if) | ~40 |

**Total:** 26 tasks, ~1110 LOC across ~21 files (2 new — `splash.h`, `splash.cpp`; 1 new test — `test_motion_math.cpp`; 1 new tool — `pass-b-soak.sh`; the rest are in-place edits to wallpaper / login / theme / boot_bringup / boot_tasks / font8x8 / compositor / 4 verification scripts / 2 wiki pages).

