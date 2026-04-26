# gfxdemo multi-mode v0 — six animated effects + key dispatch

**Last updated:** 2026-04-26
**Type:** Observation + Pattern
**Status:** Active

## Description

Extended `kernel/apps/gfxdemo.{h,cpp}` from a single static
RGB-gradient + sine + rings frame into a six-mode animated
showcase that auto-cycles through the classic real-time
graphics effects (Plasma, Mandelbrot, Wireframe Cube,
Particles, Starfield, Fire). Every mode is per-pixel /
per-vertex computed inside the kernel using only the existing
`FramebufferPutPixel` / `FramebufferFillRect` /
`FramebufferDrawString` primitives — no FPU, no allocator
churn, no new driver hooks.

Render proof: at T~80s the gfxdemo window cycled all the way
to mode 5/5 (FIRE) with the heat-diffusion plume rendering
cleanly, frame counter at 134, no panic across ~22-80s
runs under `-cpu max -machine q35`.

## Context

- `kernel/apps/gfxdemo.h`         — public API + `Mode` enum.
- `kernel/apps/gfxdemo.cpp`       — orchestration: `Init`,
  dispatcher, `DrawHud`, `FeedChar`, `SelfTest`.
- `kernel/apps/gfxdemo_modes.{h,cpp}` — Q15 sine LUT (256-entry,
  quarter-symmetric), 16.16 `FxMul`, splitmix32 PRNG, fixed-
  point Mandelbrot escape, plus the six per-frame `Render*`
  functions.
- `kernel/core/main.cpp`          — keyboard router routes
  alphanumerics + space to `GfxDemoFeedChar` when its window
  is the active one (mirrors the Calculator / Notes / Files
  hookup).
- `kernel/CMakeLists.txt`         — adds `apps/gfxdemo_modes.cpp`
  to `DUETOS_KERNEL_SHARED_SOURCES`.

## Approach

### State + animation cadence

```
constinit Mode g_mode;            // current effect (Plasma..Fire)
constinit u32  g_frame;           // monotonically incrementing frame
constinit u32  g_seed;            // splitmix32 seed for resets
constinit bool g_auto_cycle;      // toggle with 'a'
constinit u32  g_mode_frames;     // frames since last mode change
constexpr u32  kAutoCyclePeriod = 12;
```

The compositor drives `DrawFn` via the registered content-draw
callback. Each frame:

1. dispatch to the current mode's `Render*`,
2. paint the HUD (top strip = mode name, bottom strip =
   `F:NNNNN  T:NNNNNS  KEYS:0-5,N,P,A,R`),
3. `++g_frame`,
4. if auto-cycling, advance `g_mode_frames` and rotate `g_mode`
   when the period expires.

The ui-ticker recomposes once per second; user input forces
extra recomposes on demand. So animation runs at ~1-4 Hz (slow
but visible).

### Per-mode implementation notes

- **Plasma** — four-sin sum of `(x, y, x+y)/2, (x-y)/2` indexed
  through the 256-entry Q15 sine LUT, mapped through a
  three-channel hue palette (RGB phase-shift sines).
- **Mandelbrot** — 14.18 fixed-point escape iteration, 18 max
  iterations, 4×4 pixel tiles to keep cost in the ~1 Hz draw
  budget. Centre fixed at -0.7 + 0i; span breathes ±25%
  using `SinQ15(frame * 4)`.
- **Wireframe cube** — 8 vertices in 16.16 fixed-point, three-
  axis rotation by `(frame*5, frame*3, frame*2) & 0xFF` index,
  perspective divide using `cam_z = 4.0`, focal `2.0`.
  Bresenham over 12 edges, plus a 3×3 vertex dot.
- **Particles** — 64 particles with Q16 position + velocity,
  gravity = 0.125 px/frame², lossy floor bounce (3/4 vy
  reflected, 7/8 vx friction). Soft motion-trail by
  filling the client with a near-black rect each frame.
- **Starfield** — 96 stars marching toward camera. Streak
  toward centre when `z < 200`. Brightness = `255 - z/4`
  (clamped).
- **Fire** — 64×40 heat grid, bottom row reseeded with PRNG
  every frame, propagates upward via a 3-cell average minus
  random decay. Wraps at the X edges. Heat → palette via
  three colour ramps (red, red+green, near-white).

### Self-test

`GfxDemoSelfTest` exercises:

- `SinQ15` at the four cardinal points + the 256-step
  wraparound,
- `CosQ15` is `SinQ15(idx + 64)`,
- `FxMul(1.0, 1.0) == 1.0`, `0.5 * 0.5 == 0.25`, `-1.0 * 1.0 == -1.0`,
- `PrngNext` is deterministic for the same seed and divergent
  for different seeds,
- `MandelbrotEscape(0,0,32) == 32` (origin stays bounded),
- `MandelbrotEscape(1.0,0,32) < 4` (real-axis escape),
- `MandelbrotEscape(-1,0,32) == 32` (period-2 bulb).

Prints one `[gfxdemo] self-test OK ...` line on COM1 at boot.

### Input dispatch

`main.cpp`'s kbd-reader thread already routes typed input to
the active window's app (Notes / Calculator / Files). One new
branch checks `active == GfxDemoWindow()` and forwards the
char to `GfxDemoFeedChar`. Accepts:

- `'0'..'5'` jump to mode N,
- `'n' / SPACE` next mode,
- `'p'` previous,
- `'a'` toggle auto-cycle,
- `'r'` reseed PRNG + reset particles / fire.

## Pitfalls discovered

- **`-cpu max` is mandatory for ring-3 smoke tasks**. Without it
  QEMU's default q35 CPU lacks SMAP and the `STAC`/`CLAC`
  instructions in `kernel/mm/user_copy.S` fault with `#UD` the
  first time `CopyFromUser` runs. The headless screenshot
  helpers (`tools/qemu/screenshot.sh`) already pass `-cpu max`;
  any one-off QEMU script touching ring-3 paths must mirror
  this. Pre-existing issue; not gfxdemo-specific.
- **`constinit` on the `Particle[64]` / `Star[96]` arrays** keeps
  them in `.bss` rather than triggering a constructor call
  early in boot — important because the kernel hasn't installed
  any C++ pre-main runtime.
- **No `std::*`** — the trig LUT is hand-computed, the PRNG is
  splitmix32, and all multiplies stay in i64 to avoid Q16
  overflow. Saturating clamps in `FxMul` and `Pack` keep
  out-of-range arithmetic from poisoning a frame.

## Verification

- `[gfxdemo] self-test OK (sin LUT, FxMul, PRNG, Mandelbrot)`
  on every boot.
- `tools/qemu/run.sh` — 32-second clean run, 0 faults.
- Headless screenshot at T~21s: PLASMA mode, frame 77, smooth
  multi-hue gradient.
- Headless screenshot at T~80s: FIRE mode, frame 134, classic
  heat-diffusion plume.
- `cmake --build build/x86_64-debug` completes with `-Werror`
  clean.
