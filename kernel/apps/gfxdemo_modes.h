#pragma once

// gfxdemo_modes — six per-frame renderers for the multi-mode
// gfxdemo app. Split from gfxdemo.cpp to keep the orchestration
// (init, dispatcher, HUD, key feed, self-test) under the 500-line
// guideline. All renderers paint into the same framebuffer rect:
//
//   (cx, cy, cw, ch)  — the window's client area in framebuffer
//                       coordinates, supplied by the compositor.
//
// All renderers consume the shared `frame` counter so they animate
// at the ui-ticker's cadence. Modes that own mutable state
// (particles, fire grid, starfield) keep it in TU-local statics
// declared in gfxdemo_modes.cpp; the dispatcher resets them when
// the user hits 'r'.

#include "util/types.h"

namespace duetos::apps::gfxdemo
{

// ---------------------------------------------------------------
// Shared kernel-only fixed-point + trig helpers. Exposed so the
// self-test in gfxdemo.cpp can spot-check them.
// ---------------------------------------------------------------

// 256-entry signed sine LUT, range -32767..32767. Index space:
// 0..255 covers 2π. Cosine = sin(idx + 64).
duetos::i32 SinQ15(duetos::u32 idx);
duetos::i32 CosQ15(duetos::u32 idx);

// 16.16 fixed-point multiply: (a * b) >> 16 with saturation.
duetos::i32 FxMul(duetos::i32 a, duetos::i32 b);

// splitmix32-style PRNG. Pure function of `state`; caller mutates
// state externally. Used by particle / starfield / fire seeds.
duetos::u32 PrngNext(duetos::u32* state);

// Mandelbrot escape iteration count for a single point in 14.18
// fixed-point. Returns iterations until |z|^2 > 4 or `iter_max`.
// Used by the Mandelbrot mode AND by the self-test.
duetos::u32 MandelbrotEscape(duetos::i32 cx_q18, duetos::i32 cy_q18, duetos::u32 iter_max);

// ---------------------------------------------------------------
// Per-mode lifecycle hooks.
//
//   Reset*    — re-seed mutable state (called on 'r' or first init).
//   Render*   — paint one frame using the supplied frame counter.
// ---------------------------------------------------------------

void ResetParticles(duetos::u32 seed);
void ResetStarfield(duetos::u32 seed);
void ResetFire(duetos::u32 seed);

void RenderPlasma(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame);
void RenderMandelbrot(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame);
void RenderCube(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame);
void RenderParticles(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame);
void RenderStarfield(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame);
void RenderFire(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame);

} // namespace duetos::apps::gfxdemo
