#pragma once

// gfxdemo — multi-mode animated DuetOS graphics showcase.
//
// Originally a single static "RGB gradient + sine + rings" frame.
// Extended into a six-mode animated demo that auto-cycles through
// classic real-time graphics effects, every one computed per-pixel
// or per-vertex inside the kernel using the same FramebufferPutPixel
// / FramebufferFillRect / FramebufferDrawString primitives the
// DirectX v0 path relies on:
//
//   0  Plasma         four-sin sum coloured through a 64-entry palette
//   1  Mandelbrot     coarse fixed-point fractal, animated zoom
//   2  Wireframe cube 3D rotation in 16.16 fixed-point + perspective
//   3  Particles      bouncing pool with gravity + colour decay
//   4  Starfield      depth-projected moving stars, parallax
//   5  Fire           classic demoscene heat-diffusion + palette LUT
//
// State (frame counter, mode, particle pool, fire grid, prng)
// lives in the gfxdemo TU as constinit data. Each frame the
// content-draw callback advances animation state and renders the
// active mode plus a HUD strip showing the mode name + frame
// count + uptime in seconds.
//
// Input: when this window is active, the keyboard reader feeds
// GfxDemoFeedChar(c). The demo accepts:
//   '0' .. '5'   jump to mode N
//   'n' / SPACE  next mode
//   'p'          previous mode
//   'a'          toggle auto-cycle
//   'r'          reseed prng + reset particles / fire
//
// The demo runs at the ui-ticker's 1 Hz cadence (one draw per
// second) when the desktop is idle, and on every key/mouse event
// triggering a recompose.

#include "../core/types.h"
#include "../drivers/video/widget.h"

namespace duetos::apps::gfxdemo
{

enum class Mode : duetos::u8
{
    Plasma = 0,
    Mandelbrot = 1,
    Cube = 2,
    Particles = 3,
    Starfield = 4,
    Fire = 5,
    Count = 6,
};

void GfxDemoInit(duetos::drivers::video::WindowHandle handle);
duetos::drivers::video::WindowHandle GfxDemoWindow();

/// Keyboard handler — see header comment for the accepted keys.
/// Returns true iff the char was consumed (caller should then skip
/// other input paths). Safe to call from kbd-reader context with
/// the compositor lock held.
bool GfxDemoFeedChar(char c);

/// Boot-time self-test — exercises the trig LUT spot values, the
/// 16.16 fixed-point multiply helper, particle bounce wall logic,
/// and a known Mandelbrot escape count. Prints one PASS / FAIL
/// line to COM1.
void GfxDemoSelfTest();

} // namespace duetos::apps::gfxdemo
