#pragma once

// gfxdemo — a native DuetOS graphics demonstration app.
//
// Unlike the other native apps (calculator / notes / files / clock)
// which paint glyphs and chrome, gfxdemo renders a per-pixel
// computed image into its window's client area: a diagonal RGB
// gradient (one channel per axis) with a sine-wave overlay, three
// concentric outline circles, and a centred title strip.
//
// It exercises the same primitive set the DirectX v0 path uses
// internally — `FramebufferPutPixel` / `FramebufferFillRect`
// / `FramebufferBlit` — so the resulting image is visible proof
// that the kernel's pixel-rendering pipeline produces real
// graphical output, not just text on chrome.

#include "../core/types.h"
#include "../drivers/video/widget.h"

namespace duetos::apps::gfxdemo
{

void GfxDemoInit(duetos::drivers::video::WindowHandle handle);
duetos::drivers::video::WindowHandle GfxDemoWindow();
void GfxDemoSelfTest();

} // namespace duetos::apps::gfxdemo
