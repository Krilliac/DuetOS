#include "drivers/video/wallpaper.h"

#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video
{

namespace
{

// Saturating per-channel lighten / darken — same shape as the
// helpers in widget.cpp / taskbar.cpp / menu.cpp. Each TU keeps a
// private copy so the wallpaper module doesn't pull in a tree of
// chrome headers.
u32 LightenRgb(u32 rgb, u32 amount)
{
    u32 r = ((rgb >> 16) & 0xFFU) + amount;
    u32 g = ((rgb >> 8) & 0xFFU) + amount;
    u32 b = (rgb & 0xFFU) + amount;
    if (r > 0xFFU)
        r = 0xFFU;
    if (g > 0xFFU)
        g = 0xFFU;
    if (b > 0xFFU)
        b = 0xFFU;
    return (r << 16) | (g << 8) | b;
}

// Topo backdrop: a stack of low-contrast concentric circles
// centered in the visible area. The prototype's `topo` wallpaper
// is a contour-line motif; concentric circles approximate it
// without needing a vector path stroker. Painted UNDER the
// duet-arcs rings so the desktop reads as layered terrain rather
// than a single graphic element.
void PaintTopo(u32 desktop_rgb, u32 fb_w, u32 fb_h)
{
    // Single concentric stack centered on the framebuffer.
    // Stroke is a very small lift over the bg — half the
    // contrast of the duet-arcs rings, so topo reads as a base
    // layer rather than competing with the foreground arcs.
    const u32 cx = fb_w / 2;
    const u32 cy = (fb_h * 38) / 100; // same anchor as duet-arcs
    const u32 short_side = (fb_w < fb_h) ? fb_w : fb_h;
    if (short_side < 64U)
        return;
    const u32 ring_step = 28;     // px between rings
    const u32 max_r = short_side; // walk outward until off-screen
    const u32 stroke_rgb = LightenRgb(desktop_rgb, 9);
    for (u32 r = ring_step; r < max_r; r += ring_step)
    {
        FramebufferDrawCircle(static_cast<i32>(cx), static_cast<i32>(cy), r, stroke_rgb);
    }
}

// Paint two interlocking outlined circles centered horizontally
// in the visible area, each ~28% of the smaller framebuffer
// dimension. Stroke is a low-contrast lift of the desktop colour
// so the rings read as ambient texture rather than UI chrome.
// Two-pixel stroke (two concentric outline plots) so the rings
// survive the inactive-window dim overlay.
//
// The teal-tinted ring sits left, the amber-tinted ring right —
// matching the per-app icon hue convention and the in-START
// DuetMark.
void PaintDuetArcs(u32 desktop_rgb, u32 fb_w, u32 fb_h)
{
    // Diameter: ~56% of the shorter side, capped so even very
    // tall framebuffers don't draw rings off the visible area.
    const u32 short_side = (fb_w < fb_h) ? fb_w : fb_h;
    const u32 r = (short_side * 28) / 100;
    if (r < 32U)
        return; // pattern would be a low-contrast smudge — skip
    // Vertical anchor: 38% down the framebuffer, biased above
    // the centre so the taskbar at the bottom doesn't overlap
    // the rings.
    const u32 cy = (fb_h * 38) / 100;
    // Horizontal: rings overlap by half their radius — gives
    // the prototype's "interlocking" feel without having to
    // compute precise geometry from the SVG.
    const u32 cx_a = fb_w / 2 - r / 2;
    const u32 cx_b = fb_w / 2 + r / 2;
    // Stroke colours: lift the desktop bg by a small amount and
    // tint slightly toward teal / amber. The lift is the
    // contrast budget — strong enough to be visible on the
    // gradient, weak enough not to compete with windows.
    const u32 base_lift = LightenRgb(desktop_rgb, 22);
    // Tint = base_lift biased toward the accent hue. We do this
    // by running another lighten on the relevant channel and
    // letting the others stay at the base lift's level. The
    // channel-mix approximation is good enough for a backdrop.
    const u32 lift_r = (base_lift >> 16) & 0xFFU;
    const u32 lift_g = (base_lift >> 8) & 0xFFU;
    const u32 lift_b = base_lift & 0xFFU;
    // Teal: bias toward G + B.
    const u32 teal_r = lift_r;
    const u32 teal_g = (lift_g + 30U > 0xFFU) ? 0xFFU : lift_g + 30U;
    const u32 teal_b = (lift_b + 22U > 0xFFU) ? 0xFFU : lift_b + 22U;
    const u32 teal = (teal_r << 16) | (teal_g << 8) | teal_b;
    // Amber: bias toward R + G.
    const u32 amber_r = (lift_r + 32U > 0xFFU) ? 0xFFU : lift_r + 32U;
    const u32 amber_g = (lift_g + 18U > 0xFFU) ? 0xFFU : lift_g + 18U;
    const u32 amber_b = lift_b;
    const u32 amber = (amber_r << 16) | (amber_g << 8) | amber_b;

    FramebufferDrawCircle(static_cast<i32>(cx_a), static_cast<i32>(cy), r, teal);
    FramebufferDrawCircle(static_cast<i32>(cx_a), static_cast<i32>(cy), r - 1U, teal);
    FramebufferDrawCircle(static_cast<i32>(cx_b), static_cast<i32>(cy), r, amber);
    FramebufferDrawCircle(static_cast<i32>(cx_b), static_cast<i32>(cy), r - 1U, amber);
}

} // namespace

void WallpaperPaint(u32 desktop_rgb)
{
    if (!FramebufferAvailable())
    {
        return;
    }
    const auto info = FramebufferGet();

    switch (ThemeCurrentId())
    {
    case ThemeId::Duet:
        // Duet stacks the topo backdrop under the foreground
        // arcs — the layered look matches the prototype's
        // multi-layer SVG composition.
        PaintTopo(desktop_rgb, info.width, info.height);
        PaintDuetArcs(desktop_rgb, info.width, info.height);
        break;
    case ThemeId::Classic:
    case ThemeId::Slate10:
    case ThemeId::Amber:
    default:
        // Other themes intentionally keep the flat / gradient
        // look the original v0 desktop shipped with. A future
        // slice may add per-theme patterns (Classic-style
        // bubbles, Slate10 grid, Amber phosphor scanlines).
        break;
    }
}

} // namespace duetos::drivers::video
