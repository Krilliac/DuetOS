#include "drivers/video/shadow.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/video/blend_math.h"
#include "drivers/video/framebuffer.h"

// generated_shadow_atlas.h is emitted by the configure-time bake
// (tools/build/gen_shadow_atlas.py, wired into kernel/CMakeLists.txt
// at task 1) into the kernel build dir, where the kernel target's
// generated-headers include path picks it up. Defines `kShadowAtlas`
// and `kShadowAtlasSize` in duetos::drivers::video.
#include "generated_shadow_atlas.h"

namespace duetos::drivers::video
{

namespace
{

// File-scope PASS tracker for the boot umbrella aggregator. Set
// by the success branch of ShadowSelfTest; read by
// ShadowSelfTestPassed(). Initially false so an absent or
// FAILed self-test never lights up the umbrella line.
bool s_passed = false;

// Lookup ARGB-alpha at atlas coordinate (ax, ay). Out-of-range
// returns 0 (no shadow). Atlas is row-major ARGB8888 with the
// dense centre at (0, 0) and full transparency by (32, 0).
inline u8 AtlasAlpha(u32 ax, u32 ay)
{
    if (ax >= kShadowAtlasSize || ay >= kShadowAtlasSize)
    {
        return 0;
    }
    return static_cast<u8>((kShadowAtlas[ay * kShadowAtlasSize + ax] >> 24) & 0xFFU);
}

// Compose the per-pixel shadow ARGB: scaled atlas alpha + tint
// colour. Returns 0 if the resulting alpha is zero (caller skips
// the blend entirely).
inline u32 ShadowArgb(u8 atlas_a, u8 opacity, u32 colour)
{
    if (atlas_a == 0)
    {
        return 0;
    }
    const u8 a = static_cast<u8>((static_cast<u32>(atlas_a) * opacity) / 255U);
    if (a == 0)
    {
        return 0;
    }
    return (static_cast<u32>(a) << 24) | (colour & 0x00FFFFFFU);
}

// Paint one of the four corner quadrants. (qx, qy) selects the
// direction: (-1, -1) = TL, (+1, -1) = TR, (-1, +1) = BL,
// (+1, +1) = BR. (cx, cy) is the corner-pixel anchor (just
// outside the window). The atlas is sampled with (dx, dy) scaled
// from [0, radius) to [0, kShadowAtlasSize) so any radius in
// [8, 48] looks plausible.
void PaintCorner(i32 cx, i32 cy, u32 radius, u8 opacity, u32 colour, int qx, int qy)
{
    for (u32 dy = 0; dy < radius; ++dy)
    {
        for (u32 dx = 0; dx < radius; ++dx)
        {
            const u32 ax = (dx * kShadowAtlasSize) / radius;
            const u32 ay = (dy * kShadowAtlasSize) / radius;
            const u32 argb = ShadowArgb(AtlasAlpha(ax, ay), opacity, colour);
            if (argb == 0)
            {
                continue;
            }
            const i32 px = cx + qx * static_cast<i32>(dx);
            const i32 py = cy + qy * static_cast<i32>(dy);
            if (px < 0 || py < 0)
            {
                continue;
            }
            FramebufferBlendPixel(static_cast<u32>(px), static_cast<u32>(py), argb);
        }
    }
}

// Paint a vertical edge strip (left or right of the window) by
// sampling the atlas y=0 row — the "edge alpha" curve. qx = -1
// paints to the left of `ex`, +1 to the right.
void PaintVEdge(i32 ex, i32 y0, u32 h, u32 radius, u8 opacity, u32 colour, int qx)
{
    for (u32 dx = 0; dx < radius; ++dx)
    {
        const u32 ax = (dx * kShadowAtlasSize) / radius;
        const u32 argb = ShadowArgb(AtlasAlpha(ax, 0), opacity, colour);
        if (argb == 0)
        {
            continue;
        }
        const i32 px = ex + qx * static_cast<i32>(dx);
        if (px < 0)
        {
            continue;
        }
        FramebufferBlendFill(static_cast<u32>(px), static_cast<u32>(y0), 1U, h, argb);
    }
}

// Paint a horizontal edge strip (top or bottom). Symmetric to
// PaintVEdge — samples the atlas x=0 column.
void PaintHEdge(i32 x0, i32 ey, u32 w, u32 radius, u8 opacity, u32 colour, int qy)
{
    for (u32 dy = 0; dy < radius; ++dy)
    {
        const u32 ay = (dy * kShadowAtlasSize) / radius;
        const u32 argb = ShadowArgb(AtlasAlpha(0, ay), opacity, colour);
        if (argb == 0)
        {
            continue;
        }
        const i32 py = ey + qy * static_cast<i32>(dy);
        if (py < 0)
        {
            continue;
        }
        FramebufferBlendFill(static_cast<u32>(x0), static_cast<u32>(py), w, 1U, argb);
    }
}

} // anonymous namespace

void RenderSoftShadow(i32 x, i32 y, u32 w, u32 h, u32 radius, u8 opacity, u32 colour)
{
    // radius == 0 is "no shadow" — chrome paths that disable the
    // tactility lift on a per-window basis can pass 0 unconditionally.
    // Above-zero clamps to the supported [8, 48] band so a typo can't
    // make the renderer scan a 1000×1000 corner.
    if (opacity == 0 || w == 0 || h == 0 || radius == 0)
    {
        return;
    }
    if (radius < 8)
    {
        radius = 8;
    }
    if (radius > 48)
    {
        radius = 48;
    }

    // GAP: 9216-pixel-per-shadow BlendPixel call count is fine at
    // chrome paint frequency but blocks the present hook for ~half
    // a millisecond on a 1080p surface. Composing a corner row at
    // a time into a stack buffer + a single BlendRgba call would
    // collapse the per-call overhead — revisit if profiling shows
    // chrome paint as the hot path. — Revisit: tactility perf audit.

    // Corners — each anchor (cx, cy) sits one pixel OUTSIDE the
    // window so the corner curve starts immediately at the edge,
    // not after a one-pixel gap.
    PaintCorner(x - 1, y - 1, radius, opacity, colour, -1, -1);
    PaintCorner(x + static_cast<i32>(w), y - 1, radius, opacity, colour, +1, -1);
    PaintCorner(x - 1, y + static_cast<i32>(h), radius, opacity, colour, -1, +1);
    PaintCorner(x + static_cast<i32>(w), y + static_cast<i32>(h), radius, opacity, colour, +1, +1);

    // Edges
    PaintVEdge(x - 1, y, h, radius, opacity, colour, -1);
    PaintVEdge(x + static_cast<i32>(w), y, h, radius, opacity, colour, +1);
    PaintHEdge(x, y - 1, w, radius, opacity, colour, -1);
    PaintHEdge(x, y + static_cast<i32>(h), w, radius, opacity, colour, +1);
}

void RenderSoftShadowWithStroke(i32 x, i32 y, u32 w, u32 h, u32 radius, u8 opacity, u32 colour, u32 stroke_colour)
{
    RenderSoftShadow(x, y, w, h, radius, opacity, colour);
    // 1-pixel stroke at the inner edge of the rect (focus glow).
    // Skipped for off-screen anchors — negative coords can't be cast
    // to u32 for the framebuffer primitives.
    if (x < 0 || y < 0 || w == 0 || h == 0)
    {
        return;
    }
    const u32 ux = static_cast<u32>(x);
    const u32 uy = static_cast<u32>(y);
    FramebufferFillRect(ux, uy, w, 1U, stroke_colour);
    FramebufferFillRect(ux, uy + h - 1U, w, 1U, stroke_colour);
    FramebufferFillRect(ux, uy, 1U, h, stroke_colour);
    FramebufferFillRect(ux + w - 1U, uy, 1U, h, stroke_colour);
}

void ShadowSelfTest()
{
    using duetos::arch::SerialWrite;
    s_passed = false;

    // 1. Atlas dimensions: only 32 is bake-script-supported. A
    //    silent change (e.g. someone editing the bake script to
    //    emit 64×64 without touching the renderer's coordinate
    //    arithmetic) lands the chrome in unreachable atlas rows.
    if (kShadowAtlasSize != 32U)
    {
        SerialWrite("[shadow-selftest] FAIL (atlas size != 32)\n");
        KBP_PROBE(debug::ProbeId::kShadowAtlasInvalid);
        return;
    }

    // 2. Centre-pixel anchor: atlas(0, 0) must be max alpha. If
    //    this is 0 the atlas is byte-reversed and every shadow
    //    will draw inverted (transparent inside, opaque outside).
    if (AtlasAlpha(0, 0) != 0xFFU)
    {
        SerialWrite("[shadow-selftest] FAIL (atlas origin not 255)\n");
        KBP_PROBE(debug::ProbeId::kShadowAtlasInvalid);
        return;
    }

    // 3. Opacity scales linearly. opacity=128 should land ~50% of
    //    opacity=255 at the same atlas coordinate. ±2 LSB tolerates
    //    integer rounding.
    const u32 sample = AtlasAlpha(8, 8);
    const int a255 = static_cast<int>((sample * 255U) / 255U);
    const int a128 = static_cast<int>((sample * 128U) / 255U);
    const int diff = a255 - 2 * a128;
    if (diff < -2 || diff > 2)
    {
        SerialWrite("[shadow-selftest] FAIL (opacity not linear)\n");
        KBP_PROBE(debug::ProbeId::kShadowAtlasInvalid);
        return;
    }

    // 4. Rotational symmetry: atlas(8, 0) and atlas(0, 8) sample
    //    the same Euclidean distance from origin so their alphas
    //    must match within ±1 LSB (bake-time real-math rounding).
    const int axis_x = AtlasAlpha(8, 0);
    const int axis_y = AtlasAlpha(0, 8);
    if (axis_x - axis_y > 1 || axis_y - axis_x > 1)
    {
        SerialWrite("[shadow-selftest] FAIL (atlas not symmetric)\n");
        KBP_PROBE(debug::ProbeId::kShadowAtlasInvalid);
        return;
    }

    SerialWrite("[shadow-selftest] PASS (atlas=32x32, corners=4, edges=4, opacity-linear=ok)\n");
    s_passed = true;
}

bool ShadowSelfTestPassed()
{
    return s_passed;
}

} // namespace duetos::drivers::video
