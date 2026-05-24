#pragma once

// DuetOS — Porter-Duff "over" blend math.
//
// Pure constexpr arithmetic with no kernel dependencies, so the hosted
// unit test (tests/host/test_blend.cpp) can include this header
// directly and exercise the math in milliseconds rather than booting
// QEMU. The framebuffer alpha primitives (FillRectAlpha, PutPixelAlpha,
// BlendRgba, the inline BlendFill/BlendPixel forwarders) all funnel
// their inner loop through `BlendOver` so the math has exactly one
// source of truth — if the test passes, every blend path in the chrome
// uses the same rounding, the same fast paths, and the same channel
// layout (0x00RRGGBB).

#include "util/types.h"

namespace duetos::drivers::video
{

// Porter-Duff "src over dst" blend.
//
//   dst_rgb / src_rgb : 0x00RRGGBB (low 24 bits used; high byte ignored)
//   src_a             : 0..255 source alpha
//   returns           : 0x00RRGGBB blended result
//
// Fast paths: src_a == 0 returns dst unchanged (the no-op case the
// per-pixel loop in BlendRgba relies on for sparse atlases); src_a ==
// 255 returns src unchanged (saves the divide on opaque pixels).
//
// Intermediate channel math uses the (n + 127) / 255 rounding form so
// 0x80 over a black background lands on 0x80 (±1) instead of 0x7F —
// matches what the inline math in FillRectAlpha was doing before
// blend_math.h existed.
constexpr u32 BlendOver(u32 dst_rgb, u32 src_rgb, u8 src_a)
{
    if (src_a == 0)
    {
        return dst_rgb;
    }
    if (src_a == 255)
    {
        return src_rgb & 0x00FFFFFFU;
    }
    const u32 ia = 255U - src_a;
    const u32 dr = (dst_rgb >> 16) & 0xFFU;
    const u32 dg = (dst_rgb >> 8) & 0xFFU;
    const u32 db = dst_rgb & 0xFFU;
    const u32 sr = (src_rgb >> 16) & 0xFFU;
    const u32 sg = (src_rgb >> 8) & 0xFFU;
    const u32 sb = src_rgb & 0xFFU;
    const u32 r = (sr * src_a + dr * ia + 127U) / 255U;
    const u32 g = (sg * src_a + dg * ia + 127U) / 255U;
    const u32 b = (sb * src_a + db * ia + 127U) / 255U;
    return (r << 16) | (g << 8) | b;
}

// Multiply the alpha byte of an ARGB by a 0..255 scale. RGB channels
// pass through unchanged. Used by the theme system so a single base
// ARGB (e.g. 0x1AFFFFFF for a hover wash) gets per-theme intensity
// modulation without redefining the colour itself.
constexpr u32 ScaleAlpha(u32 argb, u8 scale)
{
    const u32 a = (argb >> 24) & 0xFFU;
    const u32 na = (a * scale + 127U) / 255U;
    return (na << 24) | (argb & 0x00FFFFFFU);
}

} // namespace duetos::drivers::video
