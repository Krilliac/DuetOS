#pragma once

// DuetOS — 9-slice soft-shadow renderer.
//
// Paints a soft drop-shadow OUTSIDE an axis-aligned rect using the
// 32×32 quadratic-falloff atlas baked at configure time
// (generated_shadow_atlas.h, Task 1) blended onto the live
// framebuffer via FramebufferBlendPixel / FramebufferBlendFill
// (Task 3). The "9-slice" naming is conventional: four corner
// quadrants drawn from the atlas + four edge strips that re-use
// the y=0 / x=0 atlas row for a uniform 1-D falloff along the
// edge. The interior (slot 5) is the unchanged window content
// the caller already painted.
//
// Context: kernel. Drawing is IRQ-safe (writes go through the
// existing framebuffer primitive surface, which is itself IRQ-
// safe at the pixel-write level). Cost is O(radius²) blended
// pixels per shadow — at the chrome's typical radius=16 that's
// 1024 pixels per corner × 4 corners + ~16 × (w+h) edge pixels.

#include "util/types.h"

namespace duetos::drivers::video
{

// Paint a soft drop-shadow OUTSIDE the rect [(x, y) .. (x+w, y+h)].
// `radius` is the bloom distance in pixels (clamped to [8, 48] —
// 0 is a no-op for the "no shadow" case). `opacity` scales the
// atlas alpha (0 = invisible, 255 = full strength). `colour` is
// the shadow tint as 0x00RRGGBB; the alpha channel is supplied by
// the atlas × opacity, not by `colour`'s high byte.
//
// No-op if `opacity == 0`, `radius == 0`, or w/h == 0. Off-screen
// pixels (negative coordinates near the top-left corner of the
// screen) are clipped per-pixel — the corner draws shrink instead
// of failing.
void RenderSoftShadow(i32 x, i32 y, u32 w, u32 h, u32 radius, u8 opacity, u32 colour);

// Variant that also paints a 1-px inner stroke right at the rect
// edge (focus-glow chrome reads as "shadow + outline"). The
// stroke is opaque; pass the focused accent colour as
// `stroke_colour`. No-op cases match the plain variant.
void RenderSoftShadowWithStroke(i32 x, i32 y, u32 w, u32 h, u32 radius, u8 opacity, u32 colour, u32 stroke_colour);

// Boot self-test. Verifies atlas size invariant (must be 32),
// opacity scales linearly (alpha at opacity=128 is ~half the
// alpha at opacity=255 within ±2 LSB), and the corner curve is
// rotationally symmetric (atlas(8,0) ~= atlas(0,8) within ±1).
// On PASS emits "[shadow-selftest] PASS (...)" to COM1 and sets
// ShadowSelfTestPassed() = true. On FAIL emits the FAIL sentinel
// + fires KBP_PROBE(kShadowAtlasInvalid).
void ShadowSelfTest();

// Returns true iff the last ShadowSelfTest() call passed. Used by
// the boot bringup's tactility umbrella aggregator to emit a
// single [tactility-selftest] PASS line when every sub-test
// passed (spec §8.2). False until ShadowSelfTest has run.
bool ShadowSelfTestPassed();

} // namespace duetos::drivers::video
