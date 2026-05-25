#pragma once

#include "drivers/video/ttf.h"
#include "util/types.h"

/*
 * DuetOS — TTF scanline rasterizer, v0.
 *
 * Consumes a `TtfGlyph` from `ttf.h` and produces an 8-bit alpha
 * coverage bitmap. Combined with a font + codepoint, the public
 * `TtfRenderGlyph` returns the bitmap dimensions + pixel buffer
 * (caller-supplied scratch).
 *
 * Algorithm: fixed-point edge tracking with N×N supersampling for
 * box-filter AA. For each output row, project the design-unit
 * outline into supersample-pixel space, intersect every contour
 * edge with each subpixel scanline, sort the resulting X
 * intersections, and fill spans pairwise (even-odd winding rule).
 * After all subrows are accumulated, the per-pixel coverage is
 * `total_subpixel_count_inside / (N*N) * 255`.
 *
 * Quadratic Bezier off-curve points (TrueType uses quads, not the
 * cubics in `FramebufferStrokePath`) are flattened via midpoint
 * subdivision capped at depth 4 — sufficient for chrome-size glyphs
 * (≤ 32 px height) without visibly stair-stepping.
 *
 * Scope limits intentional to v0:
 *   - Even-odd winding rule. The TrueType spec defines non-zero;
 *     for glyf-flavour fonts even-odd produces the same result on
 *     well-formed glyphs (contours are always disjoint or strictly
 *     nested). Composite / CFF fonts that overlap contours need
 *     non-zero — slice 4.x.
 *   - 4×4 supersample (16 levels of coverage). Higher quality at
 *     the same per-glyph cost would need a real edge-coverage
 *     analytic AA path.
 *   - No hinting (`fpgm` / `prep` / `glyf` instructions). Modern
 *     fonts ship unhinted variants suitable for high-DPI rendering;
 *     bitmap font caching gives us per-size pre-rastered glyphs at
 *     no quality loss for chrome sizes.
 *
 * Memory model: the rasterizer allocates nothing. Caller provides
 * `dst_rgba8` (pixel coverage bitmap, one u8 per pixel), and two
 * scratch arrays for the parser's contour decode. Cost per glyph
 * scales with `width * height * supersample² + total_edge_count`.
 *
 * Context: kernel. Chrome paint path. Not IRQ-safe (no shared state
 * but takes a measurable number of microseconds per glyph; do not
 * call from a hot interrupt handler).
 */

namespace duetos::drivers::video
{

/// Output of `TtfRenderGlyph`. The pixel buffer is row-major, one
/// u8 per pixel (alpha coverage 0..255), pitch = `width` (tightly
/// packed). Pixel (0, 0) corresponds to the pen position at
/// `(pen_x + lsb, pen_y - ascent)` — the same convention every
/// stb-style rasterizer uses.
struct TtfRenderedGlyph
{
    u8* pixels;
    u32 width;
    u32 height;
    i32 ascent;  // pixel height above the baseline
    i32 descent; // pixel depth below the baseline (positive number)
    u32 advance; // pen advance in pixels (post-scale `hmtx.advance_width`)
};

/// Render `codepoint` from `font` at `pixel_height` pixels tall (the
/// design-unit em-square scales to this many pixels). The
/// rasterizer writes `pixel_height * advance_pixel_width` bytes
/// into `dst_rgba8`; the caller is expected to size the buffer for
/// the largest expected glyph (e.g. 32 * 32 = 1024 bytes per
/// 32-pixel chrome glyph). On overflow, returns false and writes
/// nothing.
///
/// `points_scratch` / `endpoints_scratch` are the same TTF parser
/// scratch buffers `TtfDecodeGlyph` consumes — caller-owned, not
/// allocated here.
///
/// Returns false if the glyph is composite (slice 4 doesn't
/// decompose), if any scratch is too small, or if the font
/// describes a glyph we can't render.
bool TtfRenderGlyph(const TtfFont& font, u32 codepoint, u32 pixel_height, u8* dst, u32 dst_capacity,
                    TtfPoint* points_scratch, u32 max_points, u16* endpoints_scratch, u16 max_contours,
                    TtfRenderedGlyph* out);

/// Boot-time self-test. Builds a synthetic glyph (a 16×16 square,
/// hand-constructed in code without going through the parser) and
/// verifies the rasterizer produces a square coverage bitmap with
/// full alpha at the centre and zero at the corners. No font asset
/// required — the test exercises the rasterizer's edge tracker on
/// known-good geometry.
bool TtfRasterSelfTest();

/// Draw `text` at (`x`, `y`) using the chrome font registered via
/// `TtfChromeFontSet` at `pixel_height` tall. Each glyph rasterizes
/// into an internal scratch coverage bitmap and is alpha-composited
/// (src-over) into the active framebuffer surface using `fg` as the
/// ink colour. The pen advances by the per-glyph advance width.
///
/// Returns false (without painting) if no chrome font is registered
/// or `pixel_height` is 0; falls back to bitmap font in the chrome
/// paint path is the caller's responsibility.
///
/// Cost is O(num_glyphs × pixel_height² × supersample²); bounded
/// for chrome sizes (≤ 32 px) and the typical title-bar string
/// length (≤ 32 chars).
bool TtfDrawString(u32 x, u32 y, const char* text, u32 fg, u32 pixel_height);

/// Measure `text` at `pixel_height` tall using the per-glyph advance
/// widths from the supplied font's `hmtx` table. This is the exact
/// pen-advance sum a subsequent `TtfDrawString` will produce for the
/// same string + size on the same font — no estimate, no kerning
/// (TrueType `hmtx` advance already includes both side bearings).
///
/// Used by chrome_text.cpp's `ChromeTextMeasure` for the TTF path
/// instead of the previous `chars * px * 0.55` Liberation-Sans
/// estimate, so hit-rects and centring math line up with the
/// rasterizer's actual pen advance for any font (including the
/// bold companion via `font = TtfChromeBoldGet()`).
///
/// Returns 0 for nullptr / empty inputs or `pixel_height == 0`. On a
/// per-glyph lookup miss (e.g. `hmtx` parse error on a codepoint not
/// covered by the font), falls back to advancing one `em-width` for
/// that glyph — same behaviour as `TtfDrawString` on a render-miss,
/// so the measure stays in lock-step with paint even in degenerate
/// cases.
u32 TtfMeasureString(const TtfFont& font, const char* text, u32 pixel_height);

} // namespace duetos::drivers::video
