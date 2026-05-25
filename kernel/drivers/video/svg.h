#pragma once

#include "drivers/video/framebuffer.h"
#include "util/types.h"

/*
 * DuetOS — minimal SVG loader, v0.
 *
 * Parses a strict subset of SVG into a flat shape list that the
 * existing framebuffer primitives (StrokePath / DrawLine /
 * DrawCircle / FillRect) can render. Intended for the prototype's
 * topo / syscalls / DuetMark wallpaper SVGs — once the loader is
 * in place those assets ship as bytes alongside the kernel image
 * instead of being re-implemented as kernel paint code.
 *
 * Supported elements:
 *   <svg width="..." height="..." viewBox="x y w h" ...>
 *   <line x1=".." y1=".." x2=".." y2=".." stroke=".." stroke-width=".."/>
 *   <circle cx=".." cy=".." r=".." stroke=".." stroke-width=".." fill="none"/>
 *   <path d="M x y L x y C x y x y x y Z" stroke=".." stroke-width=".."/>
 *
 * Unsupported (silently dropped):
 *   - Filled shapes (every shape strokes only).
 *   - <rect>, <polygon>, <polyline>, <ellipse>, <text>.
 *   - <g> grouping (loader walks at the document level only).
 *   - Transforms (translate/rotate/scale).
 *   - CSS / class= styling.
 *   - Gradients, masks, filters.
 *   - 'lowercase' relative-coordinate path commands (M only,
 *     L only, etc. — uppercase absolute).
 *
 * Memory model: SvgImage borrows the source byte buffer; shape
 * descriptors point into a caller-supplied scratch buffer. No
 * allocation. Numeric attributes parse as integers (no fractional
 * support — wallpaper geometry is pixel-aligned anyway).
 *
 * Context: kernel. Callable from any task context; not IRQ-safe
 * (the per-instance shape list is mutated during parse).
 */

namespace duetos::drivers::video
{

enum class SvgShapeKind : u8
{
    Line = 0,
    Circle = 1,
    Path = 2,
};

struct SvgShape
{
    SvgShapeKind kind;
    u32 stroke_rgb;
    u32 stroke_width; // pixels, capped at 8

    // Per-kind fields. Unused slots are 0.
    i32 ax, ay, bx, by; // line endpoints, or circle (cx, cy, r, _)
    u32 path_segment_start;
    u32 path_segment_count;
};

struct SvgImage
{
    i32 viewbox_x;
    i32 viewbox_y;
    u32 viewbox_w;
    u32 viewbox_h;

    SvgShape* shapes;
    u32 shape_count;
    u32 max_shapes;

    // Path segments are stored in a flat shared array; each Path
    // shape owns a sub-range.
    PathSegment* path_segments;
    u32 path_segment_count;
    u32 max_path_segments;
};

/// Parse `bytes` into the caller-supplied `image` buffers. Returns
/// false on any parse failure (malformed XML, unsupported root tag,
/// out-of-space). Non-fatal: a partial parse never escapes the
/// boundary, so callers either get a fully-populated SvgImage or no
/// image at all.
bool SvgParse(const u8* bytes, u32 size, SvgImage* image);

/// Render an SvgImage into the active framebuffer surface scaled to
/// fit `(target_x, target_y, target_w, target_h)`. Each shape paints
/// via the matching framebuffer primitive (StrokePath / DrawLine /
/// DrawCircle). Pixel-aligned, no anti-aliasing — the AA path is
/// the rasterizer's job (see ttf_raster.h).
///
/// Optional `tint_argb` (0xAARRGGBB): when the alpha byte is non-zero,
/// every rendered pixel is blended toward the RGB portion of the tint
/// proportional to the alpha (0 = no tint, 255 = fully tinted). Default
/// value `0` (alpha == 0) means "use SVG colours as-is" — backwards-
/// compatible with every existing caller.
void SvgRender(const SvgImage& image, i32 target_x, i32 target_y, u32 target_w, u32 target_h, u32 tint_argb = 0);

/// Boot-time self-test. Parses a small embedded SVG and verifies
/// the shape count matches expectations. Logs the result line and
/// returns true on success.
bool SvgSelfTest();

} // namespace duetos::drivers::video
