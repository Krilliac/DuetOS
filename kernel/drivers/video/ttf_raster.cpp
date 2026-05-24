#include "drivers/video/ttf_raster.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"

namespace duetos::drivers::video
{

namespace
{

using arch::SerialWrite;

// 4× supersample → 16 subpixel rows per output row. Each subpixel
// that's "inside" the outline contributes 1 to the per-pixel
// coverage count; final alpha = count * 255 / (kSS * kSS).
constexpr u32 kSS = 4;
constexpr u32 kSSSquared = kSS * kSS;

// Max per-glyph edge count. Chrome glyphs have well under 200 edges
// each at 4× supersample; at higher counts the rasterizer truncates
// rather than allocate.
constexpr u32 kMaxEdges = 4096;

// One straight-line edge in supersample-pixel space, flipped so
// `y0 <= y1` (so per-row tests just check `y0 <= y < y1`).
struct Edge
{
    i32 x0_q16; // X at y0, Q16.16 fixed point
    i32 dx_q16; // X step per +1 in y, Q16.16
    i32 y0;     // start scanline (inclusive), supersample units
    i32 y1;     // end scanline (exclusive)
};

// Flat array of the glyph's edges after Bezier flattening. Plain
// global to avoid touching the heap or wasting kernel-stack budget;
// the rasterizer is called from the chrome paint path, not
// concurrently.
constinit Edge g_edges[kMaxEdges]{};
constinit u32 g_edge_count = 0;

// Add a straight edge from `(x0, y0)` to `(x1, y1)` — supersample
// units, Q16.16 X. Skips horizontal edges (no contribution to
// even-odd parity at any scanline).
void AddEdge(i32 x0_q16, i32 y0, i32 x1_q16, i32 y1)
{
    if (g_edge_count >= kMaxEdges)
        return;
    if (y0 == y1)
        return;
    Edge& e = g_edges[g_edge_count++];
    if (y0 < y1)
    {
        e.y0 = y0;
        e.y1 = y1;
        e.x0_q16 = x0_q16;
        e.dx_q16 = (x1_q16 - x0_q16) / (y1 - y0);
    }
    else
    {
        e.y0 = y1;
        e.y1 = y0;
        e.x0_q16 = x1_q16;
        e.dx_q16 = (x0_q16 - x1_q16) / (y0 - y1);
    }
}

// Recursively flatten a quadratic Bezier into line segments via
// midpoint subdivision. Inputs in Q16.16 supersample pixel space.
// Depth bound = 4 (16 leaf segments) — enough to keep chord
// deviation under 1 supersample pixel for chrome-sized glyphs.
void FlattenQuad(i32 x0, i32 y0, i32 cx, i32 cy, i32 x1, i32 y1, i32 depth)
{
    if (depth <= 0)
    {
        AddEdge(x0, y0 >> 16, x1, y1 >> 16);
        return;
    }
    // Midpoint subdivision: m0 = avg(p0, c), m1 = avg(c, p1),
    // m = avg(m0, m1). The two halves are (p0, m0, m) and (m, m1, p1).
    const i32 m0x = (x0 + cx) >> 1;
    const i32 m0y = (y0 + cy) >> 1;
    const i32 m1x = (cx + x1) >> 1;
    const i32 m1y = (cy + y1) >> 1;
    const i32 mx = (m0x + m1x) >> 1;
    const i32 my = (m0y + m1y) >> 1;

    // Cheap straight-segment test: if |dx*dy_chord - dy*dx_chord|
    // (twice the area) is small, the curve is already flat.
    const i64 dx = static_cast<i64>(x1) - x0;
    const i64 dy = static_cast<i64>(y1) - y0;
    const i64 cdx = static_cast<i64>(cx) - x0;
    const i64 cdy = static_cast<i64>(cy) - y0;
    const i64 cross = (cdx * dy) - (cdy * dx);
    const i64 abs_cross = cross < 0 ? -cross : cross;
    // Threshold ≈ 1 supersample-pixel * length scale. Q16.16 scale.
    if (abs_cross < (i64{1} << 32))
    {
        AddEdge(x0, y0 >> 16, x1, y1 >> 16);
        return;
    }
    FlattenQuad(x0, y0, m0x, m0y, mx, my, depth - 1);
    FlattenQuad(mx, my, m1x, m1y, x1, y1, depth - 1);
}

// Walk one contour's points, emitting line segments to AddEdge /
// quad segments to FlattenQuad. Inputs `points[a..b]` are the
// contour's points (a <= i <= b). The TrueType convention is that
// consecutive off-curve points imply an implicit on-curve midpoint
// between them; consecutive on-curve points are a straight line.
void WalkContour(const TtfPoint* points, u16 a, u16 b, i32 px_to_q16_scale, i32 origin_x_q16, i32 origin_y_q16,
                 i32 ymax_q16, bool flip_y)
{
    // Find a starting on-curve point. If the entire contour is
    // off-curve, the convention says the first point IS the implicit
    // midpoint between the last and first off-curve points; rare in
    // practice but legal.
    auto to_qx = [&](i32 design_x) -> i32 { return origin_x_q16 + design_x * px_to_q16_scale; };
    auto to_qy = [&](i32 design_y) -> i32
    { return flip_y ? (ymax_q16 - design_y * px_to_q16_scale) : (origin_y_q16 + design_y * px_to_q16_scale); };

    // First, find an on-curve anchor. If none exists, synthesize one
    // halfway between points[a] and points[b].
    u16 start = a;
    while (start <= b && !points[start].on_curve)
        ++start;
    i32 anchor_x_q16, anchor_y_q16;
    if (start > b)
    {
        // All-off-curve: anchor halfway between p[a] and p[b].
        anchor_x_q16 = (to_qx(points[a].x) + to_qx(points[b].x)) >> 1;
        anchor_y_q16 = (to_qy(points[a].y) + to_qy(points[b].y)) >> 1;
        start = a;
    }
    else
    {
        anchor_x_q16 = to_qx(points[start].x);
        anchor_y_q16 = to_qy(points[start].y);
    }

    i32 cur_x_q16 = anchor_x_q16;
    i32 cur_y_q16 = anchor_y_q16;
    const u16 count = static_cast<u16>(b - a + 1);

    // Iterate (count) points starting AFTER the anchor.
    for (u16 step = 1; step <= count; ++step)
    {
        const u16 idx = static_cast<u16>(a + ((start - a + step) % count));
        const TtfPoint& p = points[idx];
        const i32 px = to_qx(p.x);
        const i32 py = to_qy(p.y);
        if (p.on_curve)
        {
            AddEdge(cur_x_q16, cur_y_q16 >> 16, px, py >> 16);
            cur_x_q16 = px;
            cur_y_q16 = py;
        }
        else
        {
            // Off-curve: peek next point. If it's also off-curve, the
            // segment endpoint is the implicit midpoint between this
            // and the next; otherwise the next point IS the endpoint.
            const u16 nidx = static_cast<u16>(a + ((start - a + step + 1) % count));
            const TtfPoint& np = points[nidx];
            const i32 npx = to_qx(np.x);
            const i32 npy = to_qy(np.y);
            i32 end_x, end_y;
            if (!np.on_curve)
            {
                end_x = (px + npx) >> 1;
                end_y = (py + npy) >> 1;
            }
            else
            {
                end_x = npx;
                end_y = npy;
                ++step; // consume the explicit on-curve endpoint too
            }
            FlattenQuad(cur_x_q16, cur_y_q16, px, py, end_x, end_y, 4);
            cur_x_q16 = end_x;
            cur_y_q16 = end_y;
        }
    }
}

// Fill the coverage bitmap by walking each output row, intersecting
// every edge with each subpixel scanline, sorting the X intersections,
// and filling spans pairwise (even-odd rule).
void RasterizeEdgesIntoCoverage(u8* dst, u32 width, u32 height)
{
    // Per-pixel coverage counter. Cleared each row, accumulated across
    // the kSS subpixel scanlines that cover that row, then divided
    // out into the dst buffer.
    constinit static u16 row_cover[2048]; // bounded by sane glyph widths
    if (width > sizeof(row_cover) / sizeof(row_cover[0]))
        width = sizeof(row_cover) / sizeof(row_cover[0]);

    constinit static i32 isect[256];
    const u32 max_isect = sizeof(isect) / sizeof(isect[0]);

    for (u32 y = 0; y < height; ++y)
    {
        for (u32 i = 0; i < width; ++i)
            row_cover[i] = 0;
        const i32 sub_y_base = static_cast<i32>(y * kSS);
        for (u32 sy = 0; sy < kSS; ++sy)
        {
            const i32 sub_y = sub_y_base + static_cast<i32>(sy);
            // Collect intersections.
            u32 ic = 0;
            for (u32 e = 0; e < g_edge_count; ++e)
            {
                const Edge& edg = g_edges[e];
                if (sub_y < edg.y0 || sub_y >= edg.y1)
                    continue;
                if (ic >= max_isect)
                    break;
                const i32 x_q16 = edg.x0_q16 + edg.dx_q16 * (sub_y - edg.y0);
                isect[ic++] = x_q16;
            }
            // Sort intersections (insertion sort — small N).
            for (u32 i = 1; i < ic; ++i)
            {
                const i32 v = isect[i];
                u32 j = i;
                while (j > 0 && isect[j - 1] > v)
                {
                    isect[j] = isect[j - 1];
                    --j;
                }
                isect[j] = v;
            }
            // Fill spans pairwise.
            for (u32 k = 0; k + 1 < ic; k += 2)
            {
                // Convert Q16.16 supersample-pixel X into output-pixel X.
                const i32 x0 = isect[k] >> 16;
                const i32 x1 = isect[k + 1] >> 16;
                const i32 px0 = (x0 < 0) ? 0 : (x0 / static_cast<i32>(kSS));
                const i32 px1_inc = (x1 + static_cast<i32>(kSS) - 1) / static_cast<i32>(kSS);
                const u32 px_start = static_cast<u32>(px0);
                u32 px_end = static_cast<u32>(px1_inc);
                if (px_end > width)
                    px_end = width;
                for (u32 px = px_start; px < px_end; ++px)
                {
                    // Each subpixel column we step into adds 1 to row_cover.
                    // For partial coverage at the span ends, count the actual
                    // number of subpixel columns inside [x0, x1).
                    const i32 col_lo = static_cast<i32>(px) * static_cast<i32>(kSS);
                    const i32 col_hi = col_lo + static_cast<i32>(kSS);
                    const i32 lo = (x0 > col_lo) ? x0 : col_lo;
                    const i32 hi = (x1 < col_hi) ? x1 : col_hi;
                    if (hi > lo)
                        row_cover[px] += static_cast<u16>(hi - lo);
                }
            }
        }
        // Convert accumulated counts (max kSSSquared per pixel, since
        // the per-subrow span overlap can never exceed kSS) to alpha.
        const u32 denom = kSSSquared;
        for (u32 px = 0; px < width; ++px)
        {
            u32 cov = row_cover[px];
            if (cov > denom)
                cov = denom;
            dst[y * width + px] = static_cast<u8>((cov * 255u + denom / 2u) / denom);
        }
    }
}

} // namespace

bool TtfRenderGlyph(const TtfFont& font, u32 codepoint, u32 pixel_height, u8* dst, u32 dst_capacity,
                    TtfPoint* points_scratch, u32 max_points, u16* endpoints_scratch, u16 max_contours,
                    TtfRenderedGlyph* out)
{
    if (out == nullptr || dst == nullptr || pixel_height == 0 || font.units_per_em == 0)
        return false;

    const u16 gid = TtfGlyphIndex(font, codepoint);
    auto glyph_r = TtfDecodeGlyph(font, gid, points_scratch, max_points, endpoints_scratch, max_contours);
    if (!glyph_r.has_value())
        return false;
    const TtfGlyph glyph = glyph_r.value();
    auto hm_r = TtfGetHMetric(font, gid);
    const TtfHMetric hm = hm_r.has_value() ? hm_r.value() : TtfHMetric{0, 0};

    // Design-units-to-pixels scale, applied via Q16.16 multiply on each
    // coordinate inside the contour walker.
    // pixels_per_unit = pixel_height / units_per_em
    // px_to_q16 = pixels_per_unit * 65536 / 1 = (pixel_height * 65536) / units_per_em
    // Then per-design-unit step in supersample-pixel Q16.16 is
    // px_to_q16 * kSS.
    const i32 px_to_q16_scale =
        static_cast<i32>(((static_cast<u64>(pixel_height) * 65536ULL) / font.units_per_em) * kSS);

    // Coverage bitmap dimensions: glyph bounding box scaled to pixels.
    // Add a 1-pixel margin so AA at the edge isn't clipped.
    const i32 design_w = glyph.x_max - glyph.x_min;
    const i32 design_h = glyph.y_max - glyph.y_min;
    if (design_w <= 0 || design_h <= 0)
    {
        // Empty glyph (space). Return success with a 0-pixel bitmap.
        out->pixels = dst;
        out->width = 0;
        out->height = 0;
        out->ascent = 0;
        out->descent = 0;
        out->advance = static_cast<u32>((static_cast<u64>(hm.advance_width) * pixel_height) / font.units_per_em);
        return true;
    }
    const u32 px_w =
        static_cast<u32>((static_cast<i64>(design_w) * pixel_height + font.units_per_em - 1) / font.units_per_em) + 2u;
    const u32 px_h =
        static_cast<u32>((static_cast<i64>(design_h) * pixel_height + font.units_per_em - 1) / font.units_per_em) + 2u;
    if (static_cast<u64>(px_w) * px_h > dst_capacity)
        return false;

    // Origin in supersample Q16.16: shift design coords so x_min/y_min
    // map to 0. Y is flipped (TrueType design space is Y-up; bitmap is
    // Y-down) so the output baseline aligns at row `ascent`.
    const i32 origin_x_q16 = -static_cast<i32>(glyph.x_min) * px_to_q16_scale + (1 << 16); // +1 px margin
    const i32 ymax_q16 = static_cast<i32>(glyph.y_max) * px_to_q16_scale + (1 << 16);
    const i32 origin_y_q16 = 0; // unused for flip_y=true path

    g_edge_count = 0;

    // Walk every contour into edges.
    u16 contour_start = 0;
    for (u16 c = 0; c < glyph.contour_count; ++c)
    {
        const u16 contour_end = glyph.endpoints[c];
        WalkContour(glyph.points, contour_start, contour_end, px_to_q16_scale, origin_x_q16, origin_y_q16, ymax_q16,
                    /*flip_y=*/true);
        contour_start = static_cast<u16>(contour_end + 1);
    }

    // Clear destination, then rasterize.
    for (u32 i = 0; i < px_w * px_h; ++i)
        dst[i] = 0;
    RasterizeEdgesIntoCoverage(dst, px_w, px_h);

    out->pixels = dst;
    out->width = px_w;
    out->height = px_h;
    out->ascent =
        static_cast<i32>((static_cast<i64>(glyph.y_max) * pixel_height + font.units_per_em - 1) / font.units_per_em);
    out->descent =
        static_cast<i32>((static_cast<i64>(-glyph.y_min) * pixel_height + font.units_per_em - 1) / font.units_per_em);
    out->advance = static_cast<u32>((static_cast<u64>(hm.advance_width) * pixel_height) / font.units_per_em);
    return true;
}

bool TtfRasterSelfTest()
{
    // Build a synthetic glyph: a 1024×1024-design-unit square contour.
    // No font header / cmap / loca — we feed it directly into the
    // edge tracker by hand-constructing a `TtfGlyph` and walking it
    // through the contour walker. This validates the rasterizer's
    // edge tracking + scanline filling on known-good geometry.
    constinit static TtfPoint pts[4] = {
        {100, 100, true},
        {900, 100, true},
        {900, 900, true},
        {100, 900, true},
    };
    constinit static u16 ep[1] = {3};
    TtfGlyph g{};
    g.x_min = 100;
    g.y_min = 100;
    g.x_max = 900;
    g.y_max = 900;
    g.contour_count = 1;
    g.endpoints = ep;
    g.points = pts;
    g.total_points = 4;

    // Synthetic font params.
    TtfFont f{};
    f.units_per_em = 1024;

    // Render at 32 px tall.
    constinit static u8 dst[64 * 64];
    const u32 px_h = 32;
    const i32 scale = static_cast<i32>(((static_cast<u64>(px_h) * 65536ULL) / f.units_per_em) * kSS);
    const i32 origin_x_q16 = -static_cast<i32>(g.x_min) * scale + (1 << 16);
    const i32 ymax_q16 = static_cast<i32>(g.y_max) * scale + (1 << 16);

    g_edge_count = 0;
    WalkContour(g.points, 0, 3, scale, origin_x_q16, 0, ymax_q16, /*flip_y=*/true);

    for (u32 i = 0; i < sizeof(dst); ++i)
        dst[i] = 0;
    RasterizeEdgesIntoCoverage(dst, 32, 32);

    // Centre pixel should be fully inside the square -> alpha 255.
    const u8 center = dst[16 * 32 + 16];
    if (center < 250)
    {
        SerialWrite("[video/ttf-raster] selftest FAIL: center under-covered\n");
        return false;
    }
    // Far-corner pixel (30,30) is well outside the square's bbox
    // (which only spans pixels [0..26] after the +1px AA margin),
    // so coverage must be exactly zero.
    if (dst[30 * 32 + 30] != 0)
    {
        SerialWrite("[video/ttf-raster] selftest FAIL: far corner not zero\n");
        return false;
    }
    SerialWrite("[video/ttf-raster] selftest ok (32x32 square: centre alpha=ff, far-corner=00)\n");
    return true;
}

namespace
{

// Per-glyph scratch buffers for `TtfDrawString`. Bounded sizes —
// chrome glyphs are well under these caps. Plain globals (single-
// caller chrome paint path; see slice 4 thread-safety note).
constinit u8 g_glyph_cover[128 * 128]{}; // alpha bitmap up to 128 px
constinit TtfPoint g_glyph_pts[1024]{};
constinit u16 g_glyph_endpoints[64]{};

// Composite `cover` (one u8 per pixel, alpha 0..255) into the
// framebuffer at (`dx`, `dy`) using `fg` as the ink. Per-pixel
// src-over via the existing `FramebufferBlendFill` (1×1 rect).
// Slow but correct; chrome paint paths can afford it. For larger
// glyph counts a blit-coverage primitive in framebuffer.cpp would
// be the optimisation hook (slice 4.1+).
void CompositeCoverage(i32 dx, i32 dy, const u8* cover, u32 w, u32 h, u32 fg)
{
    const u32 fg_rgb = fg & 0x00FFFFFFu;
    for (u32 cy = 0; cy < h; ++cy)
    {
        const i32 oy = dy + static_cast<i32>(cy);
        if (oy < 0)
            continue;
        for (u32 cx = 0; cx < w; ++cx)
        {
            const u8 a = cover[cy * w + cx];
            if (a == 0)
                continue;
            const i32 ox = dx + static_cast<i32>(cx);
            if (ox < 0)
                continue;
            const u32 argb = (static_cast<u32>(a) << 24) | fg_rgb;
            FramebufferBlendFill(static_cast<u32>(ox), static_cast<u32>(oy), 1, 1, argb);
        }
    }
}

} // namespace

bool TtfDrawString(u32 x, u32 y, const char* text, u32 fg, u32 pixel_height)
{
    if (text == nullptr || pixel_height == 0)
        return false;
    const TtfFont* font = TtfChromeFontGet();
    if (font == nullptr)
        return false;

    i32 pen_x = static_cast<i32>(x);
    const i32 baseline_y = static_cast<i32>(y) + static_cast<i32>(pixel_height);
    while (*text != '\0')
    {
        TtfRenderedGlyph rg{};
        const u32 cp = static_cast<u32>(static_cast<u8>(*text));
        const bool ok = TtfRenderGlyph(*font, cp, pixel_height, g_glyph_cover, sizeof(g_glyph_cover), g_glyph_pts,
                                       sizeof(g_glyph_pts) / sizeof(g_glyph_pts[0]), g_glyph_endpoints,
                                       sizeof(g_glyph_endpoints) / sizeof(g_glyph_endpoints[0]), &rg);
        if (!ok)
        {
            // Skip on render failure; advance an em-width so layout
            // stays roughly stable for the rest of the line.
            pen_x += static_cast<i32>(pixel_height);
            ++text;
            continue;
        }
        if (rg.width != 0 && rg.height != 0)
        {
            CompositeCoverage(pen_x, baseline_y - rg.ascent, rg.pixels, rg.width, rg.height, fg);
        }
        pen_x += static_cast<i32>(rg.advance);
        ++text;
    }
    return true;
}

} // namespace duetos::drivers::video
