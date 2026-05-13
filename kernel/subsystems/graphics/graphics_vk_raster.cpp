#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_internal.h"

#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"

/*
 * DuetOS — Vulkan ICD software triangle rasterizer.
 *
 * Closes the v0 "vkCmdDraw produces no pixels" gap for callers that
 * fill their vertex buffer with the DuetOS v0 vertex format and
 * draw against a scanout-backed render target. No SPIR-V execution,
 * no transform: vertex positions are already in pixel-space.
 *
 * Vertex format (8 bytes, packed):
 *   bytes 0-1  i16 x_px  — signed framebuffer pixel x
 *   bytes 2-3  i16 y_px  — signed framebuffer pixel y
 *   bytes 4-7  u32 argb  — 0xAARRGGBB; the low 24 bits go to the
 *                          framebuffer (A is recorded for the
 *                          counter only — v0 doesn't blend).
 *
 * Three consecutive vertices form one triangle (TriangleList; no
 * indexed draw, no strip topology — vkCmdBindIndexBuffer + Draw is
 * recorded but the rasterizer does not consume the index buffer
 * yet). Each triangle is flat-shaded with the colour of its first
 * vertex.
 *
 * Algorithm: integer edge-function (barycentric) test over the
 * triangle's bounding box. Pixels with the same sign on all three
 * edge functions are inside; the FramebufferPutPixel path takes
 * care of clipping against the surface bounds and bumping the
 * damage rect for the next present.
 *
 * The rasterizer is invoked from `ReplayCommandBuffer` only when:
 *   - the current bound graphics pipeline + vertex buffer are
 *     valid,
 *   - the bound vertex buffer is host-visible (backing != null),
 *   - the current render-target image is scanout-backed (the same
 *     gate that already allows `vkCmdClearColorImage` to paint).
 *
 * When the gates don't hold, the per-draw triangle counter still
 * advances so the dispatch chain is observable in the self-test
 * (otherwise a non-scanout test couldn't tell whether `Draw` was
 * even reached).
 */

namespace duetos::subsystems::graphics::internal
{

namespace
{

struct VertexV0
{
    i16 x_px;
    i16 y_px;
    u32 argb;
};

inline u32 ArgbToFramebufferRgb(u32 argb)
{
    return argb & 0x00FFFFFFu; // strip alpha; framebuffer is 0x00RRGGBB
}

// 2D cross product (signed area * 2) for the triangle (a, b, c).
// Returns positive when (a, b, c) is counter-clockwise on screen
// (remember the framebuffer is Y-down, so on-screen CCW reads as
// CW in screen space — the sign just has to be consistent across
// the three edge functions, which it is).
inline i64 EdgeFn(i32 ax, i32 ay, i32 bx, i32 by, i32 cx, i32 cy)
{
    const i64 dx1 = static_cast<i64>(bx) - ax;
    const i64 dy1 = static_cast<i64>(by) - ay;
    const i64 dx2 = static_cast<i64>(cx) - ax;
    const i64 dy2 = static_cast<i64>(cy) - ay;
    return dx1 * dy2 - dy1 * dx2;
}

inline i32 Min3(i32 a, i32 b, i32 c)
{
    i32 m = a < b ? a : b;
    return m < c ? m : c;
}
inline i32 Max3(i32 a, i32 b, i32 c)
{
    i32 m = a > b ? a : b;
    return m > c ? m : c;
}

void RasterizeOne(const VertexV0& v0, const VertexV0& v1, const VertexV0& v2, u32 fb_w, u32 fb_h, u32 rt_w, u32 rt_h)
{
    // Clip the per-triangle bounding box to the smaller of the
    // render target and the live framebuffer. The render target
    // extent is the spec-shaped clip; the framebuffer is the
    // physical surface backing it for scanout-backed images.
    const i32 surface_w = static_cast<i32>(rt_w < fb_w ? rt_w : fb_w);
    const i32 surface_h = static_cast<i32>(rt_h < fb_h ? rt_h : fb_h);
    if (surface_w <= 0 || surface_h <= 0)
        return;

    const i32 x0 = v0.x_px, y0 = v0.y_px;
    const i32 x1 = v1.x_px, y1 = v1.y_px;
    const i32 x2 = v2.x_px, y2 = v2.y_px;

    i32 min_x = Min3(x0, x1, x2);
    i32 min_y = Min3(y0, y1, y2);
    i32 max_x = Max3(x0, x1, x2);
    i32 max_y = Max3(y0, y1, y2);
    if (min_x < 0)
        min_x = 0;
    if (min_y < 0)
        min_y = 0;
    if (max_x >= surface_w)
        max_x = surface_w - 1;
    if (max_y >= surface_h)
        max_y = surface_h - 1;
    if (min_x > max_x || min_y > max_y)
        return; // entirely off-surface

    // Degenerate (collinear / zero-area) triangle: skip the
    // bounding-box walk so we don't burn pixels on a sliver that
    // can't even pass the edge tests consistently.
    const i64 area2 = EdgeFn(x0, y0, x1, y1, x2, y2);
    if (area2 == 0)
        return;

    const u32 fill = ArgbToFramebufferRgb(v0.argb);

    // Walk pixels; an inside pixel has the SAME sign on all three
    // edge functions relative to the triangle's signed area. We
    // include edges (>= 0) so two adjacent triangles sharing an
    // edge both paint along the seam; v0 doesn't care about top-
    // left fill rules.
    const bool ccw = area2 > 0;
    for (i32 py = min_y; py <= max_y; ++py)
    {
        for (i32 px = min_x; px <= max_x; ++px)
        {
            const i64 e0 = EdgeFn(x1, y1, x2, y2, px, py);
            const i64 e1 = EdgeFn(x2, y2, x0, y0, px, py);
            const i64 e2 = EdgeFn(x0, y0, x1, y1, px, py);
            const bool inside = ccw ? (e0 >= 0 && e1 >= 0 && e2 >= 0) : (e0 <= 0 && e1 <= 0 && e2 <= 0);
            if (!inside)
                continue;
            drivers::video::FramebufferPutPixel(static_cast<u32>(px), static_cast<u32>(py), fill);
        }
    }
    drivers::video::FramebufferAddDamage(static_cast<u32>(min_x), static_cast<u32>(min_y),
                                         static_cast<u32>(max_x - min_x + 1), static_cast<u32>(max_y - min_y + 1));
}

} // namespace

// Replay-time entry point. Called from ReplayCommandBuffer when a
// Draw opcode is reached with valid bound state. `vertex_count`
// MUST be a multiple of 3 — extra vertices are ignored. `rt_image`
// is the render-target image handle (looked up by the caller from
// the most recent BeginRenderPass / BeginRendering / ClearColorImage
// in the cb tape). `vertex_buffer` is the bound vertex buffer for
// binding 0; `vb_offset` is the byte offset into its backing store.
//
// The function always bumps `g_triangles_drawn` for every full
// triangle in the draw — even when the render target isn't scanout-
// backed — so the self-test can observe the dispatch chain on a
// non-scanout target without painting the boot console.
void RasterizeDuetTriangles(VkImage rt_image, VkBuffer vertex_buffer, u64 vb_offset, u32 first_vertex, u32 vertex_count)
{
    if (vertex_count < 3)
        return;
    const u32 tri_count = vertex_count / 3u;
    g_triangles_drawn += tri_count;

    // Resolve the vertex buffer's backing memory. If the buffer
    // isn't host-visible (no backing), we counted the triangles
    // but can't paint them — there's no shader to fetch attributes
    // from a device-local buffer.
    if (!HandleInRange(vertex_buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(vertex_buffer, kBufferBase)))
        return;
    const auto& vb = g_buffer_data[SlotOf(vertex_buffer, kBufferBase)];
    if (vb.backing == nullptr)
        return;

    // Render-target gate: only scanout-backed images get pixels.
    if (!HandleInRange(rt_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(rt_image, kImageBase)))
        return;
    const auto& img = g_image_data[SlotOf(rt_image, kImageBase)];
    if ((img.flags & kImageScanoutBacked) == 0u)
        return;

    const auto di = drivers::video::Query();
    if (!di.available)
        return;

    constexpr u64 kStride = sizeof(VertexV0);
    const u64 first_byte = vb_offset + static_cast<u64>(first_vertex) * kStride;
    const u64 needed = static_cast<u64>(vertex_count) * kStride;
    if (first_byte + needed > vb.size)
        return; // would over-read the buffer

    const auto* base = static_cast<const u8*>(vb.backing) + first_byte;
    // The buffer's backing came from kheap (u64 alignment) and
    // VertexV0 needs 4-byte alignment for its u32 colour field.
    // Refuse a non-aligned offset rather than emit an unaligned
    // read that UBSAN would flag.
    if ((reinterpret_cast<uptr>(base) & 3u) != 0u)
        return;

    for (u32 t = 0; t < tri_count; ++t)
    {
        VertexV0 verts[3];
        const u8* tri_base = base + static_cast<u64>(t) * 3u * kStride;
        for (u32 v = 0; v < 3; ++v)
        {
            const u8* vp = tri_base + static_cast<u64>(v) * kStride;
            // Byte-wise copy keeps us aligned-safe even when the
            // base happened to land at a 2-byte boundary (the
            // alignment gate above guarantees 4-byte alignment so
            // the u32 colour is fine; the i16 fields are always
            // safe).
            i16 x = static_cast<i16>(static_cast<u16>(vp[0]) | (static_cast<u16>(vp[1]) << 8));
            i16 y = static_cast<i16>(static_cast<u16>(vp[2]) | (static_cast<u16>(vp[3]) << 8));
            u32 c = static_cast<u32>(vp[4]) | (static_cast<u32>(vp[5]) << 8) | (static_cast<u32>(vp[6]) << 16) |
                    (static_cast<u32>(vp[7]) << 24);
            verts[v].x_px = x;
            verts[v].y_px = y;
            verts[v].argb = c;
        }
        RasterizeOne(verts[0], verts[1], verts[2], di.width, di.height, img.extent.width, img.extent.height);
    }
}

} // namespace duetos::subsystems::graphics::internal
