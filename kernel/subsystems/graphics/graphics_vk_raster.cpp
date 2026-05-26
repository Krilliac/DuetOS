#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_internal.h"

#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"

/*
 * DuetOS — Vulkan ICD software rasterizer.
 *
 * What this paints (v1.1):
 *   - Triangles, lines, and points emitted by `vkCmdDraw` and
 *     `vkCmdDrawIndexed` against a scanout-backed render target.
 *   - Topologies: PointList (0), LineList (1), LineStrip (2),
 *     TriangleList (3), TriangleStrip (4), TriangleFan (5).
 *   - Per-vertex colour interpolation (Gouraud shading) for
 *     triangles via integer barycentric weights. Lines and
 *     points are flat-shaded with the first vertex's colour.
 *   - Per-pixel alpha when the interpolated alpha is < 0xFF —
 *     blended through `FramebufferBlendPixel` (src-over).
 *   - Scissor enforcement when the most-recent
 *     `vkCmdSetScissor` recorded a non-empty rect.
 *   - Front-face culling: `vkCmdSetCullMode` +
 *     `vkCmdSetFrontFace` drop triangles whose screen-space
 *     orientation matches the cull selection before bbox walk.
 *   - Software 16-bit depth buffer when the vertex format is
 *     v1 and `vkCmdSetDepthTestEnable` is on; Z is
 *     interpolated barycentrically and compared per
 *     `vkCmdSetDepthCompareOp`.
 *
 * Vertex formats (selected by `vkCmdSetVertexFormatDuet`):
 *   v0 (default, 8 bytes): `{i16 x_px; i16 y_px; u32 argb;}`
 *   v1 (12 bytes):         `{i16 x_px; i16 y_px; i16 z;
 *                            u16 _reserved; u32 argb;}`
 *   `argb` is 0xAARRGGBB; the high byte drives alpha blending.
 *
 * Indexed draws read indices from the buffer bound by
 * `vkCmdBindIndexBuffer` (UINT16 or UINT32) and offset each by
 * the draw's `vertex_offset` before vertex-buffer lookup.
 *
 * `vk_triangles_drawn` ticks per dispatched triangle regardless
 * of whether pixels reach the framebuffer (counter bumps before
 * resource resolution / scanout gate). Points and lines do not
 * tick the triangle counter.
 *
 * Out of scope today:
 *   - Texture sampling (no descriptor set fetch path).
 *   - Multi-binding vertex buffers (only binding 0 is read).
 *   - Perspective-correct interpolation (rasterizer is affine).
 *   - Wide / textured lines.
 */

namespace duetos::subsystems::graphics::internal
{

namespace
{

struct VertexV0
{
    i16 x_px;
    i16 y_px;
    i32 z_raw; // [-32768, 32767]; 0 for v0 (no depth)
    u32 argb;
};

// Vulkan spec values for VkPrimitiveTopology.
inline constexpr u32 kTopologyPointList = 0;
inline constexpr u32 kTopologyLineList = 1;
inline constexpr u32 kTopologyLineStrip = 2;
inline constexpr u32 kTopologyTriangleList = 3;
inline constexpr u32 kTopologyTriangleStrip = 4;
inline constexpr u32 kTopologyTriangleFan = 5;

// Vulkan spec values for VkCullModeFlagBits / VkFrontFace.
inline constexpr u32 kCullNone = 0;
inline constexpr u32 kCullFront = 1;
inline constexpr u32 kCullBack = 2;
inline constexpr u32 kCullBoth = 3;
inline constexpr u32 kFrontFaceCounterClockwise = 0;

// Vulkan spec VkCompareOp.
inline constexpr u32 kCompareNever = 0;
inline constexpr u32 kCompareLess = 1;
inline constexpr u32 kCompareEqual = 2;
inline constexpr u32 kCompareLessOrEqual = 3;
inline constexpr u32 kCompareGreater = 4;
inline constexpr u32 kCompareNotEqual = 5;
inline constexpr u32 kCompareGreaterOrEqual = 6;
inline constexpr u32 kCompareAlways = 7;

inline constexpr u64 kStrideV0 = 8;
inline constexpr u64 kStrideV1 = 12;

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

inline u32 LerpChannel(u32 c0, u32 c1, u32 c2, u64 w0, u64 w1, u64 w2, u64 sum)
{
    // Integer barycentric interp: the three weights are the
    // unsigned edge magnitudes opposite each vertex; their sum
    // equals the unsigned triangle area * 2. /(sum) yields the
    // correctly-rounded channel value.
    if (sum == 0)
        return c0;
    const u64 acc = w0 * c0 + w1 * c1 + w2 * c2 + (sum / 2u);
    const u64 v = acc / sum;
    return static_cast<u32>(v > 0xFFu ? 0xFFu : v);
}

// Read a v0 or v1 vertex from a host-visible vertex buffer at the
// given vertex slot. Returns false when the slot is out of range;
// the caller drops the triangle in that case. v1 layout adds an
// i16 Z and 2 bytes of reserved padding between x/y and argb.
bool FetchVertex(const u8* vb_base, u64 vb_size, u64 vertex_index, u32 vertex_format, VertexV0& out)
{
    const u64 stride = (vertex_format == 1) ? kStrideV1 : kStrideV0;
    const u64 byte_off = vertex_index * stride;
    if (byte_off + stride > vb_size)
        return false;
    const u8* vp = vb_base + byte_off;
    out.x_px = static_cast<i16>(static_cast<u16>(vp[0]) | (static_cast<u16>(vp[1]) << 8));
    out.y_px = static_cast<i16>(static_cast<u16>(vp[2]) | (static_cast<u16>(vp[3]) << 8));
    if (vertex_format == 1)
    {
        out.z_raw = static_cast<i16>(static_cast<u16>(vp[4]) | (static_cast<u16>(vp[5]) << 8));
        // bytes 6..7 reserved, ignored
        out.argb = static_cast<u32>(vp[8]) | (static_cast<u32>(vp[9]) << 8) | (static_cast<u32>(vp[10]) << 16) |
                   (static_cast<u32>(vp[11]) << 24);
    }
    else
    {
        out.z_raw = 0;
        out.argb = static_cast<u32>(vp[4]) | (static_cast<u32>(vp[5]) << 8) | (static_cast<u32>(vp[6]) << 16) |
                   (static_cast<u32>(vp[7]) << 24);
    }
    return true;
}

// Map signed i16 depth (z_raw in [-32768, 32767]) to a u16 unorm
// depth value where 0 = nearest and 65535 = farthest. The map is
// `unorm = z_raw + 32768`, which preserves ordering (smaller
// z_raw = smaller unorm = closer).
inline u32 EncodeDepthU16(i32 z_raw)
{
    const i32 v = z_raw + 32768;
    return static_cast<u32>(v < 0 ? 0 : (v > 0xFFFF ? 0xFFFF : v));
}

// Depth compare per VkCompareOp spec values.
inline bool DepthCompare(u32 src, u32 dst, u32 op)
{
    switch (op)
    {
    case kCompareNever:
        return false;
    case kCompareLess:
        return src < dst;
    case kCompareEqual:
        return src == dst;
    case kCompareLessOrEqual:
        return src <= dst;
    case kCompareGreater:
        return src > dst;
    case kCompareNotEqual:
        return src != dst;
    case kCompareGreaterOrEqual:
        return src >= dst;
    case kCompareAlways:
    default:
        return true;
    }
}

struct ClippedBBox
{
    i32 min_x;
    i32 min_y;
    i32 max_x;
    i32 max_y;
    bool empty;
};

ClippedBBox ComputeClippedBBox(i32 x0, i32 y0, i32 x1, i32 y1, i32 x2, i32 y2, const RasterState& st, u32 rt_w,
                               u32 rt_h)
{
    const i32 surface_w = static_cast<i32>(rt_w < st.fb_w ? rt_w : st.fb_w);
    const i32 surface_h = static_cast<i32>(rt_h < st.fb_h ? rt_h : st.fb_h);
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
    if (st.has_scissor)
    {
        const i32 sx0 = st.scissor.offset.x;
        const i32 sy0 = st.scissor.offset.y;
        const i32 sx1 = sx0 + static_cast<i32>(st.scissor.extent.width);
        const i32 sy1 = sy0 + static_cast<i32>(st.scissor.extent.height);
        if (sx0 > min_x)
            min_x = sx0;
        if (sy0 > min_y)
            min_y = sy0;
        if (sx1 - 1 < max_x)
            max_x = sx1 - 1;
        if (sy1 - 1 < max_y)
            max_y = sy1 - 1;
    }
    return ClippedBBox{min_x, min_y, max_x, max_y, (min_x > max_x || min_y > max_y)};
}

// Paint a single Vulkan-Point at the vertex's pixel using the
// vertex colour. Honours scissor and the rasterizer's per-pixel
// alpha path. Bumps the damage rect.
void RasterizePoint(const VertexV0& v, const RasterState& st, u32 rt_w, u32 rt_h)
{
    if (rt_w == 0 || rt_h == 0 || st.fb_w == 0 || st.fb_h == 0)
        return;
    const i32 surface_w = static_cast<i32>(rt_w < st.fb_w ? rt_w : st.fb_w);
    const i32 surface_h = static_cast<i32>(rt_h < st.fb_h ? rt_h : st.fb_h);
    const i32 px = v.x_px;
    const i32 py = v.y_px;
    if (px < 0 || py < 0 || px >= surface_w || py >= surface_h)
        return;
    if (st.has_scissor)
    {
        const i32 sx0 = st.scissor.offset.x;
        const i32 sy0 = st.scissor.offset.y;
        const i32 sx1 = sx0 + static_cast<i32>(st.scissor.extent.width);
        const i32 sy1 = sy0 + static_cast<i32>(st.scissor.extent.height);
        if (px < sx0 || py < sy0 || px >= sx1 || py >= sy1)
            return;
    }
    const u32 a = (v.argb >> 24) & 0xFFu;
    const u32 rgb = v.argb & 0x00FFFFFFu;
    if (a == 0xFFu)
        drivers::video::FramebufferPutPixel(static_cast<u32>(px), static_cast<u32>(py), rgb);
    else if (a > 0)
        drivers::video::FramebufferBlendPixel(static_cast<u32>(px), static_cast<u32>(py), v.argb);
    drivers::video::FramebufferAddDamage(static_cast<u32>(px), static_cast<u32>(py), 1, 1);
}

// Paint a line from v0 to v1 using DDA / Bresenham at 1-pixel
// thickness. Honours scissor; flat-shaded with v0's colour
// (line endpoint interpolation isn't needed for v0). Each plotted
// pixel goes through the alpha-aware writer like points do.
void RasterizeLine(const VertexV0& v0, const VertexV0& v1, const RasterState& st, u32 rt_w, u32 rt_h)
{
    if (rt_w == 0 || rt_h == 0 || st.fb_w == 0 || st.fb_h == 0)
        return;
    const i32 surface_w = static_cast<i32>(rt_w < st.fb_w ? rt_w : st.fb_w);
    const i32 surface_h = static_cast<i32>(rt_h < st.fb_h ? rt_h : st.fb_h);
    i32 sx0 = 0, sy0 = 0, sx1 = surface_w, sy1 = surface_h;
    if (st.has_scissor)
    {
        sx0 = st.scissor.offset.x;
        sy0 = st.scissor.offset.y;
        sx1 = sx0 + static_cast<i32>(st.scissor.extent.width);
        sy1 = sy0 + static_cast<i32>(st.scissor.extent.height);
        if (sx0 < 0)
            sx0 = 0;
        if (sy0 < 0)
            sy0 = 0;
        if (sx1 > surface_w)
            sx1 = surface_w;
        if (sy1 > surface_h)
            sy1 = surface_h;
    }
    i32 x0 = v0.x_px, y0 = v0.y_px;
    i32 x1 = v1.x_px, y1 = v1.y_px;
    i32 dx = x1 - x0;
    if (dx < 0)
        dx = -dx;
    i32 dy = y1 - y0;
    if (dy < 0)
        dy = -dy;
    const i32 step_x = (x0 < x1) ? 1 : -1;
    const i32 step_y = (y0 < y1) ? 1 : -1;
    i32 err = dx - dy;
    const i32 max_steps = dx + dy + 4; // safety bound — bounded by surface extent in the worst case
    const u32 a = (v0.argb >> 24) & 0xFFu;
    const u32 rgb = v0.argb & 0x00FFFFFFu;
    for (i32 step = 0; step < max_steps; ++step)
    {
        if (x0 >= sx0 && y0 >= sy0 && x0 < sx1 && y0 < sy1)
        {
            if (a == 0xFFu)
                drivers::video::FramebufferPutPixel(static_cast<u32>(x0), static_cast<u32>(y0), rgb);
            else if (a > 0)
                drivers::video::FramebufferBlendPixel(static_cast<u32>(x0), static_cast<u32>(y0), v0.argb);
        }
        if (x0 == x1 && y0 == y1)
            break;
        const i32 e2 = err << 1;
        if (e2 > -dy)
        {
            err -= dy;
            x0 += step_x;
        }
        if (e2 < dx)
        {
            err += dx;
            y0 += step_y;
        }
    }
    // Crude damage rect — bounding box of endpoints clipped to scissor.
    i32 min_x = v0.x_px < v1.x_px ? v0.x_px : v1.x_px;
    i32 max_x = v0.x_px < v1.x_px ? v1.x_px : v0.x_px;
    i32 min_y = v0.y_px < v1.y_px ? v0.y_px : v1.y_px;
    i32 max_y = v0.y_px < v1.y_px ? v1.y_px : v0.y_px;
    if (min_x < sx0)
        min_x = sx0;
    if (min_y < sy0)
        min_y = sy0;
    if (max_x >= sx1)
        max_x = sx1 - 1;
    if (max_y >= sy1)
        max_y = sy1 - 1;
    if (min_x <= max_x && min_y <= max_y)
        drivers::video::FramebufferAddDamage(static_cast<u32>(min_x), static_cast<u32>(min_y),
                                             static_cast<u32>(max_x - min_x + 1), static_cast<u32>(max_y - min_y + 1));
}

// Decide whether a triangle is culled by the current CullMode +
// FrontFace state. Returns true when the triangle should be
// dropped.
bool TriangleCulled(i64 area2, const RasterState& st)
{
    if (st.cull_mode == kCullNone)
        return false;
    if (st.cull_mode == kCullBoth)
        return true;
    // Sign of `area2` decides screen-space orientation:
    //   area2 > 0  -> the (v0, v1, v2) order is CCW in framebuffer
    //                 coordinates (Y-down).
    //   area2 < 0  -> CW.
    // VkFrontFace::CounterClockwise (0): CCW is front.
    // VkFrontFace::Clockwise (1): CW is front.
    const bool ccw = area2 > 0;
    const bool front_is_ccw = (st.front_face == kFrontFaceCounterClockwise);
    const bool is_front = (ccw == front_is_ccw);
    if (st.cull_mode == kCullFront)
        return is_front;
    if (st.cull_mode == kCullBack)
        return !is_front;
    return false;
}

void RasterizeOne(const VertexV0& v0, const VertexV0& v1, const VertexV0& v2, const RasterState& st, u32 rt_w, u32 rt_h)
{
    if (rt_w == 0 || rt_h == 0 || st.fb_w == 0 || st.fb_h == 0)
        return;

    const i32 x0 = v0.x_px, y0 = v0.y_px;
    const i32 x1 = v1.x_px, y1 = v1.y_px;
    const i32 x2 = v2.x_px, y2 = v2.y_px;

    const ClippedBBox bb = ComputeClippedBBox(x0, y0, x1, y1, x2, y2, st, rt_w, rt_h);
    if (bb.empty)
        return;

    const i64 area2 = EdgeFn(x0, y0, x1, y1, x2, y2);
    if (area2 == 0)
        return;
    if (TriangleCulled(area2, st))
        return;
    const bool ccw = area2 > 0;
    const u64 area_abs = static_cast<u64>(ccw ? area2 : -area2);

    // Per-vertex channels — extracted once outside the inner loop.
    const u32 v0_r = (v0.argb >> 16) & 0xFFu;
    const u32 v0_g = (v0.argb >> 8) & 0xFFu;
    const u32 v0_b = v0.argb & 0xFFu;
    const u32 v0_a = (v0.argb >> 24) & 0xFFu;
    const u32 v1_r = (v1.argb >> 16) & 0xFFu;
    const u32 v1_g = (v1.argb >> 8) & 0xFFu;
    const u32 v1_b = v1.argb & 0xFFu;
    const u32 v1_a = (v1.argb >> 24) & 0xFFu;
    const u32 v2_r = (v2.argb >> 16) & 0xFFu;
    const u32 v2_g = (v2.argb >> 8) & 0xFFu;
    const u32 v2_b = v2.argb & 0xFFu;
    const u32 v2_a = (v2.argb >> 24) & 0xFFu;

    // Depth test setup. Only honoured when the vertex format
    // carries Z (v1) AND depth-test is enabled AND the depth
    // surface can be allocated. Otherwise the rasterizer paints
    // without sampling Z.
    const bool depth_active = st.depth_test && st.vertex_format == 1;
    DepthSurface* dsurf = depth_active ? DepthSurfaceGetOrAlloc() : nullptr;
    const bool depth_enabled = dsurf != nullptr;
    const u32 v0_z = depth_enabled ? EncodeDepthU16(v0.z_raw) : 0;
    const u32 v1_z = depth_enabled ? EncodeDepthU16(v1.z_raw) : 0;
    const u32 v2_z = depth_enabled ? EncodeDepthU16(v2.z_raw) : 0;
    const u32 depth_op = (st.depth_compare == 0u && !depth_enabled) ? kCompareAlways : st.depth_compare;
    const bool depth_write = st.depth_write;

    // Flat-shade fast path: all three vertex colours identical.
    // Skip the barycentric divide in the inner loop.
    const bool flat = (v0.argb == v1.argb) && (v1.argb == v2.argb);
    const u32 flat_argb = v0.argb;

    for (i32 py = bb.min_y; py <= bb.max_y; ++py)
    {
        for (i32 px = bb.min_x; px <= bb.max_x; ++px)
        {
            // Edge functions at this pixel — barycentric weights
            // are |e0| (opposite v0), |e1| (opposite v1), |e2|
            // (opposite v2).
            const i64 e0 = EdgeFn(x1, y1, x2, y2, px, py);
            const i64 e1 = EdgeFn(x2, y2, x0, y0, px, py);
            const i64 e2 = EdgeFn(x0, y0, x1, y1, px, py);
            const bool inside = ccw ? (e0 >= 0 && e1 >= 0 && e2 >= 0) : (e0 <= 0 && e1 <= 0 && e2 <= 0);
            if (!inside)
                continue;
            const u64 w0 = static_cast<u64>(ccw ? e0 : -e0);
            const u64 w1 = static_cast<u64>(ccw ? e1 : -e1);
            const u64 w2 = static_cast<u64>(ccw ? e2 : -e2);
            // Depth test (when active): interpolate Z, compare,
            // optionally write back. The depth surface is sized
            // to the framebuffer so the bbox clip above
            // guarantees the index is in range.
            if (depth_enabled)
            {
                const u64 z_acc = w0 * v0_z + w1 * v1_z + w2 * v2_z + (area_abs / 2u);
                const u32 z_pix = static_cast<u32>(z_acc / area_abs);
                const u32 idx = static_cast<u32>(py) * dsurf->w + static_cast<u32>(px);
                const u32 dst_z = dsurf->data[idx];
                if (!DepthCompare(z_pix, dst_z, depth_op))
                    continue;
                if (depth_write)
                    dsurf->data[idx] = static_cast<u16>(z_pix);
            }
            if (flat)
            {
                if (((flat_argb >> 24) & 0xFFu) == 0xFFu)
                    drivers::video::FramebufferPutPixel(static_cast<u32>(px), static_cast<u32>(py),
                                                        flat_argb & 0x00FFFFFFu);
                else
                    drivers::video::FramebufferBlendPixel(static_cast<u32>(px), static_cast<u32>(py), flat_argb);
                continue;
            }
            const u32 r = LerpChannel(v0_r, v1_r, v2_r, w0, w1, w2, area_abs);
            const u32 g = LerpChannel(v0_g, v1_g, v2_g, w0, w1, w2, area_abs);
            const u32 b = LerpChannel(v0_b, v1_b, v2_b, w0, w1, w2, area_abs);
            const u32 a = LerpChannel(v0_a, v1_a, v2_a, w0, w1, w2, area_abs);
            if (a == 0xFFu)
                drivers::video::FramebufferPutPixel(static_cast<u32>(px), static_cast<u32>(py),
                                                    (r << 16) | (g << 8) | b);
            else if (a > 0)
                drivers::video::FramebufferBlendPixel(static_cast<u32>(px), static_cast<u32>(py),
                                                      (a << 24) | (r << 16) | (g << 8) | b);
        }
    }
    drivers::video::FramebufferAddDamage(static_cast<u32>(bb.min_x), static_cast<u32>(bb.min_y),
                                         static_cast<u32>(bb.max_x - bb.min_x + 1),
                                         static_cast<u32>(bb.max_y - bb.min_y + 1));
}

// Fetch one index from the bound index buffer. Returns the 32-bit
// upgraded value (UINT16 indices are zero-extended). On any
// out-of-range or bad-type, returns false and the caller drops the
// triangle.
bool FetchIndex(const RasterState& st, u32 index_pos, u32& out)
{
    if (!st.has_index_buffer)
        return false;
    if (!HandleInRange(st.index_buffer, kBufferBase) ||
        !PoolIsLive(g_buffer_pool, SlotOf(st.index_buffer, kBufferBase)))
        return false;
    const auto& ib = g_buffer_data[SlotOf(st.index_buffer, kBufferBase)];
    if (ib.backing == nullptr)
        return false;
    const u8* base = static_cast<const u8*>(ib.backing) + st.index_offset;
    const u64 stride = (st.index_type == VkIndexType::Uint32) ? 4u : 2u;
    const u64 byte_off = static_cast<u64>(index_pos) * stride;
    if (st.index_offset + byte_off + stride > ib.size)
        return false;
    if (stride == 2u)
    {
        out = static_cast<u32>(base[byte_off]) | (static_cast<u32>(base[byte_off + 1]) << 8);
    }
    else
    {
        const u8* p = base + byte_off;
        out = static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
              (static_cast<u32>(p[3]) << 24);
    }
    return true;
}

bool ResolveRenderTarget(const RasterState& st, u32& rt_w_out, u32& rt_h_out)
{
    if (!HandleInRange(st.rt_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(st.rt_image, kImageBase)))
        return false;
    const auto& img = g_image_data[SlotOf(st.rt_image, kImageBase)];
    if ((img.flags & kImageScanoutBacked) == 0u)
        return false;
    rt_w_out = img.extent.width;
    rt_h_out = img.extent.height;
    return true;
}

bool ResolveVertexBuffer(const RasterState& st, const u8*& base_out, u64& size_out)
{
    if (!HandleInRange(st.vertex_buffer, kBufferBase) ||
        !PoolIsLive(g_buffer_pool, SlotOf(st.vertex_buffer, kBufferBase)))
        return false;
    const auto& vb = g_buffer_data[SlotOf(st.vertex_buffer, kBufferBase)];
    if (vb.backing == nullptr)
        return false;
    if (st.vertex_offset > vb.size)
        return false;
    const u8* base = static_cast<const u8*>(vb.backing) + st.vertex_offset;
    // 4-byte alignment for the u32 argb field. Refuse rather than
    // emit an unaligned load.
    if ((reinterpret_cast<uptr>(base) & 3u) != 0u)
        return false;
    base_out = base;
    size_out = vb.size - st.vertex_offset;
    return true;
}

} // namespace

void RasterizeDuetDraw(const RasterState& st, u32 first_vertex, u32 vertex_count)
{
    if (vertex_count == 0)
        return;

    // Triangle / line / point count from topology.
    u32 tri_count = 0;
    switch (st.topology)
    {
    case kTopologyPointList:
        tri_count = 0;
        break;
    case kTopologyLineList:
        if (vertex_count < 2)
            return;
        tri_count = 0;
        break;
    case kTopologyLineStrip:
        if (vertex_count < 2)
            return;
        tri_count = 0;
        break;
    case kTopologyTriangleList:
        if (vertex_count < 3)
            return;
        tri_count = vertex_count / 3u;
        break;
    case kTopologyTriangleStrip:
    case kTopologyTriangleFan:
        if (vertex_count < 3)
            return;
        tri_count = vertex_count - 2u;
        break;
    default:
        // Unsupported topology — record the dispatch but paint no
        // pixels. Counter stays at zero for this draw so a
        // wrong-topology slice is observable.
        return;
    }
    g_triangles_drawn += tri_count;

    u32 rt_w = 0, rt_h = 0;
    if (!ResolveRenderTarget(st, rt_w, rt_h))
        return;
    const u8* vb_base = nullptr;
    u64 vb_size = 0;
    if (!ResolveVertexBuffer(st, vb_base, vb_size))
        return;
    const auto di = drivers::video::Query();
    if (!di.available)
        return;

    auto fetch = [&](u32 logical_vertex_index, VertexV0& out)
    { return FetchVertex(vb_base, vb_size, logical_vertex_index, st.vertex_format, out); };

    // Point / line topologies bypass the triangle bbox walk and
    // paint one pixel / one Bresenham segment per primitive.
    if (st.topology == kTopologyPointList)
    {
        for (u32 i = 0; i < vertex_count; ++i)
        {
            VertexV0 v;
            if (!fetch(first_vertex + i, v))
                continue;
            RasterizePoint(v, st, rt_w, rt_h);
        }
        return;
    }
    if (st.topology == kTopologyLineList)
    {
        const u32 line_count = vertex_count / 2u;
        for (u32 i = 0; i < line_count; ++i)
        {
            VertexV0 a, b;
            if (!fetch(first_vertex + i * 2u, a) || !fetch(first_vertex + i * 2u + 1u, b))
                continue;
            RasterizeLine(a, b, st, rt_w, rt_h);
        }
        return;
    }
    if (st.topology == kTopologyLineStrip)
    {
        for (u32 i = 0; i + 1u < vertex_count; ++i)
        {
            VertexV0 a, b;
            if (!fetch(first_vertex + i, a) || !fetch(first_vertex + i + 1u, b))
                continue;
            RasterizeLine(a, b, st, rt_w, rt_h);
        }
        return;
    }

    for (u32 t = 0; t < tri_count; ++t)
    {
        VertexV0 verts[3] = {};
        switch (st.topology)
        {
        case kTopologyTriangleList:
        {
            const u32 base = first_vertex + t * 3u;
            if (!fetch(base + 0u, verts[0]) || !fetch(base + 1u, verts[1]) || !fetch(base + 2u, verts[2]))
                continue;
            break;
        }
        case kTopologyTriangleStrip:
        {
            // Every triangle shares two vertices with the previous;
            // odd-indexed triangles flip winding via index swap so
            // the visible winding stays consistent. v0's rasterizer
            // doesn't enforce winding (it paints both sides), so
            // the swap is here for spec accuracy and to keep the
            // gouraud weights consistent.
            const u32 base = first_vertex + t;
            if (!fetch(base + 0u, verts[0]) || !fetch(base + 1u, verts[1]) || !fetch(base + 2u, verts[2]))
                continue;
            if ((t & 1u) != 0u)
            {
                VertexV0 tmp = verts[1];
                verts[1] = verts[2];
                verts[2] = tmp;
            }
            break;
        }
        case kTopologyTriangleFan:
        {
            // Every triangle shares vertex 0 (the fan centre).
            if (!fetch(first_vertex + 0u, verts[0]) || !fetch(first_vertex + t + 1u, verts[1]) ||
                !fetch(first_vertex + t + 2u, verts[2]))
                continue;
            break;
        }
        default:
            continue;
        }
        RasterizeOne(verts[0], verts[1], verts[2], st, rt_w, rt_h);
    }
}

void RasterizeDuetDrawIndexed(const RasterState& st, u32 first_index, u32 index_count, i32 vertex_offset)
{
    if (index_count == 0)
        return;

    u32 tri_count = 0;
    switch (st.topology)
    {
    case kTopologyPointList:
    case kTopologyLineList:
    case kTopologyLineStrip:
        if (index_count < ((st.topology == kTopologyPointList) ? 1u : 2u))
            return;
        tri_count = 0;
        break;
    case kTopologyTriangleList:
        if (index_count < 3)
            return;
        tri_count = index_count / 3u;
        break;
    case kTopologyTriangleStrip:
    case kTopologyTriangleFan:
        if (index_count < 3)
            return;
        tri_count = index_count - 2u;
        break;
    default:
        return;
    }
    g_triangles_drawn += tri_count;

    u32 rt_w = 0, rt_h = 0;
    if (!ResolveRenderTarget(st, rt_w, rt_h))
        return;
    const u8* vb_base = nullptr;
    u64 vb_size = 0;
    if (!ResolveVertexBuffer(st, vb_base, vb_size))
        return;
    const auto di = drivers::video::Query();
    if (!di.available)
        return;

    auto fetch_vert_at_index = [&](u32 index_pos, VertexV0& out)
    {
        u32 idx = 0;
        if (!FetchIndex(st, index_pos, idx))
            return false;
        const i64 logical = static_cast<i64>(idx) + vertex_offset;
        if (logical < 0)
            return false;
        return FetchVertex(vb_base, vb_size, static_cast<u64>(logical), st.vertex_format, out);
    };

    if (st.topology == kTopologyPointList)
    {
        for (u32 i = 0; i < index_count; ++i)
        {
            VertexV0 v;
            if (!fetch_vert_at_index(first_index + i, v))
                continue;
            RasterizePoint(v, st, rt_w, rt_h);
        }
        return;
    }
    if (st.topology == kTopologyLineList)
    {
        const u32 line_count = index_count / 2u;
        for (u32 i = 0; i < line_count; ++i)
        {
            VertexV0 a, b;
            if (!fetch_vert_at_index(first_index + i * 2u, a) || !fetch_vert_at_index(first_index + i * 2u + 1u, b))
                continue;
            RasterizeLine(a, b, st, rt_w, rt_h);
        }
        return;
    }
    if (st.topology == kTopologyLineStrip)
    {
        for (u32 i = 0; i + 1u < index_count; ++i)
        {
            VertexV0 a, b;
            if (!fetch_vert_at_index(first_index + i, a) || !fetch_vert_at_index(first_index + i + 1u, b))
                continue;
            RasterizeLine(a, b, st, rt_w, rt_h);
        }
        return;
    }

    for (u32 t = 0; t < tri_count; ++t)
    {
        VertexV0 verts[3] = {};
        switch (st.topology)
        {
        case kTopologyTriangleList:
        {
            const u32 base = first_index + t * 3u;
            if (!fetch_vert_at_index(base + 0u, verts[0]) || !fetch_vert_at_index(base + 1u, verts[1]) ||
                !fetch_vert_at_index(base + 2u, verts[2]))
                continue;
            break;
        }
        case kTopologyTriangleStrip:
        {
            const u32 base = first_index + t;
            if (!fetch_vert_at_index(base + 0u, verts[0]) || !fetch_vert_at_index(base + 1u, verts[1]) ||
                !fetch_vert_at_index(base + 2u, verts[2]))
                continue;
            if ((t & 1u) != 0u)
            {
                VertexV0 tmp = verts[1];
                verts[1] = verts[2];
                verts[2] = tmp;
            }
            break;
        }
        case kTopologyTriangleFan:
        {
            if (!fetch_vert_at_index(first_index + 0u, verts[0]) ||
                !fetch_vert_at_index(first_index + t + 1u, verts[1]) ||
                !fetch_vert_at_index(first_index + t + 2u, verts[2]))
                continue;
            break;
        }
        default:
            continue;
        }
        RasterizeOne(verts[0], verts[1], verts[2], st, rt_w, rt_h);
    }
}

// Legacy entry point — keeps `graphics_vk.cpp`'s `Draw` op-dispatch
// from needing to know about RasterState directly. The replay
// walker fills `st` from its current bound state and calls into
// the new entry point.
void RasterizeDuetTriangles(VkImage rt_image, VkBuffer vertex_buffer, u64 vb_offset, u32 first_vertex, u32 vertex_count)
{
    RasterState st{};
    st.rt_image = rt_image;
    st.vertex_buffer = vertex_buffer;
    st.vertex_offset = vb_offset;
    st.topology = kTopologyTriangleList;
    const auto di = drivers::video::Query();
    if (di.available)
    {
        st.fb_w = di.width;
        st.fb_h = di.height;
    }
    RasterizeDuetDraw(st, first_vertex, vertex_count);
}

} // namespace duetos::subsystems::graphics::internal
