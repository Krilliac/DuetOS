#include "apps/gfxdemo_modes.h"

#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"
#include "subsystems/graphics/graphics.h"

/*
 * DuetOS — gfxdemo Vulkan-cube mode.
 *
 * Drives the in-kernel Vulkan ICD's software rasterizer through a
 * full draw call: indexed DrawIndexed with the v1 vertex format,
 * Gouraud-shaded per-vertex colours, depth test, and scissor
 * clipping to the gfxdemo window's client rect. Boring solid cube
 * scenes are the canonical 3D test pattern; this is the same.
 *
 * Resources are lazy-allocated on the first call and reused for
 * every subsequent frame — the per-frame work is just writing 8
 * fresh vertex slots and re-recording the command buffer. If any
 * Vulkan call fails during init the mode silently degrades to a
 * "Vulkan ICD unavailable" text panel; the rest of gfxdemo keeps
 * working.
 */

namespace duetos::apps::gfxdemo
{

namespace
{

namespace vk = duetos::subsystems::graphics;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;

constexpr duetos::u64 kVertexBufBytes = 4096; // host-visible; only first ~96 bytes used
constexpr duetos::u64 kIndexBufOffset = 2048; // index buffer lives in the second half
constexpr duetos::u32 kCubeVertexCount = 8;
constexpr duetos::u32 kCubeIndexCount = 36; // 12 triangles
constexpr duetos::u64 kVertexStride = 12;   // v1: i16 x, i16 y, i16 z, u16 _, u32 argb

// Cube indices — 12 triangles, 6 faces, two tris per face. Each
// face's two triangles share an edge so the winding is consistent.
constexpr duetos::u16 kCubeIndices[kCubeIndexCount] = {
    // Front (-Z)
    0,
    1,
    2,
    0,
    2,
    3,
    // Back (+Z)
    5,
    4,
    7,
    5,
    7,
    6,
    // Left (-X)
    4,
    0,
    3,
    4,
    3,
    7,
    // Right (+X)
    1,
    5,
    6,
    1,
    6,
    2,
    // Top (+Y)
    3,
    2,
    6,
    3,
    6,
    7,
    // Bottom (-Y)
    4,
    5,
    1,
    4,
    1,
    0,
};

// Per-vertex base colours. Rainbow rotation so the Gouraud
// interpolation reads visually.
constexpr duetos::u32 kVertexColours[kCubeVertexCount] = {
    0xFFFF0000u, // 0 red
    0xFF00FF00u, // 1 green
    0xFF0000FFu, // 2 blue
    0xFFFFFF00u, // 3 yellow
    0xFF00FFFFu, // 4 cyan
    0xFFFF00FFu, // 5 magenta
    0xFFFFFFFFu, // 6 white
    0xFFFF8000u, // 7 orange
};

// Unit-cube corner positions (-1..+1 in each axis).
constexpr duetos::i32 kCorners[kCubeVertexCount][3] = {
    {-1, -1, -1}, {+1, -1, -1}, {+1, +1, -1}, {-1, +1, -1}, {-1, -1, +1}, {+1, -1, +1}, {+1, +1, +1}, {-1, +1, +1},
};

struct VkState
{
    bool ready;
    bool init_failed;
    vk::VkInstance inst;
    vk::VkPhysicalDevice phys;
    vk::VkDevice dev;
    vk::VkQueue queue;
    vk::VkCommandPool pool;
    vk::VkCommandBuffer cb;
    vk::VkDeviceMemory mem;
    vk::VkBuffer vb;
    vk::VkBuffer ib;
    vk::VkImage img;          // scanout-backed; extent matches the live framebuffer
    vk::VkImageView img_view; // attached to a one-shot framebuffer for dynamic rendering
    void* mapped;             // covers both vb (offset 0) and ib (offset kIndexBufOffset)
};

VkState g_vk{};

bool VkOk(vk::VkResult r)
{
    return r == vk::VkResult::Success;
}

bool InitVulkan()
{
    if (g_vk.ready)
        return true;
    if (g_vk.init_failed)
        return false;

    const auto di = duetos::drivers::video::Query();
    if (!di.available || di.width == 0 || di.height == 0)
    {
        g_vk.init_failed = true;
        return false;
    }

    if (!VkOk(vk::VkCreateInstance(&g_vk.inst)))
    {
        g_vk.init_failed = true;
        return false;
    }
    duetos::u32 phys_count = 1;
    if (!VkOk(vk::VkEnumeratePhysicalDevices(g_vk.inst, &phys_count, &g_vk.phys)) || g_vk.phys == 0)
        goto fail;
    if (!VkOk(vk::VkCreateDevice(g_vk.phys, &g_vk.dev)))
        goto fail;
    if (!VkOk(vk::VkGetDeviceQueue(g_vk.dev, &g_vk.queue)))
        goto fail;
    if (!VkOk(vk::VkCreateCommandPool(g_vk.dev, &g_vk.pool)))
        goto fail;
    if (!VkOk(vk::VkAllocateCommandBuffers(g_vk.dev, g_vk.pool, 1, &g_vk.cb)))
        goto fail;
    // Memory type 1 = host-visible + coherent (per the ICD's
    // memory-type table). Allocate one shared block; vb + ib live
    // at disjoint offsets inside it.
    if (!VkOk(vk::VkAllocateMemory(g_vk.dev, kVertexBufBytes, 1, &g_vk.mem)))
        goto fail;
    if (!VkOk(vk::VkCreateBuffer(g_vk.dev, kIndexBufOffset, &g_vk.vb)))
        goto fail;
    if (!VkOk(vk::VkCreateBuffer(g_vk.dev, kVertexBufBytes - kIndexBufOffset, &g_vk.ib)))
        goto fail;
    if (!VkOk(vk::VkBindBufferMemory(g_vk.dev, g_vk.vb, g_vk.mem, 0)))
        goto fail;
    if (!VkOk(vk::VkBindBufferMemory(g_vk.dev, g_vk.ib, g_vk.mem, kIndexBufOffset)))
        goto fail;
    if (!VkOk(vk::VkMapMemory(g_vk.dev, g_vk.mem, 0, kVertexBufBytes, &g_vk.mapped)) || g_vk.mapped == nullptr)
        goto fail;
    // Pre-fill the index buffer once — it never changes.
    {
        auto* iptr =
            static_cast<duetos::u16*>(static_cast<void*>(static_cast<duetos::u8*>(g_vk.mapped) + kIndexBufOffset));
        for (duetos::u32 i = 0; i < kCubeIndexCount; ++i)
            iptr[i] = kCubeIndices[i];
    }
    if (!VkOk(vk::VkCreateImage(g_vk.dev, vk::VkExtent3D{di.width, di.height, 1}, vk::kImageScanoutBacked, &g_vk.img)))
        goto fail;
    if (!VkOk(vk::VkCreateImageView(g_vk.dev, g_vk.img, &g_vk.img_view)))
        goto fail;

    g_vk.ready = true;
    return true;

fail:
    g_vk.init_failed = true;
    return false;
}

// Rotate (x, y, z) in Q16 fixed-point. The three angle indices
// each cover 256 == 2π. Same shape as RenderCube's rotation block.
void RotateQ16(duetos::i32& x, duetos::i32& y, duetos::i32& z, duetos::u32 ax, duetos::u32 ay, duetos::u32 az)
{
    const duetos::i32 sx = SinQ15(ax) << 1;
    const duetos::i32 cxr = CosQ15(ax) << 1;
    const duetos::i32 sy = SinQ15(ay) << 1;
    const duetos::i32 cyr = CosQ15(ay) << 1;
    const duetos::i32 sz = SinQ15(az) << 1;
    const duetos::i32 czr = CosQ15(az) << 1;
    // X
    const duetos::i32 y1 = FxMul(y, cxr) - FxMul(z, sx);
    const duetos::i32 z1 = FxMul(y, sx) + FxMul(z, cxr);
    y = y1;
    z = z1;
    // Y
    const duetos::i32 x2 = FxMul(x, cyr) + FxMul(z, sy);
    const duetos::i32 z2 = -FxMul(x, sy) + FxMul(z, cyr);
    x = x2;
    z = z2;
    // Z
    const duetos::i32 x3 = FxMul(x, czr) - FxMul(y, sz);
    const duetos::i32 y3 = FxMul(x, sz) + FxMul(y, czr);
    x = x3;
    y = y3;
}

void WriteVertex(duetos::u8* vp, duetos::i16 x, duetos::i16 y, duetos::i16 z, duetos::u32 argb)
{
    vp[0] = static_cast<duetos::u8>(static_cast<duetos::u16>(x) & 0xFFu);
    vp[1] = static_cast<duetos::u8>((static_cast<duetos::u16>(x) >> 8) & 0xFFu);
    vp[2] = static_cast<duetos::u8>(static_cast<duetos::u16>(y) & 0xFFu);
    vp[3] = static_cast<duetos::u8>((static_cast<duetos::u16>(y) >> 8) & 0xFFu);
    vp[4] = static_cast<duetos::u8>(static_cast<duetos::u16>(z) & 0xFFu);
    vp[5] = static_cast<duetos::u8>((static_cast<duetos::u16>(z) >> 8) & 0xFFu);
    vp[6] = 0;
    vp[7] = 0;
    vp[8] = static_cast<duetos::u8>(argb & 0xFFu);
    vp[9] = static_cast<duetos::u8>((argb >> 8) & 0xFFu);
    vp[10] = static_cast<duetos::u8>((argb >> 16) & 0xFFu);
    vp[11] = static_cast<duetos::u8>((argb >> 24) & 0xFFu);
}

void DrawUnavailable(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch)
{
    FramebufferFillRect(cx, cy, cw, ch, 0x00200000);
    if (cw >= 200 && ch >= 16)
        FramebufferDrawString(cx + 8, cy + 8, "Vulkan ICD unavailable; check graphics init", 0x00FFAA66, 0x00000000);
}

} // namespace

void RenderVulkanCube(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 frame)
{
    if (cw == 0 || ch == 0)
        return;
    if (!InitVulkan())
    {
        DrawUnavailable(cx, cy, cw, ch);
        return;
    }
    // Paint window background so the cube reads against a known
    // dark colour. The Vulkan rasterizer's scissor then keeps the
    // triangle pixels inside this rect.
    FramebufferFillRect(cx, cy, cw, ch, 0x00080820);

    // Project 8 corners into window pixel space + i16 Z. Same
    // 16.16 pipeline as RenderCube but the result feeds the v1
    // vertex format instead of going straight to FramebufferDrawLine.
    const duetos::u32 ax = (frame * 5) & 0xFFu;
    const duetos::u32 ay = (frame * 3) & 0xFFu;
    const duetos::u32 az = (frame * 2) & 0xFFu;
    const duetos::i32 cam_z = 4 << 16;
    const duetos::i32 focal = 2 << 16;
    const duetos::i32 half_w = static_cast<duetos::i32>(cw / 2);
    const duetos::i32 half_h = static_cast<duetos::i32>(ch / 2);
    const duetos::i32 scale = static_cast<duetos::i32>((cw < ch ? cw : ch) / 4);

    auto* vp_base = static_cast<duetos::u8*>(g_vk.mapped);
    for (duetos::u32 i = 0; i < kCubeVertexCount; ++i)
    {
        duetos::i32 x = kCorners[i][0] << 16;
        duetos::i32 y = kCorners[i][1] << 16;
        duetos::i32 z = kCorners[i][2] << 16;
        RotateQ16(x, y, z, ax, ay, az);
        const duetos::i32 zc = z + cam_z;
        duetos::i16 px = 0;
        duetos::i16 py = 0;
        duetos::i16 pz = 0x7FFF; // far by default if behind camera
        if (zc > (1 << 14))
        {
            const duetos::i64 sx_q16 = (static_cast<duetos::i64>(focal) * x) / zc;
            const duetos::i64 sy_q16 = (static_cast<duetos::i64>(focal) * y) / zc;
            const duetos::i32 vx =
                static_cast<duetos::i32>(cx) + half_w + static_cast<duetos::i32>((sx_q16 * scale) >> 16);
            const duetos::i32 vy =
                static_cast<duetos::i32>(cy) + half_h + static_cast<duetos::i32>((sy_q16 * scale) >> 16);
            // Clamp to i16 framebuffer range.
            px = static_cast<duetos::i16>(vx < -32768 ? -32768 : (vx > 32767 ? 32767 : vx));
            py = static_cast<duetos::i16>(vy < -32768 ? -32768 : (vy > 32767 ? 32767 : vy));
            // Z in the rasterizer's i16 space — near has the smaller
            // raw Z so the Less compare op keeps the closer surface.
            // Map zc roughly into [-30000, +30000].
            const duetos::i64 z_norm = static_cast<duetos::i64>(zc - cam_z) * 7000 / (1 << 16);
            pz = static_cast<duetos::i16>(z_norm < -32000 ? -32000 : (z_norm > 32000 ? 32000 : z_norm));
        }
        WriteVertex(vp_base + i * kVertexStride, px, py, pz, kVertexColours[i]);
    }

    // Re-record the command buffer for this frame.
    (void)vk::VkResetCommandBuffer(g_vk.cb);
    if (!VkOk(vk::VkBeginCommandBuffer(g_vk.cb)))
        return;
    (void)vk::VkCmdSetVertexFormatDuet(g_vk.cb, 1);
    (void)vk::VkCmdSetPrimitiveTopology(g_vk.cb, 3); // TriangleList
    const vk::VkRect2D scissor{vk::VkOffset2D{static_cast<duetos::i32>(cx), static_cast<duetos::i32>(cy)},
                               vk::VkExtent2D{cw, ch}};
    (void)vk::VkCmdSetScissor(g_vk.cb, 0, 1, &scissor);
    (void)vk::VkCmdSetDepthTestEnable(g_vk.cb, 1);
    (void)vk::VkCmdSetDepthCompareOp(g_vk.cb, 1); // Less
    (void)vk::VkCmdSetDepthWriteEnable(g_vk.cb, 1);
    (void)vk::VkCmdClearDepthStencilImage(g_vk.cb, g_vk.img, 1.0f, 0);
    const duetos::u64 vb_off = 0;
    (void)vk::VkCmdBindVertexBuffers(g_vk.cb, 0, 1, &g_vk.vb, &vb_off);
    (void)vk::VkCmdBindIndexBuffer(g_vk.cb, g_vk.ib, 0, vk::VkIndexType::Uint16);
    // Set the render target via BeginRendering with loadOp =
    // DontCare so the rasterizer's replay walker captures
    // rt_image without overpainting the FramebufferFillRect
    // background we just wrote above.
    vk::VkRenderingAttachmentInfo attach{};
    attach.imageView = g_vk.img_view;
    attach.loadOp = 2; // DontCare
    const vk::VkRect2D rend_area{vk::VkOffset2D{0, 0}, vk::VkExtent2D{cw, ch}};
    (void)vk::VkCmdBeginRendering(g_vk.cb, rend_area, 1, &attach);
    (void)vk::VkCmdDrawIndexed(g_vk.cb, kCubeIndexCount, 1, 0, 0, 0);
    (void)vk::VkCmdEndRendering(g_vk.cb);
    (void)vk::VkEndCommandBuffer(g_vk.cb);
    (void)vk::VkQueueSubmit(g_vk.queue, 1, &g_vk.cb, 0);
    (void)vk::VkQueueWaitIdle(g_vk.queue);

    // HUD readout — show the rasterizer's triangle counter so the
    // user can see frames advancing.
    if (cw >= 200 && ch >= 16)
    {
        const auto stats = vk::GraphicsStatsRead();
        char buf[40];
        // Hand-format "tris=%u" without pulling in printf.
        const duetos::u32 v = stats.vk_triangles_drawn;
        char num[12];
        duetos::u32 n = 0;
        duetos::u32 tmp = v == 0 ? 0 : v;
        if (tmp == 0)
        {
            num[n++] = '0';
        }
        else
        {
            while (tmp != 0)
            {
                num[n++] = static_cast<char>('0' + (tmp % 10));
                tmp /= 10;
            }
        }
        duetos::u32 pos = 0;
        const char* prefix = "tris=";
        while (*prefix && pos < sizeof(buf) - 1)
            buf[pos++] = *prefix++;
        while (n > 0 && pos < sizeof(buf) - 1)
            buf[pos++] = num[--n];
        buf[pos] = '\0';
        FramebufferDrawString(cx + 4, cy + ch - 12, buf, 0x00FFFFFF, 0x00000000);
    }
}

} // namespace duetos::apps::gfxdemo
