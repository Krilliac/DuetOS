#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_internal.h"

#include "drivers/video/display_info.h"
#include "log/klog.h"
#include "mm/kheap.h"

/*
 * DuetOS — Vulkan ICD software depth surface.
 *
 * Single shared 16-bit depth buffer sized to the live framebuffer
 * extent. The v0 ICD has one scanout target, so one depth buffer
 * is enough; a follow-on slice that exposes multiple swapchains
 * or off-screen render targets will need to key this by image
 * handle and let `VkDestroyImage` drop its entry.
 *
 * Lazy allocation: the buffer is only allocated when the first
 * Z-test draw asks for it. Boot ICD init costs nothing. Boot
 * self-test teardown frees the surface so the leak walk stays
 * clean.
 *
 * Cleared to `0xFFFF` (far) on alloc so the first draw passes
 * the Less compare unconditionally.
 */

namespace duetos::subsystems::graphics::internal
{

namespace
{

DepthSurface g_depth{};
bool g_alloc_failed_once = false;

void FillU16(u16* data, u64 count, u16 value)
{
    for (u64 i = 0; i < count; ++i)
        data[i] = value;
}

} // namespace

DepthSurface* DepthSurfaceGetOrAlloc()
{
    if (g_depth.data != nullptr)
        return &g_depth;
    if (g_alloc_failed_once)
        return nullptr;
    const auto di = drivers::video::Query();
    if (!di.available || di.width == 0 || di.height == 0)
        return nullptr;
    const u64 pixel_count = static_cast<u64>(di.width) * di.height;
    const u64 bytes = pixel_count * sizeof(u16);
    void* mem = mm::KMalloc(bytes);
    if (mem == nullptr)
    {
        g_alloc_failed_once = true;
        KLOG_WARN_V("subsystems/graphics", "depth surface alloc failed; depth test will be skipped", bytes);
        return nullptr;
    }
    g_depth.data = static_cast<u16*>(mem);
    g_depth.w = di.width;
    g_depth.h = di.height;
    FillU16(g_depth.data, pixel_count, 0xFFFFu);
    return &g_depth;
}

void DepthSurfaceClear(u16 value)
{
    if (g_depth.data == nullptr)
        return;
    FillU16(g_depth.data, static_cast<u64>(g_depth.w) * g_depth.h, value);
}

void DepthSurfaceFree()
{
    if (g_depth.data != nullptr)
        mm::KFree(g_depth.data);
    g_depth.data = nullptr;
    g_depth.w = 0;
    g_depth.h = 0;
    g_alloc_failed_once = false;
}

} // namespace duetos::subsystems::graphics::internal
