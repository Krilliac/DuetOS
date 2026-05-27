#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_internal.h"

#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"

/*
 * DuetOS — Vulkan WSI (surface + swapchain) implementation.
 *
 * Lives in its own TU so the surface / swapchain bring-up
 * stays separable from the rest of the ICD.  All cross-TU
 * symbols (per-kind handle pools, per-record storage, the
 * Pool primitive, kBase constants) come through
 * `graphics_vk_internal.h` and the file-scope
 * `using namespace internal;`; the actual entry-point
 * functions are defined in the public Vulkan namespace so
 * graphics.h's declarations bind to these definitions.
 */

namespace duetos::subsystems::graphics
{

using namespace internal;
// -------------------------------------------------------------------
// Surface + swapchain (WSI).
// -------------------------------------------------------------------

VkResult VkCreateDuetSurfaceKHR(VkInstance inst, VkSurfaceKHR* out)
{
    if (!HandleInRange(inst, kInstanceBase) || !PoolIsLive(g_instance_pool, SlotOf(inst, kInstanceBase)))
        return VkResult::ErrorInitializationFailed;
    const auto di = drivers::video::Query();
    if (!di.available)
        return VkResult::ErrorInitializationFailed; // no framebuffer to attach to
    u32 slot = 0;
    if (!PoolAlloc(g_surface_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kSurfaceBase, slot);
    return VkResult::Success;
}

void VkDestroySurfaceKHR(VkInstance inst, VkSurfaceKHR surface)
{
    (void)inst;
    if (surface == 0 || !HandleInRange(surface, kSurfaceBase))
        return;
    (void)PoolFree(g_surface_pool, SlotOf(surface, kSurfaceBase));
}

VkResult VkGetPhysicalDeviceSurfaceCapabilitiesKHR(VkPhysicalDevice phys, VkSurfaceKHR surface,
                                                   VkSurfaceCapabilitiesKHR* out)
{
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(surface, kSurfaceBase) || !PoolIsLive(g_surface_pool, SlotOf(surface, kSurfaceBase)))
        return VkResult::ErrorInitializationFailed;
    const auto di = drivers::video::Query();
    *out = VkSurfaceCapabilitiesKHR{};
    out->minImageCount = 2;
    out->maxImageCount = kMaxSwapchainImages;
    out->currentExtent = VkExtent2D{di.available ? di.width : 0u, di.available ? di.height : 0u};
    out->minImageExtent = out->currentExtent;
    out->maxImageExtent = out->currentExtent;
    out->maxImageArrayLayers = 1;
    out->supportedTransforms = 1;     // identity only
    out->currentTransform = 1;        // identity
    out->supportedCompositeAlpha = 1; // opaque only
    out->supportedUsageFlags = 0x10;  // VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT
    return VkResult::Success;
}

VkResult VkGetPhysicalDeviceSurfaceFormatsKHR(VkPhysicalDevice phys, VkSurfaceKHR surface, u32* count,
                                              VkSurfaceFormatKHR* formats)
{
    if (count == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(surface, kSurfaceBase) || !PoolIsLive(g_surface_pool, SlotOf(surface, kSurfaceBase)))
        return VkResult::ErrorInitializationFailed;
    if (formats == nullptr)
    {
        *count = 1;
        return VkResult::Success;
    }
    if (*count == 0)
        return VkResult::Incomplete;
    formats[0].format = 0; // B8G8R8A8_UNORM
    formats[0].colorSpace = VkColorSpaceKHR::SrgbNonlinear;
    *count = 1;
    return VkResult::Success;
}

VkResult VkGetPhysicalDeviceSurfacePresentModesKHR(VkPhysicalDevice phys, VkSurfaceKHR surface, u32* count,
                                                   VkPresentModeKHR* modes)
{
    if (count == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(surface, kSurfaceBase) || !PoolIsLive(g_surface_pool, SlotOf(surface, kSurfaceBase)))
        return VkResult::ErrorInitializationFailed;
    if (modes == nullptr)
    {
        *count = 1;
        return VkResult::Success;
    }
    if (*count == 0)
        return VkResult::Incomplete;
    modes[0] = VkPresentModeKHR::Fifo;
    *count = 1;
    return VkResult::Success;
}

VkResult VkCreateSwapchainKHR(VkDevice dev, VkSurfaceKHR surface, u32 min_image_count, VkExtent2D extent,
                              VkSwapchainKHR* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(surface, kSurfaceBase) || !PoolIsLive(g_surface_pool, SlotOf(surface, kSurfaceBase)))
        return VkResult::ErrorInitializationFailed;
    if (min_image_count < 2)
        min_image_count = 2;
    if (min_image_count > kMaxSwapchainImages)
        return VkResult::ErrorOutOfHostMemory;

    u32 sc_slot = 0;
    if (!PoolAlloc(g_swapchain_pool, &sc_slot))
        return VkResult::ErrorOutOfHostMemory;
    auto& rec = g_swapchain_data[sc_slot];
    rec = SwapchainRecord{};
    rec.surface = surface;
    rec.extent = extent;
    rec.image_count = min_image_count;
    rec.next_image = 0;
    rec.image_acquired = false;

    // Allocate scanout-backed images for each swapchain slot.  If
    // image-pool allocation fails partway, roll back so the
    // swapchain handle is never visible with partial backing.
    for (u32 i = 0; i < min_image_count; ++i)
    {
        u32 img_slot = 0;
        if (!PoolAlloc(g_image_pool, &img_slot))
        {
            for (u32 j = 0; j < i; ++j)
                (void)PoolFree(g_image_pool, SlotOf(rec.images[j], kImageBase));
            (void)PoolFree(g_swapchain_pool, sc_slot);
            return VkResult::ErrorOutOfHostMemory;
        }
        g_image_data[img_slot].extent = VkExtent3D{extent.width, extent.height, 1};
        g_image_data[img_slot].flags = kImageScanoutBacked;
        g_image_data[img_slot].memory_bound = true; // implicit-bound for swapchain images
        rec.images[i] = HandleFor(kImageBase, img_slot);
    }
    if (out != nullptr)
        *out = HandleFor(kSwapchainBase, sc_slot);
    return VkResult::Success;
}

void VkDestroySwapchainKHR(VkDevice dev, VkSwapchainKHR sc)
{
    (void)dev;
    if (sc == 0 || !HandleInRange(sc, kSwapchainBase))
        return;
    const u32 slot = SlotOf(sc, kSwapchainBase);
    if (!PoolIsLive(g_swapchain_pool, slot))
        return;
    auto& rec = g_swapchain_data[slot];
    for (u32 i = 0; i < rec.image_count; ++i)
    {
        if (HandleInRange(rec.images[i], kImageBase))
            (void)PoolFree(g_image_pool, SlotOf(rec.images[i], kImageBase));
    }
    rec.image_count = 0;
    (void)PoolFree(g_swapchain_pool, slot);
}

VkResult VkGetSwapchainImagesKHR(VkDevice dev, VkSwapchainKHR sc, u32* count, VkImage* images)
{
    (void)dev;
    if (count == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(sc, kSwapchainBase) || !PoolIsLive(g_swapchain_pool, SlotOf(sc, kSwapchainBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_swapchain_data[SlotOf(sc, kSwapchainBase)];
    if (images == nullptr)
    {
        *count = rec.image_count;
        return VkResult::Success;
    }
    const u32 give = (*count < rec.image_count) ? *count : rec.image_count;
    for (u32 i = 0; i < give; ++i)
        images[i] = rec.images[i];
    *count = give;
    return (give < rec.image_count) ? VkResult::Incomplete : VkResult::Success;
}

VkResult VkAcquireNextImageKHR(VkDevice dev, VkSwapchainKHR sc, u64 timeout_ns, VkSemaphore signal_semaphore,
                               VkFence signal_fence, u32* image_index_out)
{
    (void)dev;
    (void)timeout_ns;
    if (image_index_out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(sc, kSwapchainBase) || !PoolIsLive(g_swapchain_pool, SlotOf(sc, kSwapchainBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_swapchain_data[SlotOf(sc, kSwapchainBase)];
    if (rec.image_count == 0)
        return VkResult::ErrorDeviceLost;
    rec.acquired_index = rec.next_image;
    rec.next_image = (rec.next_image + 1) % rec.image_count;
    rec.image_acquired = true;
    *image_index_out = rec.acquired_index;
    ++g_swapchain_acquires;
    // The spec's contract: when the image becomes "available for
    // rendering", the caller-supplied semaphore + fence are
    // signalled. v0 swapchain images are always immediately
    // available (one frame in flight; no real present-engine wait),
    // so we signal both here. A real-GPU backend would defer these
    // signals to the page-flip-completion event.
    if (signal_semaphore != 0)
        (void)internal::SignalSemaphoreInternal(signal_semaphore);
    if (signal_fence != 0 && HandleInRange(signal_fence, kFenceBase))
    {
        const u32 fslot = SlotOf(signal_fence, kFenceBase);
        if (PoolIsLive(g_fence_pool, fslot))
            g_fence_data[fslot].signalled = true;
    }
    return VkResult::Success;
}

VkResult VkQueuePresentKHR(VkQueue q, VkSwapchainKHR sc, u32 image_index)
{
    if (!HandleInRange(q, kQueueBase) || !PoolIsLive(g_queue_pool, SlotOf(q, kQueueBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(sc, kSwapchainBase) || !PoolIsLive(g_swapchain_pool, SlotOf(sc, kSwapchainBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_swapchain_data[SlotOf(sc, kSwapchainBase)];
    if (image_index >= rec.image_count)
        return VkResult::ErrorInitializationFailed;
    if (!rec.image_acquired || rec.acquired_index != image_index)
        return VkResult::ErrorInitializationFailed; // present without acquire == bug
    rec.image_acquired = false;
    drivers::video::FramebufferPresent();
    ++g_swapchain_presents;
    return VkResult::Success;
}

} // namespace duetos::subsystems::graphics
