#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_internal.h"

#include "arch/x86_64/serial.h"
#include "drivers/gpu/gpu.h"
#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "time/timekeeper.h"
#include "util/string.h"

/*
 * DuetOS — Vulkan ICD implementation, v0.
 *
 * Owns every Vulkan-flavour handle the graphics subsystem hands
 * out.  Splits cleanly from `graphics.cpp` (which keeps init,
 * D3D translation stubs, and the merged stats reader) so the
 * Vulkan-vs-D3D boundary is one TU each.
 *
 * Handle layout: each Vk* type lives in its own fixed-size slot
 * pool whose handle is `kBase + slot`.  The base ranges are
 * disjoint so a Destroy can validate the input by range; the
 * slot index is the low 8 bits.
 *
 * No locking — this code runs at boot for the self-test, plus
 * (eventually) from the Win32 D3D thunks once those are wired
 * in.  Concurrent submission from multiple tasks is a future
 * slice's concern.
 */

namespace duetos::subsystems::graphics
{

// All file-scope helpers + per-kind handle storage live in
// `internal::` so a sibling TU (graphics_vk_selftest.cpp today,
// future graphics_vk_commands.cpp / _wsi.cpp / _misc.cpp) can
// reach them through the bridge declared in
// `graphics_vk_internal.h`.  The using-directive below means
// every entry point in the rest of this file finds those names
// unqualified, so the existing references compile unchanged.
namespace internal
{
}
using namespace internal;

namespace internal
{

// -------------------------------------------------------------------
// Per-kind storage.  Types + extern decls live in
// graphics_vk_internal.h; this TU is the single point of
// definition.  A multi-TU split (graphics_vk_commands.cpp,
// _wsi.cpp, _misc.cpp) reaches the same storage through the
// header without duplicating any of it.
// -------------------------------------------------------------------

ImageRecord g_image_data[kPoolCapacity];
ShaderRecord g_shader_data[kPoolCapacity];
BufferRecord g_buffer_data[kPoolCapacity];
ImageViewRecord g_imageview_data[kPoolCapacity];
FramebufferRecord g_framebuffer_data[kPoolCapacity];
DeviceMemoryRecord g_memory_data[kPoolCapacity];
CmdBufferRecord g_cmdbuf_data[kPoolCapacity];
DescriptorSetLayoutRecord g_desc_set_layout_data[kPoolCapacity];
DescriptorPoolRecord g_desc_pool_data[kPoolCapacity];
DescriptorSetRecord g_desc_set_data[kPoolCapacity];
SwapchainRecord g_swapchain_data[kPoolCapacity];
EventRecord g_event_data[kPoolCapacity];
PipelineCacheRecord g_pipeline_cache_data[kPoolCapacity];
QueryPoolRecord g_query_pool_data[kPoolCapacity];
PhysicalDeviceRecord g_phys_data[kPoolCapacity];
QueueRecord g_queue_data[kPoolCapacity];
PipelineRecord g_pipeline_data[kPoolCapacity];

Pool g_instance_pool;
Pool g_phys_pool;
Pool g_device_pool;
Pool g_queue_pool;
Pool g_cmdpool_pool;
Pool g_cmdbuf_pool;
Pool g_shader_pool;
Pool g_pipelinelayout_pool;
Pool g_pipeline_pool;
Pool g_renderpass_pool;
Pool g_framebuffer_pool;
Pool g_image_pool;
Pool g_imageview_pool;
Pool g_buffer_pool;
Pool g_memory_pool;
Pool g_fence_pool;
Pool g_semaphore_pool;
Pool g_desc_set_layout_pool;
Pool g_desc_pool_pool;
Pool g_desc_set_pool;
Pool g_surface_pool;
Pool g_swapchain_pool;
Pool g_sampler_pool;
Pool g_event_pool;
Pool g_pipeline_cache_pool;
Pool g_query_pool_pool;

// -------------------------------------------------------------------
// Aggregate counters.
// -------------------------------------------------------------------

u32 g_queue_submits = 0;
u32 g_command_recorded = 0;
u32 g_command_replayed = 0;
u32 g_clear_pixels_painted = 0;
u32 g_invalid_spirv_rejections = 0;
u32 g_descriptor_writes = 0;
u32 g_swapchain_acquires = 0;
u32 g_swapchain_presents = 0;
u32 g_spirv_modules_parsed = 0;
u32 g_spirv_entry_points_seen = 0;
u32 g_spirv_capabilities_seen = 0;
u32 g_spirv_decorations_seen = 0;
u32 g_spirv_execution_modes_seen = 0;
u32 g_buffer_copy_bytes = 0;
u32 g_buffer_fill_bytes = 0;
u32 g_push_constant_writes = 0;
u32 g_pipeline_barriers = 0;
u32 g_dispatches = 0;
u32 g_queries_executed = 0;
u32 g_memory_maps = 0;
u32 g_image_upload_pixels = 0;
u32 g_triangles_drawn = 0;
u32 g_spirv_programs_built = 0;
u32 g_spirv_program_build_failures = 0;
u32 g_spirv_entry_point_executions = 0;
u32 g_spirv_step_budget_exhausted = 0;
u32 g_shader_raster_draws_painted = 0;
u32 g_shader_raster_draws_skipped = 0;
u32 g_dynamic_renderings = 0;
u32 g_debug_labels = 0;
u32 g_secondary_executes = 0;
u32 g_secondary_ops_replayed = 0;
u32 g_push_descriptor_writes = 0;

// Tiny debug-utils name table.  A circular slot table keyed by
// the (handle, name) tuple — we never need more than a handful
// of named handles.  Lookup is linear (tiny N).
constexpr u32 kMaxDebugLabels = 16;
struct DebugLabelEntry
{
    u64 handle;
    char name[kMaxDebugLabelLen];
};
DebugLabelEntry g_debug_label_table[kMaxDebugLabels] = {};
u32 g_debug_label_head = 0;

// One-shot logging keyed by entry point.  Enum + LogOnce
// signature live in `graphics_vk_internal.h` so other TUs can
// participate.  Storage lives here.
bool g_logged[EpCount] = {};
void LogOnce(EpId id, const char* name)
{
    if (id < 0 || id >= EpCount)
        return;
    if (g_logged[id])
        return;
    g_logged[id] = true;
    arch::SerialWrite("[vk] ");
    arch::SerialWrite(name);
    arch::SerialWrite(" reached (v0 ICD)\n");
}

void StrCopyN(char* dst, const char* src, u32 cap)
{
    if (cap == 0)
        return;
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < cap && src[i] != '\0'; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

u32 PciVendorIdFromName(const char* name)
{
    // Reverse-map of drivers/gpu/gpu.h vendor strings to PCI vendor IDs.
    // display_info reports the short name only; the ID is what
    // vkGetPhysicalDeviceProperties advertises.
    if (name == nullptr)
        return 0;
    if (name[0] == 'I' && name[1] == 'n')
        return 0x8086; // Intel
    if (name[0] == 'A' && name[1] == 'M')
        return 0x1002; // AMD
    if (name[0] == 'N' && name[1] == 'V')
        return 0x10DE; // NVIDIA
    if (name[0] == 'V' && name[1] == 'M')
        return 0x15AD; // VMware
    if (name[0] == 'Q' && name[1] == 'E')
        return 0x1234; // QEMU-Bochs
    if (name[0] == 'V' && name[1] == 'i')
        return 0x1AF4; // virtio
    return 0;
}

u32 ColorToRgb(const VkClearColorValue& c)
{
    // Kernel has no float runtime — read the integer alias.
    // Each lane's low byte is the 0-255 colour component; the
    // upper bits are masked off so a caller filling the union as
    // `{{r, g, b, a}}` directly works without further conversion.
    const u32 r = c.uint32[0] & 0xFFu;
    const u32 g = c.uint32[1] & 0xFFu;
    const u32 b = c.uint32[2] & 0xFFu;
    return (r << 16) | (g << 8) | b;
}

} // namespace internal

// -------------------------------------------------------------------
// Instance + physical device.
// -------------------------------------------------------------------

VkResult VkCreateInstance(VkInstance* out)
{
    LogOnce(EpCreateInstance, "vkCreateInstance");
    u32 slot = 0;
    if (!PoolAlloc(g_instance_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kInstanceBase, slot);
    return VkResult::Success;
}

void VkDestroyInstance(VkInstance inst)
{
    if (inst == 0 || !HandleInRange(inst, kInstanceBase))
        return;
    const u32 inst_slot = SlotOf(inst, kInstanceBase);
    // Per Vulkan spec, destroying an instance invalidates every
    // physical device enumerated from it. Walk g_phys_pool and
    // free any handle whose owning_instance_slot matches.
    // Without this, the boot self-test's leak walk reports a
    // "physical-device" pool leak after teardown.
    for (u32 s = 0; s < kPoolCapacity; ++s)
    {
        if (PoolIsLive(g_phys_pool, s) && g_phys_data[s].owning_instance_slot == inst_slot)
            (void)PoolFree(g_phys_pool, s);
    }
    (void)PoolFree(g_instance_pool, inst_slot);
}

VkResult VkEnumeratePhysicalDevices(VkInstance inst, u32* count, VkPhysicalDevice* devs)
{
    LogOnce(EpEnumeratePhysicalDevices, "vkEnumeratePhysicalDevices");
    if (!HandleInRange(inst, kInstanceBase) || !PoolIsLive(g_instance_pool, SlotOf(inst, kInstanceBase)))
        return VkResult::ErrorInitializationFailed;

    // Report at least one physical device so a caller's "find a
    // GPU" path always has something to land on.  The handle pool
    // tracks the count so destroy round-trips remain symmetric.
    u32 reported = static_cast<u32>(drivers::gpu::GpuCount());
    if (reported == 0)
        reported = 1; // virtual fallback so vkCreateDevice can always succeed
    if (reported > kPoolCapacity)
        reported = kPoolCapacity;

    if (count != nullptr && devs == nullptr)
    {
        *count = reported;
        return VkResult::Success;
    }
    if (count == nullptr)
        return VkResult::ErrorInitializationFailed;

    const u32 want = *count;
    const u32 give = (want < reported) ? want : reported;
    for (u32 i = 0; i < give; ++i)
    {
        u32 slot = 0;
        if (!PoolAlloc(g_phys_pool, &slot))
        {
            *count = i;
            return VkResult::ErrorOutOfHostMemory;
        }
        // Map the handle slot back to a real GPU index so the
        // property queries can report per-device vendor/family
        // (a multi-GPU host gets distinct VkPhysicalDevice
        // properties per handle, not the same struct repeated).
        g_phys_data[slot].gpu_index = i;
        // Pin the handle to the owning instance so VkDestroyInstance
        // can walk g_phys_pool and release every phys this enumerate
        // call produced (Vulkan spec: phys lifetime <= instance).
        g_phys_data[slot].owning_instance_slot = SlotOf(inst, kInstanceBase);
        devs[i] = HandleFor(kPhysDevBase, slot);
    }
    *count = give;
    return (give < reported) ? VkResult::Incomplete : VkResult::Success;
}

VkResult VkGetPhysicalDeviceProperties(VkPhysicalDevice phys, VkPhysicalDeviceProperties* out)
{
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;

    *out = VkPhysicalDeviceProperties{};
    out->apiVersion = kApiVersion1_3;
    out->driverVersion = MakeApiVersion(0, 0, 1, 0); // DuetOS ICD epoch

    // Source per-handle: pick the GPU this phys handle was
    // allocated for, falling back to display_info when the GPU
    // index is out of range (no display-class device discovered).
    const u32 gpu_index = g_phys_data[SlotOf(phys, kPhysDevBase)].gpu_index;
    const auto di = drivers::video::Query();
    const char* vendor_str = nullptr;
    const char* family_str = nullptr;
    if (gpu_index < drivers::gpu::GpuCount())
    {
        const auto& g = drivers::gpu::Gpu(gpu_index);
        vendor_str = g.vendor;
        family_str = g.family;
        out->vendorID = g.vendor_id;
        out->deviceID = g.device_id;
    }
    else
    {
        vendor_str = di.gpu_vendor;
        family_str = di.gpu_family;
        out->vendorID = di.gpu_present ? PciVendorIdFromName(di.gpu_vendor) : 0u;
        out->deviceID = 0;
    }

    // Device type: virtio-gpu / Bochs are virtual; Intel iGPU is
    // integrated; AMD/NVIDIA are discrete.  CPU fallback when no
    // display-class device was discovered.
    if (vendor_str == nullptr)
        out->deviceType = 4; // CPU
    else if (out->vendorID == 0x8086)
        out->deviceType = 1; // IntegratedGPU
    else if (out->vendorID == 0x1002 || out->vendorID == 0x10DE)
        out->deviceType = 2; // DiscreteGPU
    else
        out->deviceType = 3; // VirtualGpu

    // Compose a deterministic device name from vendor + family.
    char buf[kMaxDeviceName];
    u32 i = 0;
    auto append = [&](const char* s)
    {
        if (s == nullptr)
            return;
        while (i + 1 < kMaxDeviceName && *s != '\0')
            buf[i++] = *s++;
    };
    append("DuetOS-vk-");
    append(vendor_str != nullptr ? vendor_str : "cpu");
    if (family_str != nullptr)
    {
        append("-");
        append(family_str);
    }
    buf[i] = '\0';
    StrCopyN(out->deviceName, buf, kMaxDeviceName);

    out->limits = VkPhysicalDeviceLimits{};
    out->limits.maxImageDimension2D = 16384;
    out->limits.maxFramebufferWidth = di.available ? di.width : 4096;
    out->limits.maxFramebufferHeight = di.available ? di.height : 4096;
    out->limits.maxBoundDescriptorSets = 4;
    out->limits.maxPushConstantsSize = 128;
    out->limits.maxComputeWorkGroupCount[0] = 65535;
    out->limits.maxComputeWorkGroupCount[1] = 65535;
    out->limits.maxComputeWorkGroupCount[2] = 65535;
    return VkResult::Success;
}

VkResult VkGetPhysicalDeviceFeatures(VkPhysicalDevice phys, VkPhysicalDeviceFeatures* out)
{
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;
    // No GPU-side features are supported by the v0 CPU ICD.
    *out = VkPhysicalDeviceFeatures{};
    return VkResult::Success;
}

VkResult VkGetPhysicalDeviceMemoryProperties(VkPhysicalDevice phys, VkPhysicalDeviceMemoryProperties* out)
{
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;

    *out = VkPhysicalDeviceMemoryProperties{};
    // One DEVICE_LOCAL heap (sized to the framebuffer if known —
    // 64 MiB fallback) and one HOST_VISIBLE heap (small, 16 MiB)
    // so the caller's heap-selection code finds two distinct
    // entries.
    const auto di = drivers::video::Query();
    const u64 fb_bytes = di.available ? static_cast<u64>(di.height) * di.pitch : 0u;
    out->memoryHeapCount = 2;
    out->memoryHeaps[0].size = fb_bytes != 0 ? fb_bytes : (64u * 1024u * 1024u);
    out->memoryHeaps[0].flags = kMemoryPropertyDeviceLocal;
    out->memoryHeaps[1].size = 16u * 1024u * 1024u;
    out->memoryHeaps[1].flags = 0;

    out->memoryTypeCount = 2;
    out->memoryTypes[0].propertyFlags = kMemoryPropertyDeviceLocal;
    out->memoryTypes[0].heapIndex = 0;
    out->memoryTypes[1].propertyFlags = kMemoryPropertyHostVisible | kMemoryPropertyHostCoherent;
    out->memoryTypes[1].heapIndex = 1;
    return VkResult::Success;
}

VkResult VkGetPhysicalDeviceQueueFamilyProperties(VkPhysicalDevice phys, u32* count, VkQueueFamilyProperties* out)
{
    if (count == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;
    if (out == nullptr)
    {
        *count = 1;
        return VkResult::Success;
    }
    if (*count == 0)
        return VkResult::Incomplete;
    out[0].queueFlags = kQueueGraphicsBit | kQueueComputeBit | kQueueTransferBit;
    out[0].queueCount = 1;
    out[0].timestampValidBits = 0; // no timestamp pool yet
    out[0].minImageTransferGranularity = VkExtent3D{1, 1, 1};
    *count = 1;
    return VkResult::Success;
}

VkResult VkEnumerateInstanceExtensionProperties(u32* count)
{
    if (count == nullptr)
        return VkResult::ErrorInitializationFailed;
    *count = 0; // No extensions yet.
    return VkResult::Success;
}

VkResult VkEnumerateInstanceLayerProperties(u32* count)
{
    if (count == nullptr)
        return VkResult::ErrorInitializationFailed;
    *count = 0;
    return VkResult::Success;
}

VkResult VkEnumerateDeviceExtensionProperties(VkPhysicalDevice phys, u32* count)
{
    if (count == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;
    *count = 0;
    return VkResult::Success;
}

VkResult VkEnumerateInstanceVersion(u32* api_version)
{
    if (api_version == nullptr)
        return VkResult::ErrorInitializationFailed;
    *api_version = kApiVersion1_3;
    return VkResult::Success;
}

namespace internal
{

// Loader-style name -> token table.  The token value is opaque
// (a small integer prefix); only `!= 0` is meaningful to a
// caller.  One table covers both instance + device queries — an
// entry not appropriate for the device-level call returns 0
// from VkGetDeviceProcAddr.
struct NamedEntry
{
    const char* name;
    u64 token;
    bool device_level;
};

constexpr u64 kEpFnBase = 0xF000'0000ull;
constexpr NamedEntry kKnownEntries[] = {
    {"vkCreateInstance", kEpFnBase + 1, false},
    {"vkDestroyInstance", kEpFnBase + 2, false},
    {"vkEnumeratePhysicalDevices", kEpFnBase + 3, false},
    {"vkGetPhysicalDeviceProperties", kEpFnBase + 4, false},
    {"vkGetPhysicalDeviceFeatures", kEpFnBase + 5, false},
    {"vkGetPhysicalDeviceMemoryProperties", kEpFnBase + 6, false},
    {"vkGetPhysicalDeviceQueueFamilyProperties", kEpFnBase + 7, false},
    {"vkCreateDevice", kEpFnBase + 8, false},
    {"vkDestroyDevice", kEpFnBase + 9, true},
    {"vkGetDeviceQueue", kEpFnBase + 10, true},
    {"vkQueueSubmit", kEpFnBase + 11, true},
    {"vkQueueWaitIdle", kEpFnBase + 12, true},
    {"vkDeviceWaitIdle", kEpFnBase + 13, true},
    {"vkAllocateMemory", kEpFnBase + 14, true},
    {"vkFreeMemory", kEpFnBase + 15, true},
    {"vkMapMemory", kEpFnBase + 16, true},
    {"vkUnmapMemory", kEpFnBase + 17, true},
    {"vkCreateBuffer", kEpFnBase + 18, true},
    {"vkDestroyBuffer", kEpFnBase + 19, true},
    {"vkBindBufferMemory", kEpFnBase + 20, true},
    {"vkCreateImage", kEpFnBase + 21, true},
    {"vkDestroyImage", kEpFnBase + 22, true},
    {"vkCreateImageView", kEpFnBase + 23, true},
    {"vkDestroyImageView", kEpFnBase + 24, true},
    {"vkCreateRenderPass", kEpFnBase + 25, true},
    {"vkCreateFramebuffer", kEpFnBase + 26, true},
    {"vkCreateShaderModule", kEpFnBase + 27, true},
    {"vkCreateGraphicsPipelines", kEpFnBase + 28, true},
    {"vkCreateCommandPool", kEpFnBase + 29, true},
    {"vkAllocateCommandBuffers", kEpFnBase + 30, true},
    {"vkBeginCommandBuffer", kEpFnBase + 31, true},
    {"vkEndCommandBuffer", kEpFnBase + 32, true},
    {"vkCmdClearColorImage", kEpFnBase + 33, true},
    {"vkCmdDraw", kEpFnBase + 34, true},
    {"vkCreateSwapchainKHR", kEpFnBase + 35, true},
    {"vkAcquireNextImageKHR", kEpFnBase + 36, true},
    {"vkQueuePresentKHR", kEpFnBase + 37, true},
    {"vkGetInstanceProcAddr", kEpFnBase + 38, false},
    {"vkGetDeviceProcAddr", kEpFnBase + 39, true},
    {"vkEnumerateInstanceVersion", kEpFnBase + 40, false},
};

using duetos::core::StrEqual;

u64 ResolveProc(const char* name, bool device_level_only)
{
    if (name == nullptr)
        return 0;
    for (const auto& e : kKnownEntries)
    {
        if (StrEqual(e.name, name))
        {
            if (device_level_only && !e.device_level)
                return 0;
            return e.token;
        }
    }
    return 0;
}

} // namespace internal

u64 VkGetInstanceProcAddr(VkInstance inst, const char* name)
{
    (void)inst;
    return ResolveProc(name, /*device_level_only=*/false);
}

u64 VkGetDeviceProcAddr(VkDevice dev, const char* name)
{
    (void)dev;
    return ResolveProc(name, /*device_level_only=*/true);
}

VkResult VkGetPhysicalDeviceProperties2(VkPhysicalDevice phys, VkPhysicalDeviceProperties2* out)
{
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    return VkGetPhysicalDeviceProperties(phys, &out->properties);
}

VkResult VkGetPhysicalDeviceFeatures2(VkPhysicalDevice phys, VkPhysicalDeviceFeatures2* out)
{
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    return VkGetPhysicalDeviceFeatures(phys, &out->features);
}

VkResult VkGetPhysicalDeviceMemoryProperties2(VkPhysicalDevice phys, VkPhysicalDeviceMemoryProperties2* out)
{
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    return VkGetPhysicalDeviceMemoryProperties(phys, &out->memoryProperties);
}

// -------------------------------------------------------------------
// Device + queue.
// -------------------------------------------------------------------

VkResult VkCreateDevice(VkPhysicalDevice phys, VkDevice* out)
{
    LogOnce(EpCreateDevice, "vkCreateDevice");
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_device_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kDeviceBase, slot);
    return VkResult::Success;
}

void VkDestroyDevice(VkDevice dev)
{
    if (dev == 0 || !HandleInRange(dev, kDeviceBase))
        return;
    const u32 dev_slot = SlotOf(dev, kDeviceBase);
    // Per Vulkan spec, queues retrieved from a device share the
    // device's lifetime — destroying the device implicitly retires
    // every queue handle from it. Without this walk the boot
    // self-test's leak-checker reports a "queue" pool leak after
    // every clean teardown.
    for (u32 s = 0; s < kPoolCapacity; ++s)
    {
        if (PoolIsLive(g_queue_pool, s) && g_queue_data[s].owning_device_slot == dev_slot)
            (void)PoolFree(g_queue_pool, s);
    }
    (void)PoolFree(g_device_pool, dev_slot);
}

VkResult VkGetDeviceQueue(VkDevice dev, VkQueue* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_queue_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    // Pin the queue to its owning device so VkDestroyDevice can
    // walk g_queue_pool and release every queue retrieved from
    // this device (Vulkan spec: queue lifetime <= device).
    g_queue_data[slot].owning_device_slot = SlotOf(dev, kDeviceBase);
    if (out != nullptr)
        *out = HandleFor(kQueueBase, slot);
    return VkResult::Success;
}

VkResult VkQueueWaitIdle(VkQueue q)
{
    if (!HandleInRange(q, kQueueBase) || !PoolIsLive(g_queue_pool, SlotOf(q, kQueueBase)))
        return VkResult::ErrorInitializationFailed;
    return VkResult::Success; // no real queue to drain
}

VkResult VkDeviceWaitIdle(VkDevice dev)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    return VkResult::Success;
}

// -------------------------------------------------------------------
// Memory + buffer + image + view.
// -------------------------------------------------------------------

VkResult VkAllocateMemory(VkDevice dev, u64 size, u32 memory_type_index, VkDeviceMemory* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (size == 0)
        return VkResult::ErrorOutOfDeviceMemory;
    // Memory type 0 = DEVICE_LOCAL, 1 = HOST_VISIBLE+COHERENT.
    // (See VkGetPhysicalDeviceMemoryProperties.)
    if (memory_type_index >= 2)
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_memory_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    auto& rec = g_memory_data[slot];
    rec.size = size;
    rec.type_index = memory_type_index;
    rec.host_visible = (memory_type_index == 1);
    rec.map_count = 0;
    rec.host_ptr = nullptr;
    if (rec.host_visible)
    {
        // Back host-visible memory with kheap so vkMapMemory can
        // hand the caller a real pointer they can read/write.
        // DEVICE_LOCAL stays nullptr — caller can't map it anyway.
        rec.host_ptr = mm::KMalloc(size);
        if (rec.host_ptr == nullptr)
        {
            (void)PoolFree(g_memory_pool, slot);
            return VkResult::ErrorOutOfDeviceMemory;
        }
    }
    if (out != nullptr)
        *out = HandleFor(kMemoryBase, slot);
    return VkResult::Success;
}

void VkFreeMemory(VkDevice dev, VkDeviceMemory mem)
{
    (void)dev;
    if (mem == 0 || !HandleInRange(mem, kMemoryBase))
        return;
    const u32 slot = SlotOf(mem, kMemoryBase);
    if (!PoolIsLive(g_memory_pool, slot))
        return;
    if (g_memory_data[slot].host_ptr != nullptr)
    {
        mm::KFree(g_memory_data[slot].host_ptr);
        g_memory_data[slot].host_ptr = nullptr;
    }
    (void)PoolFree(g_memory_pool, slot);
}

VkResult VkMapMemory(VkDevice dev, VkDeviceMemory mem, u64 offset, u64 size, void** out_ptr)
{
    (void)size;
    if (out_ptr == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(mem, kMemoryBase) || !PoolIsLive(g_memory_pool, SlotOf(mem, kMemoryBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_memory_data[SlotOf(mem, kMemoryBase)];
    if (!rec.host_visible || rec.host_ptr == nullptr)
        return VkResult::ErrorMemoryMapFailed;
    if (offset >= rec.size)
        return VkResult::ErrorMemoryMapFailed;
    ++rec.map_count;
    ++g_memory_maps;
    *out_ptr = static_cast<u8*>(rec.host_ptr) + offset;
    return VkResult::Success;
}

void VkUnmapMemory(VkDevice dev, VkDeviceMemory mem)
{
    (void)dev;
    if (!HandleInRange(mem, kMemoryBase) || !PoolIsLive(g_memory_pool, SlotOf(mem, kMemoryBase)))
        return;
    auto& rec = g_memory_data[SlotOf(mem, kMemoryBase)];
    if (rec.map_count > 0)
        --rec.map_count;
}

VkResult VkFlushMappedMemoryRanges(VkDevice dev, u32 count, const VkDeviceMemory* mems)
{
    (void)dev;
    (void)count;
    (void)mems;
    // Memory type 1 advertises HOST_COHERENT, so flushes are
    // implicit; this entry is here for spec compatibility.
    return VkResult::Success;
}

VkResult VkInvalidateMappedMemoryRanges(VkDevice dev, u32 count, const VkDeviceMemory* mems)
{
    (void)dev;
    (void)count;
    (void)mems;
    return VkResult::Success;
}

VkResult VkCreateBuffer(VkDevice dev, u64 size, VkBuffer* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_buffer_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_buffer_data[slot] = BufferRecord{};
    g_buffer_data[slot].size = size;
    if (out != nullptr)
        *out = HandleFor(kBufferBase, slot);
    return VkResult::Success;
}

void VkDestroyBuffer(VkDevice dev, VkBuffer buf)
{
    (void)dev;
    if (buf == 0 || !HandleInRange(buf, kBufferBase))
        return;
    (void)PoolFree(g_buffer_pool, SlotOf(buf, kBufferBase));
}

VkResult VkBindBufferMemory(VkDevice dev, VkBuffer buf, VkDeviceMemory mem, u64 offset)
{
    (void)dev;
    if (!HandleInRange(buf, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buf, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(mem, kMemoryBase) || !PoolIsLive(g_memory_pool, SlotOf(mem, kMemoryBase)))
        return VkResult::ErrorInitializationFailed;
    auto& buf_rec = g_buffer_data[SlotOf(buf, kBufferBase)];
    auto& mem_rec = g_memory_data[SlotOf(mem, kMemoryBase)];
    if (offset > mem_rec.size || offset + buf_rec.size > mem_rec.size)
        return VkResult::ErrorInitializationFailed;
    buf_rec.memory_bound = true;
    buf_rec.bound_memory = mem;
    buf_rec.backing_offset = offset;
    buf_rec.backing = (mem_rec.host_ptr != nullptr) ? static_cast<u8*>(mem_rec.host_ptr) + offset : nullptr;
    return VkResult::Success;
}

VkResult VkCreateImage(VkDevice dev, VkExtent3D extent, u32 flags, VkImage* out)
{
    LogOnce(EpCreateImage, "vkCreateImage");
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    // Bound the extent so `VkGetImageMemoryRequirements` can't be
    // tricked into computing `width*height*4` past u64 — and so a
    // future real-GPU bring-up doesn't try to back a 4 PB image.
    // The advertised `maxExtent` from VkGetPhysicalDeviceImage-
    // FormatProperties is {16384, 16384, 1}; enforce the same cap
    // here at creation time.
    constexpr u32 kMaxImageDim = 16384;
    if (extent.width == 0 || extent.width > kMaxImageDim || extent.height == 0 || extent.height > kMaxImageDim ||
        extent.depth == 0 || extent.depth > 1)
    {
        return VkResult::ErrorInitializationFailed;
    }
    u32 slot = 0;
    if (!PoolAlloc(g_image_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_image_data[slot].extent = extent;
    g_image_data[slot].flags = flags;
    g_image_data[slot].memory_bound = false;
    g_image_data[slot].backing = nullptr;
    if (out != nullptr)
        *out = HandleFor(kImageBase, slot);
    return VkResult::Success;
}

void VkDestroyImage(VkDevice dev, VkImage img)
{
    (void)dev;
    if (img == 0 || !HandleInRange(img, kImageBase))
        return;
    (void)PoolFree(g_image_pool, SlotOf(img, kImageBase));
}

VkResult VkBindImageMemory(VkDevice dev, VkImage img, VkDeviceMemory mem, u64 offset)
{
    (void)dev;
    if (!HandleInRange(img, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(img, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(mem, kMemoryBase) || !PoolIsLive(g_memory_pool, SlotOf(mem, kMemoryBase)))
        return VkResult::ErrorInitializationFailed;
    const u32 islot = SlotOf(img, kImageBase);
    const u32 mslot = SlotOf(mem, kMemoryBase);
    g_image_data[islot].memory_bound = true;
    // Capture the backing pointer at bind time so the texture-
    // sample path can fetch texels without walking the memory
    // pool. The backing is offset-into the host-visible block
    // bound; when the memory wasn't host-visible (host_ptr nullptr)
    // we leave backing as null and the sampler falls back to the
    // diagnostic checkerboard.
    if (g_memory_data[mslot].host_visible && g_memory_data[mslot].host_ptr != nullptr)
        g_image_data[islot].backing = static_cast<u8*>(g_memory_data[mslot].host_ptr) + offset;
    else
        g_image_data[islot].backing = nullptr;
    return VkResult::Success;
}

VkResult VkCreateImageView(VkDevice dev, VkImage img, VkImageView* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(img, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(img, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_imageview_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_imageview_data[slot].image = img;
    if (out != nullptr)
        *out = HandleFor(kImageViewBase, slot);
    return VkResult::Success;
}

void VkDestroyImageView(VkDevice dev, VkImageView view)
{
    (void)dev;
    if (view == 0 || !HandleInRange(view, kImageViewBase))
        return;
    (void)PoolFree(g_imageview_pool, SlotOf(view, kImageViewBase));
}

// -------------------------------------------------------------------
// Render pass + framebuffer.
// -------------------------------------------------------------------

VkResult VkCreateRenderPass(VkDevice dev, VkRenderPass* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_renderpass_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kRenderPassBase, slot);
    return VkResult::Success;
}

void VkDestroyRenderPass(VkDevice dev, VkRenderPass rp)
{
    (void)dev;
    if (rp == 0 || !HandleInRange(rp, kRenderPassBase))
        return;
    (void)PoolFree(g_renderpass_pool, SlotOf(rp, kRenderPassBase));
}

VkResult VkCreateFramebuffer(VkDevice dev, VkRenderPass rp, VkImageView attachment, VkExtent2D extent,
                             VkFramebuffer* out)
{
    (void)extent;
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(rp, kRenderPassBase) || !PoolIsLive(g_renderpass_pool, SlotOf(rp, kRenderPassBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(attachment, kImageViewBase) || !PoolIsLive(g_imageview_pool, SlotOf(attachment, kImageViewBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_framebuffer_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_framebuffer_data[slot].attachment = attachment;
    if (out != nullptr)
        *out = HandleFor(kFramebufferBase, slot);
    return VkResult::Success;
}

void VkDestroyFramebuffer(VkDevice dev, VkFramebuffer fb)
{
    (void)dev;
    if (fb == 0 || !HandleInRange(fb, kFramebufferBase))
        return;
    (void)PoolFree(g_framebuffer_pool, SlotOf(fb, kFramebufferBase));
}

// -------------------------------------------------------------------
// Shader module + pipeline.
// -------------------------------------------------------------------

namespace internal
{

// SPIR-V opcodes we recognise.  Full opcode table is huge — only
// the instructions whose presence is interesting for v1
// diagnostics are listed.  Reference: SPIR-V 1.6 spec § 3.37.
constexpr u16 kOpSource = 3;
constexpr u16 kOpName = 5;
constexpr u16 kOpMemoryModel = 14;
constexpr u16 kOpEntryPoint = 15;
constexpr u16 kOpExecutionMode = 16;
constexpr u16 kOpCapability = 17;
constexpr u16 kOpDecorate = 71;
constexpr u16 kOpMemberDecorate = 72;

ShaderModuleInfo ParseSpirv(const u32* code, u64 byte_size)
{
    ShaderModuleInfo info{};
    if (code == nullptr || byte_size < 5u * 4u || (byte_size & 3u) != 0u)
        return info;
    if (code[0] != 0x07230203u)
        return info;

    info.word_count = static_cast<u32>(byte_size / 4u);
    info.generator = code[2];
    info.bound = code[3];

    u32 i = 5; // skip 5-word header
    while (i < info.word_count)
    {
        const u32 instr = code[i];
        const u32 wc = instr >> 16;
        const u16 op = static_cast<u16>(instr & 0xFFFFu);
        if (wc == 0 || i + wc > info.word_count)
            return info; // malformed — leave info.valid == false
        switch (op)
        {
        case kOpEntryPoint:
            ++info.entry_point_count;
            // First entry point's execution model + name fed back
            // for diagnostics.  Layout: [instr][model][id][name...].
            if (info.entry_point_count == 1 && wc >= 4)
            {
                info.first_execution_model = code[i + 1];
                const u32 name_words = wc - 3;
                const u32 name_max_bytes = name_words * 4u;
                const auto* name_bytes = reinterpret_cast<const char*>(&code[i + 3]);
                u32 j = 0;
                const u32 cap = kMaxEntryPointName - 1;
                while (j < name_max_bytes && j < cap && name_bytes[j] != '\0')
                {
                    info.first_entry_name[j] = name_bytes[j];
                    ++j;
                }
                info.first_entry_name[j] = '\0';
            }
            break;
        case kOpExecutionMode:
            ++info.execution_mode_count;
            break;
        case kOpCapability:
            ++info.capability_count;
            break;
        case kOpDecorate:
        case kOpMemberDecorate:
            ++info.decoration_count;
            break;
        case kOpSource:
        case kOpName:
        case kOpMemoryModel:
        default:
            // Recognised but uncounted — instruction stream still
            // advances by `wc` words.
            break;
        }
        i += wc;
    }
    info.valid = true;
    return info;
}

} // namespace internal

VkResult VkCreateShaderModule(VkDevice dev, const u32* code, u64 code_size_bytes, VkShaderModule* out)
{
    LogOnce(EpCreateShaderModule, "vkCreateShaderModule");
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (code == nullptr || code_size_bytes < 4 || (code_size_bytes & 3u) != 0)
    {
        ++g_invalid_spirv_rejections;
        return VkResult::ErrorInvalidShaderNV;
    }
    // SPIR-V magic word (little-endian): 0x07230203.  Spec requires
    // it as the first word of every SPIR-V module.
    if (code[0] != 0x07230203u)
    {
        ++g_invalid_spirv_rejections;
        return VkResult::ErrorInvalidShaderNV;
    }
    u32 slot = 0;
    if (!PoolAlloc(g_shader_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_shader_data[slot].byte_size = code_size_bytes;
    g_shader_data[slot].info = ParseSpirv(code, code_size_bytes);
    g_shader_data[slot].code_copy = nullptr;
    g_shader_data[slot].code_word_count = 0;
    g_shader_data[slot].spirv_program = nullptr;
    if (g_shader_data[slot].info.valid)
    {
        ++g_spirv_modules_parsed;
        g_spirv_entry_points_seen += g_shader_data[slot].info.entry_point_count;
        g_spirv_capabilities_seen += g_shader_data[slot].info.capability_count;
        g_spirv_decorations_seen += g_shader_data[slot].info.decoration_count;
        g_spirv_execution_modes_seen += g_shader_data[slot].info.execution_mode_count;

        // Take an owning copy of the SPIR-V word stream and try to
        // build a v1 interpreter program. The copy outlives the
        // caller's pointer; the program is what the rasterizer hook
        // executes when a graphics pipeline binds this module.
        // Failures here leave `spirv_program = nullptr`, which the
        // rasterizer treats as "no shader available — fall back to
        // the fixed-function path" rather than refusing the module.
        const u64 words = code_size_bytes / 4u;
        void* copy = mm::KMalloc(words * 4u);
        if (copy != nullptr)
        {
            auto* dst = static_cast<u32*>(copy);
            for (u64 i = 0; i < words; ++i)
                dst[i] = code[i];
            g_shader_data[slot].code_copy = dst;
            g_shader_data[slot].code_word_count = words;
            void* prog_mem = mm::KMalloc(sizeof(spirv::Program));
            if (prog_mem != nullptr)
            {
                auto* prog = static_cast<spirv::Program*>(prog_mem);
                if (spirv::Parse(dst, static_cast<u32>(words), prog))
                {
                    g_shader_data[slot].spirv_program = prog;
                    ++g_spirv_programs_built;
                }
                else
                {
                    mm::KFree(prog_mem);
                    ++g_spirv_program_build_failures;
                }
            }
        }
    }
    if (out != nullptr)
        *out = HandleFor(kShaderBase, slot);
    return VkResult::Success;
}

VkResult VkGetShaderModuleInfoDuet(VkShaderModule module, ShaderModuleInfo* out)
{
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(module, kShaderBase) || !PoolIsLive(g_shader_pool, SlotOf(module, kShaderBase)))
        return VkResult::ErrorInitializationFailed;
    *out = g_shader_data[SlotOf(module, kShaderBase)].info;
    return VkResult::Success;
}

void VkDestroyShaderModule(VkDevice dev, VkShaderModule module)
{
    (void)dev;
    if (module == 0 || !HandleInRange(module, kShaderBase))
        return;
    const u32 slot = SlotOf(module, kShaderBase);
    if (g_shader_data[slot].spirv_program != nullptr)
    {
        mm::KFree(g_shader_data[slot].spirv_program);
        g_shader_data[slot].spirv_program = nullptr;
    }
    if (g_shader_data[slot].code_copy != nullptr)
    {
        mm::KFree(g_shader_data[slot].code_copy);
        g_shader_data[slot].code_copy = nullptr;
        g_shader_data[slot].code_word_count = 0;
    }
    (void)PoolFree(g_shader_pool, slot);
}

VkResult VkCreatePipelineLayout(VkDevice dev, VkPipelineLayout* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_pipelinelayout_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kPipelineLayoutBase, slot);
    return VkResult::Success;
}

void VkDestroyPipelineLayout(VkDevice dev, VkPipelineLayout layout)
{
    (void)dev;
    if (layout == 0 || !HandleInRange(layout, kPipelineLayoutBase))
        return;
    (void)PoolFree(g_pipelinelayout_pool, SlotOf(layout, kPipelineLayoutBase));
}

VkResult VkCreateGraphicsPipeline(VkDevice dev, VkPipelineLayout layout, VkShaderModule vs, VkShaderModule fs,
                                  VkPipeline* out)
{
    LogOnce(EpCreateGraphicsPipeline, "vkCreateGraphicsPipelines");
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(layout, kPipelineLayoutBase) ||
        !PoolIsLive(g_pipelinelayout_pool, SlotOf(layout, kPipelineLayoutBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(vs, kShaderBase) || !PoolIsLive(g_shader_pool, SlotOf(vs, kShaderBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(fs, kShaderBase) || !PoolIsLive(g_shader_pool, SlotOf(fs, kShaderBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_pipeline_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_pipeline_data[slot].vertex_shader = vs;
    g_pipeline_data[slot].fragment_shader = fs;
    g_pipeline_data[slot].compute_shader = 0;
    g_pipeline_data[slot].vertex_binding_count = 0;
    g_pipeline_data[slot].vertex_attribute_count = 0;
    if (out != nullptr)
        *out = HandleFor(kPipelineBase, slot);
    return VkResult::Success;
}

VkResult VkCreateComputePipeline(VkDevice dev, VkPipelineLayout layout, VkShaderModule cs, VkPipeline* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(layout, kPipelineLayoutBase) ||
        !PoolIsLive(g_pipelinelayout_pool, SlotOf(layout, kPipelineLayoutBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(cs, kShaderBase) || !PoolIsLive(g_shader_pool, SlotOf(cs, kShaderBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_pipeline_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_pipeline_data[slot].vertex_shader = 0;
    g_pipeline_data[slot].fragment_shader = 0;
    g_pipeline_data[slot].compute_shader = cs;
    g_pipeline_data[slot].vertex_binding_count = 0;
    g_pipeline_data[slot].vertex_attribute_count = 0;
    if (out != nullptr)
        *out = HandleFor(kPipelineBase, slot);
    return VkResult::Success;
}

VkResult VkSetVertexInputDuet(VkPipeline pipe, const VkVertexBindingDuet* bindings, u32 binding_count,
                              const VkVertexAttributeDuet* attributes, u32 attribute_count)
{
    if (!HandleInRange(pipe, kPipelineBase) || !PoolIsLive(g_pipeline_pool, SlotOf(pipe, kPipelineBase)))
        return VkResult::ErrorInitializationFailed;
    const u32 slot = SlotOf(pipe, kPipelineBase);
    const u32 nb = (binding_count < kMaxVertexBindings) ? binding_count : kMaxVertexBindings;
    const u32 na = (attribute_count < kMaxVertexAttributes) ? attribute_count : kMaxVertexAttributes;
    g_pipeline_data[slot].vertex_binding_count = nb;
    g_pipeline_data[slot].vertex_attribute_count = na;
    for (u32 i = 0; i < nb; ++i)
        g_pipeline_data[slot].vertex_bindings[i] = bindings[i];
    for (u32 i = 0; i < na; ++i)
        g_pipeline_data[slot].vertex_attributes[i] = attributes[i];
    return VkResult::Success;
}

void VkDestroyPipeline(VkDevice dev, VkPipeline pipe)
{
    (void)dev;
    if (pipe == 0 || !HandleInRange(pipe, kPipelineBase))
        return;
    (void)PoolFree(g_pipeline_pool, SlotOf(pipe, kPipelineBase));
}


// -------------------------------------------------------------------
// Memory requirements + buffer device address.
// -------------------------------------------------------------------

VkResult VkGetBufferMemoryRequirements(VkDevice dev, VkBuffer buffer, VkMemoryRequirements* out)
{
    (void)dev;
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buffer, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    *out = VkMemoryRequirements{};
    out->size = g_buffer_data[SlotOf(buffer, kBufferBase)].size;
    out->alignment = 256;      // matches the spec's nonCoherentAtomSize floor
    out->memoryTypeBits = 0x3; // both memory types are usable
    return VkResult::Success;
}

VkResult VkGetImageMemoryRequirements(VkDevice dev, VkImage image, VkMemoryRequirements* out)
{
    (void)dev;
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    const auto& img = g_image_data[SlotOf(image, kImageBase)];
    *out = VkMemoryRequirements{};
    out->size = static_cast<u64>(img.extent.width) * img.extent.height * 4u; // assume B8G8R8A8
    out->alignment = 4096;
    out->memoryTypeBits = 0x1; // device-local only
    return VkResult::Success;
}

VkResult VkGetDeviceMemoryCommitment(VkDevice dev, VkDeviceMemory mem, u64* committed)
{
    (void)dev;
    if (committed == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(mem, kMemoryBase) || !PoolIsLive(g_memory_pool, SlotOf(mem, kMemoryBase)))
        return VkResult::ErrorInitializationFailed;
    const auto& rec = g_memory_data[SlotOf(mem, kMemoryBase)];
    *committed = (rec.host_ptr != nullptr) ? rec.size : 0;
    return VkResult::Success;
}

u64 VkGetBufferDeviceAddress(VkDevice dev, VkBuffer buffer)
{
    (void)dev;
    if (!HandleInRange(buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buffer, kBufferBase)))
        return 0;
    const auto& buf = g_buffer_data[SlotOf(buffer, kBufferBase)];
    return reinterpret_cast<u64>(buf.backing); // 0 if unbound or device-local-only
}

// -------------------------------------------------------------------
// Dynamic rendering.
// -------------------------------------------------------------------

VkResult VkCmdBeginRendering(VkCommandBuffer cb, VkRect2D render_area, u32 color_attachment_count,
                             const VkRenderingAttachmentInfo* color_attachments)
{
    (void)render_area;
    if (color_attachment_count > 0 && color_attachments == nullptr)
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::BeginRendering;
    if (color_attachment_count > 0)
    {
        // Record the first attachment only — single-MRT v0.  Trace
        // the image-view to its image so the replay can paint a
        // clear into the framebuffer when scanout-backed.
        const auto& a = color_attachments[0];
        if (HandleInRange(a.imageView, kImageViewBase) &&
            PoolIsLive(g_imageview_pool, SlotOf(a.imageView, kImageViewBase)))
        {
            op.image = g_imageview_data[SlotOf(a.imageView, kImageViewBase)].image;
        }
        op.color = a.clearValue;
        // Stash loadOp in fill_pattern (unused for this opcode).
        // Replay only paints when loadOp == 1 (Clear); Load /
        // DontCare update rt_image without overwriting the
        // attachment.
        op.fill_pattern = a.loadOp;
    }
    return AppendOp(cb, op);
}

VkResult VkCmdEndRendering(VkCommandBuffer cb)
{
    CmdRecord op{};
    op.op = CmdOp::EndRendering;
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// Dynamic state setters.
// -------------------------------------------------------------------

VkResult VkCmdSetLineWidth(VkCommandBuffer cb, float line_width)
{
    (void)line_width;
    CmdRecord op{};
    op.op = CmdOp::SetLineWidth;
    return AppendOp(cb, op);
}

VkResult VkCmdSetDepthBias(VkCommandBuffer cb, float constant_factor, float clamp, float slope_factor)
{
    (void)constant_factor;
    (void)clamp;
    (void)slope_factor;
    CmdRecord op{};
    op.op = CmdOp::SetDepthBias;
    return AppendOp(cb, op);
}

VkResult VkCmdSetBlendConstants(VkCommandBuffer cb, const float blend_constants[4])
{
    (void)blend_constants;
    CmdRecord op{};
    op.op = CmdOp::SetBlendConstants;
    return AppendOp(cb, op);
}

VkResult VkCmdSetDepthBounds(VkCommandBuffer cb, float min_depth_bounds, float max_depth_bounds)
{
    (void)min_depth_bounds;
    (void)max_depth_bounds;
    CmdRecord op{};
    op.op = CmdOp::SetDepthBounds;
    return AppendOp(cb, op);
}

VkResult VkCmdSetStencilCompareMask(VkCommandBuffer cb, u32 face_mask, u32 compare_mask)
{
    (void)face_mask;
    (void)compare_mask;
    CmdRecord op{};
    op.op = CmdOp::SetStencilState;
    return AppendOp(cb, op);
}

VkResult VkCmdSetStencilWriteMask(VkCommandBuffer cb, u32 face_mask, u32 write_mask)
{
    (void)face_mask;
    (void)write_mask;
    CmdRecord op{};
    op.op = CmdOp::SetStencilState;
    return AppendOp(cb, op);
}

VkResult VkCmdSetStencilReference(VkCommandBuffer cb, u32 face_mask, u32 reference)
{
    (void)face_mask;
    (void)reference;
    CmdRecord op{};
    op.op = CmdOp::SetStencilState;
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// Debug-utils object naming.
// -------------------------------------------------------------------

VkResult VkSetDebugUtilsObjectNameEXT(VkDevice dev, const VkDebugUtilsObjectNameInfoEXT* info)
{
    (void)dev;
    if (info == nullptr || info->objectHandle == 0 || info->pObjectName == nullptr)
        return VkResult::ErrorInitializationFailed;
    auto& slot = g_debug_label_table[g_debug_label_head];
    slot.handle = info->objectHandle;
    u32 i = 0;
    while (i + 1 < kMaxDebugLabelLen && info->pObjectName[i] != '\0')
    {
        slot.name[i] = info->pObjectName[i];
        ++i;
    }
    slot.name[i] = '\0';
    g_debug_label_head = (g_debug_label_head + 1) % kMaxDebugLabels;
    ++g_debug_labels;
    return VkResult::Success;
}

VkResult VkGetDebugUtilsObjectNameDuet(u64 object_handle, char* out_buf, u32 buf_len)
{
    if (out_buf == nullptr || buf_len == 0)
        return VkResult::ErrorInitializationFailed;
    for (const auto& e : g_debug_label_table)
    {
        if (e.handle == object_handle)
        {
            u32 i = 0;
            while (i + 1 < buf_len && e.name[i] != '\0')
            {
                out_buf[i] = e.name[i];
                ++i;
            }
            out_buf[i] = '\0';
            return VkResult::Success;
        }
    }
    out_buf[0] = '\0';
    return VkResult::Incomplete;
}

namespace internal
{

VkResult AppendCmdLabel(VkCommandBuffer cb, CmdOp tag, const char* label)
{
    CmdRecord op{};
    op.op = tag;
    op.push_size = 0;
    if (label != nullptr)
    {
        u32 i = 0;
        while (i + 1 < kMaxPushConstantBytes && label[i] != '\0')
        {
            op.push_data[i] = static_cast<u8>(label[i]);
            ++i;
        }
        op.push_data[i] = 0;
        op.push_size = i;
    }
    return AppendOp(cb, op);
}

} // namespace internal

VkResult VkCmdBeginDebugUtilsLabelEXT(VkCommandBuffer cb, const char* label)
{
    return AppendCmdLabel(cb, CmdOp::BeginDebugLabel, label);
}

VkResult VkCmdEndDebugUtilsLabelEXT(VkCommandBuffer cb)
{
    return AppendCmdLabel(cb, CmdOp::EndDebugLabel, nullptr);
}

VkResult VkCmdInsertDebugUtilsLabelEXT(VkCommandBuffer cb, const char* label)
{
    return AppendCmdLabel(cb, CmdOp::InsertDebugLabel, label);
}

VkResult VkCmdPushDescriptorSetKHR(VkCommandBuffer cb, VkPipelineBindPoint bind_point, VkPipelineLayout layout, u32 set,
                                   u32 write_count, const VkWriteDescriptorSet* writes)
{
    (void)bind_point;
    (void)layout;
    (void)set;
    if (write_count == 0)
        return VkResult::Success;
    if (writes == nullptr)
        return VkResult::ErrorInitializationFailed;
    // Each write is recorded as its own PushDescriptor op so the
    // counter aggregates correctly.
    for (u32 i = 0; i < write_count; ++i)
    {
        CmdRecord op{};
        op.op = CmdOp::PushDescriptor;
        op.dst_buffer = writes[i].resourceHandle; // store handle in any field
        const VkResult r = AppendOp(cb, op);
        if (r != VkResult::Success)
            return r;
        ++g_push_descriptor_writes;
    }
    return VkResult::Success;
}

VkResult VkAllocateCommandBuffers2(VkDevice dev, VkCommandPool pool, VkCommandBufferLevel level, u32 count,
                                   VkCommandBuffer* out)
{
    const VkResult r = VkAllocateCommandBuffers(dev, pool, count, out);
    if (r != VkResult::Success)
        return r;
    if (level == VkCommandBufferLevel::Secondary)
    {
        for (u32 i = 0; i < count; ++i)
        {
            if (HandleInRange(out[i], kCmdBufBase))
                g_cmdbuf_data[SlotOf(out[i], kCmdBufBase)].is_secondary = true;
        }
    }
    return VkResult::Success;
}

VkResult VkCmdExecuteCommands(VkCommandBuffer cb, u32 count, const VkCommandBuffer* secondaries)
{
    if (count == 0)
        return VkResult::Success;
    if (secondaries == nullptr)
        return VkResult::ErrorInitializationFailed;
    // Validate every secondary up front so a partial record is
    // never appended.  Spec lets a primary cb call execute on
    // multiple secondaries; v0 records each as its own op.
    for (u32 i = 0; i < count; ++i)
    {
        if (!HandleInRange(secondaries[i], kCmdBufBase) ||
            !PoolIsLive(g_cmdbuf_pool, SlotOf(secondaries[i], kCmdBufBase)))
            return VkResult::ErrorInitializationFailed;
        if (!g_cmdbuf_data[SlotOf(secondaries[i], kCmdBufBase)].is_secondary)
            return VkResult::ErrorInitializationFailed; // primary cbs can't be inlined
    }
    for (u32 i = 0; i < count; ++i)
    {
        CmdRecord op{};
        op.op = CmdOp::ExecuteCommands;
        op.secondary_cb = secondaries[i];
        const VkResult r = AppendOp(cb, op);
        if (r != VkResult::Success)
            return r;
    }
    return VkResult::Success;
}

VkResult VkBindBufferMemory2(VkDevice dev, u32 count, const VkBindBufferMemoryInfo* infos)
{
    if (count == 0)
        return VkResult::Success;
    if (infos == nullptr)
        return VkResult::ErrorInitializationFailed;
    for (u32 i = 0; i < count; ++i)
    {
        const VkResult r = VkBindBufferMemory(dev, infos[i].buffer, infos[i].memory, infos[i].memoryOffset);
        if (r != VkResult::Success)
            return r;
    }
    return VkResult::Success;
}

VkResult VkBindImageMemory2(VkDevice dev, u32 count, const VkBindImageMemoryInfo* infos)
{
    if (count == 0)
        return VkResult::Success;
    if (infos == nullptr)
        return VkResult::ErrorInitializationFailed;
    for (u32 i = 0; i < count; ++i)
    {
        const VkResult r = VkBindImageMemory(dev, infos[i].image, infos[i].memory, infos[i].memoryOffset);
        if (r != VkResult::Success)
            return r;
    }
    return VkResult::Success;
}

VkResult VkGetPhysicalDeviceFormatProperties(VkPhysicalDevice phys, u32 format, VkFormatProperties* out)
{
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;
    *out = VkFormatProperties{};
    // Recognised formats use a small DuetOS-internal numbering:
    //   0  -> VK_FORMAT_B8G8R8A8_UNORM (the canonical scanout)
    //   1  -> VK_FORMAT_R8G8B8A8_UNORM (RGBA8, mirror layout)
    //   2  -> VK_FORMAT_R8_UNORM       (single-channel)
    //   3  -> VK_FORMAT_R8G8_UNORM     (two-channel)
    //   4  -> VK_FORMAT_R16_UNORM      (16-bit single-channel)
    //   5  -> VK_FORMAT_R32G32B32A32_SFLOAT (HDR / compute outputs)
    // All carry the same baseline feature set today: sampleable,
    // valid as a color attachment, valid as transfer src/dst.
    // Spec-correct format-specific feature restrictions land when
    // the format-aware sampler / blit paths arrive.
    const u32 baseline = kFormatFeatureSampledImage | kFormatFeatureColorAttachment | kFormatFeatureTransferSrc |
                         kFormatFeatureTransferDst;
    const u32 buffer_baseline = kFormatFeatureTransferSrc | kFormatFeatureTransferDst;
    switch (format)
    {
    case 0: // B8G8R8A8_UNORM
    case 1: // R8G8B8A8_UNORM
    case 2: // R8_UNORM
    case 3: // R8G8_UNORM
    case 4: // R16_UNORM
    case 5: // R32G32B32A32_SFLOAT
        out->linearTilingFeatures = baseline;
        out->optimalTilingFeatures = baseline;
        out->bufferFeatures = buffer_baseline;
        break;
    default:
        // Unknown format reports zero features (the canonical "not
        // supported" answer) but the call still returns Success.
        break;
    }
    return VkResult::Success;
}

VkResult VkGetPhysicalDeviceImageFormatProperties(VkPhysicalDevice phys, u32 format, u32 type, u32 tiling, u32 usage,
                                                  u32 flags, VkImageFormatProperties* out)
{
    (void)type;
    (void)tiling;
    (void)usage;
    (void)flags;
    if (out == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(phys, kPhysDevBase) || !PoolIsLive(g_phys_pool, SlotOf(phys, kPhysDevBase)))
        return VkResult::ErrorInitializationFailed;
    // Accept the same internal format set as
    // VkGetPhysicalDeviceFormatProperties — 0..5 inclusive.
    if (format > 5u)
        return VkResult::ErrorFormatNotSupported;
    *out = VkImageFormatProperties{};
    out->maxExtent = VkExtent3D{16384, 16384, 1};
    out->maxMipLevels = 14; // log2(16384) + 1
    out->maxArrayLayers = 1;
    out->sampleCounts = 1;
    out->maxResourceSize = 256u * 1024u * 1024u;
    return VkResult::Success;
}

// -------------------------------------------------------------------
// Submit replay.
// -------------------------------------------------------------------

namespace internal
{

void PaintScanoutClear(VkImage image, VkClearColorValue color)
{
    if (!HandleInRange(image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(image, kImageBase)))
        return;
    const auto& img = g_image_data[SlotOf(image, kImageBase)];
    if ((img.flags & kImageScanoutBacked) == 0)
        return;
    const auto di = drivers::video::Query();
    if (!di.available)
        return;
    u32 w = img.extent.width;
    u32 h = img.extent.height;
    if (w > di.width)
        w = di.width;
    if (h > di.height)
        h = di.height;
    if (w == 0 || h == 0)
        return;
    drivers::video::FramebufferFillRect(0, 0, w, h, ColorToRgb(color));
    drivers::video::FramebufferAddDamage(0, 0, w, h);
    g_clear_pixels_painted += w * h;
}

void ReplayClear(const CmdRecord& op)
{
    PaintScanoutClear(op.image, op.color);
}

// vkCmdBeginRenderPass replay: trace the framebuffer through its
// image-view to the underlying image; if the image is scanout-
// backed, paint the begin-rp clear color across it.  This is
// what completes the v0 "render-pass clear actually clears"
// loop that was a GAP at the original ICD landing.
void ReplayBeginRenderPass(const CmdRecord& op)
{
    if (!HandleInRange(op.framebuffer, kFramebufferBase) ||
        !PoolIsLive(g_framebuffer_pool, SlotOf(op.framebuffer, kFramebufferBase)))
        return;
    const auto& fb = g_framebuffer_data[SlotOf(op.framebuffer, kFramebufferBase)];
    if (!HandleInRange(fb.attachment, kImageViewBase) ||
        !PoolIsLive(g_imageview_pool, SlotOf(fb.attachment, kImageViewBase)))
        return;
    const auto& view = g_imageview_data[SlotOf(fb.attachment, kImageViewBase)];
    PaintScanoutClear(view.image, op.color);
}

void ReplayCopyBuffer(const CmdRecord& op)
{
    if (!HandleInRange(op.src_buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(op.src_buffer, kBufferBase)))
        return;
    if (!HandleInRange(op.dst_buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(op.dst_buffer, kBufferBase)))
        return;
    const auto& src = g_buffer_data[SlotOf(op.src_buffer, kBufferBase)];
    auto& dst = g_buffer_data[SlotOf(op.dst_buffer, kBufferBase)];
    if (src.backing == nullptr || dst.backing == nullptr)
        return; // not host-visible — no real bytes to move
    if (op.src_offset + op.region_size > src.size)
        return;
    if (op.dst_offset + op.region_size > dst.size)
        return;
    const u8* sp = static_cast<const u8*>(src.backing) + op.src_offset;
    u8* dp = static_cast<u8*>(dst.backing) + op.dst_offset;
    for (u64 i = 0; i < op.region_size; ++i)
        dp[i] = sp[i];
    g_buffer_copy_bytes += static_cast<u32>(op.region_size);
}

void ReplayFillBuffer(const CmdRecord& op)
{
    if (!HandleInRange(op.dst_buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(op.dst_buffer, kBufferBase)))
        return;
    auto& dst = g_buffer_data[SlotOf(op.dst_buffer, kBufferBase)];
    if (dst.backing == nullptr)
        return;
    if (op.dst_offset + op.region_size > dst.size)
        return;
    // vkCmdFillBuffer's region_size must be a multiple of 4
    // and the pattern is a u32 broadcast across the range.
    const u64 words = op.region_size / 4u;
    auto* dp = reinterpret_cast<u32*>(static_cast<u8*>(dst.backing) + op.dst_offset);
    for (u64 i = 0; i < words; ++i)
        dp[i] = op.fill_pattern;
    g_buffer_fill_bytes += static_cast<u32>(words * 4u);
}

void ReplaySetEvent(const CmdRecord& op)
{
    if (!HandleInRange(op.event, kEventBase) || !PoolIsLive(g_event_pool, SlotOf(op.event, kEventBase)))
        return;
    g_event_data[SlotOf(op.event, kEventBase)].signalled = true;
}

void ReplayResetEvent(const CmdRecord& op)
{
    if (!HandleInRange(op.event, kEventBase) || !PoolIsLive(g_event_pool, SlotOf(op.event, kEventBase)))
        return;
    g_event_data[SlotOf(op.event, kEventBase)].signalled = false;
}

void ReplayResetQueryPool(const CmdRecord& op)
{
    if (!HandleInRange(op.query_pool, kQueryPoolBase) ||
        !PoolIsLive(g_query_pool_pool, SlotOf(op.query_pool, kQueryPoolBase)))
        return;
    auto& rec = g_query_pool_data[SlotOf(op.query_pool, kQueryPoolBase)];
    if (op.query_first + op.query_count > rec.query_count)
        return;
    for (u32 i = 0; i < op.query_count; ++i)
    {
        rec.results[op.query_first + i] = 0;
        rec.available[op.query_first + i] = false;
    }
}

void ReplayCommandBuffer(VkCommandBuffer cb); // forward — recursion through ExecuteCommands

void ReplayExecuteCommands(const CmdRecord& op)
{
    if (!HandleInRange(op.secondary_cb, kCmdBufBase) ||
        !PoolIsLive(g_cmdbuf_pool, SlotOf(op.secondary_cb, kCmdBufBase)))
        return;
    const auto& sec = g_cmdbuf_data[SlotOf(op.secondary_cb, kCmdBufBase)];
    if (!sec.is_secondary || sec.state != CbState::Executable)
        return;
    ++g_secondary_executes;
    g_secondary_ops_replayed += sec.op_count;
    ReplayCommandBuffer(op.secondary_cb);
}

void ReplayUpdateBuffer(const CmdRecord& op)
{
    if (!HandleInRange(op.dst_buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(op.dst_buffer, kBufferBase)))
        return;
    auto& dst = g_buffer_data[SlotOf(op.dst_buffer, kBufferBase)];
    if (dst.backing == nullptr)
        return;
    if (op.dst_offset + op.push_size > dst.size)
        return;
    auto* dp = static_cast<u8*>(dst.backing) + op.dst_offset;
    for (u32 i = 0; i < op.push_size; ++i)
        dp[i] = op.push_data[i];
    g_buffer_copy_bytes += op.push_size;
}

void ReplayCopyBufferToImage(const CmdRecord& op)
{
    if (!HandleInRange(op.src_buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(op.src_buffer, kBufferBase)))
        return;
    if (!HandleInRange(op.image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(op.image, kImageBase)))
        return;
    const auto& src = g_buffer_data[SlotOf(op.src_buffer, kBufferBase)];
    const auto& img = g_image_data[SlotOf(op.image, kImageBase)];
    if (src.backing == nullptr)
        return; // not host-visible — nothing to upload
    if ((img.flags & kImageScanoutBacked) == 0)
        return; // non-scanout images have no real storage in v0
    const auto di = drivers::video::Query();
    if (!di.available)
        return;
    const u32 region_w = op.region_width;
    const u32 region_h = op.region_height;
    if (region_w == 0 || region_h == 0)
        return;
    const u64 byte_count = static_cast<u64>(region_w) * region_h * 4u;
    if (op.src_offset + byte_count > src.size)
        return;
    // src.backing came from KMalloc (u64-aligned). The
    // src_offset that lands `pixels` at a non-u32-aligned
    // address would be a caller bug — UBSAN flags it as
    // type-mismatch and FramebufferBlit's u32 stores would
    // emit unaligned ops. Refuse rather than propagate.
    const u8* base = static_cast<const u8*>(src.backing) + op.src_offset;
    if ((reinterpret_cast<uptr>(base) & 3u) != 0)
        return;
    const u32* pixels = reinterpret_cast<const u32*>(base);
    // FramebufferBlit expects a tightly packed src_pitch_px == width.
    drivers::video::FramebufferBlit(0, 0, pixels, region_w, region_h, region_w);
    drivers::video::FramebufferAddDamage(0, 0, region_w, region_h);
    g_image_upload_pixels += region_w * region_h;
}

void ReplayWriteQueryResult(const CmdRecord& op, bool is_timestamp)
{
    if (!HandleInRange(op.query_pool, kQueryPoolBase) ||
        !PoolIsLive(g_query_pool_pool, SlotOf(op.query_pool, kQueryPoolBase)))
        return;
    auto& rec = g_query_pool_data[SlotOf(op.query_pool, kQueryPoolBase)];
    if (op.query_index >= rec.query_count)
        return;
    // Timestamp queries write the kernel monotonic clock (ns).
    // Occlusion / pipeline-statistics queries write a counter
    // that increments per replay so the self-test can prove
    // ordering.  Both go through the same slot.
    if (is_timestamp)
        rec.results[op.query_index] = duetos::time::MonotonicNs();
    else
        rec.results[op.query_index] = static_cast<u64>(g_queries_executed) + 1u;
    rec.available[op.query_index] = true;
    ++g_queries_executed;
}

// Resolve a framebuffer handle to its underlying image (via the
// single attached image view). Returns 0 when any link in the chain
// is dead, which signals the rasterizer / clear paths to skip.
static VkImage ResolveFramebufferImage(VkFramebuffer fb_handle)
{
    if (!HandleInRange(fb_handle, kFramebufferBase) ||
        !PoolIsLive(g_framebuffer_pool, SlotOf(fb_handle, kFramebufferBase)))
        return 0;
    const auto& fb = g_framebuffer_data[SlotOf(fb_handle, kFramebufferBase)];
    if (!HandleInRange(fb.attachment, kImageViewBase) ||
        !PoolIsLive(g_imageview_pool, SlotOf(fb.attachment, kImageViewBase)))
        return 0;
    return g_imageview_data[SlotOf(fb.attachment, kImageViewBase)].image;
}

void ReplayCommandBuffer(VkCommandBuffer cb)
{
    if (!HandleInRange(cb, kCmdBufBase) || !PoolIsLive(g_cmdbuf_pool, SlotOf(cb, kCmdBufBase)))
        return;
    const auto& rec = g_cmdbuf_data[SlotOf(cb, kCmdBufBase)];
    if (rec.state != CbState::Executable)
        return;

    // Per-replay state shadow. Tracks the bound state the v1
    // rasterizer needs for Draw / DrawIndexed dispatch:
    //   * render-target image (set by BeginRenderPass /
    //     BeginRendering / ClearColorImage),
    //   * binding-0 vertex buffer + offset (set by
    //     BindVertexBuffer),
    //   * index buffer + offset + type (set by BindIndexBuffer),
    //   * primitive topology (set by SetPrimitiveTopology; defaults
    //     to TriangleList = 3 per spec when never set),
    //   * scissor rect (set by SetScissor).
    // Reset per command-buffer; a secondary cb invoked via
    // ExecuteCommands gets its own state via the recursive call.
    RasterState st{};
    st.topology = 3; // TriangleList
    {
        const auto di = drivers::video::Query();
        if (di.available)
        {
            st.fb_w = di.width;
            st.fb_h = di.height;
        }
    }

    for (u32 i = 0; i < rec.op_count; ++i)
    {
        const auto& op = rec.ops[i];
        ++g_command_replayed;
        switch (op.op)
        {
        case CmdOp::ClearColorImage:
            ReplayClear(op);
            st.rt_image = op.image;
            break;
        case CmdOp::BeginRenderPass:
            ReplayBeginRenderPass(op);
            st.rt_image = ResolveFramebufferImage(op.framebuffer);
            break;
        case CmdOp::CopyBuffer:
            ReplayCopyBuffer(op);
            break;
        case CmdOp::FillBuffer:
            ReplayFillBuffer(op);
            break;
        case CmdOp::PipelineBarrier:
            ++g_pipeline_barriers;
            break;
        case CmdOp::PushConstants:
            ++g_push_constant_writes;
            break;
        case CmdOp::Dispatch:
            ++g_dispatches;
            // Route through the shader-rasterizer's compute path
            // when a compute pipeline with parseable CS Program is
            // bound. Returns true on actual execution; false on
            // graphics-only / no-shader pipeline (counter still
            // ticked so the dispatch is observable to tests).
            (void)ShaderDispatchCompute(st, op.dispatch_x, op.dispatch_y, op.dispatch_z);
            break;
        case CmdOp::SetEvent:
            ReplaySetEvent(op);
            break;
        case CmdOp::ResetEvent:
            ReplayResetEvent(op);
            break;
        case CmdOp::ResetQueryPool:
            ReplayResetQueryPool(op);
            break;
        case CmdOp::EndQuery:
            ReplayWriteQueryResult(op, /*is_timestamp=*/false);
            break;
        case CmdOp::WriteTimestamp:
            ReplayWriteQueryResult(op, /*is_timestamp=*/true);
            break;
        case CmdOp::CopyBufferToImage:
            ReplayCopyBufferToImage(op);
            break;
        case CmdOp::UpdateBuffer:
            ReplayUpdateBuffer(op);
            break;
        case CmdOp::BeginRendering:
            // Dynamic rendering's loadOp gates the clear paint —
            // Clear (1) repaints the attachment, Load (0) and
            // DontCare (2) leave existing pixels alone. Either way
            // the attachment image becomes the active render
            // target for subsequent Draw ops.
            if (op.fill_pattern == 1u)
                PaintScanoutClear(op.image, op.color);
            st.rt_image = op.image;
            ++g_dynamic_renderings;
            break;
        case CmdOp::CopyImage: // no real image storage in v0
        case CmdOp::BlitImage:
        case CmdOp::CopyImageToBuffer:
        case CmdOp::ResolveImage:
        case CmdOp::ClearAttachments: // no concept of bound attachments outside RP begin
        case CmdOp::ExecuteCommands:
            ReplayExecuteCommands(op);
            break;
        case CmdOp::EndRendering:
        case CmdOp::SetLineWidth:
        case CmdOp::SetDepthBias:
        case CmdOp::SetBlendConstants:
        case CmdOp::SetDepthBounds:
        case CmdOp::SetStencilState:
        case CmdOp::BeginDebugLabel:
        case CmdOp::EndDebugLabel:
        case CmdOp::InsertDebugLabel:
        case CmdOp::PushDescriptor:
            break;
        case CmdOp::BindVertexBuffer:
            if (op.vertex_binding == 0)
            {
                st.vertex_buffer = op.vertex_buffer;
                st.vertex_offset = op.vertex_offset_bytes;
            }
            break;
        case CmdOp::BindIndexBuffer:
            st.index_buffer = op.index_buffer;
            st.index_offset = op.index_offset;
            st.index_type = op.index_type;
            st.has_index_buffer = true;
            break;
        case CmdOp::SetScissor:
            // Recorder stashes the first scissor rect in `op.area`.
            // A zero-extent rect means "scissor disabled" for the
            // rasterizer's purposes.
            if (op.area.extent.width != 0 && op.area.extent.height != 0)
            {
                st.scissor = op.area;
                st.has_scissor = true;
            }
            else
            {
                st.has_scissor = false;
            }
            break;
        case CmdOp::SetPrimitiveTopology:
            // Recorder stashes the topology in `op.vertex_count`.
            st.topology = op.vertex_count;
            break;
        case CmdOp::SetDepthTestEnable:
            st.depth_test = (op.vertex_count != 0u);
            break;
        case CmdOp::SetDepthWriteEnable:
            st.depth_write = (op.vertex_count != 0u);
            break;
        case CmdOp::SetDepthCompareOp:
            st.depth_compare = op.vertex_count;
            break;
        case CmdOp::SetVertexFormatDuet:
            st.vertex_format = op.vertex_count;
            break;
        case CmdOp::SetCullMode:
            st.cull_mode = op.vertex_count;
            break;
        case CmdOp::SetFrontFace:
            st.front_face = op.vertex_count;
            break;
        case CmdOp::ClearDepthStencilImage:
            // Spec: the depth float in `op.depth_bits` is in
            // [0.0, 1.0]; we map it to the u16 unorm value. To
            // avoid pulling in soft-float, recognise just the
            // canonical 0.0 / 1.0 bit patterns plus a "treat
            // anything else as 1.0" fallback — every real caller
            // is going to clear to 0.0 (near) or 1.0 (far).
            if (op.image == 0 ||
                (HandleInRange(op.image, kImageBase) && PoolIsLive(g_image_pool, SlotOf(op.image, kImageBase))))
            {
                const u16 clear_val = (op.depth_bits == 0u) ? 0u : 0xFFFFu;
                if (DepthSurfaceGetOrAlloc() != nullptr)
                    DepthSurfaceClear(clear_val);
            }
            break;
        case CmdOp::Draw:
            // Try the SPIR-V shader-based rasterizer first; it
            // returns true if the bound pipeline has VS+FS programs
            // matching the supported v1 shape and the draw actually
            // painted. On false the fixed-function fallback runs
            // (DuetOS v0/v1 vertex format + Gouraud raster).
            if (!ShaderRasterizeDraw(st, op.first_vertex, op.vertex_count))
                RasterizeDuetDraw(st, op.first_vertex, op.vertex_count);
            break;
        case CmdOp::DrawIndexed:
            if (!ShaderRasterizeDrawIndexed(st, op.first_index, op.index_count, op.vertex_offset))
                RasterizeDuetDrawIndexed(st, op.first_index, op.index_count, op.vertex_offset);
            break;
        case CmdOp::BindPipeline:
            // Record the pipeline handle so the shader-rasterizer
            // hook can fetch (vs, fs) and decide whether to take
            // the SPIR-V path.
            st.bound_pipeline = op.pipeline;
            break;
        case CmdOp::BindDescriptorSets:
            // Stash the first bound set for the next draw — the
            // shader-rasterizer hook walks its bindings via
            // DescriptorSetRecord to populate the SPIR-V
            // program's descriptor table.
            st.bound_descriptor_set = op.descriptor_set;
            break;
        case CmdOp::WaitEvents: // no-op replay (events already signalled)
        case CmdOp::BeginQuery: // pairs with EndQuery — write happens at End
        case CmdOp::EndRenderPass:
        case CmdOp::SetViewport:
        // Indirect / dynamic-state-2 / sync2 / subpass / extended-query
        // recorded entries — no GPU side effect in v0; the AppendOp at
        // record time already ticked the per-op counter, so the
        // replay walk just acknowledges and moves on.
        case CmdOp::DrawIndirect:
        case CmdOp::DrawIndexedIndirect:
        case CmdOp::DispatchIndirect:
        case CmdOp::SetStencilTestEnable:
        case CmdOp::SetStencilOp:
        case CmdOp::SetDepthBoundsTestEnable:
        case CmdOp::SetViewportWithCount:
        case CmdOp::SetScissorWithCount:
        case CmdOp::BindVertexBuffers2:
        case CmdOp::NextSubpass:
        case CmdOp::CopyQueryPoolResults:
        case CmdOp::BeginQueryIndexed:
        case CmdOp::EndQueryIndexed:
        case CmdOp::SetEvent2:
        case CmdOp::ResetEvent2:
        case CmdOp::WaitEvents2:
        case CmdOp::PipelineBarrier2:
        case CmdOp::None:
            break;
        }
    }
}

} // namespace internal

VkResult VkQueueSubmit(VkQueue q, u32 cb_count, const VkCommandBuffer* cbs, VkFence signal_fence)
{
    LogOnce(EpQueueSubmit, "vkQueueSubmit");
    if (!HandleInRange(q, kQueueBase) || !PoolIsLive(g_queue_pool, SlotOf(q, kQueueBase)))
        return VkResult::ErrorInitializationFailed;
    if (cbs == nullptr && cb_count != 0)
        return VkResult::ErrorInitializationFailed;
    ++g_queue_submits;
    for (u32 i = 0; i < cb_count; ++i)
        ReplayCommandBuffer(cbs[i]);
    // signal_fence — fences in this v0 ICD are pre-signalled
    // sentinels, so the submit doesn't need to do anything to
    // drive vkWaitForFences to Success.
    (void)signal_fence;
    return VkResult::Success;
}

// -------------------------------------------------------------------
// Sync primitives.
// -------------------------------------------------------------------

VkResult VkCreateFence(VkDevice dev, bool signalled, VkFence* out)
{
    (void)signalled;
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_fence_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kFenceBase, slot);
    return VkResult::Success;
}

void VkDestroyFence(VkDevice dev, VkFence fence)
{
    (void)dev;
    if (fence == 0 || !HandleInRange(fence, kFenceBase))
        return;
    (void)PoolFree(g_fence_pool, SlotOf(fence, kFenceBase));
}

VkResult VkResetFences(VkDevice dev, u32 count, const VkFence* fences)
{
    (void)dev;
    (void)count;
    (void)fences;
    return VkResult::Success;
}

VkResult VkWaitForFences(VkDevice dev, u32 count, const VkFence* fences, u64 timeout_ns)
{
    (void)dev;
    (void)timeout_ns;
    if (fences == nullptr && count != 0)
        return VkResult::ErrorInitializationFailed;
    // All submits are synchronous in this ICD, so any fence the
    // caller is waiting on is already "signalled".
    return VkResult::Success;
}

VkResult VkCreateSemaphore(VkDevice dev, VkSemaphore* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_semaphore_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kSemaphoreBase, slot);
    return VkResult::Success;
}

void VkDestroySemaphore(VkDevice dev, VkSemaphore sem)
{
    (void)dev;
    if (sem == 0 || !HandleInRange(sem, kSemaphoreBase))
        return;
    (void)PoolFree(g_semaphore_pool, SlotOf(sem, kSemaphoreBase));
}


// -------------------------------------------------------------------
// Stats accessor — graphics.cpp's GraphicsStatsRead reads this and
// then overlays the D3D-side counters.
// -------------------------------------------------------------------

GraphicsStats VkStatsSnapshot()
{
    GraphicsStats s{};
    s.vk_instances_live = g_instance_pool.live;
    s.vk_instances_created = g_instance_pool.created;
    s.vk_instances_destroyed = g_instance_pool.destroyed;
    s.vk_devices_live = g_device_pool.live;
    s.vk_devices_created = g_device_pool.created;
    s.vk_devices_destroyed = g_device_pool.destroyed;
    s.vk_command_pools_live = g_cmdpool_pool.live;
    s.vk_command_buffers_live = g_cmdbuf_pool.live;
    s.vk_shader_modules_live = g_shader_pool.live;
    s.vk_pipelines_live = g_pipeline_pool.live;
    s.vk_render_passes_live = g_renderpass_pool.live;
    s.vk_framebuffers_live = g_framebuffer_pool.live;
    s.vk_images_live = g_image_pool.live;
    s.vk_image_views_live = g_imageview_pool.live;
    s.vk_buffers_live = g_buffer_pool.live;
    s.vk_device_memory_live = g_memory_pool.live;
    s.vk_fences_live = g_fence_pool.live;
    s.vk_semaphores_live = g_semaphore_pool.live;
    s.vk_pipeline_layouts_live = g_pipelinelayout_pool.live;
    s.vk_descriptor_set_layouts_live = g_desc_set_layout_pool.live;
    s.vk_descriptor_pools_live = g_desc_pool_pool.live;
    s.vk_descriptor_sets_live = g_desc_set_pool.live;
    s.vk_descriptor_writes = g_descriptor_writes;
    s.vk_surfaces_live = g_surface_pool.live;
    s.vk_swapchains_live = g_swapchain_pool.live;
    s.vk_swapchain_acquires = g_swapchain_acquires;
    s.vk_swapchain_presents = g_swapchain_presents;
    s.vk_buffer_copy_bytes = g_buffer_copy_bytes;
    s.vk_buffer_fill_bytes = g_buffer_fill_bytes;
    s.vk_push_constant_writes = g_push_constant_writes;
    s.vk_pipeline_barriers = g_pipeline_barriers;
    s.vk_dispatches = g_dispatches;
    s.vk_image_upload_pixels = g_image_upload_pixels;
    s.vk_triangles_drawn = g_triangles_drawn;
    s.vk_samplers_live = g_sampler_pool.live;
    s.vk_events_live = g_event_pool.live;
    s.vk_pipeline_caches_live = g_pipeline_cache_pool.live;
    s.vk_query_pools_live = g_query_pool_pool.live;
    s.vk_queries_executed = g_queries_executed;
    s.vk_memory_maps = g_memory_maps;
    s.vk_dynamic_renderings = g_dynamic_renderings;
    s.vk_debug_labels = g_debug_labels;
    s.vk_secondary_executes = g_secondary_executes;
    s.vk_secondary_ops_replayed = g_secondary_ops_replayed;
    s.vk_push_descriptor_writes = g_push_descriptor_writes;
    s.vk_queue_submits = g_queue_submits;
    s.vk_command_recorded = g_command_recorded;
    s.vk_command_replayed = g_command_replayed;
    s.vk_clear_pixels_painted = g_clear_pixels_painted;
    s.vk_invalid_spirv_rejections = g_invalid_spirv_rejections;
    s.vk_spirv_modules_parsed = g_spirv_modules_parsed;
    s.vk_spirv_entry_points_seen = g_spirv_entry_points_seen;
    s.vk_spirv_capabilities_seen = g_spirv_capabilities_seen;
    s.vk_spirv_decorations_seen = g_spirv_decorations_seen;
    s.vk_spirv_execution_modes_seen = g_spirv_execution_modes_seen;
    s.vk_spirv_programs_built = g_spirv_programs_built;
    s.vk_spirv_program_build_failures = g_spirv_program_build_failures;
    s.vk_spirv_entry_point_executions = g_spirv_entry_point_executions;
    s.vk_spirv_step_budget_exhausted = g_spirv_step_budget_exhausted;
    s.vk_shader_raster_draws_painted = g_shader_raster_draws_painted;
    s.vk_shader_raster_draws_skipped = g_shader_raster_draws_skipped;
    return s;
}

// -------------------------------------------------------------------
// Cross-TU bridge for the boot self-test (graphics_vk_selftest.cpp).
// -------------------------------------------------------------------
//
// The selftest needs read access to a handful of internal counters
// and the leak-walk over every per-kind handle pool.  We expose
// those through a thin `internal::` namespace declared in
// `graphics_vk_internal.h` rather than reaching into the anon-ns
// state directly — this keeps the implementation TU's static
// storage truly private while the selftest TU stays
// self-contained.

} // namespace duetos::subsystems::graphics

namespace duetos::subsystems::graphics::internal
{

u32 DynamicRenderingsCount()
{
    return g_dynamic_renderings;
}
u32 SecondaryExecutesCount()
{
    return g_secondary_executes;
}
u32 SecondaryOpsReplayedCount()
{
    return g_secondary_ops_replayed;
}
u32 PushDescriptorWritesCount()
{
    return g_push_descriptor_writes;
}
u32 InvalidSpirvRejectionsCount()
{
    return g_invalid_spirv_rejections;
}
u32 CommandRecordedCount()
{
    return g_command_recorded;
}
u32 CommandReplayedCount()
{
    return g_command_replayed;
}
u32 SpirvModulesParsedCount()
{
    return g_spirv_modules_parsed;
}
u32 SpirvEntryPointsSeenCount()
{
    return g_spirv_entry_points_seen;
}
u32 SpirvCapabilitiesSeenCount()
{
    return g_spirv_capabilities_seen;
}
u32 TrianglesDrawnCount()
{
    return g_triangles_drawn;
}

bool LeakCheckHandlePools()
{
    const Pool* pools[] = {
        &g_instance_pool,    &g_phys_pool,      &g_device_pool,          &g_queue_pool,     &g_cmdpool_pool,
        &g_cmdbuf_pool,      &g_shader_pool,    &g_pipelinelayout_pool,  &g_pipeline_pool,  &g_renderpass_pool,
        &g_framebuffer_pool, &g_image_pool,     &g_imageview_pool,       &g_buffer_pool,    &g_memory_pool,
        &g_fence_pool,       &g_semaphore_pool, &g_desc_set_layout_pool, &g_desc_pool_pool, &g_desc_set_pool,
        &g_surface_pool,     &g_swapchain_pool, &g_sampler_pool,         &g_event_pool,     &g_pipeline_cache_pool,
        &g_query_pool_pool};
    const char* names[] = {
        "instance",        "physical-device", "device",        "queue",       "command-pool", "command-buffer",
        "shader-module",   "pipeline-layout", "pipeline",      "render-pass", "framebuffer",  "image",
        "image-view",      "buffer",          "device-memory", "fence",       "semaphore",    "descriptor-set-layout",
        "descriptor-pool", "descriptor-set",  "surface",       "swapchain",   "sampler",      "event",
        "pipeline-cache",  "query-pool"};
    constexpr u32 n = sizeof(pools) / sizeof(pools[0]);
    for (u32 i = 0; i < n; ++i)
    {
        if (pools[i]->live != 0)
        {
            KLOG_WARN_V("subsystems/graphics", "[selftest:graphics] handle pool leaked after teardown", pools[i]->live);
            KLOG_WARN(names[i], "  ^-- which pool");
            return false;
        }
    }
    return true;
}

} // namespace duetos::subsystems::graphics::internal
