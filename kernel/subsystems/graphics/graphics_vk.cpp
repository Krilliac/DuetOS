#include "subsystems/graphics/graphics.h"

#include "arch/x86_64/serial.h"
#include "drivers/gpu/gpu.h"
#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "time/timekeeper.h"

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

namespace
{

// -------------------------------------------------------------------
// Handle pool primitive.
// -------------------------------------------------------------------
//
// Every Vk* type has its own pool.  A pool is a small fixed-size
// bitmap of live slots plus a per-kind base; a handle is `base +
// slot`.  Capacity is sized for the canonical self-test path plus
// a comfortable headroom; this is a v0 ICD, not a benchmark.

constexpr u32 kPoolCapacity = 32;

struct Pool
{
    u32 live = 0;
    u32 created = 0;
    u32 destroyed = 0;
    u32 used_bitmap = 0; // bit N = slot N live
};

bool PoolAlloc(Pool& p, u32* slot_out)
{
    for (u32 i = 0; i < kPoolCapacity; ++i)
    {
        const u32 bit = 1u << i;
        if ((p.used_bitmap & bit) == 0u)
        {
            p.used_bitmap |= bit;
            ++p.live;
            ++p.created;
            *slot_out = i;
            return true;
        }
    }
    return false;
}

bool PoolFree(Pool& p, u32 slot)
{
    if (slot >= kPoolCapacity)
        return false;
    const u32 bit = 1u << slot;
    if ((p.used_bitmap & bit) == 0u)
        return false;
    p.used_bitmap &= ~bit;
    --p.live;
    ++p.destroyed;
    return true;
}

bool PoolIsLive(const Pool& p, u32 slot)
{
    if (slot >= kPoolCapacity)
        return false;
    return (p.used_bitmap & (1u << slot)) != 0u;
}

// Disjoint base ranges per handle kind so a stray handle from one
// kind passed to another's Destroy can be range-rejected cheaply.
constexpr u64 kInstanceBase = 0x1'0000;
constexpr u64 kPhysDevBase = 0x2'0000;
constexpr u64 kDeviceBase = 0x3'0000;
constexpr u64 kQueueBase = 0x4'0000;
constexpr u64 kCmdPoolBase = 0x5'0000;
constexpr u64 kCmdBufBase = 0x6'0000;
constexpr u64 kShaderBase = 0x7'0000;
constexpr u64 kPipelineLayoutBase = 0x8'0000;
constexpr u64 kPipelineBase = 0x9'0000;
constexpr u64 kRenderPassBase = 0xA'0000;
constexpr u64 kFramebufferBase = 0xB'0000;
constexpr u64 kImageBase = 0xC'0000;
constexpr u64 kImageViewBase = 0xD'0000;
constexpr u64 kBufferBase = 0xE'0000;
constexpr u64 kMemoryBase = 0xF'0000;
constexpr u64 kFenceBase = 0x10'0000;
constexpr u64 kSemaphoreBase = 0x11'0000;
constexpr u64 kDescSetLayoutBase = 0x12'0000;
constexpr u64 kDescPoolBase = 0x13'0000;
constexpr u64 kDescSetBase = 0x14'0000;
constexpr u64 kSurfaceBase = 0x15'0000;
constexpr u64 kSwapchainBase = 0x16'0000;
constexpr u64 kSamplerBase = 0x17'0000;
constexpr u64 kEventBase = 0x18'0000;
constexpr u64 kPipelineCacheBase = 0x19'0000;
constexpr u64 kQueryPoolBase = 0x1A'0000;

bool HandleInRange(u64 h, u64 base)
{
    return h >= base && h < base + kPoolCapacity;
}
u32 SlotOf(u64 h, u64 base)
{
    return static_cast<u32>(h - base);
}
u64 HandleFor(u64 base, u32 slot)
{
    return base + slot;
}

// -------------------------------------------------------------------
// Per-kind data.
// -------------------------------------------------------------------
//
// Most pools carry no state beyond the bitmap.  Three need it:
//   - Image: scanout-backed flag + extent (drives clear replay).
//   - ShaderModule: byte size (so the self-test can reason about
//     "the bytes I gave you ended up tracked").
//   - CommandBuffer: a fixed-size tape of recorded ops + record
//     state.

struct ImageRecord
{
    VkExtent3D extent;
    u32 flags;
    bool memory_bound;
};
ImageRecord g_image_data[kPoolCapacity];

struct ShaderRecord
{
    u64 byte_size;
    ShaderModuleInfo info;
};
ShaderRecord g_shader_data[kPoolCapacity];

struct BufferRecord
{
    u64 size;
    bool memory_bound;
    void* backing;      // host-visible pointer (filled in by VkMapMemory or
                        // implicit-bound for swapchain images / self-test buffers)
    u64 backing_offset; // offset into the bound memory's host backing
    VkDeviceMemory bound_memory;
};
BufferRecord g_buffer_data[kPoolCapacity];

struct ImageViewRecord
{
    VkImage image;
};
ImageViewRecord g_imageview_data[kPoolCapacity];

struct FramebufferRecord
{
    VkImageView attachment;
};
FramebufferRecord g_framebuffer_data[kPoolCapacity];

struct DeviceMemoryRecord
{
    u64 size;
    void* host_ptr; // KMalloc-backed allocation, nullptr until bound
    u32 type_index;
    bool host_visible;
    u32 map_count; // current vkMapMemory ref count
};
DeviceMemoryRecord g_memory_data[kPoolCapacity];

enum class CmdOp : u8
{
    None = 0,
    BeginRenderPass = 1,
    EndRenderPass = 2,
    BindPipeline = 3,
    ClearColorImage = 4,
    Draw = 5,
    DrawIndexed = 6,
    SetViewport = 7,
    SetScissor = 8,
    BindVertexBuffer = 9,
    BindIndexBuffer = 10,
    CopyBuffer = 11,
    FillBuffer = 12,
    PipelineBarrier = 13,
    PushConstants = 14,
    Dispatch = 15,
    CopyBufferToImage = 16,
    SetEvent = 17,
    ResetEvent = 18,
    WaitEvents = 19,
    BeginQuery = 20,
    EndQuery = 21,
    ResetQueryPool = 22,
    WriteTimestamp = 23,
};

struct CmdRecord
{
    CmdOp op;
    VkImage image;
    VkRenderPass render_pass;
    VkFramebuffer framebuffer;
    VkRect2D area;
    VkClearColorValue color;
    VkPipelineBindPoint bind_point;
    VkPipeline pipeline;
    u32 vertex_count;
    u32 instance_count;
    u32 first_vertex;
    u32 first_instance;
    // Indexed draw + index-binding fields.
    u32 index_count;
    u32 first_index;
    i32 vertex_offset;
    VkBuffer index_buffer;
    u64 index_offset;
    VkIndexType index_type;
    // Vertex binding (single-binding subset; spec allows arrays).
    VkBuffer vertex_buffer;
    u64 vertex_offset_bytes;
    u32 vertex_binding;
    // Buffer copy / fill.
    VkBuffer src_buffer;
    VkBuffer dst_buffer;
    u64 src_offset;
    u64 dst_offset;
    u64 region_size;
    u32 fill_pattern;
    // Push constants — fixed-size payload + actual length.
    u32 push_offset;
    u32 push_size;
    u8 push_data[kMaxPushConstantBytes];
    // Dispatch dimensions.
    u32 dispatch_x;
    u32 dispatch_y;
    u32 dispatch_z;
    // Event ops.
    VkEvent event;
    // Query ops.
    VkQueryPool query_pool;
    u32 query_first;
    u32 query_count;
    u32 query_index;
    // CopyBufferToImage geometry.
    u32 region_width;
    u32 region_height;
};

constexpr u32 kCmdTapeCapacity = 32;

enum class CbState : u8
{
    Initial = 0,
    Recording = 1,
    Executable = 2,
};

struct CmdBufferRecord
{
    CbState state;
    u32 op_count;
    CmdRecord ops[kCmdTapeCapacity];
};
CmdBufferRecord g_cmdbuf_data[kPoolCapacity];

// Descriptor-set layouts: just the bindings list.
struct DescriptorSetLayoutRecord
{
    u32 binding_count;
    VkDescriptorSetLayoutBinding bindings[kMaxDescriptorBindings];
};
DescriptorSetLayoutRecord g_desc_set_layout_data[kPoolCapacity];

// Descriptor pools: track max-sets budget + current allocation
// count so an exhausted pool returns ErrorOutOfPoolMemory rather
// than oversubscribing.
struct DescriptorPoolRecord
{
    u32 max_sets;
    u32 sets_allocated;
};
DescriptorPoolRecord g_desc_pool_data[kPoolCapacity];

// Descriptor sets: which pool owns them + which layout shaped
// them + last-known binding writes (for stats only).
struct DescriptorSetRecord
{
    VkDescriptorPool pool;
    VkDescriptorSetLayout layout;
    u32 writes;
};
DescriptorSetRecord g_desc_set_data[kPoolCapacity];

// A swapchain owns a small set of scanout-backed images plus a
// rotating "next-image" cursor.  `acquired_image` tracks the
// most recent vkAcquireNextImageKHR result so VkQueuePresentKHR
// can validate the index the caller hands back.
struct SwapchainRecord
{
    VkSurfaceKHR surface;
    VkExtent2D extent;
    u32 image_count;
    u32 next_image; // round-robin cursor advanced by Acquire
    u32 acquired_index;
    bool image_acquired;
    VkImage images[kMaxSwapchainImages];
};
SwapchainRecord g_swapchain_data[kPoolCapacity];

// Event: device-visible signal bit, plus map_count style ref
// counting on host accesses.
struct EventRecord
{
    bool signalled;
};
EventRecord g_event_data[kPoolCapacity];

// Pipeline cache: blobless; we just record initial-data size to
// satisfy GetPipelineCacheData round trips.
struct PipelineCacheRecord
{
    u64 stored_size;
};
PipelineCacheRecord g_pipeline_cache_data[kPoolCapacity];

// Query pool: small fixed-size results array.
constexpr u32 kMaxQueriesPerPool = 16;
struct QueryPoolRecord
{
    VkQueryType type;
    u32 query_count;
    u64 results[kMaxQueriesPerPool];
    bool available[kMaxQueriesPerPool];
};
QueryPoolRecord g_query_pool_data[kPoolCapacity];

// Per-physical-device record — which GPU index this handle
// represents.  Set at enum time, read by the property queries
// so a caller with multiple GPUs sees per-device vendor / family.
struct PhysicalDeviceRecord
{
    u32 gpu_index;
};
PhysicalDeviceRecord g_phys_data[kPoolCapacity];

// -------------------------------------------------------------------
// Pools.
// -------------------------------------------------------------------

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

// One-shot logging keyed by entry point.
enum EpId
{
    EpCreateInstance,
    EpEnumeratePhysicalDevices,
    EpCreateDevice,
    EpQueueSubmit,
    EpCreateShaderModule,
    EpCreateGraphicsPipeline,
    EpCreateImage,
    EpClearColorImage,
    EpCount
};
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

} // namespace

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
    (void)PoolFree(g_instance_pool, SlotOf(inst, kInstanceBase));
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
    (void)PoolFree(g_device_pool, SlotOf(dev, kDeviceBase));
}

VkResult VkGetDeviceQueue(VkDevice dev, VkQueue* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_queue_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
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
    u32 slot = 0;
    if (!PoolAlloc(g_image_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_image_data[slot].extent = extent;
    g_image_data[slot].flags = flags;
    g_image_data[slot].memory_bound = false;
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
    (void)offset;
    if (!HandleInRange(img, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(img, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(mem, kMemoryBase) || !PoolIsLive(g_memory_pool, SlotOf(mem, kMemoryBase)))
        return VkResult::ErrorInitializationFailed;
    g_image_data[SlotOf(img, kImageBase)].memory_bound = true;
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

namespace
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

} // namespace

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
    if (g_shader_data[slot].info.valid)
    {
        ++g_spirv_modules_parsed;
        g_spirv_entry_points_seen += g_shader_data[slot].info.entry_point_count;
        g_spirv_capabilities_seen += g_shader_data[slot].info.capability_count;
        g_spirv_decorations_seen += g_shader_data[slot].info.decoration_count;
        g_spirv_execution_modes_seen += g_shader_data[slot].info.execution_mode_count;
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
    (void)PoolFree(g_shader_pool, SlotOf(module, kShaderBase));
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
    if (out != nullptr)
        *out = HandleFor(kPipelineBase, slot);
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
// Command pool + command buffer.
// -------------------------------------------------------------------

VkResult VkCreateCommandPool(VkDevice dev, VkCommandPool* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_cmdpool_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kCmdPoolBase, slot);
    return VkResult::Success;
}

void VkDestroyCommandPool(VkDevice dev, VkCommandPool pool)
{
    (void)dev;
    if (pool == 0 || !HandleInRange(pool, kCmdPoolBase))
        return;
    (void)PoolFree(g_cmdpool_pool, SlotOf(pool, kCmdPoolBase));
}

VkResult VkAllocateCommandBuffers(VkDevice dev, VkCommandPool pool, u32 count, VkCommandBuffer* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(pool, kCmdPoolBase) || !PoolIsLive(g_cmdpool_pool, SlotOf(pool, kCmdPoolBase)))
        return VkResult::ErrorInitializationFailed;
    if (out == nullptr || count == 0)
        return VkResult::ErrorInitializationFailed;
    for (u32 i = 0; i < count; ++i)
    {
        u32 slot = 0;
        if (!PoolAlloc(g_cmdbuf_pool, &slot))
        {
            // Roll back the partial allocation so the caller's
            // count stays consistent with what it owns.
            for (u32 j = 0; j < i; ++j)
                (void)PoolFree(g_cmdbuf_pool, SlotOf(out[j], kCmdBufBase));
            return VkResult::ErrorOutOfHostMemory;
        }
        g_cmdbuf_data[slot].state = CbState::Initial;
        g_cmdbuf_data[slot].op_count = 0;
        out[i] = HandleFor(kCmdBufBase, slot);
    }
    return VkResult::Success;
}

VkResult VkFreeCommandBuffers(VkDevice dev, VkCommandPool pool, u32 count, const VkCommandBuffer* cbs)
{
    (void)dev;
    if (!HandleInRange(pool, kCmdPoolBase) || !PoolIsLive(g_cmdpool_pool, SlotOf(pool, kCmdPoolBase)))
        return VkResult::ErrorInitializationFailed;
    if (cbs == nullptr)
        return VkResult::ErrorInitializationFailed;
    for (u32 i = 0; i < count; ++i)
    {
        if (HandleInRange(cbs[i], kCmdBufBase))
            (void)PoolFree(g_cmdbuf_pool, SlotOf(cbs[i], kCmdBufBase));
    }
    return VkResult::Success;
}

VkResult VkBeginCommandBuffer(VkCommandBuffer cb)
{
    if (!HandleInRange(cb, kCmdBufBase) || !PoolIsLive(g_cmdbuf_pool, SlotOf(cb, kCmdBufBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_cmdbuf_data[SlotOf(cb, kCmdBufBase)];
    rec.state = CbState::Recording;
    rec.op_count = 0;
    return VkResult::Success;
}

VkResult VkEndCommandBuffer(VkCommandBuffer cb)
{
    if (!HandleInRange(cb, kCmdBufBase) || !PoolIsLive(g_cmdbuf_pool, SlotOf(cb, kCmdBufBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_cmdbuf_data[SlotOf(cb, kCmdBufBase)];
    if (rec.state != CbState::Recording)
        return VkResult::ErrorInitializationFailed;
    rec.state = CbState::Executable;
    return VkResult::Success;
}

VkResult VkResetCommandBuffer(VkCommandBuffer cb)
{
    if (!HandleInRange(cb, kCmdBufBase) || !PoolIsLive(g_cmdbuf_pool, SlotOf(cb, kCmdBufBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_cmdbuf_data[SlotOf(cb, kCmdBufBase)];
    rec.state = CbState::Initial;
    rec.op_count = 0;
    return VkResult::Success;
}

VkResult VkResetCommandPool(VkDevice dev, VkCommandPool pool, u32 flags)
{
    (void)dev;
    (void)flags;
    if (!HandleInRange(pool, kCmdPoolBase) || !PoolIsLive(g_cmdpool_pool, SlotOf(pool, kCmdPoolBase)))
        return VkResult::ErrorInitializationFailed;
    // The pool itself doesn't track which command buffers it owns
    // (the spec says caller must not free across pools), so reset
    // walks every live cb.  Cheap — only kPoolCapacity slots.
    for (u32 i = 0; i < kPoolCapacity; ++i)
    {
        if (!PoolIsLive(g_cmdbuf_pool, i))
            continue;
        g_cmdbuf_data[i].state = CbState::Initial;
        g_cmdbuf_data[i].op_count = 0;
    }
    return VkResult::Success;
}

namespace
{

VkResult AppendOp(VkCommandBuffer cb, const CmdRecord& op)
{
    if (!HandleInRange(cb, kCmdBufBase) || !PoolIsLive(g_cmdbuf_pool, SlotOf(cb, kCmdBufBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_cmdbuf_data[SlotOf(cb, kCmdBufBase)];
    if (rec.state != CbState::Recording)
        return VkResult::ErrorInitializationFailed;
    if (rec.op_count >= kCmdTapeCapacity)
        return VkResult::ErrorOutOfHostMemory;
    rec.ops[rec.op_count++] = op;
    ++g_command_recorded;
    return VkResult::Success;
}

} // namespace

VkResult VkCmdBeginRenderPass(VkCommandBuffer cb, VkRenderPass rp, VkFramebuffer fb, VkRect2D area,
                              VkClearColorValue clear)
{
    if (!HandleInRange(rp, kRenderPassBase) || !PoolIsLive(g_renderpass_pool, SlotOf(rp, kRenderPassBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(fb, kFramebufferBase) || !PoolIsLive(g_framebuffer_pool, SlotOf(fb, kFramebufferBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::BeginRenderPass;
    op.render_pass = rp;
    op.framebuffer = fb;
    op.area = area;
    op.color = clear;
    return AppendOp(cb, op);
}

VkResult VkCmdEndRenderPass(VkCommandBuffer cb)
{
    CmdRecord op{};
    op.op = CmdOp::EndRenderPass;
    return AppendOp(cb, op);
}

VkResult VkCmdBindPipeline(VkCommandBuffer cb, VkPipelineBindPoint bind_point, VkPipeline pipe)
{
    if (!HandleInRange(pipe, kPipelineBase) || !PoolIsLive(g_pipeline_pool, SlotOf(pipe, kPipelineBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::BindPipeline;
    op.bind_point = bind_point;
    op.pipeline = pipe;
    return AppendOp(cb, op);
}

VkResult VkCmdClearColorImage(VkCommandBuffer cb, VkImage image, VkClearColorValue clear)
{
    LogOnce(EpClearColorImage, "vkCmdClearColorImage");
    if (!HandleInRange(image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::ClearColorImage;
    op.image = image;
    op.color = clear;
    return AppendOp(cb, op);
}

VkResult VkCmdDraw(VkCommandBuffer cb, u32 vertex_count, u32 instance_count, u32 first_vertex, u32 first_instance)
{
    CmdRecord op{};
    op.op = CmdOp::Draw;
    op.vertex_count = vertex_count;
    op.instance_count = instance_count;
    op.first_vertex = first_vertex;
    op.first_instance = first_instance;
    return AppendOp(cb, op);
}

VkResult VkCmdDrawIndexed(VkCommandBuffer cb, u32 index_count, u32 instance_count, u32 first_index, i32 vertex_offset,
                          u32 first_instance)
{
    CmdRecord op{};
    op.op = CmdOp::DrawIndexed;
    op.index_count = index_count;
    op.instance_count = instance_count;
    op.first_index = first_index;
    op.vertex_offset = vertex_offset;
    op.first_instance = first_instance;
    return AppendOp(cb, op);
}

VkResult VkCmdSetViewport(VkCommandBuffer cb, u32 first_viewport, u32 count, const VkViewport* viewports)
{
    (void)first_viewport;
    (void)count;
    (void)viewports;
    // Recorded as state-only; the rasterizer doesn't read it yet.
    CmdRecord op{};
    op.op = CmdOp::SetViewport;
    return AppendOp(cb, op);
}

VkResult VkCmdSetScissor(VkCommandBuffer cb, u32 first_scissor, u32 count, const VkRect2D* scissors)
{
    (void)first_scissor;
    if (count == 0 || scissors == nullptr)
    {
        CmdRecord op{};
        op.op = CmdOp::SetScissor;
        return AppendOp(cb, op);
    }
    CmdRecord op{};
    op.op = CmdOp::SetScissor;
    op.area = scissors[0]; // first scissor only — multi-scissor isn't wired
    return AppendOp(cb, op);
}

VkResult VkCmdBindVertexBuffers(VkCommandBuffer cb, u32 first_binding, u32 count, const VkBuffer* buffers,
                                const u64* offsets)
{
    if (count == 0)
        return VkResult::Success;
    if (buffers == nullptr)
        return VkResult::ErrorInitializationFailed;
    // Spec lets the caller bind multiple in a single call; v0
    // records the first binding only and validates each handle.
    for (u32 i = 0; i < count; ++i)
    {
        if (!HandleInRange(buffers[i], kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buffers[i], kBufferBase)))
            return VkResult::ErrorInitializationFailed;
    }
    CmdRecord op{};
    op.op = CmdOp::BindVertexBuffer;
    op.vertex_buffer = buffers[0];
    op.vertex_offset_bytes = (offsets != nullptr) ? offsets[0] : 0;
    op.vertex_binding = first_binding;
    return AppendOp(cb, op);
}

VkResult VkCmdBindIndexBuffer(VkCommandBuffer cb, VkBuffer buffer, u64 offset, VkIndexType type)
{
    if (!HandleInRange(buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buffer, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::BindIndexBuffer;
    op.index_buffer = buffer;
    op.index_offset = offset;
    op.index_type = type;
    return AppendOp(cb, op);
}

VkResult VkCmdCopyBuffer(VkCommandBuffer cb, VkBuffer src, VkBuffer dst, u64 src_offset, u64 dst_offset, u64 size)
{
    if (!HandleInRange(src, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(src, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(dst, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(dst, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::CopyBuffer;
    op.src_buffer = src;
    op.dst_buffer = dst;
    op.src_offset = src_offset;
    op.dst_offset = dst_offset;
    op.region_size = size;
    return AppendOp(cb, op);
}

VkResult VkCmdFillBuffer(VkCommandBuffer cb, VkBuffer dst, u64 dst_offset, u64 size, u32 data)
{
    if (!HandleInRange(dst, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(dst, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::FillBuffer;
    op.dst_buffer = dst;
    op.dst_offset = dst_offset;
    op.region_size = size;
    op.fill_pattern = data;
    return AppendOp(cb, op);
}

VkResult VkCmdPipelineBarrier(VkCommandBuffer cb, u32 src_stage_mask, u32 dst_stage_mask, u32 dependency_flags)
{
    (void)src_stage_mask;
    (void)dst_stage_mask;
    (void)dependency_flags;
    CmdRecord op{};
    op.op = CmdOp::PipelineBarrier;
    return AppendOp(cb, op);
}

VkResult VkCmdPushConstants(VkCommandBuffer cb, VkPipelineLayout layout, u32 stage_flags, u32 offset, u32 size,
                            const void* values)
{
    (void)stage_flags;
    if (!HandleInRange(layout, kPipelineLayoutBase) ||
        !PoolIsLive(g_pipelinelayout_pool, SlotOf(layout, kPipelineLayoutBase)))
        return VkResult::ErrorInitializationFailed;
    if (size > kMaxPushConstantBytes)
        return VkResult::ErrorTooManyObjects;
    if (size > 0 && values == nullptr)
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::PushConstants;
    op.push_offset = offset;
    op.push_size = size;
    if (size > 0)
    {
        const auto* src = static_cast<const u8*>(values);
        for (u32 i = 0; i < size; ++i)
            op.push_data[i] = src[i];
    }
    return AppendOp(cb, op);
}

VkResult VkCmdDispatch(VkCommandBuffer cb, u32 group_count_x, u32 group_count_y, u32 group_count_z)
{
    CmdRecord op{};
    op.op = CmdOp::Dispatch;
    op.dispatch_x = group_count_x;
    op.dispatch_y = group_count_y;
    op.dispatch_z = group_count_z;
    return AppendOp(cb, op);
}

VkResult VkCmdCopyBufferToImage(VkCommandBuffer cb, VkBuffer src_buffer, VkImage dst_image, u64 src_offset, u32 width,
                                u32 height)
{
    if (!HandleInRange(src_buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(src_buffer, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(dst_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(dst_image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::CopyBufferToImage;
    op.src_buffer = src_buffer;
    op.image = dst_image;
    op.src_offset = src_offset;
    op.region_width = width;
    op.region_height = height;
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// Sampler.
// -------------------------------------------------------------------

VkResult VkCreateSampler(VkDevice dev, const VkSamplerCreateInfo* info, VkSampler* out)
{
    (void)info;
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_sampler_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kSamplerBase, slot);
    return VkResult::Success;
}

void VkDestroySampler(VkDevice dev, VkSampler sampler)
{
    (void)dev;
    if (sampler == 0 || !HandleInRange(sampler, kSamplerBase))
        return;
    (void)PoolFree(g_sampler_pool, SlotOf(sampler, kSamplerBase));
}

// -------------------------------------------------------------------
// Event.
// -------------------------------------------------------------------

VkResult VkCreateEvent(VkDevice dev, VkEvent* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_event_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_event_data[slot].signalled = false;
    if (out != nullptr)
        *out = HandleFor(kEventBase, slot);
    return VkResult::Success;
}

void VkDestroyEvent(VkDevice dev, VkEvent event)
{
    (void)dev;
    if (event == 0 || !HandleInRange(event, kEventBase))
        return;
    (void)PoolFree(g_event_pool, SlotOf(event, kEventBase));
}

VkResult VkSetEvent(VkDevice dev, VkEvent event)
{
    (void)dev;
    if (!HandleInRange(event, kEventBase) || !PoolIsLive(g_event_pool, SlotOf(event, kEventBase)))
        return VkResult::ErrorInitializationFailed;
    g_event_data[SlotOf(event, kEventBase)].signalled = true;
    return VkResult::Success;
}

VkResult VkResetEvent(VkDevice dev, VkEvent event)
{
    (void)dev;
    if (!HandleInRange(event, kEventBase) || !PoolIsLive(g_event_pool, SlotOf(event, kEventBase)))
        return VkResult::ErrorInitializationFailed;
    g_event_data[SlotOf(event, kEventBase)].signalled = false;
    return VkResult::Success;
}

VkResult VkGetEventStatus(VkDevice dev, VkEvent event)
{
    (void)dev;
    if (!HandleInRange(event, kEventBase) || !PoolIsLive(g_event_pool, SlotOf(event, kEventBase)))
        return VkResult::ErrorInitializationFailed;
    return g_event_data[SlotOf(event, kEventBase)].signalled ? VkResult::EventSet : VkResult::EventReset;
}

VkResult VkCmdSetEvent(VkCommandBuffer cb, VkEvent event, u32 stage_mask)
{
    (void)stage_mask;
    if (!HandleInRange(event, kEventBase) || !PoolIsLive(g_event_pool, SlotOf(event, kEventBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::SetEvent;
    op.event = event;
    return AppendOp(cb, op);
}

VkResult VkCmdResetEvent(VkCommandBuffer cb, VkEvent event, u32 stage_mask)
{
    (void)stage_mask;
    if (!HandleInRange(event, kEventBase) || !PoolIsLive(g_event_pool, SlotOf(event, kEventBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::ResetEvent;
    op.event = event;
    return AppendOp(cb, op);
}

VkResult VkCmdWaitEvents(VkCommandBuffer cb, u32 count, const VkEvent* events)
{
    if (count == 0)
        return VkResult::Success;
    if (events == nullptr)
        return VkResult::ErrorInitializationFailed;
    for (u32 i = 0; i < count; ++i)
    {
        if (!HandleInRange(events[i], kEventBase) || !PoolIsLive(g_event_pool, SlotOf(events[i], kEventBase)))
            return VkResult::ErrorInitializationFailed;
    }
    CmdRecord op{};
    op.op = CmdOp::WaitEvents;
    op.event = events[0]; // first event only — multi-event isn't recorded individually
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// Pipeline cache.
// -------------------------------------------------------------------

VkResult VkCreatePipelineCache(VkDevice dev, const void* initial_data, u64 initial_size, VkPipelineCache* out)
{
    (void)initial_data;
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_pipeline_cache_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_pipeline_cache_data[slot].stored_size = initial_size;
    if (out != nullptr)
        *out = HandleFor(kPipelineCacheBase, slot);
    return VkResult::Success;
}

void VkDestroyPipelineCache(VkDevice dev, VkPipelineCache cache)
{
    (void)dev;
    if (cache == 0 || !HandleInRange(cache, kPipelineCacheBase))
        return;
    (void)PoolFree(g_pipeline_cache_pool, SlotOf(cache, kPipelineCacheBase));
}

VkResult VkMergePipelineCaches(VkDevice dev, VkPipelineCache dst, u32 src_count, const VkPipelineCache* sources)
{
    (void)dev;
    if (!HandleInRange(dst, kPipelineCacheBase) || !PoolIsLive(g_pipeline_cache_pool, SlotOf(dst, kPipelineCacheBase)))
        return VkResult::ErrorInitializationFailed;
    if (sources == nullptr && src_count != 0)
        return VkResult::ErrorInitializationFailed;
    for (u32 i = 0; i < src_count; ++i)
    {
        if (!HandleInRange(sources[i], kPipelineCacheBase) ||
            !PoolIsLive(g_pipeline_cache_pool, SlotOf(sources[i], kPipelineCacheBase)))
            return VkResult::ErrorInitializationFailed;
    }
    return VkResult::Success;
}

VkResult VkGetPipelineCacheData(VkDevice dev, VkPipelineCache cache, u64* size, void* data)
{
    (void)dev;
    if (size == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(cache, kPipelineCacheBase) ||
        !PoolIsLive(g_pipeline_cache_pool, SlotOf(cache, kPipelineCacheBase)))
        return VkResult::ErrorInitializationFailed;
    // Spec defines a 16-byte VkPipelineCacheHeaderVersionOne:
    //   u32 size, u32 version (=1), u32 vendor_id, u32 device_id,
    //   u8[16] uuid (we leave zeroed).
    constexpr u64 kHeaderBytes = 16 + 16; // 16-byte header struct + 16-byte UUID
    if (data == nullptr)
    {
        *size = kHeaderBytes;
        return VkResult::Success;
    }
    if (*size < kHeaderBytes)
    {
        *size = kHeaderBytes;
        return VkResult::Incomplete;
    }
    auto* p = static_cast<u32*>(data);
    p[0] = static_cast<u32>(kHeaderBytes);
    p[1] = 1; // header version
    p[2] = 0; // vendor id
    p[3] = 0; // device id
    auto* uuid = static_cast<u8*>(data) + 16;
    for (u32 i = 0; i < 16; ++i)
        uuid[i] = 0;
    *size = kHeaderBytes;
    return VkResult::Success;
}

// -------------------------------------------------------------------
// Query pool.
// -------------------------------------------------------------------

VkResult VkCreateQueryPool(VkDevice dev, VkQueryType type, u32 query_count, VkQueryPool* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (query_count == 0 || query_count > kMaxQueriesPerPool)
        return VkResult::ErrorTooManyObjects;
    u32 slot = 0;
    if (!PoolAlloc(g_query_pool_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    auto& rec = g_query_pool_data[slot];
    rec = QueryPoolRecord{};
    rec.type = type;
    rec.query_count = query_count;
    if (out != nullptr)
        *out = HandleFor(kQueryPoolBase, slot);
    return VkResult::Success;
}

void VkDestroyQueryPool(VkDevice dev, VkQueryPool pool)
{
    (void)dev;
    if (pool == 0 || !HandleInRange(pool, kQueryPoolBase))
        return;
    (void)PoolFree(g_query_pool_pool, SlotOf(pool, kQueryPoolBase));
}

VkResult VkResetQueryPool(VkDevice dev, VkQueryPool pool, u32 first_query, u32 query_count)
{
    (void)dev;
    if (!HandleInRange(pool, kQueryPoolBase) || !PoolIsLive(g_query_pool_pool, SlotOf(pool, kQueryPoolBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_query_pool_data[SlotOf(pool, kQueryPoolBase)];
    if (first_query + query_count > rec.query_count)
        return VkResult::ErrorInitializationFailed;
    for (u32 i = 0; i < query_count; ++i)
    {
        rec.results[first_query + i] = 0;
        rec.available[first_query + i] = false;
    }
    return VkResult::Success;
}

VkResult VkCmdResetQueryPool(VkCommandBuffer cb, VkQueryPool pool, u32 first_query, u32 query_count)
{
    if (!HandleInRange(pool, kQueryPoolBase) || !PoolIsLive(g_query_pool_pool, SlotOf(pool, kQueryPoolBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::ResetQueryPool;
    op.query_pool = pool;
    op.query_first = first_query;
    op.query_count = query_count;
    return AppendOp(cb, op);
}

VkResult VkCmdBeginQuery(VkCommandBuffer cb, VkQueryPool pool, u32 query, u32 flags)
{
    (void)flags;
    if (!HandleInRange(pool, kQueryPoolBase) || !PoolIsLive(g_query_pool_pool, SlotOf(pool, kQueryPoolBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::BeginQuery;
    op.query_pool = pool;
    op.query_index = query;
    return AppendOp(cb, op);
}

VkResult VkCmdEndQuery(VkCommandBuffer cb, VkQueryPool pool, u32 query)
{
    if (!HandleInRange(pool, kQueryPoolBase) || !PoolIsLive(g_query_pool_pool, SlotOf(pool, kQueryPoolBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::EndQuery;
    op.query_pool = pool;
    op.query_index = query;
    return AppendOp(cb, op);
}

VkResult VkCmdWriteTimestamp(VkCommandBuffer cb, u32 stage, VkQueryPool pool, u32 query)
{
    (void)stage;
    if (!HandleInRange(pool, kQueryPoolBase) || !PoolIsLive(g_query_pool_pool, SlotOf(pool, kQueryPoolBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::WriteTimestamp;
    op.query_pool = pool;
    op.query_index = query;
    return AppendOp(cb, op);
}

VkResult VkGetQueryPoolResults(VkDevice dev, VkQueryPool pool, u32 first_query, u32 query_count, u64* data, u32 stride,
                               u32 flags)
{
    (void)dev;
    (void)flags;
    if (data == nullptr || stride == 0)
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(pool, kQueryPoolBase) || !PoolIsLive(g_query_pool_pool, SlotOf(pool, kQueryPoolBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_query_pool_data[SlotOf(pool, kQueryPoolBase)];
    if (first_query + query_count > rec.query_count)
        return VkResult::ErrorInitializationFailed;
    bool any_unavailable = false;
    for (u32 i = 0; i < query_count; ++i)
    {
        const u32 q = first_query + i;
        if (!rec.available[q])
        {
            any_unavailable = true;
            data[i] = 0;
        }
        else
        {
            data[i] = rec.results[q];
        }
    }
    return any_unavailable ? VkResult::NotReady : VkResult::Success;
}

// -------------------------------------------------------------------
// Submit replay.
// -------------------------------------------------------------------

namespace
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
    const u32* pixels = reinterpret_cast<const u32*>(static_cast<const u8*>(src.backing) + op.src_offset);
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

void ReplayCommandBuffer(VkCommandBuffer cb)
{
    if (!HandleInRange(cb, kCmdBufBase) || !PoolIsLive(g_cmdbuf_pool, SlotOf(cb, kCmdBufBase)))
        return;
    const auto& rec = g_cmdbuf_data[SlotOf(cb, kCmdBufBase)];
    if (rec.state != CbState::Executable)
        return;
    for (u32 i = 0; i < rec.op_count; ++i)
    {
        const auto& op = rec.ops[i];
        ++g_command_replayed;
        switch (op.op)
        {
        case CmdOp::ClearColorImage:
            ReplayClear(op);
            break;
        case CmdOp::BeginRenderPass:
            ReplayBeginRenderPass(op);
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
        case CmdOp::WaitEvents: // no-op replay (events already signalled)
        case CmdOp::BeginQuery: // pairs with EndQuery — write happens at End
        case CmdOp::EndRenderPass:
        case CmdOp::BindPipeline:
        case CmdOp::Draw:
        case CmdOp::DrawIndexed:
        case CmdOp::SetViewport:
        case CmdOp::SetScissor:
        case CmdOp::BindVertexBuffer:
        case CmdOp::BindIndexBuffer:
        case CmdOp::None:
            break;
        }
    }
}

} // namespace

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
// Descriptor sets + pools.
// -------------------------------------------------------------------

VkResult VkCreateDescriptorSetLayout(VkDevice dev, u32 binding_count, const VkDescriptorSetLayoutBinding* bindings,
                                     VkDescriptorSetLayout* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (binding_count > kMaxDescriptorBindings)
        return VkResult::ErrorTooManyObjects;
    if (binding_count > 0 && bindings == nullptr)
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_desc_set_layout_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    auto& rec = g_desc_set_layout_data[slot];
    rec.binding_count = binding_count;
    for (u32 i = 0; i < binding_count; ++i)
        rec.bindings[i] = bindings[i];
    if (out != nullptr)
        *out = HandleFor(kDescSetLayoutBase, slot);
    return VkResult::Success;
}

void VkDestroyDescriptorSetLayout(VkDevice dev, VkDescriptorSetLayout layout)
{
    (void)dev;
    if (layout == 0 || !HandleInRange(layout, kDescSetLayoutBase))
        return;
    (void)PoolFree(g_desc_set_layout_pool, SlotOf(layout, kDescSetLayoutBase));
}

VkResult VkCreateDescriptorPool(VkDevice dev, u32 max_sets, u32 pool_size_count, const VkDescriptorPoolSize* pool_sizes,
                                VkDescriptorPool* out)
{
    (void)pool_sizes;
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (max_sets == 0)
        return VkResult::ErrorInitializationFailed;
    if (pool_size_count > 0 && pool_sizes == nullptr)
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_desc_pool_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_desc_pool_data[slot].max_sets = max_sets;
    g_desc_pool_data[slot].sets_allocated = 0;
    if (out != nullptr)
        *out = HandleFor(kDescPoolBase, slot);
    return VkResult::Success;
}

void VkDestroyDescriptorPool(VkDevice dev, VkDescriptorPool pool)
{
    (void)dev;
    if (pool == 0 || !HandleInRange(pool, kDescPoolBase))
        return;
    // Free any sets that still claim this pool — protects against
    // a caller that destroys the pool without first freeing the
    // sets (matches the spec's implicit free behaviour).
    for (u32 i = 0; i < kPoolCapacity; ++i)
    {
        if (PoolIsLive(g_desc_set_pool, i) && g_desc_set_data[i].pool == pool)
            (void)PoolFree(g_desc_set_pool, i);
    }
    (void)PoolFree(g_desc_pool_pool, SlotOf(pool, kDescPoolBase));
}

VkResult VkResetDescriptorPool(VkDevice dev, VkDescriptorPool pool)
{
    (void)dev;
    if (!HandleInRange(pool, kDescPoolBase) || !PoolIsLive(g_desc_pool_pool, SlotOf(pool, kDescPoolBase)))
        return VkResult::ErrorInitializationFailed;
    for (u32 i = 0; i < kPoolCapacity; ++i)
    {
        if (PoolIsLive(g_desc_set_pool, i) && g_desc_set_data[i].pool == pool)
            (void)PoolFree(g_desc_set_pool, i);
    }
    g_desc_pool_data[SlotOf(pool, kDescPoolBase)].sets_allocated = 0;
    return VkResult::Success;
}

VkResult VkAllocateDescriptorSets(VkDevice dev, VkDescriptorPool pool, u32 count, const VkDescriptorSetLayout* layouts,
                                  VkDescriptorSet* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(pool, kDescPoolBase) || !PoolIsLive(g_desc_pool_pool, SlotOf(pool, kDescPoolBase)))
        return VkResult::ErrorInitializationFailed;
    if (out == nullptr || layouts == nullptr || count == 0)
        return VkResult::ErrorInitializationFailed;

    auto& pool_rec = g_desc_pool_data[SlotOf(pool, kDescPoolBase)];
    if (pool_rec.sets_allocated + count > pool_rec.max_sets)
        return VkResult::ErrorFragmentedPool;

    for (u32 i = 0; i < count; ++i)
    {
        if (!HandleInRange(layouts[i], kDescSetLayoutBase) ||
            !PoolIsLive(g_desc_set_layout_pool, SlotOf(layouts[i], kDescSetLayoutBase)))
        {
            // Roll back partials so the caller's `out` array stays
            // consistent with what's been allocated.
            for (u32 j = 0; j < i; ++j)
                (void)PoolFree(g_desc_set_pool, SlotOf(out[j], kDescSetBase));
            return VkResult::ErrorInitializationFailed;
        }
        u32 slot = 0;
        if (!PoolAlloc(g_desc_set_pool, &slot))
        {
            for (u32 j = 0; j < i; ++j)
                (void)PoolFree(g_desc_set_pool, SlotOf(out[j], kDescSetBase));
            return VkResult::ErrorOutOfHostMemory;
        }
        g_desc_set_data[slot].pool = pool;
        g_desc_set_data[slot].layout = layouts[i];
        g_desc_set_data[slot].writes = 0;
        out[i] = HandleFor(kDescSetBase, slot);
        ++pool_rec.sets_allocated;
    }
    return VkResult::Success;
}

VkResult VkFreeDescriptorSets(VkDevice dev, VkDescriptorPool pool, u32 count, const VkDescriptorSet* sets)
{
    (void)dev;
    if (!HandleInRange(pool, kDescPoolBase) || !PoolIsLive(g_desc_pool_pool, SlotOf(pool, kDescPoolBase)))
        return VkResult::ErrorInitializationFailed;
    if (sets == nullptr && count != 0)
        return VkResult::ErrorInitializationFailed;
    auto& pool_rec = g_desc_pool_data[SlotOf(pool, kDescPoolBase)];
    for (u32 i = 0; i < count; ++i)
    {
        if (!HandleInRange(sets[i], kDescSetBase))
            continue;
        const u32 slot = SlotOf(sets[i], kDescSetBase);
        if (!PoolIsLive(g_desc_set_pool, slot))
            continue;
        if (g_desc_set_data[slot].pool != pool)
            continue; // not from this pool — spec forbids
        (void)PoolFree(g_desc_set_pool, slot);
        if (pool_rec.sets_allocated > 0)
            --pool_rec.sets_allocated;
    }
    return VkResult::Success;
}

VkResult VkUpdateDescriptorSet(VkDescriptorSet set, u32 binding, VkDescriptorType type, u64 resource_handle)
{
    (void)binding;
    (void)type;
    (void)resource_handle;
    if (!HandleInRange(set, kDescSetBase) || !PoolIsLive(g_desc_set_pool, SlotOf(set, kDescSetBase)))
        return VkResult::ErrorInitializationFailed;
    ++g_desc_set_data[SlotOf(set, kDescSetBase)].writes;
    ++g_descriptor_writes;
    return VkResult::Success;
}

VkResult VkUpdateDescriptorSets(VkDevice dev, u32 write_count, const VkWriteDescriptorSet* writes, u32 copy_count,
                                const void* copies)
{
    (void)dev;
    (void)copies;
    if (write_count == 0 && copy_count == 0)
        return VkResult::Success;
    if (write_count > 0 && writes == nullptr)
        return VkResult::ErrorInitializationFailed;
    // Copy-from-set (VkCopyDescriptorSet) is accepted but not
    // tracked — there's no shader-visible state to copy.  This
    // matches the spec's "no observable side effect" path for a
    // copy that the implementation chooses to no-op.
    for (u32 i = 0; i < write_count; ++i)
    {
        const VkResult r =
            VkUpdateDescriptorSet(writes[i].dstSet, writes[i].dstBinding, writes[i].type, writes[i].resourceHandle);
        if (r != VkResult::Success)
            return r;
    }
    return VkResult::Success;
}

VkResult VkCmdBindDescriptorSets(VkCommandBuffer cb, VkPipelineBindPoint bind_point, VkPipelineLayout layout,
                                 u32 first_set, u32 set_count, const VkDescriptorSet* sets)
{
    (void)bind_point;
    (void)layout;
    (void)first_set;
    if (!HandleInRange(cb, kCmdBufBase) || !PoolIsLive(g_cmdbuf_pool, SlotOf(cb, kCmdBufBase)))
        return VkResult::ErrorInitializationFailed;
    auto& rec = g_cmdbuf_data[SlotOf(cb, kCmdBufBase)];
    if (rec.state != CbState::Recording)
        return VkResult::ErrorInitializationFailed;
    // Validate all sets up front; no opcode is recorded for the
    // bind today (no shader to consume it) but we still want to
    // catch a stale-handle bug at record time, not submit time.
    for (u32 i = 0; i < set_count; ++i)
    {
        if (!HandleInRange(sets[i], kDescSetBase) || !PoolIsLive(g_desc_set_pool, SlotOf(sets[i], kDescSetBase)))
            return VkResult::ErrorInitializationFailed;
    }
    return VkResult::Success;
}

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
    (void)signal_semaphore;
    (void)signal_fence;
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
    s.vk_samplers_live = g_sampler_pool.live;
    s.vk_events_live = g_event_pool.live;
    s.vk_pipeline_caches_live = g_pipeline_cache_pool.live;
    s.vk_query_pools_live = g_query_pool_pool.live;
    s.vk_queries_executed = g_queries_executed;
    s.vk_memory_maps = g_memory_maps;
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
    return s;
}

// -------------------------------------------------------------------
// Boot self-test.
// -------------------------------------------------------------------
//
// Drives the canonical Vulkan lifecycle and asserts every live
// counter returns to zero.  Failure leaves a WARN sentinel in the
// boot log; success is silent.  The test deliberately does NOT
// exercise the scanout-backed clear path — the framebuffer is
// owned by the boot console at this point in init and a clear
// against the live framebuffer would erase the boot log.

namespace
{

// Minimal valid SPIR-V header: magic + version + generator +
// bound + schema + a single OpReturn (0xFD0001).  The v1 parser
// walks this and reports all counts as zero — proves the
// "well-formed but feature-light" path.
constexpr u32 kFakeSpirvBlob[] = {
    0x07230203u, // magic
    0x00010300u, // version 1.3
    0x0000000Bu, // generator (DuetOS placeholder)
    0x00000001u, // bound
    0x00000000u, // schema
    0x000100FDu, // OpReturn
};

// Real-shape SPIR-V fragment shader module.  Used by the
// self-test to prove the v1 parser reaches every interesting
// instruction class: OpCapability, OpMemoryModel, OpEntryPoint
// (with a name), OpExecutionMode, OpDecorate.  Layout:
//   header (5 words) + OpCapability Shader (2)
//   + OpMemoryModel Logical GLSL450 (3)
//   + OpEntryPoint Fragment %4 "main" (5)
//   + OpExecutionMode %4 OriginUpperLeft (3)
//   + OpDecorate %5 Location 0 (4)
// = 22 words.  Bound = 6 (highest id 5 + 1).
constexpr u32 kRichSpirvBlob[] = {
    // Header.
    0x07230203u,
    0x00010300u,
    0xDE020104u,
    0x00000006u,
    0x00000000u,
    // OpCapability Shader (1).
    0x00020011u,
    0x00000001u,
    // OpMemoryModel Logical(0) GLSL450(1).
    0x0003000Eu,
    0x00000000u,
    0x00000001u,
    // OpEntryPoint Fragment(4) %4 "main".
    0x0005000Fu,
    0x00000004u,
    0x00000004u,
    0x6E69616Du,
    0x00000000u,
    // OpExecutionMode %4 OriginUpperLeft(7).
    0x00030010u,
    0x00000004u,
    0x00000007u,
    // OpDecorate %5 Location(30) 0.
    0x00040047u,
    0x00000005u,
    0x0000001Eu,
    0x00000000u,
};

bool SelftestFail(const char* what, u64 detail)
{
    KLOG_WARN_V("subsystems/graphics", what, detail);
    return false;
}

bool RunCanonicalLifecycle()
{
    VkInstance inst = 0;
    if (VkCreateInstance(&inst) != VkResult::Success || inst == 0)
        return SelftestFail("[selftest:graphics] vkCreateInstance failed", 0);

    u32 phys_count = 0;
    if (VkEnumeratePhysicalDevices(inst, &phys_count, nullptr) != VkResult::Success || phys_count == 0)
        return SelftestFail("[selftest:graphics] vkEnumeratePhysicalDevices(query) failed", phys_count);

    VkPhysicalDevice phys[2] = {};
    u32 want = phys_count > 2 ? 2 : phys_count;
    const VkResult enum_r = VkEnumeratePhysicalDevices(inst, &want, phys);
    if (enum_r != VkResult::Success && enum_r != VkResult::Incomplete)
        return SelftestFail("[selftest:graphics] vkEnumeratePhysicalDevices(fetch) failed", static_cast<u64>(enum_r));
    if (want == 0 || phys[0] == 0)
        return SelftestFail("[selftest:graphics] no physical device returned", 0);

    VkPhysicalDeviceProperties props{};
    if (VkGetPhysicalDeviceProperties(phys[0], &props) != VkResult::Success)
        return SelftestFail("[selftest:graphics] GetPhysicalDeviceProperties failed", 0);
    if (props.apiVersion != kApiVersion1_3)
        return SelftestFail("[selftest:graphics] apiVersion mismatch", props.apiVersion);

    VkPhysicalDeviceMemoryProperties mem{};
    if (VkGetPhysicalDeviceMemoryProperties(phys[0], &mem) != VkResult::Success || mem.memoryTypeCount < 2)
        return SelftestFail("[selftest:graphics] GetPhysicalDeviceMemoryProperties failed", mem.memoryTypeCount);

    u32 qf_count = 0;
    if (VkGetPhysicalDeviceQueueFamilyProperties(phys[0], &qf_count, nullptr) != VkResult::Success || qf_count == 0)
        return SelftestFail("[selftest:graphics] GetQueueFamilyProperties(query) failed", qf_count);

    VkDevice dev = 0;
    if (VkCreateDevice(phys[0], &dev) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateDevice failed", 0);

    VkQueue queue = 0;
    if (VkGetDeviceQueue(dev, &queue) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkGetDeviceQueue failed", 0);

    // Build a tiny pipeline: layout + two shader modules + graphics pipeline.
    VkPipelineLayout pl_layout = 0;
    if (VkCreatePipelineLayout(dev, &pl_layout) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreatePipelineLayout failed", 0);

    VkShaderModule vs = 0, fs = 0;
    if (VkCreateShaderModule(dev, kFakeSpirvBlob, sizeof(kFakeSpirvBlob), &vs) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateShaderModule(vs) failed", 0);
    if (VkCreateShaderModule(dev, kFakeSpirvBlob, sizeof(kFakeSpirvBlob), &fs) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateShaderModule(fs) failed", 0);

    // Negative path: a blob whose magic word is wrong must be
    // rejected with ErrorInvalidShaderNV — proves the validator
    // is doing its job.
    static const u32 bad[] = {0xDEADBEEFu, 0u, 0u, 0u, 0u};
    VkShaderModule bogus = 0;
    if (VkCreateShaderModule(dev, bad, sizeof(bad), &bogus) != VkResult::ErrorInvalidShaderNV)
        return SelftestFail("[selftest:graphics] SPIR-V magic-word validator did not reject bad blob", 0);
    if (bogus != 0)
        return SelftestFail("[selftest:graphics] SPIR-V validator emitted a handle on rejection", bogus);

    // Parser leg: a real-shape SPIR-V module reaches the v1
    // walker.  The walker is run inside VkCreateShaderModule;
    // VkGetShaderModuleInfoDuet exposes the parse result for
    // the test to assert against.
    VkShaderModule rich = 0;
    if (VkCreateShaderModule(dev, kRichSpirvBlob, sizeof(kRichSpirvBlob), &rich) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateShaderModule(rich) failed", 0);

    ShaderModuleInfo rich_info{};
    if (VkGetShaderModuleInfoDuet(rich, &rich_info) != VkResult::Success || !rich_info.valid)
        return SelftestFail("[selftest:graphics] SPIR-V parser failed on rich module", 0);
    if (rich_info.entry_point_count != 1)
        return SelftestFail("[selftest:graphics] entry_point_count mismatch", rich_info.entry_point_count);
    if (rich_info.capability_count != 1)
        return SelftestFail("[selftest:graphics] capability_count mismatch", rich_info.capability_count);
    if (rich_info.execution_mode_count != 1)
        return SelftestFail("[selftest:graphics] execution_mode_count mismatch", rich_info.execution_mode_count);
    if (rich_info.decoration_count != 1)
        return SelftestFail("[selftest:graphics] decoration_count mismatch", rich_info.decoration_count);
    if (rich_info.first_execution_model != 4) // Fragment
        return SelftestFail("[selftest:graphics] first_execution_model not Fragment", rich_info.first_execution_model);
    if (rich_info.first_entry_name[0] != 'm' || rich_info.first_entry_name[1] != 'a' ||
        rich_info.first_entry_name[2] != 'i' || rich_info.first_entry_name[3] != 'n')
        return SelftestFail("[selftest:graphics] first_entry_name did not decode to 'main'", 0);
    VkDestroyShaderModule(dev, rich);

    VkPipeline pipe = 0;
    if (VkCreateGraphicsPipeline(dev, pl_layout, vs, fs, &pipe) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateGraphicsPipeline failed", 0);

    // Descriptor leg: layout(2 bindings) -> pool(1 set) -> set ->
    // update each binding -> bind during recording -> destroy.
    const VkDescriptorSetLayoutBinding bindings[] = {
        VkDescriptorSetLayoutBinding{0, VkDescriptorType::UniformBuffer, 1, 0xFFu},
        VkDescriptorSetLayoutBinding{1, VkDescriptorType::CombinedImageSampler, 1, 0xFFu},
    };
    VkDescriptorSetLayout dsl = 0;
    if (VkCreateDescriptorSetLayout(dev, 2, bindings, &dsl) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateDescriptorSetLayout failed", 0);

    const VkDescriptorPoolSize pool_sizes[] = {
        VkDescriptorPoolSize{VkDescriptorType::UniformBuffer, 1},
        VkDescriptorPoolSize{VkDescriptorType::CombinedImageSampler, 1},
    };
    VkDescriptorPool dpool = 0;
    if (VkCreateDescriptorPool(dev, 1, 2, pool_sizes, &dpool) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateDescriptorPool failed", 0);

    VkDescriptorSet dset = 0;
    if (VkAllocateDescriptorSets(dev, dpool, 1, &dsl, &dset) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkAllocateDescriptorSets failed", 0);

    // Pool budget enforcement: a second alloc against a max=1 pool
    // must fail with ErrorFragmentedPool.  Proves the budget gate
    // is wired and not hard-coded to Success.
    VkDescriptorSet dset_overflow = 0;
    if (VkAllocateDescriptorSets(dev, dpool, 1, &dsl, &dset_overflow) != VkResult::ErrorFragmentedPool)
        return SelftestFail("[selftest:graphics] descriptor pool budget did not enforce max_sets", 0);
    if (dset_overflow != 0)
        return SelftestFail("[selftest:graphics] over-budget allocate emitted a handle", dset_overflow);

    // Resource leg: memory + buffer bind + non-scanout image.
    VkDeviceMemory mem_handle = 0;
    if (VkAllocateMemory(dev, 4096, 0, &mem_handle) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkAllocateMemory failed", 0);

    VkBuffer buf = 0;
    if (VkCreateBuffer(dev, 4096, &buf) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateBuffer failed", 0);
    if (VkBindBufferMemory(dev, buf, mem_handle, 0) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkBindBufferMemory failed", 0);

    VkImage img = 0;
    // No kImageScanoutBacked — replay must NOT touch the framebuffer.
    if (VkCreateImage(dev, VkExtent3D{16, 16, 1}, 0, &img) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateImage failed", 0);

    VkImageView view = 0;
    if (VkCreateImageView(dev, img, &view) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateImageView failed", 0);

    VkRenderPass rp = 0;
    if (VkCreateRenderPass(dev, &rp) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateRenderPass failed", 0);

    VkFramebuffer fb = 0;
    if (VkCreateFramebuffer(dev, rp, view, VkExtent2D{16, 16}, &fb) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateFramebuffer failed", 0);

    // Command leg: pool + cb + record clear + submit.
    VkCommandPool pool = 0;
    if (VkCreateCommandPool(dev, &pool) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateCommandPool failed", 0);

    VkCommandBuffer cb = 0;
    if (VkAllocateCommandBuffers(dev, pool, 1, &cb) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkAllocateCommandBuffers failed", 0);
    if (VkBeginCommandBuffer(cb) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkBeginCommandBuffer failed", 0);

    // Spec-form descriptor writes — exercises the array entry
    // alongside the per-binding form so both code paths cover.
    const VkWriteDescriptorSet writes[] = {
        VkWriteDescriptorSet{dset, 0, VkDescriptorType::UniformBuffer, buf},
        VkWriteDescriptorSet{dset, 1, VkDescriptorType::CombinedImageSampler, view},
    };
    if (VkUpdateDescriptorSets(dev, 2, writes, 0, nullptr) != VkResult::Success)
        return SelftestFail("[selftest:graphics] VkUpdateDescriptorSets(array) failed", 0);
    if (VkCmdBindDescriptorSets(cb, VkPipelineBindPoint::Graphics, pl_layout, 0, 1, &dset) != VkResult::Success)
        return SelftestFail("[selftest:graphics] VkCmdBindDescriptorSets failed", 0);

    // New tape ops — viewport / scissor / vertex+index binding /
    // indexed draw / pipeline barrier / push constants / dispatch.
    const VkViewport vp{0, 0, 16, 16, 0, 1};
    if (VkCmdSetViewport(cb, 0, 1, &vp) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdSetViewport failed", 0);
    const VkRect2D scissor{VkOffset2D{0, 0}, VkExtent2D{16, 16}};
    if (VkCmdSetScissor(cb, 0, 1, &scissor) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdSetScissor failed", 0);
    const u64 vb_offset = 0;
    if (VkCmdBindVertexBuffers(cb, 0, 1, &buf, &vb_offset) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdBindVertexBuffers failed", 0);
    if (VkCmdBindIndexBuffer(cb, buf, 0, VkIndexType::Uint16) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdBindIndexBuffer failed", 0);
    if (VkCmdPipelineBarrier(cb, 0x10, 0x20, 0) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdPipelineBarrier failed", 0);
    const u32 push_payload[] = {0xCAFEF00Du, 0xDEADBEEFu};
    if (VkCmdPushConstants(cb, pl_layout, 0xFFu, 0, sizeof(push_payload), push_payload) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdPushConstants failed", 0);
    if (VkCmdDispatch(cb, 8, 8, 1) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdDispatch failed", 0);

    // Use the integer (UNORM 8) alias so the test path doesn't
    // pull in the soft-float runtime — see VkClearColorValue.
    VkClearColorValue color{};
    color.uint32[0] = 0x00; // R
    color.uint32[1] = 0x80; // G
    color.uint32[2] = 0xFF; // B
    color.uint32[3] = 0xFF; // A
    if (VkCmdBindPipeline(cb, VkPipelineBindPoint::Graphics, pipe) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdBindPipeline failed", 0);
    if (VkCmdClearColorImage(cb, img, color) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdClearColorImage failed", 0);
    if (VkCmdDraw(cb, 3, 1, 0, 0) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdDraw failed", 0);
    if (VkCmdDrawIndexed(cb, 6, 1, 0, 0, 0) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCmdDrawIndexed failed", 0);
    if (VkEndCommandBuffer(cb) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkEndCommandBuffer failed", 0);

    VkFence fence = 0;
    if (VkCreateFence(dev, false, &fence) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateFence failed", 0);

    if (VkQueueSubmit(queue, 1, &cb, fence) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkQueueSubmit failed", 0);
    if (VkWaitForFences(dev, 1, &fence, 0) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkWaitForFences failed", 0);
    if (VkQueueWaitIdle(queue) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkQueueWaitIdle failed", 0);

    // Memory-mapping leg: allocate host-visible memory, bind two
    // buffers into it, map the source, write a recognisable byte
    // pattern, record CopyBuffer + FillBuffer + CopyBufferToImage
    // (against a non-scanout image so no pixels reach the live
    // framebuffer), submit, assert the destination buffer
    // matches the source.
    {
        VkDeviceMemory hmem = 0;
        if (VkAllocateMemory(dev, 4096, /*memory_type_index=*/1, &hmem) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkAllocateMemory(host-visible) failed", 0);
        VkBuffer hsrc = 0, hdst = 0;
        if (VkCreateBuffer(dev, 1024, &hsrc) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateBuffer(host-src) failed", 0);
        if (VkCreateBuffer(dev, 1024, &hdst) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateBuffer(host-dst) failed", 0);
        if (VkBindBufferMemory(dev, hsrc, hmem, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] BindBufferMemory(host-src) failed", 0);
        if (VkBindBufferMemory(dev, hdst, hmem, 1024) != VkResult::Success)
            return SelftestFail("[selftest:graphics] BindBufferMemory(host-dst) failed", 0);

        // Map the memory + write a pattern across the src half.
        void* mapped = nullptr;
        if (VkMapMemory(dev, hmem, 0, 1024, &mapped) != VkResult::Success || mapped == nullptr)
            return SelftestFail("[selftest:graphics] VkMapMemory failed", 0);
        auto* src_bytes = static_cast<u8*>(mapped);
        for (u32 i = 0; i < 256; ++i)
            src_bytes[i] = static_cast<u8>(i);
        VkUnmapMemory(dev, hmem);

        // Record CopyBuffer + FillBuffer into a second cb, submit.
        VkCommandBuffer cb2 = 0;
        if (VkAllocateCommandBuffers(dev, pool, 1, &cb2) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkAllocateCommandBuffers(cb2) failed", 0);
        if (VkBeginCommandBuffer(cb2) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkBeginCommandBuffer(cb2) failed", 0);
        if (VkCmdCopyBuffer(cb2, hsrc, hdst, 0, 0, 256) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCmdCopyBuffer failed", 0);
        if (VkCmdFillBuffer(cb2, hdst, 256, 256, 0xA5A5A5A5u) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCmdFillBuffer failed", 0);
        if (VkEndCommandBuffer(cb2) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkEndCommandBuffer(cb2) failed", 0);
        if (VkQueueSubmit(queue, 1, &cb2, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkQueueSubmit(cb2) failed", 0);
        if (VkQueueWaitIdle(queue) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkQueueWaitIdle(cb2) failed", 0);

        // Read the dst region back through a second mapping and
        // assert the byte pattern propagated.
        if (VkMapMemory(dev, hmem, 1024, 512, &mapped) != VkResult::Success || mapped == nullptr)
            return SelftestFail("[selftest:graphics] VkMapMemory(dst) failed", 0);
        const auto* dst_bytes = static_cast<const u8*>(mapped);
        for (u32 i = 0; i < 256; ++i)
        {
            if (dst_bytes[i] != static_cast<u8>(i))
                return SelftestFail("[selftest:graphics] CopyBuffer didn't propagate byte", i);
        }
        const auto* fill_words = reinterpret_cast<const u32*>(dst_bytes + 256);
        for (u32 i = 0; i < 64; ++i)
        {
            if (fill_words[i] != 0xA5A5A5A5u)
                return SelftestFail("[selftest:graphics] FillBuffer didn't broadcast pattern", fill_words[i]);
        }
        VkUnmapMemory(dev, hmem);

        if (VkFreeCommandBuffers(dev, pool, 1, &cb2) != VkResult::Success)
            return SelftestFail("[selftest:graphics] FreeCommandBuffers(cb2) failed", 0);
        VkDestroyBuffer(dev, hdst);
        VkDestroyBuffer(dev, hsrc);
        VkFreeMemory(dev, hmem);
    }

    // Sampler / event / pipeline-cache / query-pool leg.
    {
        const VkSamplerCreateInfo sci{VkFilter::Linear, VkFilter::Linear, VkSamplerAddressMode::ClampToEdge,
                                      VkSamplerAddressMode::ClampToEdge, VkSamplerAddressMode::ClampToEdge};
        VkSampler smp = 0;
        if (VkCreateSampler(dev, &sci, &smp) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateSampler failed", 0);
        VkDestroySampler(dev, smp);

        VkEvent evt = 0;
        if (VkCreateEvent(dev, &evt) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateEvent failed", 0);
        if (VkGetEventStatus(dev, evt) != VkResult::EventReset)
            return SelftestFail("[selftest:graphics] new event was not Reset", 0);
        if (VkSetEvent(dev, evt) != VkResult::Success || VkGetEventStatus(dev, evt) != VkResult::EventSet)
            return SelftestFail("[selftest:graphics] VkSetEvent did not signal", 0);
        if (VkResetEvent(dev, evt) != VkResult::Success || VkGetEventStatus(dev, evt) != VkResult::EventReset)
            return SelftestFail("[selftest:graphics] VkResetEvent did not clear", 0);
        VkDestroyEvent(dev, evt);

        VkPipelineCache pcache = 0;
        if (VkCreatePipelineCache(dev, nullptr, 0, &pcache) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreatePipelineCache failed", 0);
        u64 cache_size = 0;
        if (VkGetPipelineCacheData(dev, pcache, &cache_size, nullptr) != VkResult::Success || cache_size == 0)
            return SelftestFail("[selftest:graphics] cache size query failed", cache_size);
        u8 cache_buf[64] = {};
        u64 fill_size = sizeof(cache_buf);
        if (VkGetPipelineCacheData(dev, pcache, &fill_size, cache_buf) != VkResult::Success || fill_size != cache_size)
            return SelftestFail("[selftest:graphics] cache data fetch failed", fill_size);
        VkDestroyPipelineCache(dev, pcache);

        // Query pool: timestamp queries.  Record reset + two
        // timestamps + submit, fetch results, assert ordering.
        VkQueryPool qpool = 0;
        if (VkCreateQueryPool(dev, VkQueryType::Timestamp, 2, &qpool) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateQueryPool failed", 0);
        VkCommandBuffer qcb = 0;
        if (VkAllocateCommandBuffers(dev, pool, 1, &qcb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] AllocateCommandBuffers(qcb) failed", 0);
        if (VkBeginCommandBuffer(qcb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] Begin(qcb) failed", 0);
        if (VkCmdResetQueryPool(qcb, qpool, 0, 2) != VkResult::Success)
            return SelftestFail("[selftest:graphics] CmdResetQueryPool failed", 0);
        if (VkCmdWriteTimestamp(qcb, 0x10, qpool, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] CmdWriteTimestamp(0) failed", 0);
        if (VkCmdWriteTimestamp(qcb, 0x10, qpool, 1) != VkResult::Success)
            return SelftestFail("[selftest:graphics] CmdWriteTimestamp(1) failed", 0);
        if (VkEndCommandBuffer(qcb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] End(qcb) failed", 0);
        if (VkQueueSubmit(queue, 1, &qcb, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] QueueSubmit(qcb) failed", 0);
        if (VkQueueWaitIdle(queue) != VkResult::Success)
            return SelftestFail("[selftest:graphics] WaitIdle(qcb) failed", 0);
        u64 ts[2] = {};
        if (VkGetQueryPoolResults(dev, qpool, 0, 2, ts, sizeof(u64), 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] GetQueryPoolResults failed", 0);
        if (ts[1] < ts[0])
            return SelftestFail("[selftest:graphics] timestamp ordering inverted", ts[0]);
        VkFreeCommandBuffers(dev, pool, 1, &qcb);
        VkDestroyQueryPool(dev, qpool);
    }

    // ResetCommandPool exercises the new pool-wide reset path.
    if (VkResetCommandPool(dev, pool, 0) != VkResult::Success)
        return SelftestFail("[selftest:graphics] VkResetCommandPool failed", 0);

    // WSI leg: surface + swapchain + acquire / present cycle.
    // Skipped when no framebuffer is live (headless boot) — the
    // surface create itself fails in that case, which is the
    // intended behaviour, so the test asserts the right error
    // code rather than treating it as a regression.
    const auto di_for_wsi = drivers::video::Query();
    if (di_for_wsi.available)
    {
        VkSurfaceKHR surface = 0;
        if (VkCreateDuetSurfaceKHR(inst, &surface) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateDuetSurfaceKHR failed", 0);

        VkSurfaceCapabilitiesKHR caps{};
        if (VkGetPhysicalDeviceSurfaceCapabilitiesKHR(phys[0], surface, &caps) != VkResult::Success)
            return SelftestFail("[selftest:graphics] GetPhysicalDeviceSurfaceCapabilities failed", 0);
        if (caps.currentExtent.width == 0 || caps.currentExtent.height == 0)
            return SelftestFail("[selftest:graphics] surface caps reported a zero extent", 0);

        u32 fmt_count = 0;
        if (VkGetPhysicalDeviceSurfaceFormatsKHR(phys[0], surface, &fmt_count, nullptr) != VkResult::Success ||
            fmt_count == 0)
            return SelftestFail("[selftest:graphics] surface formats(query) failed", fmt_count);

        u32 mode_count = 0;
        if (VkGetPhysicalDeviceSurfacePresentModesKHR(phys[0], surface, &mode_count, nullptr) != VkResult::Success ||
            mode_count == 0)
            return SelftestFail("[selftest:graphics] surface present modes(query) failed", mode_count);

        VkSwapchainKHR sc = 0;
        // Use a 1x1 extent so the present's FramebufferPresent
        // call doesn't actually paint anything visible — the
        // swapchain images are scanout-backed but no clear gets
        // recorded against them in the self-test.
        if (VkCreateSwapchainKHR(dev, surface, 2, VkExtent2D{1, 1}, &sc) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateSwapchainKHR failed", 0);

        u32 sc_image_count = 0;
        if (VkGetSwapchainImagesKHR(dev, sc, &sc_image_count, nullptr) != VkResult::Success || sc_image_count != 2)
            return SelftestFail("[selftest:graphics] swapchain image count mismatch", sc_image_count);

        VkImage sc_images[kMaxSwapchainImages] = {};
        u32 want_images = sc_image_count;
        if (VkGetSwapchainImagesKHR(dev, sc, &want_images, sc_images) != VkResult::Success)
            return SelftestFail("[selftest:graphics] swapchain images(fetch) failed", 0);

        // Two acquire + present round trips so the rotation cursor
        // actually advances and the second present validates the
        // index handed back by Acquire.  Present without a prior
        // Acquire must fail — proves the index gate is wired.
        u32 idx = 0;
        if (VkQueuePresentKHR(queue, sc, 0) != VkResult::ErrorInitializationFailed)
            return SelftestFail("[selftest:graphics] QueuePresent without Acquire did not fail", 0);
        if (VkAcquireNextImageKHR(dev, sc, 0, 0, 0, &idx) != VkResult::Success)
            return SelftestFail("[selftest:graphics] AcquireNextImage failed", 0);
        if (VkQueuePresentKHR(queue, sc, idx) != VkResult::Success)
            return SelftestFail("[selftest:graphics] QueuePresent failed", 0);
        if (VkAcquireNextImageKHR(dev, sc, 0, 0, 0, &idx) != VkResult::Success)
            return SelftestFail("[selftest:graphics] AcquireNextImage(2) failed", 0);
        if (VkQueuePresentKHR(queue, sc, idx) != VkResult::Success)
            return SelftestFail("[selftest:graphics] QueuePresent(2) failed", 0);

        VkDestroySwapchainKHR(dev, sc);
        VkDestroySurfaceKHR(inst, surface);
    }

    // Tear down in reverse order.
    VkDestroyFence(dev, fence);
    if (VkFreeCommandBuffers(dev, pool, 1, &cb) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkFreeCommandBuffers failed", 0);
    VkDestroyCommandPool(dev, pool);
    if (VkFreeDescriptorSets(dev, dpool, 1, &dset) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkFreeDescriptorSets failed", 0);
    VkDestroyDescriptorPool(dev, dpool);
    VkDestroyDescriptorSetLayout(dev, dsl);
    VkDestroyFramebuffer(dev, fb);
    VkDestroyRenderPass(dev, rp);
    VkDestroyImageView(dev, view);
    VkDestroyImage(dev, img);
    VkDestroyBuffer(dev, buf);
    VkFreeMemory(dev, mem_handle);
    VkDestroyPipeline(dev, pipe);
    VkDestroyShaderModule(dev, fs);
    VkDestroyShaderModule(dev, vs);
    VkDestroyPipelineLayout(dev, pl_layout);
    VkDestroyDevice(dev);
    VkDestroyInstance(inst);
    return true;
}

bool AssertAllPoolsClean()
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

} // namespace

VkResult GraphicsIcdSelfTest()
{
    KLOG_TRACE_SCOPE("subsystems/graphics", "GraphicsIcdSelfTest");
    if (!RunCanonicalLifecycle())
        return VkResult::ErrorInitializationFailed;
    if (!AssertAllPoolsClean())
        return VkResult::ErrorInitializationFailed;
    if (g_invalid_spirv_rejections == 0)
    {
        KLOG_WARN("subsystems/graphics",
                  "[selftest:graphics] expected SPIR-V validator to register at least one rejection");
        return VkResult::ErrorInitializationFailed;
    }
    if (g_command_recorded < 3)
    {
        KLOG_WARN_V("subsystems/graphics", "[selftest:graphics] command tape recorded fewer ops than expected",
                    g_command_recorded);
        return VkResult::ErrorInitializationFailed;
    }
    if (g_command_replayed < 3)
    {
        KLOG_WARN_V("subsystems/graphics", "[selftest:graphics] command replay covered fewer ops than expected",
                    g_command_replayed);
        return VkResult::ErrorInitializationFailed;
    }
    if (g_spirv_modules_parsed < 3)
    {
        KLOG_WARN_V("subsystems/graphics", "[selftest:graphics] SPIR-V parser covered fewer modules than expected",
                    g_spirv_modules_parsed);
        return VkResult::ErrorInitializationFailed;
    }
    if (g_spirv_entry_points_seen == 0 || g_spirv_capabilities_seen == 0)
    {
        KLOG_WARN("subsystems/graphics",
                  "[selftest:graphics] SPIR-V parser did not aggregate entry-points or capabilities");
        return VkResult::ErrorInitializationFailed;
    }
    KLOG_INFO_V("subsystems/graphics", "Vulkan ICD self-test passed; ops replayed", g_command_replayed);
    return VkResult::Success;
}

} // namespace duetos::subsystems::graphics
