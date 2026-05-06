#include "subsystems/graphics/graphics.h"

#include "arch/x86_64/serial.h"
#include "drivers/gpu/gpu.h"
#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"
#include "log/klog.h"

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
};
ShaderRecord g_shader_data[kPoolCapacity];

struct BufferRecord
{
    u64 size;
    bool memory_bound;
};
BufferRecord g_buffer_data[kPoolCapacity];

enum class CmdOp : u8
{
    None = 0,
    BeginRenderPass = 1,
    EndRenderPass = 2,
    BindPipeline = 3,
    ClearColorImage = 4,
    Draw = 5,
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

// -------------------------------------------------------------------
// Aggregate counters.
// -------------------------------------------------------------------

u32 g_queue_submits = 0;
u32 g_command_recorded = 0;
u32 g_command_replayed = 0;
u32 g_clear_pixels_painted = 0;
u32 g_invalid_spirv_rejections = 0;
u32 g_descriptor_writes = 0;

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
    const auto di = drivers::video::Query();
    out->vendorID = di.gpu_present ? PciVendorIdFromName(di.gpu_vendor) : 0u;
    out->deviceID = 0;

    // Device type: virtio-gpu / Bochs are virtual; Intel iGPU is
    // integrated; AMD/NVIDIA are discrete.  CPU fallback when no
    // display-class device was discovered.
    if (!di.gpu_present)
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
    append(di.gpu_present ? di.gpu_vendor : "cpu");
    if (di.gpu_present && di.gpu_family != nullptr)
    {
        append("-");
        append(di.gpu_family);
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
    if (memory_type_index >= 2)
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_memory_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = HandleFor(kMemoryBase, slot);
    return VkResult::Success;
}

void VkFreeMemory(VkDevice dev, VkDeviceMemory mem)
{
    (void)dev;
    if (mem == 0 || !HandleInRange(mem, kMemoryBase))
        return;
    (void)PoolFree(g_memory_pool, SlotOf(mem, kMemoryBase));
}

VkResult VkCreateBuffer(VkDevice dev, u64 size, VkBuffer* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_buffer_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    g_buffer_data[slot].size = size;
    g_buffer_data[slot].memory_bound = false;
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
    (void)offset;
    if (!HandleInRange(buf, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buf, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(mem, kMemoryBase) || !PoolIsLive(g_memory_pool, SlotOf(mem, kMemoryBase)))
        return VkResult::ErrorInitializationFailed;
    g_buffer_data[SlotOf(buf, kBufferBase)].memory_bound = true;
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
    if (out != nullptr)
        *out = HandleFor(kShaderBase, slot);
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

// -------------------------------------------------------------------
// Submit replay.
// -------------------------------------------------------------------

namespace
{

void ReplayClear(const CmdRecord& op)
{
    if (!HandleInRange(op.image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(op.image, kImageBase)))
        return;
    const auto& img = g_image_data[SlotOf(op.image, kImageBase)];
    if ((img.flags & kImageScanoutBacked) == 0)
        return;
    // Map RGBA float to the framebuffer's 0xRRGGBB format and
    // paint.  Framebuffer dimensions clamp the rect — the image
    // extent may exceed the live framebuffer (caller resized).
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
    drivers::video::FramebufferFillRect(0, 0, w, h, ColorToRgb(op.color));
    drivers::video::FramebufferAddDamage(0, 0, w, h);
    g_clear_pixels_painted += w * h;
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
            // The render-pass clear value would also paint the
            // attachment if the attachment image were scanout-
            // backed.  Wiring that path needs the framebuffer ->
            // attachment ImageView mapping, which is a follow-on
            // slice; for v0 we record the op for stats only.
            break;
        case CmdOp::EndRenderPass:
        case CmdOp::BindPipeline:
        case CmdOp::Draw:
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
    s.vk_queue_submits = g_queue_submits;
    s.vk_command_recorded = g_command_recorded;
    s.vk_command_replayed = g_command_replayed;
    s.vk_clear_pixels_painted = g_clear_pixels_painted;
    s.vk_invalid_spirv_rejections = g_invalid_spirv_rejections;
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
// bound + schema + a single OpReturn (0xFD0001).  Real shaders
// have orders of magnitude more, but our v0 ICD only checks the
// magic word; the trailing words satisfy the "must be 4-byte
// aligned and at least 5 words" test the spec mandates so a
// downstream consumer can size-check the blob.
constexpr u32 kFakeSpirvBlob[] = {
    0x07230203u, // magic
    0x00010300u, // version 1.3
    0x0000000Bu, // generator (DuetOS placeholder)
    0x00000001u, // bound
    0x00000000u, // schema
    0x000100FDu, // OpReturn
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

    // Wire descriptor writes + bind into the recording leg so the
    // happy path covers the full set surface.
    if (VkUpdateDescriptorSet(dset, 0, VkDescriptorType::UniformBuffer, buf) != VkResult::Success)
        return SelftestFail("[selftest:graphics] VkUpdateDescriptorSet(uniform) failed", 0);
    if (VkUpdateDescriptorSet(dset, 1, VkDescriptorType::CombinedImageSampler, view) != VkResult::Success)
        return SelftestFail("[selftest:graphics] VkUpdateDescriptorSet(image) failed", 0);
    if (VkCmdBindDescriptorSets(cb, VkPipelineBindPoint::Graphics, pl_layout, 0, 1, &dset) != VkResult::Success)
        return SelftestFail("[selftest:graphics] VkCmdBindDescriptorSets failed", 0);

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
        &g_fence_pool,       &g_semaphore_pool, &g_desc_set_layout_pool, &g_desc_pool_pool, &g_desc_set_pool};
    const char* names[] = {
        "instance",        "physical-device", "device",        "queue",       "command-pool", "command-buffer",
        "shader-module",   "pipeline-layout", "pipeline",      "render-pass", "framebuffer",  "image",
        "image-view",      "buffer",          "device-memory", "fence",       "semaphore",    "descriptor-set-layout",
        "descriptor-pool", "descriptor-set"};
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
    KLOG_INFO_V("subsystems/graphics", "Vulkan ICD self-test passed; ops replayed", g_command_replayed);
    return VkResult::Success;
}

} // namespace duetos::subsystems::graphics
