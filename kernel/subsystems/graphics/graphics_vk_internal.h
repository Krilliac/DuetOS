#pragma once

#include "subsystems/graphics/graphics.h"

#include "util/types.h"

/*
 * DuetOS — Vulkan ICD internal interface.
 *
 * Cross-TU surface used to split the Vulkan ICD across more
 * than one TU.  Today: graphics_vk.cpp (entry-point
 * implementations + storage definitions) and
 * graphics_vk_selftest.cpp (boot self-test).  The header is
 * sized for arbitrary further splits — every per-kind handle
 * pool, every record struct, every shared helper and every
 * counter is declared here so a follow-on slice can carve out
 * graphics_vk_commands.cpp / _wsi.cpp / _misc.cpp without
 * further header churn.
 *
 * Discipline:
 *   - Types + constants live here as inline definitions.
 *   - Helpers small enough to inline (Pool primitives + handle
 *     range maths) live here as inline functions.
 *   - Per-kind handle storage lives here as `extern` decls;
 *     the storage is defined exactly once in graphics_vk.cpp.
 *   - Counters likewise — `extern` here, defined in
 *     graphics_vk.cpp.
 *
 * Not part of the public Vulkan ICD surface.  Userland code
 * never includes this file.
 */

namespace duetos::subsystems::graphics::internal
{

// -------------------------------------------------------------------
// Pool primitive + per-kind base ranges.
// -------------------------------------------------------------------
//
// Every Vk* type has its own handle pool: a fixed-size bitmap
// of live slots plus a per-kind base.  A handle is `base + slot`.
// Capacity is sized for the canonical self-test path plus a
// comfortable headroom; this is a v0 ICD, not a benchmark.

inline constexpr u32 kPoolCapacity = 32;

struct Pool
{
    u32 live = 0;
    u32 created = 0;
    u32 destroyed = 0;
    u32 used_bitmap = 0; // bit N = slot N live
};

inline bool PoolAlloc(Pool& p, u32* slot_out)
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

inline bool PoolFree(Pool& p, u32 slot)
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

inline bool PoolIsLive(const Pool& p, u32 slot)
{
    if (slot >= kPoolCapacity)
        return false;
    return (p.used_bitmap & (1u << slot)) != 0u;
}

inline constexpr u64 kInstanceBase = 0x1'0000;
inline constexpr u64 kPhysDevBase = 0x2'0000;
inline constexpr u64 kDeviceBase = 0x3'0000;
inline constexpr u64 kQueueBase = 0x4'0000;
inline constexpr u64 kCmdPoolBase = 0x5'0000;
inline constexpr u64 kCmdBufBase = 0x6'0000;
inline constexpr u64 kShaderBase = 0x7'0000;
inline constexpr u64 kPipelineLayoutBase = 0x8'0000;
inline constexpr u64 kPipelineBase = 0x9'0000;
inline constexpr u64 kRenderPassBase = 0xA'0000;
inline constexpr u64 kFramebufferBase = 0xB'0000;
inline constexpr u64 kImageBase = 0xC'0000;
inline constexpr u64 kImageViewBase = 0xD'0000;
inline constexpr u64 kBufferBase = 0xE'0000;
inline constexpr u64 kMemoryBase = 0xF'0000;
inline constexpr u64 kFenceBase = 0x10'0000;
inline constexpr u64 kSemaphoreBase = 0x11'0000;
inline constexpr u64 kDescSetLayoutBase = 0x12'0000;
inline constexpr u64 kDescPoolBase = 0x13'0000;
inline constexpr u64 kDescSetBase = 0x14'0000;
inline constexpr u64 kSurfaceBase = 0x15'0000;
inline constexpr u64 kSwapchainBase = 0x16'0000;
inline constexpr u64 kSamplerBase = 0x17'0000;
inline constexpr u64 kEventBase = 0x18'0000;
inline constexpr u64 kPipelineCacheBase = 0x19'0000;
inline constexpr u64 kQueryPoolBase = 0x1A'0000;

inline bool HandleInRange(u64 h, u64 base)
{
    return h >= base && h < base + kPoolCapacity;
}
inline u32 SlotOf(u64 h, u64 base)
{
    return static_cast<u32>(h - base);
}
inline u64 HandleFor(u64 base, u32 slot)
{
    return base + slot;
}

// -------------------------------------------------------------------
// Per-kind record types.
// -------------------------------------------------------------------

struct ImageRecord
{
    VkExtent3D extent;
    u32 flags;
    bool memory_bound;
};

struct ShaderRecord
{
    u64 byte_size;
    ShaderModuleInfo info;
};

struct BufferRecord
{
    u64 size;
    bool memory_bound;
    void* backing;
    u64 backing_offset;
    VkDeviceMemory bound_memory;
};

struct ImageViewRecord
{
    VkImage image;
};

struct FramebufferRecord
{
    VkImageView attachment;
};

struct DeviceMemoryRecord
{
    u64 size;
    void* host_ptr;
    u32 type_index;
    bool host_visible;
    u32 map_count;
};

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
    CopyImage = 24,
    BlitImage = 25,
    CopyImageToBuffer = 26,
    ResolveImage = 27,
    UpdateBuffer = 28,
    ClearAttachments = 29,
    ClearDepthStencilImage = 30,
    BeginRendering = 31,
    EndRendering = 32,
    SetLineWidth = 33,
    SetDepthBias = 34,
    SetBlendConstants = 35,
    SetDepthBounds = 36,
    SetStencilState = 37,
    BeginDebugLabel = 38,
    EndDebugLabel = 39,
    InsertDebugLabel = 40,
    PushDescriptor = 41,
    ExecuteCommands = 42,
    DrawIndirect = 43,
    DrawIndexedIndirect = 44,
    DispatchIndirect = 45,
    SetCullMode = 46,
    SetFrontFace = 47,
    SetPrimitiveTopology = 48,
    SetDepthTestEnable = 49,
    SetDepthWriteEnable = 50,
    SetDepthCompareOp = 51,
    SetStencilTestEnable = 52,
    SetStencilOp = 53,
    SetDepthBoundsTestEnable = 54,
    SetViewportWithCount = 55,
    SetScissorWithCount = 56,
    BindVertexBuffers2 = 57,
    NextSubpass = 58,
    CopyQueryPoolResults = 59,
    BeginQueryIndexed = 60,
    EndQueryIndexed = 61,
    SetEvent2 = 62,
    ResetEvent2 = 63,
    WaitEvents2 = 64,
    PipelineBarrier2 = 65,
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
    u32 index_count;
    u32 first_index;
    i32 vertex_offset;
    VkBuffer index_buffer;
    u64 index_offset;
    VkIndexType index_type;
    VkBuffer vertex_buffer;
    u64 vertex_offset_bytes;
    u32 vertex_binding;
    VkBuffer src_buffer;
    VkBuffer dst_buffer;
    u64 src_offset;
    u64 dst_offset;
    u64 region_size;
    u32 fill_pattern;
    u32 push_offset;
    u32 push_size;
    u8 push_data[kMaxPushConstantBytes];
    u32 dispatch_x;
    u32 dispatch_y;
    u32 dispatch_z;
    VkEvent event;
    VkQueryPool query_pool;
    u32 query_first;
    u32 query_count;
    u32 query_index;
    u32 region_width;
    u32 region_height;
    VkImage src_image;
    VkRect2D src_rect;
    VkRect2D dst_rect;
    VkFilter blit_filter;
    u32 depth_bits;
    u32 stencil;
    u32 attachment_count;
    u32 rect_count;
    VkCommandBuffer secondary_cb;
};

inline constexpr u32 kCmdTapeCapacity = 32;

enum class CbState : u8
{
    Initial = 0,
    Recording = 1,
    Executable = 2,
};

struct CmdBufferRecord
{
    CbState state;
    bool is_secondary;
    u32 op_count;
    CmdRecord ops[kCmdTapeCapacity];
};

struct DescriptorSetLayoutRecord
{
    u32 binding_count;
    VkDescriptorSetLayoutBinding bindings[kMaxDescriptorBindings];
};

struct DescriptorPoolRecord
{
    u32 max_sets;
    u32 sets_allocated;
};

struct DescriptorSetRecord
{
    VkDescriptorPool pool;
    VkDescriptorSetLayout layout;
    u32 writes;
};

struct SwapchainRecord
{
    VkSurfaceKHR surface;
    VkExtent2D extent;
    u32 image_count;
    u32 next_image;
    u32 acquired_index;
    bool image_acquired;
    VkImage images[kMaxSwapchainImages];
};

struct EventRecord
{
    bool signalled;
};

struct PipelineCacheRecord
{
    u64 stored_size;
};

inline constexpr u32 kMaxQueriesPerPool = 16;
struct QueryPoolRecord
{
    VkQueryType type;
    u32 query_count;
    u64 results[kMaxQueriesPerPool];
    bool available[kMaxQueriesPerPool];
};

struct PhysicalDeviceRecord
{
    u32 gpu_index;
    u32 owning_instance_slot; ///< Slot in g_instance_pool that allocated this phys; freed on VkDestroyInstance.
};

struct QueueRecord
{
    u32 owning_device_slot; ///< Slot in g_device_pool that vkGetDeviceQueue allocated from; freed on VkDestroyDevice.
};

// -------------------------------------------------------------------
// Per-kind storage.  Defined exactly once in graphics_vk.cpp.
// -------------------------------------------------------------------

extern Pool g_instance_pool;
extern Pool g_phys_pool;
extern Pool g_device_pool;
extern Pool g_queue_pool;
extern Pool g_cmdpool_pool;
extern Pool g_cmdbuf_pool;
extern Pool g_shader_pool;
extern Pool g_pipelinelayout_pool;
extern Pool g_pipeline_pool;
extern Pool g_renderpass_pool;
extern Pool g_framebuffer_pool;
extern Pool g_image_pool;
extern Pool g_imageview_pool;
extern Pool g_buffer_pool;
extern Pool g_memory_pool;
extern Pool g_fence_pool;
extern Pool g_semaphore_pool;
extern Pool g_desc_set_layout_pool;
extern Pool g_desc_pool_pool;
extern Pool g_desc_set_pool;
extern Pool g_surface_pool;
extern Pool g_swapchain_pool;
extern Pool g_sampler_pool;
extern Pool g_event_pool;
extern Pool g_pipeline_cache_pool;
extern Pool g_query_pool_pool;

extern ImageRecord g_image_data[kPoolCapacity];
extern ShaderRecord g_shader_data[kPoolCapacity];
extern BufferRecord g_buffer_data[kPoolCapacity];
extern ImageViewRecord g_imageview_data[kPoolCapacity];
extern FramebufferRecord g_framebuffer_data[kPoolCapacity];
extern DeviceMemoryRecord g_memory_data[kPoolCapacity];
extern CmdBufferRecord g_cmdbuf_data[kPoolCapacity];
extern DescriptorSetLayoutRecord g_desc_set_layout_data[kPoolCapacity];
extern DescriptorPoolRecord g_desc_pool_data[kPoolCapacity];
extern DescriptorSetRecord g_desc_set_data[kPoolCapacity];
extern SwapchainRecord g_swapchain_data[kPoolCapacity];
extern EventRecord g_event_data[kPoolCapacity];
extern PipelineCacheRecord g_pipeline_cache_data[kPoolCapacity];
extern QueryPoolRecord g_query_pool_data[kPoolCapacity];
extern PhysicalDeviceRecord g_phys_data[kPoolCapacity];
extern QueueRecord g_queue_data[kPoolCapacity];

// -------------------------------------------------------------------
// Aggregate counters.
// -------------------------------------------------------------------

extern u32 g_queue_submits;
extern u32 g_command_recorded;
extern u32 g_command_replayed;
extern u32 g_clear_pixels_painted;
extern u32 g_invalid_spirv_rejections;
extern u32 g_descriptor_writes;
extern u32 g_swapchain_acquires;
extern u32 g_swapchain_presents;
extern u32 g_spirv_modules_parsed;
extern u32 g_spirv_entry_points_seen;
extern u32 g_spirv_capabilities_seen;
extern u32 g_spirv_decorations_seen;
extern u32 g_spirv_execution_modes_seen;
extern u32 g_buffer_copy_bytes;
extern u32 g_buffer_fill_bytes;
extern u32 g_push_constant_writes;
extern u32 g_pipeline_barriers;
extern u32 g_dispatches;
extern u32 g_queries_executed;
extern u32 g_memory_maps;
extern u32 g_image_upload_pixels;
extern u32 g_dynamic_renderings;
extern u32 g_debug_labels;
extern u32 g_secondary_executes;
extern u32 g_secondary_ops_replayed;
extern u32 g_push_descriptor_writes;
extern u32 g_triangles_drawn;

// -------------------------------------------------------------------
// Shared helper functions.
// -------------------------------------------------------------------

u32 ColorToRgb(const VkClearColorValue& c);
void PaintScanoutClear(VkImage image, VkClearColorValue color);
VkResult AppendOp(VkCommandBuffer cb, const CmdRecord& op);
void ReplayCommandBuffer(VkCommandBuffer cb);

/// Software triangle rasterizer for `vkCmdDraw` replay. Reads
/// triangles from the bound vertex buffer using the DuetOS v0
/// fixed vertex format (see `graphics_vk_raster.cpp`) and paints
/// flat-shaded triangles into the bound scanout-backed render
/// target via `FramebufferPutPixel`. Always bumps
/// `g_triangles_drawn` by `vertex_count / 3` so the dispatch
/// chain is observable even when no pixels are produced
/// (non-scanout target, no live framebuffer, etc.).
void RasterizeDuetTriangles(VkImage rt_image, VkBuffer vertex_buffer, u64 vb_offset, u32 first_vertex,
                            u32 vertex_count);

// One-shot logging dedupe across the ICD.  Each entry-point id
// gets a single boot-log line the first time it's reached;
// subsequent calls are silent.  Storage (the seen-bitmap) lives
// in graphics_vk.cpp.
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
void LogOnce(EpId id, const char* name);

// ----- counter accessors used by the boot self-test ----------------
//
// Same shape as before the header expanded — the selftest TU
// sticks to function-call accessors so it doesn't depend on the
// exact storage layout.

u32 DynamicRenderingsCount();
u32 SecondaryExecutesCount();
u32 SecondaryOpsReplayedCount();
u32 PushDescriptorWritesCount();
u32 InvalidSpirvRejectionsCount();
u32 CommandRecordedCount();
u32 CommandReplayedCount();
u32 SpirvModulesParsedCount();
u32 SpirvEntryPointsSeenCount();
u32 SpirvCapabilitiesSeenCount();
u32 TrianglesDrawnCount();

// ----- leak check ---------------------------------------------------

bool LeakCheckHandlePools();

} // namespace duetos::subsystems::graphics::internal
