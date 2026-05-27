#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_internal.h"

/*
 * DuetOS — Vulkan ICD: sampler / event / pipeline-cache /
 * query-pool entry points.
 *
 * Four small subsystems whose entry points share a shape
 * (Create / Destroy + a few accessors) and whose storage is
 * already declared in `graphics_vk_internal.h`.  Lives in its
 * own TU so a future "what does the cache surface do?" change
 * has a single, focused file to edit.
 */

namespace duetos::subsystems::graphics
{

using namespace internal;
// -------------------------------------------------------------------
// Sampler.
// -------------------------------------------------------------------

VkResult VkCreateSampler(VkDevice dev, const VkSamplerCreateInfo* info, VkSampler* out)
{
    if (!HandleInRange(dev, kDeviceBase) || !PoolIsLive(g_device_pool, SlotOf(dev, kDeviceBase)))
        return VkResult::ErrorInitializationFailed;
    u32 slot = 0;
    if (!PoolAlloc(g_sampler_pool, &slot))
        return VkResult::ErrorOutOfHostMemory;
    // Capture address modes + filters so the SPIR-V executor's
    // OpImageSample path can honour the caller's choice instead
    // of defaulting to Repeat. nullptr info -> Vulkan-default
    // (Repeat / Nearest) for symmetry with what most CTS tests
    // expect when they forget to fill the struct.
    SamplerRecord& rec = g_sampler_data[slot];
    if (info != nullptr)
    {
        rec.address_mode_u = static_cast<u8>(info->addressModeU);
        rec.address_mode_v = static_cast<u8>(info->addressModeV);
        rec.address_mode_w = static_cast<u8>(info->addressModeW);
        rec.mag_filter = static_cast<u8>(info->magFilter);
        rec.min_filter = static_cast<u8>(info->minFilter);
    }
    else
    {
        rec.address_mode_u = static_cast<u8>(VkSamplerAddressMode::Repeat);
        rec.address_mode_v = static_cast<u8>(VkSamplerAddressMode::Repeat);
        rec.address_mode_w = static_cast<u8>(VkSamplerAddressMode::Repeat);
        rec.mag_filter = static_cast<u8>(VkFilter::Nearest);
        rec.min_filter = static_cast<u8>(VkFilter::Nearest);
    }
    if (out != nullptr)
        *out = HandleFor(kSamplerBase, slot);
    return VkResult::Success;
}

SamplerAddressMode SamplerAddressModeFor(u64 sampler_handle)
{
    if (sampler_handle == 0 || !HandleInRange(sampler_handle, kSamplerBase))
        return SamplerAddressMode::ClampToEdge;
    const u32 slot = SlotOf(sampler_handle, kSamplerBase);
    if (!PoolIsLive(g_sampler_pool, slot))
        return SamplerAddressMode::ClampToEdge;
    const u8 raw = g_sampler_data[slot].address_mode_u;
    if (raw > static_cast<u8>(SamplerAddressMode::ClampToBorder))
        return SamplerAddressMode::ClampToEdge;
    return static_cast<SamplerAddressMode>(raw);
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

} // namespace duetos::subsystems::graphics
