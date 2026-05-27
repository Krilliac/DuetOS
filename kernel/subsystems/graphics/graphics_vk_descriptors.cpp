#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_internal.h"

/*
 * DuetOS — Vulkan ICD: descriptor set / descriptor pool /
 * descriptor set layout entry points.
 *
 * Lifted into its own TU so a future "real shader, real
 * resource binding" slice has a focused file to evolve.
 * Per-handle storage + counters live in graphics_vk.cpp; this
 * TU reaches them through `graphics_vk_internal.h`.
 */

namespace duetos::subsystems::graphics
{

using namespace internal;

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
        DescriptorSetRecord& dsr = g_desc_set_data[slot];
        dsr.pool = pool;
        dsr.layout = layouts[i];
        dsr.writes = 0;
        for (u32 b = 0; b < kMaxDescriptorBindings; ++b)
        {
            dsr.bindings[b].type = 0;
            dsr.bindings[b].handle = 0;
            dsr.bindings[b].sampler_handle = 0;
        }
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

VkResult VkUpdateDescriptorSetSampled(VkDescriptorSet set, u32 binding, VkDescriptorType type, u64 resource_handle,
                                      u64 sampler_handle)
{
    if (!HandleInRange(set, kDescSetBase) || !PoolIsLive(g_desc_set_pool, SlotOf(set, kDescSetBase)))
        return VkResult::ErrorInitializationFailed;
    const u32 slot = SlotOf(set, kDescSetBase);
    ++g_desc_set_data[slot].writes;
    ++g_descriptor_writes;
    // Record the (binding, type, image, sampler) tuple so the
    // shader-rasterizer hook can hand it to spirv::BindDescriptor
    // at draw time. Out-of-range binding silently no-ops the write
    // (keeps the existing counter behaviour).
    if (binding < kMaxDescriptorBindings)
    {
        g_desc_set_data[slot].bindings[binding].type = static_cast<u32>(type);
        g_desc_set_data[slot].bindings[binding].handle = resource_handle;
        g_desc_set_data[slot].bindings[binding].sampler_handle = sampler_handle;
    }
    return VkResult::Success;
}

VkResult VkUpdateDescriptorSet(VkDescriptorSet set, u32 binding, VkDescriptorType type, u64 resource_handle)
{
    return VkUpdateDescriptorSetSampled(set, binding, type, resource_handle, 0);
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
        const VkResult r = VkUpdateDescriptorSetSampled(writes[i].dstSet, writes[i].dstBinding, writes[i].type,
                                                        writes[i].resourceHandle, writes[i].samplerHandle);
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
    // Validate every handle up front to catch a stale-handle bug
    // at record time rather than at submit replay.
    for (u32 i = 0; i < set_count; ++i)
    {
        if (!HandleInRange(sets[i], kDescSetBase) || !PoolIsLive(g_desc_set_pool, SlotOf(sets[i], kDescSetBase)))
            return VkResult::ErrorInitializationFailed;
    }
    // Record the first bound set so the replay walker can stash
    // it in RasterState and the shader-rasterizer hook can pull
    // its (binding, handle) tuples into spirv::BindDescriptor.
    // v0 only honours set 0 — the bindings array in
    // DescriptorSetRecord handles up to kMaxDescriptorBindings.
    if (set_count > 0)
    {
        CmdRecord op{};
        op.op = CmdOp::BindDescriptorSets;
        op.descriptor_set = sets[0];
        return AppendOp(cb, op);
    }
    return VkResult::Success;
}

} // namespace duetos::subsystems::graphics
