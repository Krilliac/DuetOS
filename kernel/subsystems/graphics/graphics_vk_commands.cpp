#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_internal.h"

#include "log/klog.h"

/*
 * DuetOS — Vulkan ICD: command pool + command buffer surface
 * and the vkCmd* recording entry points.
 *
 * Covers VkCreateCommandPool / VkAllocateCommandBuffers /
 * VkBegin/EndCommandBuffer / VkResetCommandBuffer /
 * VkResetCommandPool plus every recording entry the ICD
 * advertises (vkCmdBeginRenderPass, vkCmdClearColorImage,
 * vkCmdDraw, vkCmdDrawIndexed, vkCmdSetViewport / Scissor,
 * vkCmdBindVertexBuffers / IndexBuffer, vkCmdCopyBuffer /
 * FillBuffer / CopyImage / BlitImage / CopyImageToBuffer /
 * ResolveImage / CopyBufferToImage / UpdateBuffer,
 * vkCmdPipelineBarrier, vkCmdPushConstants, vkCmdDispatch,
 * vkCmdClearAttachments, vkCmdClearDepthStencilImage).
 *
 * The submit-replay machinery + vkQueueSubmit stay in
 * graphics_vk.cpp for now because they reference internal
 * counter aggregates that haven't been promoted to the
 * cross-TU bridge.  When that promotion happens the replay
 * code will join this TU.
 *
 * Cross-TU bridge through `graphics_vk_internal.h`:  every
 * Cmd* uses AppendOp + the per-kind Pool helpers + the
 * record types declared there.
 */

namespace duetos::subsystems::graphics
{

using namespace internal;
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

namespace internal
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

} // namespace internal

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

VkResult VkCmdCopyImage(VkCommandBuffer cb, VkImage src_image, VkImage dst_image, u32 width, u32 height)
{
    if (!HandleInRange(src_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(src_image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(dst_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(dst_image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::CopyImage;
    op.src_image = src_image;
    op.image = dst_image;
    op.region_width = width;
    op.region_height = height;
    return AppendOp(cb, op);
}

VkResult VkCmdBlitImage(VkCommandBuffer cb, VkImage src_image, VkImage dst_image, VkRect2D src_rect, VkRect2D dst_rect,
                        VkFilter filter)
{
    if (!HandleInRange(src_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(src_image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(dst_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(dst_image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::BlitImage;
    op.src_image = src_image;
    op.image = dst_image;
    op.src_rect = src_rect;
    op.dst_rect = dst_rect;
    op.blit_filter = filter;
    return AppendOp(cb, op);
}

VkResult VkCmdCopyImageToBuffer(VkCommandBuffer cb, VkImage src_image, VkBuffer dst_buffer, u64 dst_offset, u32 width,
                                u32 height)
{
    if (!HandleInRange(src_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(src_image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(dst_buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(dst_buffer, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::CopyImageToBuffer;
    op.src_image = src_image;
    op.dst_buffer = dst_buffer;
    op.dst_offset = dst_offset;
    op.region_width = width;
    op.region_height = height;
    return AppendOp(cb, op);
}

VkResult VkCmdResolveImage(VkCommandBuffer cb, VkImage src_image, VkImage dst_image, u32 width, u32 height)
{
    if (!HandleInRange(src_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(src_image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    if (!HandleInRange(dst_image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(dst_image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::ResolveImage;
    op.src_image = src_image;
    op.image = dst_image;
    op.region_width = width;
    op.region_height = height;
    return AppendOp(cb, op);
}

VkResult VkCmdUpdateBuffer(VkCommandBuffer cb, VkBuffer dst, u64 dst_offset, u64 size, const void* data)
{
    if (!HandleInRange(dst, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(dst, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    if (size == 0)
        return VkResult::Success;
    if (data == nullptr)
        return VkResult::ErrorInitializationFailed;
    if (size > kMaxPushConstantBytes)
        return VkResult::ErrorTooManyObjects; // v0 inline cap; spec allows 64 KiB
    CmdRecord op{};
    op.op = CmdOp::UpdateBuffer;
    op.dst_buffer = dst;
    op.dst_offset = dst_offset;
    op.region_size = size;
    const auto* src = static_cast<const u8*>(data);
    for (u64 i = 0; i < size; ++i)
        op.push_data[i] = src[i];
    op.push_size = static_cast<u32>(size);
    return AppendOp(cb, op);
}

VkResult VkCmdClearAttachments(VkCommandBuffer cb, u32 attachment_count, u32 rect_count, VkClearColorValue clear)
{
    CmdRecord op{};
    op.op = CmdOp::ClearAttachments;
    op.attachment_count = attachment_count;
    op.rect_count = rect_count;
    op.color = clear;
    return AppendOp(cb, op);
}

VkResult VkCmdClearDepthStencilImage(VkCommandBuffer cb, VkImage image, float depth, u32 stencil)
{
    if (!HandleInRange(image, kImageBase) || !PoolIsLive(g_image_pool, SlotOf(image, kImageBase)))
        return VkResult::ErrorInitializationFailed;
    // Kernel can't touch a `float` (no SSE / soft-float runtime),
    // so capture the bit pattern through the union form to avoid
    // ever reading the value as a float.
    CmdRecord op{};
    op.op = CmdOp::ClearDepthStencilImage;
    op.image = image;
    union
    {
        float f;
        u32 u;
    } cast = {depth};
    op.depth_bits = cast.u;
    op.stencil = stencil & 0xFFu;
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// Indirect draw / dispatch (VK 1.0 core).
// -------------------------------------------------------------------

VkResult VkCmdDrawIndirect(VkCommandBuffer cb, VkBuffer buffer, u64 offset, u32 draw_count, u32 stride)
{
    if (!HandleInRange(buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buffer, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::DrawIndirect;
    op.src_buffer = buffer;
    op.src_offset = offset;
    op.vertex_count = draw_count;
    op.first_vertex = stride;
    return AppendOp(cb, op);
}

VkResult VkCmdDrawIndexedIndirect(VkCommandBuffer cb, VkBuffer buffer, u64 offset, u32 draw_count, u32 stride)
{
    if (!HandleInRange(buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buffer, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::DrawIndexedIndirect;
    op.src_buffer = buffer;
    op.src_offset = offset;
    op.index_count = draw_count;
    op.first_index = stride;
    return AppendOp(cb, op);
}

VkResult VkCmdDispatchIndirect(VkCommandBuffer cb, VkBuffer buffer, u64 offset)
{
    if (!HandleInRange(buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buffer, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::DispatchIndirect;
    op.src_buffer = buffer;
    op.src_offset = offset;
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// VK 1.3 core dynamic state — recorded only.
// -------------------------------------------------------------------

VkResult VkCmdSetCullMode(VkCommandBuffer cb, u32 cull_mode)
{
    CmdRecord op{};
    op.op = CmdOp::SetCullMode;
    op.vertex_count = cull_mode;
    return AppendOp(cb, op);
}

VkResult VkCmdSetFrontFace(VkCommandBuffer cb, u32 front_face)
{
    CmdRecord op{};
    op.op = CmdOp::SetFrontFace;
    op.vertex_count = front_face;
    return AppendOp(cb, op);
}

VkResult VkCmdSetPrimitiveTopology(VkCommandBuffer cb, u32 topology)
{
    CmdRecord op{};
    op.op = CmdOp::SetPrimitiveTopology;
    op.vertex_count = topology;
    return AppendOp(cb, op);
}

VkResult VkCmdSetVertexFormatDuet(VkCommandBuffer cb, u32 format)
{
    CmdRecord op{};
    op.op = CmdOp::SetVertexFormatDuet;
    op.vertex_count = format;
    return AppendOp(cb, op);
}

VkResult VkCmdSetDepthTestEnable(VkCommandBuffer cb, u32 enable)
{
    CmdRecord op{};
    op.op = CmdOp::SetDepthTestEnable;
    op.vertex_count = enable;
    return AppendOp(cb, op);
}

VkResult VkCmdSetDepthWriteEnable(VkCommandBuffer cb, u32 enable)
{
    CmdRecord op{};
    op.op = CmdOp::SetDepthWriteEnable;
    op.vertex_count = enable;
    return AppendOp(cb, op);
}

VkResult VkCmdSetDepthCompareOp(VkCommandBuffer cb, u32 compare_op)
{
    CmdRecord op{};
    op.op = CmdOp::SetDepthCompareOp;
    op.vertex_count = compare_op;
    return AppendOp(cb, op);
}

VkResult VkCmdSetStencilTestEnable(VkCommandBuffer cb, u32 enable)
{
    CmdRecord op{};
    op.op = CmdOp::SetStencilTestEnable;
    op.vertex_count = enable;
    return AppendOp(cb, op);
}

VkResult VkCmdSetStencilOp(VkCommandBuffer cb, u32 face_mask, u32 fail_op, u32 pass_op, u32 depth_fail_op,
                           u32 compare_op)
{
    CmdRecord op{};
    op.op = CmdOp::SetStencilOp;
    op.vertex_count = face_mask;
    op.first_vertex = fail_op;
    op.instance_count = pass_op;
    op.first_instance = depth_fail_op;
    op.index_count = compare_op;
    return AppendOp(cb, op);
}

VkResult VkCmdSetDepthBoundsTestEnable(VkCommandBuffer cb, u32 enable)
{
    CmdRecord op{};
    op.op = CmdOp::SetDepthBoundsTestEnable;
    op.vertex_count = enable;
    return AppendOp(cb, op);
}

VkResult VkCmdSetViewportWithCount(VkCommandBuffer cb, u32 count, const VkViewport* viewports)
{
    (void)viewports;
    CmdRecord op{};
    op.op = CmdOp::SetViewportWithCount;
    op.vertex_count = count;
    return AppendOp(cb, op);
}

VkResult VkCmdSetScissorWithCount(VkCommandBuffer cb, u32 count, const VkRect2D* scissors)
{
    CmdRecord op{};
    op.op = CmdOp::SetScissorWithCount;
    op.vertex_count = count;
    if (count > 0 && scissors != nullptr)
        op.area = scissors[0];
    return AppendOp(cb, op);
}

VkResult VkCmdBindVertexBuffers2(VkCommandBuffer cb, u32 first_binding, u32 count, const VkBuffer* buffers,
                                 const u64* offsets, const u64* sizes, const u64* strides)
{
    (void)sizes;
    (void)strides;
    if (count == 0)
        return VkResult::Success;
    if (buffers == nullptr)
        return VkResult::ErrorInitializationFailed;
    for (u32 i = 0; i < count; ++i)
    {
        if (!HandleInRange(buffers[i], kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(buffers[i], kBufferBase)))
            return VkResult::ErrorInitializationFailed;
    }
    CmdRecord op{};
    op.op = CmdOp::BindVertexBuffers2;
    op.vertex_buffer = buffers[0];
    op.vertex_offset_bytes = (offsets != nullptr) ? offsets[0] : 0;
    op.vertex_binding = first_binding;
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// Subpass advance.
// -------------------------------------------------------------------

VkResult VkCmdNextSubpass(VkCommandBuffer cb, u32 contents)
{
    CmdRecord op{};
    op.op = CmdOp::NextSubpass;
    op.vertex_count = contents;
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// Extended query commands.
// -------------------------------------------------------------------

VkResult VkCmdCopyQueryPoolResults(VkCommandBuffer cb, VkQueryPool pool, u32 first_query, u32 query_count,
                                   VkBuffer dst_buffer, u64 dst_offset, u64 stride, u32 flags)
{
    if (!HandleInRange(dst_buffer, kBufferBase) || !PoolIsLive(g_buffer_pool, SlotOf(dst_buffer, kBufferBase)))
        return VkResult::ErrorInitializationFailed;
    CmdRecord op{};
    op.op = CmdOp::CopyQueryPoolResults;
    op.dst_buffer = dst_buffer;
    op.dst_offset = dst_offset;
    op.first_index = first_query;
    op.index_count = query_count;
    op.vertex_count = static_cast<u32>(stride);
    op.first_instance = flags;
    op.vertex_offset_bytes = pool;
    return AppendOp(cb, op);
}

VkResult VkCmdBeginQueryIndexed(VkCommandBuffer cb, VkQueryPool pool, u32 query, u32 flags, u32 index)
{
    CmdRecord op{};
    op.op = CmdOp::BeginQueryIndexed;
    op.vertex_offset_bytes = pool;
    op.first_index = query;
    op.first_instance = flags;
    op.vertex_count = index;
    return AppendOp(cb, op);
}

VkResult VkCmdEndQueryIndexed(VkCommandBuffer cb, VkQueryPool pool, u32 query, u32 index)
{
    CmdRecord op{};
    op.op = CmdOp::EndQueryIndexed;
    op.vertex_offset_bytes = pool;
    op.first_index = query;
    op.vertex_count = index;
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// Synchronization2 (recorded only — v0 has no GPU hazard tracking).
// -------------------------------------------------------------------

VkResult VkCmdSetEvent2(VkCommandBuffer cb, VkEvent event, u64 stage_mask)
{
    CmdRecord op{};
    op.op = CmdOp::SetEvent2;
    op.index_buffer = event;
    op.index_offset = stage_mask;
    return AppendOp(cb, op);
}

VkResult VkCmdResetEvent2(VkCommandBuffer cb, VkEvent event, u64 stage_mask)
{
    CmdRecord op{};
    op.op = CmdOp::ResetEvent2;
    op.index_buffer = event;
    op.index_offset = stage_mask;
    return AppendOp(cb, op);
}

VkResult VkCmdWaitEvents2(VkCommandBuffer cb, u32 count, const VkEvent* events)
{
    (void)events;
    CmdRecord op{};
    op.op = CmdOp::WaitEvents2;
    op.vertex_count = count;
    return AppendOp(cb, op);
}

VkResult VkCmdPipelineBarrier2(VkCommandBuffer cb, u64 src_stage_mask, u64 dst_stage_mask, u32 dependency_flags)
{
    CmdRecord op{};
    op.op = CmdOp::PipelineBarrier2;
    op.src_offset = src_stage_mask;
    op.dst_offset = dst_stage_mask;
    op.vertex_count = dependency_flags;
    return AppendOp(cb, op);
}

// -------------------------------------------------------------------
// Physical-device sparse format queries.
// -------------------------------------------------------------------

VkResult VkGetPhysicalDeviceSparseImageFormatProperties(VkPhysicalDevice phys, u32 format, u32 type, u32 samples,
                                                        u32 usage, u32 tiling, u32* count)
{
    (void)phys;
    (void)format;
    (void)type;
    (void)samples;
    (void)usage;
    (void)tiling;
    if (count != nullptr)
        *count = 0; // no sparse formats supported in v0
    return VkResult::Success;
}

} // namespace duetos::subsystems::graphics
