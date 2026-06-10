#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_internal.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/display_info.h"
#include "log/klog.h"
#include "util/soft_float.h"

/*
 * DuetOS — Vulkan ICD boot self-test.
 *
 * Drives the canonical Vulkan lifecycle and asserts every live
 * counter returns to zero.  Failure leaves a WARN sentinel in
 * the boot log; success is silent.  The test deliberately does
 * NOT exercise the scanout-backed clear path — the framebuffer
 * is owned by the boot console at this point in init and a
 * clear against the live framebuffer would erase the boot log.
 *
 * This TU only reaches the ICD's internal state through the
 * accessors declared in `graphics_vk_internal.h` — counters
 * are read via `internal::*Count()` calls and the per-kind
 * pool leak walk goes through `internal::LeakCheckHandlePools()`.
 * The test is otherwise pure public-API consumption.
 */

namespace duetos::subsystems::graphics
{

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
        VkWriteDescriptorSet{dset, 0, VkDescriptorType::UniformBuffer, buf, 0},
        VkWriteDescriptorSet{dset, 1, VkDescriptorType::CombinedImageSampler, view, 0},
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
    // A freshly-created unsignalled fence must report NotReady;
    // the pre-fix path returned Success unconditionally because
    // FenceRecord didn't exist.
    if (VkGetFenceStatus(dev, fence) != VkResult::NotReady)
        return SelftestFail("[selftest:graphics] new unsignalled fence reported ready", 0);

    // The cb above recorded `VkCmdDraw(cb, 3, ...)` against a
    // non-scanout image — the rasterizer must STILL bump the
    // triangles-drawn counter (one triangle = vertex_count / 3)
    // even though it skips painting pixels, so the dispatch
    // chain is observable in tests that don't own the live
    // framebuffer.
    const u32 tri_before = internal::TrianglesDrawnCount();
    if (VkQueueSubmit(queue, 1, &cb, fence) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkQueueSubmit failed", 0);
    // VkQueueSubmit must flip the fence to signalled — the
    // synchronous v0 submit completes before this line.
    if (VkGetFenceStatus(dev, fence) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkQueueSubmit did not signal fence", 0);
    if (VkWaitForFences(dev, 1, &fence, 0) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkWaitForFences failed", 0);
    // VkResetFences must clear the signalled bit, returning the
    // fence to NotReady status.
    if (VkResetFences(dev, 1, &fence) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkResetFences failed", 0);
    if (VkGetFenceStatus(dev, fence) != VkResult::NotReady)
        return SelftestFail("[selftest:graphics] reset fence did not clear signalled bit", 0);
    // A wait against an unsignalled fence must return Timeout
    // (rather than the legacy Success-no-matter-what).
    if (VkWaitForFences(dev, 1, &fence, 0) != VkResult::Timeout)
        return SelftestFail("[selftest:graphics] wait on unsignalled fence did not Timeout", 0);
    // VkCreateFence(signalled=true) — the create-info bit must
    // reach the FenceRecord so callers that want to immediately
    // wait without blocking get Success on the first call.
    VkFence pre_signalled = 0;
    if (VkCreateFence(dev, true, &pre_signalled) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkCreateFence(signalled=true) failed", 0);
    if (VkGetFenceStatus(dev, pre_signalled) != VkResult::Success)
        return SelftestFail("[selftest:graphics] pre-signalled fence reported NotReady", 0);
    VkDestroyFence(dev, pre_signalled);
    if (VkQueueWaitIdle(queue) != VkResult::Success)
        return SelftestFail("[selftest:graphics] vkQueueWaitIdle failed", 0);
    if (internal::TrianglesDrawnCount() <= tri_before)
        return SelftestFail("[selftest:graphics] triangles-drawn counter did not advance after vkCmdDraw",
                            internal::TrianglesDrawnCount());

    // Rasterizer-feature leg. Records the v1 state machine the
    // software rasterizer exposes for game-like workloads:
    //   - SetVertexFormatDuet(v1): 12-byte vertices with Z.
    //   - SetPrimitiveTopology(TriangleStrip): 4 verts -> 2 tris.
    //   - SetScissor(0,0,8,8): clip the bbox at raster time.
    //   - SetDepthTestEnable/CompareOp/WriteEnable: gate the Z
    //     test.
    //   - ClearDepthStencilImage: lazy-alloc the shared depth
    //     surface and clear it.
    //   - DrawIndexed with the existing non-scanout image: the
    //     rasterizer ticks `g_triangles_drawn` (by `index_count
    //     - 2` for strips), then bails before painting.
    {
        VkCommandBuffer rcb = 0;
        if (VkAllocateCommandBuffers(dev, pool, 1, &rcb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] rcb allocate failed", 0);
        if (VkBeginCommandBuffer(rcb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] rcb begin failed", 0);
        if (VkCmdSetVertexFormatDuet(rcb, 1) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCmdSetVertexFormatDuet failed", 0);
        if (VkCmdSetPrimitiveTopology(rcb, 4) != VkResult::Success) // TriangleStrip
            return SelftestFail("[selftest:graphics] SetPrimitiveTopology(strip) failed", 0);
        const VkRect2D rscissor{VkOffset2D{0, 0}, VkExtent2D{8, 8}};
        if (VkCmdSetScissor(rcb, 0, 1, &rscissor) != VkResult::Success)
            return SelftestFail("[selftest:graphics] SetScissor failed", 0);
        if (VkCmdSetDepthTestEnable(rcb, 1) != VkResult::Success)
            return SelftestFail("[selftest:graphics] SetDepthTestEnable failed", 0);
        if (VkCmdSetDepthCompareOp(rcb, 1) != VkResult::Success) // Less
            return SelftestFail("[selftest:graphics] SetDepthCompareOp failed", 0);
        if (VkCmdSetDepthWriteEnable(rcb, 1) != VkResult::Success)
            return SelftestFail("[selftest:graphics] SetDepthWriteEnable failed", 0);
        if (VkCmdClearDepthStencilImage(rcb, img, 1.0f, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] CmdClearDepthStencilImage failed", 0);
        const u64 rvb_off = 0;
        if (VkCmdBindVertexBuffers(rcb, 0, 1, &buf, &rvb_off) != VkResult::Success)
            return SelftestFail("[selftest:graphics] BindVertexBuffers(rcb) failed", 0);
        if (VkCmdBindIndexBuffer(rcb, buf, 0, VkIndexType::Uint16) != VkResult::Success)
            return SelftestFail("[selftest:graphics] BindIndexBuffer(rcb) failed", 0);
        // Four-vertex strip -> 2 triangles.
        if (VkCmdDrawIndexed(rcb, 4, 1, 0, 0, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] DrawIndexed(strip) failed", 0);
        if (VkEndCommandBuffer(rcb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] rcb end failed", 0);

        const u32 raster_before = internal::TrianglesDrawnCount();
        if (VkQueueSubmit(queue, 1, &rcb, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] rcb submit failed", 0);
        if (VkQueueWaitIdle(queue) != VkResult::Success)
            return SelftestFail("[selftest:graphics] rcb wait failed", 0);
        // strip with 4 indices -> 2 triangles. The counter ticks
        // even though the image isn't scanout-backed, so the
        // dispatch chain (including the new strip / scissor /
        // depth / vertex-format / index-fetch paths) is
        // verified end-to-end.
        if (internal::TrianglesDrawnCount() - raster_before != 2u)
            return SelftestFail("[selftest:graphics] strip DrawIndexed did not produce 2 triangles",
                                internal::TrianglesDrawnCount() - raster_before);
        VkFreeCommandBuffers(dev, pool, 1, &rcb);
    }

    // Point / line / cull leg. Exercises the non-triangle
    // topologies and the cull-mode + front-face state. None of
    // these paint pixels (image is non-scanout) but every recorded
    // op must dispatch cleanly: a wrong dispatch path crashes
    // here rather than silently producing nothing.
    {
        VkCommandBuffer pcb = 0;
        if (VkAllocateCommandBuffers(dev, pool, 1, &pcb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] pcb allocate failed", 0);
        if (VkBeginCommandBuffer(pcb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] pcb begin failed", 0);
        const u64 pcb_vb_off = 0;
        if (VkCmdBindVertexBuffers(pcb, 0, 1, &buf, &pcb_vb_off) != VkResult::Success)
            return SelftestFail("[selftest:graphics] BindVertexBuffers(pcb) failed", 0);
        // Cull-back, CCW front. Won't affect non-triangle paths.
        if (VkCmdSetCullMode(pcb, 2u) != VkResult::Success)
            return SelftestFail("[selftest:graphics] SetCullMode failed", 0);
        if (VkCmdSetFrontFace(pcb, 0u) != VkResult::Success)
            return SelftestFail("[selftest:graphics] SetFrontFace failed", 0);
        // PointList — three vertices = three pixels.
        if (VkCmdSetPrimitiveTopology(pcb, 0u) != VkResult::Success)
            return SelftestFail("[selftest:graphics] SetPrimitiveTopology(point) failed", 0);
        if (VkCmdDraw(pcb, 3, 1, 0, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] Draw(point) failed", 0);
        // LineList — four vertices = two lines.
        if (VkCmdSetPrimitiveTopology(pcb, 1u) != VkResult::Success)
            return SelftestFail("[selftest:graphics] SetPrimitiveTopology(line list) failed", 0);
        if (VkCmdDraw(pcb, 4, 1, 0, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] Draw(line list) failed", 0);
        // LineStrip — three vertices = two lines.
        if (VkCmdSetPrimitiveTopology(pcb, 2u) != VkResult::Success)
            return SelftestFail("[selftest:graphics] SetPrimitiveTopology(line strip) failed", 0);
        if (VkCmdDraw(pcb, 3, 1, 0, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] Draw(line strip) failed", 0);
        if (VkEndCommandBuffer(pcb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] pcb end failed", 0);
        if (VkQueueSubmit(queue, 1, &pcb, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] pcb submit failed", 0);
        if (VkQueueWaitIdle(queue) != VkResult::Success)
            return SelftestFail("[selftest:graphics] pcb wait failed", 0);
        VkFreeCommandBuffers(dev, pool, 1, &pcb);
    }

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
        // The create-info's addressModeU must reach the executor's
        // OpImageSample path via `SamplerAddressModeFor(smp)`. The
        // pre-fix path threw the field on the floor — every sampler
        // collapsed to Repeat — so this assertion pins the
        // regression bound.
        if (internal::SamplerAddressModeFor(smp) != internal::SamplerAddressMode::ClampToEdge)
            return SelftestFail("[selftest:graphics] sampler addressModeU did not propagate (ClampToEdge)", 0);
        VkDestroySampler(dev, smp);
        // A second sampler with a different mode confirms the
        // record isn't a single-shared-slot bug.
        const VkSamplerCreateInfo sci_border{VkFilter::Nearest, VkFilter::Nearest, VkSamplerAddressMode::ClampToBorder,
                                             VkSamplerAddressMode::ClampToBorder, VkSamplerAddressMode::ClampToBorder};
        VkSampler smp_border = 0;
        if (VkCreateSampler(dev, &sci_border, &smp_border) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateSampler(border) failed", 0);
        if (internal::SamplerAddressModeFor(smp_border) != internal::SamplerAddressMode::ClampToBorder)
            return SelftestFail("[selftest:graphics] sampler addressModeU did not propagate (ClampToBorder)", 0);
        VkDestroySampler(dev, smp_border);
        // Handle == 0 must produce a defined fallback so descriptor
        // writes that don't pin a sampler keep working.
        if (internal::SamplerAddressModeFor(0) != internal::SamplerAddressMode::ClampToEdge)
            return SelftestFail("[selftest:graphics] sampler handle=0 fallback wrong", 0);
        if (internal::SamplerMagFilterFor(0) != 1u)
            return SelftestFail("[selftest:graphics] sampler handle=0 filter fallback wrong", 0);
        // Per-axis decoupling: an asymmetric sampler (Repeat-U /
        // ClampToEdge-V) must report distinct modes on each axis.
        // The pre-decouple path only honoured the U axis; this
        // pins the regression bound.
        const VkSamplerCreateInfo sci_mixed{VkFilter::Linear, VkFilter::Linear, VkSamplerAddressMode::Repeat,
                                            VkSamplerAddressMode::ClampToEdge, VkSamplerAddressMode::Repeat};
        VkSampler smp_mixed = 0;
        if (VkCreateSampler(dev, &sci_mixed, &smp_mixed) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateSampler(mixed) failed", 0);
        if (internal::SamplerAddressModeFor(smp_mixed) != internal::SamplerAddressMode::Repeat)
            return SelftestFail("[selftest:graphics] mixed sampler U axis wrong", 0);
        if (internal::SamplerAddressModeVFor(smp_mixed) != internal::SamplerAddressMode::ClampToEdge)
            return SelftestFail("[selftest:graphics] mixed sampler V axis wrong", 0);
        // The mixed sampler was created with VkFilter::Linear above,
        // so the SamplerMagFilterFor lookup must return 1.
        if (internal::SamplerMagFilterFor(smp_mixed) != 1u)
            return SelftestFail("[selftest:graphics] mixed sampler magFilter not Linear", 0);
        VkDestroySampler(dev, smp_mixed);
        // Nearest-filter sampler: VkCreateSampler(magFilter=Nearest)
        // must round-trip to SamplerMagFilterFor(handle) == 0.
        const VkSamplerCreateInfo sci_nearest{VkFilter::Nearest, VkFilter::Nearest, VkSamplerAddressMode::ClampToEdge,
                                              VkSamplerAddressMode::ClampToEdge, VkSamplerAddressMode::ClampToEdge};
        VkSampler smp_nearest = 0;
        if (VkCreateSampler(dev, &sci_nearest, &smp_nearest) != VkResult::Success)
            return SelftestFail("[selftest:graphics] VkCreateSampler(nearest) failed", 0);
        if (internal::SamplerMagFilterFor(smp_nearest) != 0u)
            return SelftestFail("[selftest:graphics] nearest sampler magFilter not propagated", 0);
        VkDestroySampler(dev, smp_nearest);

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

    // Loader leg: ProcAddr returns non-zero for known names + 0
    // for unknown.  Same call against the device variant must
    // return 0 for instance-only entries (proves the
    // device_level filter works).
    if (VkGetInstanceProcAddr(inst, "vkCreateInstance") == 0)
        return SelftestFail("[selftest:graphics] InstanceProcAddr did not resolve vkCreateInstance", 0);
    if (VkGetInstanceProcAddr(inst, "vkBogusEntryThatDoesNotExist") != 0)
        return SelftestFail("[selftest:graphics] InstanceProcAddr resolved a fake name", 0);
    if (VkGetDeviceProcAddr(dev, "vkCreateInstance") != 0)
        return SelftestFail("[selftest:graphics] DeviceProcAddr resolved an instance-only name", 0);
    if (VkGetDeviceProcAddr(dev, "vkQueueSubmit") == 0)
        return SelftestFail("[selftest:graphics] DeviceProcAddr did not resolve vkQueueSubmit", 0);
    u32 instance_version = 0;
    if (VkEnumerateInstanceVersion(&instance_version) != VkResult::Success || instance_version != kApiVersion1_3)
        return SelftestFail("[selftest:graphics] EnumerateInstanceVersion mismatch", instance_version);

    // Properties2 leg: round-trip through the wrapper.
    VkPhysicalDeviceProperties2 props2{};
    if (VkGetPhysicalDeviceProperties2(phys[0], &props2) != VkResult::Success)
        return SelftestFail("[selftest:graphics] GetPhysicalDeviceProperties2 failed", 0);
    if (props2.properties.apiVersion != kApiVersion1_3)
        return SelftestFail("[selftest:graphics] Properties2 apiVersion mismatch", props2.properties.apiVersion);

    // Memory requirements leg: ask the ICD to report the size /
    // memory-type-bits a buffer / image needs.  Both queries are
    // pure read; assert the values look right.
    VkBuffer mr_buf = 0;
    if (VkCreateBuffer(dev, 4096, &mr_buf) != VkResult::Success)
        return SelftestFail("[selftest:graphics] mr-buffer create failed", 0);
    VkMemoryRequirements buf_req{};
    if (VkGetBufferMemoryRequirements(dev, mr_buf, &buf_req) != VkResult::Success || buf_req.size != 4096)
        return SelftestFail("[selftest:graphics] GetBufferMemoryRequirements wrong size", buf_req.size);
    VkDestroyBuffer(dev, mr_buf);
    VkMemoryRequirements img_req{};
    if (VkGetImageMemoryRequirements(dev, img, &img_req) != VkResult::Success || img_req.size == 0)
        return SelftestFail("[selftest:graphics] GetImageMemoryRequirements wrong size", img_req.size);

    // Debug-utils naming leg: attach a label, read it back.
    const VkDebugUtilsObjectNameInfoEXT name_info{phys[0], "test-physical-device"};
    if (VkSetDebugUtilsObjectNameEXT(dev, &name_info) != VkResult::Success)
        return SelftestFail("[selftest:graphics] SetDebugUtilsObjectName failed", 0);
    char read_back[kMaxDebugLabelLen] = {};
    if (VkGetDebugUtilsObjectNameDuet(phys[0], read_back, sizeof(read_back)) != VkResult::Success)
        return SelftestFail("[selftest:graphics] GetDebugUtilsObjectNameDuet failed", 0);
    if (read_back[0] != 't' || read_back[1] != 'e' || read_back[2] != 's' || read_back[3] != 't')
        return SelftestFail("[selftest:graphics] debug label round-trip corrupted", 0);

    // Dynamic rendering leg: record begin/end, submit, assert
    // the dynamic-rendering counter advanced.  Use the
    // non-scanout image so no pixels reach the framebuffer.
    VkCommandBuffer dyn_cb = 0;
    if (VkAllocateCommandBuffers(dev, pool, 1, &dyn_cb) != VkResult::Success)
        return SelftestFail("[selftest:graphics] dyn cb allocate failed", 0);
    if (VkBeginCommandBuffer(dyn_cb) != VkResult::Success)
        return SelftestFail("[selftest:graphics] dyn cb begin failed", 0);
    VkRenderingAttachmentInfo dyn_attach{};
    dyn_attach.imageView = view;
    dyn_attach.loadOp = 1; // clear
    dyn_attach.clearValue.uint32[0] = 0x12;
    dyn_attach.clearValue.uint32[1] = 0x34;
    dyn_attach.clearValue.uint32[2] = 0x56;
    dyn_attach.clearValue.uint32[3] = 0x78;
    const VkRect2D dyn_area{VkOffset2D{0, 0}, VkExtent2D{16, 16}};
    if (VkCmdBeginRendering(dyn_cb, dyn_area, 1, &dyn_attach) != VkResult::Success)
        return SelftestFail("[selftest:graphics] CmdBeginRendering failed", 0);
    if (VkCmdEndRendering(dyn_cb) != VkResult::Success)
        return SelftestFail("[selftest:graphics] CmdEndRendering failed", 0);
    if (VkEndCommandBuffer(dyn_cb) != VkResult::Success)
        return SelftestFail("[selftest:graphics] dyn cb end failed", 0);
    const u32 dyn_before = internal::DynamicRenderingsCount();
    if (VkQueueSubmit(queue, 1, &dyn_cb, 0) != VkResult::Success)
        return SelftestFail("[selftest:graphics] dyn cb submit failed", 0);
    if (VkQueueWaitIdle(queue) != VkResult::Success)
        return SelftestFail("[selftest:graphics] dyn cb wait failed", 0);
    if (internal::DynamicRenderingsCount() <= dyn_before)
        return SelftestFail("[selftest:graphics] dynamic rendering counter did not advance",
                            internal::DynamicRenderingsCount());
    VkFreeCommandBuffers(dev, pool, 1, &dyn_cb);

    // Format-properties leg: only B8G8R8A8_UNORM (format 0)
    // is recognised; any other format reports zero features.
    VkFormatProperties fmt_props{};
    if (VkGetPhysicalDeviceFormatProperties(phys[0], 0, &fmt_props) != VkResult::Success ||
        fmt_props.optimalTilingFeatures == 0)
        return SelftestFail("[selftest:graphics] FormatProperties for B8G8R8A8 reported no features",
                            fmt_props.optimalTilingFeatures);
    VkFormatProperties unknown_fmt{};
    if (VkGetPhysicalDeviceFormatProperties(phys[0], 0xDEAD, &unknown_fmt) != VkResult::Success ||
        unknown_fmt.optimalTilingFeatures != 0)
        return SelftestFail("[selftest:graphics] FormatProperties for unknown format leaked features", 0);

    // BindMemory2 leg: bind a buffer through the array form.
    {
        VkBuffer arr_buf = 0;
        VkDeviceMemory arr_mem = 0;
        if (VkCreateBuffer(dev, 256, &arr_buf) != VkResult::Success ||
            VkAllocateMemory(dev, 256, 1, &arr_mem) != VkResult::Success)
            return SelftestFail("[selftest:graphics] bind2 create failed", 0);
        const VkBindBufferMemoryInfo info{arr_buf, arr_mem, 0};
        if (VkBindBufferMemory2(dev, 1, &info) != VkResult::Success)
            return SelftestFail("[selftest:graphics] BindBufferMemory2 failed", 0);
        if (VkGetBufferDeviceAddress(dev, arr_buf) == 0)
            return SelftestFail("[selftest:graphics] BufferDeviceAddress reported 0 on bound host-visible buffer", 0);
        VkDestroyBuffer(dev, arr_buf);
        VkFreeMemory(dev, arr_mem);
    }

    // Storage-image texel write/read round-trip: covers the
    // OpImageWrite -> OpImageRead path the SPIR-V executor now
    // routes compute shaders through. Allocate a host-visible
    // image, write a cookie at (3, 4), read it back, assert the
    // exact bit pattern survives. Out-of-bounds writes must be
    // silently dropped without corrupting neighbours.
    {
        VkImage stor_img = 0;
        VkDeviceMemory stor_mem = 0;
        if (VkCreateImage(dev, VkExtent3D{8, 8, 1}, 0, &stor_img) != VkResult::Success)
            return SelftestFail("[selftest:graphics] storage-image create failed", 0);
        if (VkAllocateMemory(dev, 8 * 8 * 4u, /*memory_type_index=*/1, &stor_mem) != VkResult::Success)
            return SelftestFail("[selftest:graphics] storage-image AllocateMemory failed", 0);
        if (VkBindImageMemory(dev, stor_img, stor_mem, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] storage-image BindImageMemory failed", 0);
        // Sentinel write at (1, 0) so we can verify the OOB-drop
        // assertion below didn't clobber a neighbour.
        internal::WriteTexelBgra8(stor_img, 1, 0, 0xFF112233u);
        // Cookie at (3, 4); read back must match.
        internal::WriteTexelBgra8(stor_img, 3, 4, 0xAABBCCDDu);
        const u32 texel_back = internal::FetchTexelBgra8(stor_img, 3, 4);
        if (texel_back != 0xAABBCCDDu)
            return SelftestFail("[selftest:graphics] storage-image texel round-trip mismatch", texel_back);
        // Out-of-bounds write: silently dropped; sentinel at (1, 0)
        // must still read back unchanged.
        internal::WriteTexelBgra8(stor_img, 999, 999, 0xDEADBEEFu);
        if (internal::FetchTexelBgra8(stor_img, 1, 0) != 0xFF112233u)
            return SelftestFail("[selftest:graphics] storage-image OOB write clobbered neighbour", 0);
        // Out-of-bounds read: spec returns 0 (no border colour for
        // sampler-less image reads).
        if (internal::FetchTexelBgra8(stor_img, 999, 999) != 0x00000000u)
            return SelftestFail("[selftest:graphics] storage-image OOB read returned non-zero", 0);
        VkDestroyImage(dev, stor_img);
        VkFreeMemory(dev, stor_mem);
    }

    // Format-aware texel write/read round-trip: covers the path
    // SPIR-V's OpImageRead / OpImageWrite take through FetchTexel
    // / WriteTexel when a non-default format is in play. Two legs
    // exercise R8_UNORM (1 byte/texel UNORM) and R32G32B32A32_SFLOAT
    // (16 bytes/texel raw f32) — the smallest and largest format
    // strides DuetOS recognises.
    {
        VkImage r8_img = 0;
        VkDeviceMemory r8_mem = 0;
        // 8x8 R8_UNORM = 64 bytes; round up to a page for the host-
        // visible memory backing.
        if (VkCreateImageWithFormat(dev, VkExtent3D{8, 8, 1}, /*format=*/2u, 0, &r8_img) != VkResult::Success)
            return SelftestFail("[selftest:graphics] R8 image create failed", 0);
        if (VkAllocateMemory(dev, 256, /*memory_type_index=*/1, &r8_mem) != VkResult::Success)
            return SelftestFail("[selftest:graphics] R8 AllocateMemory failed", 0);
        if (VkBindImageMemory(dev, r8_img, r8_mem, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] R8 BindImageMemory failed", 0);
        // Write Sf32(1.0) -> u8 255 -> Sf32(1.0) on the round-trip.
        // The other three components are ignored by R8 (output is
        // single-channel) but we keep `(0, 0, 0, 1)` so the spec
        // contract for unwritten channels is satisfied.
        const u32 one_bits = 0x3F800000u;  // Sf32(1.0)
        const u32 half_bits = 0x3F000000u; // Sf32(0.5)
        u32 wrote[4] = {one_bits, 0, 0, 0x3F800000u};
        internal::WriteTexel(r8_img, 2, 3, wrote);
        wrote[0] = half_bits;
        internal::WriteTexel(r8_img, 4, 5, wrote);
        u32 r8_back[4]{};
        internal::FetchTexel(r8_img, 2, 3, r8_back);
        // R8 round-trip: 1.0 packs to 255 then unpacks to 1.0
        // exactly (255/255 == 1.0).
        if (r8_back[0] != one_bits)
            return SelftestFail("[selftest:graphics] R8 round-trip(1.0) mismatch", r8_back[0]);
        if (r8_back[3] != one_bits) // alpha default
            return SelftestFail("[selftest:graphics] R8 alpha default wrong", r8_back[3]);
        internal::FetchTexel(r8_img, 4, 5, r8_back);
        // 0.5 packs to u8 127 (Sf32ToI32 truncates: 0.5*255 = 127.5 -> 127);
        // 127/255 = 0.498... ≈ 0x3EFEFEFE
        // Just assert it's bounded — exact value would over-pin to
        // the truncation choice.
        const ::duetos::core::Sf32 unpacked{r8_back[0]};
        if (::duetos::core::Sf32LessThan(unpacked, ::duetos::core::Sf32FromBits(0x3E800000u)) || // < 0.25
            ::duetos::core::Sf32GreaterThan(unpacked, ::duetos::core::Sf32FromBits(0x3F800000u)))
            return SelftestFail("[selftest:graphics] R8 round-trip(0.5) out of range", r8_back[0]);
        VkDestroyImage(dev, r8_img);
        VkFreeMemory(dev, r8_mem);
    }
    {
        VkImage f32_img = 0;
        VkDeviceMemory f32_mem = 0;
        // 4x4 R32G32B32A32_SFLOAT = 4*4*16 = 256 bytes.
        if (VkCreateImageWithFormat(dev, VkExtent3D{4, 4, 1}, /*format=*/5u, 0, &f32_img) != VkResult::Success)
            return SelftestFail("[selftest:graphics] f32x4 image create failed", 0);
        if (VkAllocateMemory(dev, 512, /*memory_type_index=*/1, &f32_mem) != VkResult::Success)
            return SelftestFail("[selftest:graphics] f32x4 AllocateMemory failed", 0);
        if (VkBindImageMemory(dev, f32_img, f32_mem, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] f32x4 BindImageMemory failed", 0);
        // HDR-range values: 2.5, -1.0, 100.0, 0.0 must survive
        // exact round-trip on R32G32B32A32_SFLOAT (raw f32 bits in
        // memory; no clamp/quantise).
        const u32 wrote[4] = {0x40200000u, 0xBF800000u, 0x42C80000u, 0x00000000u};
        internal::WriteTexel(f32_img, 1, 2, wrote);
        u32 f32_back[4]{};
        internal::FetchTexel(f32_img, 1, 2, f32_back);
        for (u32 c = 0; c < 4; ++c)
        {
            if (f32_back[c] != wrote[c])
                return SelftestFail("[selftest:graphics] f32x4 component round-trip mismatch", c);
        }
        VkDestroyImage(dev, f32_img);
        VkFreeMemory(dev, f32_mem);
    }

    // Cmd-debug-label + push-descriptor leg: record a few ops on
    // a transient cb, submit, assert the push-descriptor
    // counter advanced.
    {
        VkCommandBuffer dbg_cb = 0;
        if (VkAllocateCommandBuffers(dev, pool, 1, &dbg_cb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] dbg cb allocate failed", 0);
        if (VkBeginCommandBuffer(dbg_cb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] dbg cb begin failed", 0);
        if (VkCmdBeginDebugUtilsLabelEXT(dbg_cb, "selftest-region") != VkResult::Success)
            return SelftestFail("[selftest:graphics] BeginDebugUtilsLabel failed", 0);
        if (VkCmdInsertDebugUtilsLabelEXT(dbg_cb, "midpoint") != VkResult::Success)
            return SelftestFail("[selftest:graphics] InsertDebugUtilsLabel failed", 0);
        const VkWriteDescriptorSet pd_write{dset, 0, VkDescriptorType::UniformBuffer, buf, 0};
        const u32 pd_before = internal::PushDescriptorWritesCount();
        if (VkCmdPushDescriptorSetKHR(dbg_cb, VkPipelineBindPoint::Graphics, pl_layout, 0, 1, &pd_write) !=
            VkResult::Success)
            return SelftestFail("[selftest:graphics] PushDescriptorSet failed", 0);
        if (internal::PushDescriptorWritesCount() <= pd_before)
            return SelftestFail("[selftest:graphics] push descriptor counter did not advance", 0);
        if (VkCmdEndDebugUtilsLabelEXT(dbg_cb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] EndDebugUtilsLabel failed", 0);
        if (VkEndCommandBuffer(dbg_cb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] dbg cb end failed", 0);
        if (VkQueueSubmit(queue, 1, &dbg_cb, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] dbg cb submit failed", 0);
        if (VkQueueWaitIdle(queue) != VkResult::Success)
            return SelftestFail("[selftest:graphics] dbg cb wait failed", 0);
        VkFreeCommandBuffers(dev, pool, 1, &dbg_cb);
    }

    // Secondary command buffer leg: record an inner op into a
    // secondary, then call ExecuteCommands from a primary.
    {
        VkCommandBuffer secondary = 0;
        if (VkAllocateCommandBuffers2(dev, pool, VkCommandBufferLevel::Secondary, 1, &secondary) != VkResult::Success)
            return SelftestFail("[selftest:graphics] secondary allocate failed", 0);
        if (VkBeginCommandBuffer(secondary) != VkResult::Success)
            return SelftestFail("[selftest:graphics] secondary begin failed", 0);
        // Record three barriers in the secondary so the executes
        // counter has a non-zero ops_replayed delta to assert.
        for (u32 i = 0; i < 3; ++i)
        {
            if (VkCmdPipelineBarrier(secondary, 0x10, 0x20, 0) != VkResult::Success)
                return SelftestFail("[selftest:graphics] secondary inner record failed", i);
        }
        if (VkEndCommandBuffer(secondary) != VkResult::Success)
            return SelftestFail("[selftest:graphics] secondary end failed", 0);

        VkCommandBuffer primary = 0;
        if (VkAllocateCommandBuffers(dev, pool, 1, &primary) != VkResult::Success)
            return SelftestFail("[selftest:graphics] primary allocate failed", 0);
        if (VkBeginCommandBuffer(primary) != VkResult::Success)
            return SelftestFail("[selftest:graphics] primary begin failed", 0);
        if (VkCmdExecuteCommands(primary, 1, &secondary) != VkResult::Success)
            return SelftestFail("[selftest:graphics] CmdExecuteCommands failed", 0);
        // Negative path: a primary cb passed to ExecuteCommands
        // must be rejected.  Proves the level filter is wired.
        if (VkCmdExecuteCommands(primary, 1, &primary) != VkResult::ErrorInitializationFailed)
            return SelftestFail("[selftest:graphics] ExecuteCommands accepted a primary as secondary", 0);
        if (VkEndCommandBuffer(primary) != VkResult::Success)
            return SelftestFail("[selftest:graphics] primary end failed", 0);

        const u32 sec_before = internal::SecondaryExecutesCount();
        const u32 sec_ops_before = internal::SecondaryOpsReplayedCount();
        if (VkQueueSubmit(queue, 1, &primary, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] primary submit failed", 0);
        if (VkQueueWaitIdle(queue) != VkResult::Success)
            return SelftestFail("[selftest:graphics] primary wait failed", 0);
        if (internal::SecondaryExecutesCount() <= sec_before)
            return SelftestFail("[selftest:graphics] secondary executes counter did not advance",
                                internal::SecondaryExecutesCount());
        if (internal::SecondaryOpsReplayedCount() - sec_ops_before < 3)
            return SelftestFail("[selftest:graphics] secondary ops_replayed did not pick up inner barriers",
                                internal::SecondaryOpsReplayedCount() - sec_ops_before);

        VkFreeCommandBuffers(dev, pool, 1, &primary);
        VkFreeCommandBuffers(dev, pool, 1, &secondary);
    }

    // Image-backed render-target leg: the D3D11→Vulkan back-buffer
    // shape. A non-scanout BGRA8 image bound to host-visible memory
    // takes a tape-recorded clear + one v0-format triangle draw;
    // the pixels must land in the image backing (NOT the live
    // framebuffer — the boot console owns that). Asserts the clear
    // color at two corners, the triangle color at an interior
    // pixel, and the image-clear pixel counter delta.
    {
        constexpr u32 kRtW = 16;
        constexpr u32 kRtH = 16;
        VkImage rt_img = 0;
        VkDeviceMemory rt_mem = 0;
        if (VkCreateImage(dev, VkExtent3D{kRtW, kRtH, 1}, 0, &rt_img) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt create failed", 0);
        // One host-visible allocation backs both the image (offset
        // 0, 1 KiB) and the vertex staging (offset 1024).
        if (VkAllocateMemory(dev, 4096, /*memory_type_index=*/1, &rt_mem) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt AllocateMemory failed", 0);
        if (VkBindImageMemory(dev, rt_img, rt_mem, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt BindImageMemory failed", 0);
        VkBuffer rt_vb = 0;
        if (VkCreateBuffer(dev, 1024, &rt_vb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt vb create failed", 0);
        if (VkBindBufferMemory(dev, rt_vb, rt_mem, 1024) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt vb bind failed", 0);

        // Three v0-format vertices ({i16 x, i16 y, u32 argb} LE):
        // an opaque red triangle covering the image centre.
        void* mapped = nullptr;
        if (VkMapMemory(dev, rt_mem, 1024, 24, &mapped) != VkResult::Success || mapped == nullptr)
            return SelftestFail("[selftest:graphics] image-rt map failed", 0);
        {
            auto* v = static_cast<u8*>(mapped);
            const i16 xs[3] = {2, 13, 7};
            const i16 ys[3] = {2, 2, 12};
            for (u32 i = 0; i < 3; ++i)
            {
                v[i * 8 + 0] = static_cast<u8>(xs[i] & 0xFF);
                v[i * 8 + 1] = static_cast<u8>((static_cast<u16>(xs[i]) >> 8) & 0xFF);
                v[i * 8 + 2] = static_cast<u8>(ys[i] & 0xFF);
                v[i * 8 + 3] = static_cast<u8>((static_cast<u16>(ys[i]) >> 8) & 0xFF);
                v[i * 8 + 4] = 0x00; // B
                v[i * 8 + 5] = 0x00; // G
                v[i * 8 + 6] = 0xFF; // R
                v[i * 8 + 7] = 0xFF; // A
            }
        }
        VkUnmapMemory(dev, rt_mem);

        VkCommandBuffer icb = 0;
        if (VkAllocateCommandBuffers(dev, pool, 1, &icb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt cb allocate failed", 0);
        if (VkBeginCommandBuffer(icb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt cb begin failed", 0);
        VkClearColorValue blue{};
        blue.uint32[0] = 0x00; // R
        blue.uint32[1] = 0x00; // G
        blue.uint32[2] = 0xFF; // B
        blue.uint32[3] = 0xFF; // A
        if (VkCmdClearColorImage(icb, rt_img, blue) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt clear record failed", 0);
        const u64 ivb_off = 0;
        if (VkCmdBindVertexBuffers(icb, 0, 1, &rt_vb, &ivb_off) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt vb bind record failed", 0);
        if (VkCmdDraw(icb, 3, 1, 0, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt draw record failed", 0);
        if (VkEndCommandBuffer(icb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt cb end failed", 0);

        const u32 clear_px_before = internal::ImageClearPixelsCount();
        if (VkQueueSubmit(queue, 1, &icb, 0) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt submit failed", 0);
        if (VkQueueWaitIdle(queue) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt wait failed", 0);
        if (internal::ImageClearPixelsCount() - clear_px_before != kRtW * kRtH)
            return SelftestFail("[selftest:graphics] image-clear pixel counter delta wrong",
                                internal::ImageClearPixelsCount() - clear_px_before);

        // Read the backing through a fresh mapping and assert the
        // painted words. Clear blue is 0xFF0000FF; the rasterizer's
        // opaque-flat path writes 0xFF000000 | rgb, so red reads
        // back as 0xFFFF0000 exactly.
        if (VkMapMemory(dev, rt_mem, 0, kRtW * kRtH * 4u, &mapped) != VkResult::Success || mapped == nullptr)
            return SelftestFail("[selftest:graphics] image-rt readback map failed", 0);
        const auto* px = static_cast<const u32*>(mapped);
        if (px[0] != 0xFF0000FFu)
            return SelftestFail("[selftest:graphics] image-rt corner(0,0) not clear color", px[0]);
        if (px[(kRtH - 1) * kRtW + (kRtW - 1)] != 0xFF0000FFu)
            return SelftestFail("[selftest:graphics] image-rt corner(15,15) not clear color",
                                px[(kRtH - 1) * kRtW + (kRtW - 1)]);
        if (px[5 * kRtW + 7] != 0xFFFF0000u)
            return SelftestFail("[selftest:graphics] image-rt interior not triangle color", px[5 * kRtW + 7]);
        VkUnmapMemory(dev, rt_mem);

        if (VkFreeCommandBuffers(dev, pool, 1, &icb) != VkResult::Success)
            return SelftestFail("[selftest:graphics] image-rt cb free failed", 0);
        VkDestroyBuffer(dev, rt_vb);
        VkDestroyImage(dev, rt_img);
        VkFreeMemory(dev, rt_mem);
        // Grep-able PASS sentinel for the boot smoke. This is the
        // QEMU-visible proof of the D3D11→Vulkan kernel paint path
        // (the d3d11_smoke PE that drives the same path from
        // ring 3 runs on bare metal only — see ring3_smoke.cpp's
        // !emulator gate).
        arch::SerialWrite("[vk-selftest] PASS (image-backed clear+draw)\n");
    }

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

        // Acquire/Fence signal-through leg: the caller-supplied
        // VkSemaphore + VkFence must flip to signalled when the
        // image becomes "available". v0 returns the image
        // immediately, so signal happens during the Acquire call.
        VkSemaphore acquire_sem = 0;
        VkFence acquire_fence = 0;
        if (VkCreateSemaphore(dev, &acquire_sem) != VkResult::Success ||
            VkCreateFence(dev, false, &acquire_fence) != VkResult::Success)
            return SelftestFail("[selftest:graphics] sync handle alloc for Acquire failed", 0);
        if (VkAcquireNextImageKHR(dev, sc, 0, acquire_sem, acquire_fence, &idx) != VkResult::Success)
            return SelftestFail("[selftest:graphics] AcquireNextImage(with sync) failed", 0);
        if (!internal::SemaphoreIsSignalled(acquire_sem))
            return SelftestFail("[selftest:graphics] Acquire did not signal semaphore", 0);
        if (VkGetFenceStatus(dev, acquire_fence) != VkResult::Success)
            return SelftestFail("[selftest:graphics] Acquire did not signal fence", 0);
        if (VkQueuePresentKHR(queue, sc, idx) != VkResult::Success)
            return SelftestFail("[selftest:graphics] QueuePresent(with sync) failed", 0);
        VkDestroyFence(dev, acquire_fence);
        VkDestroySemaphore(dev, acquire_sem);

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

} // namespace

VkResult GraphicsIcdSelfTest()
{
    KLOG_TRACE_SCOPE("subsystems/graphics", "GraphicsIcdSelfTest");
    if (!RunCanonicalLifecycle())
        return VkResult::ErrorInitializationFailed;
    if (!internal::LeakCheckHandlePools())
        return VkResult::ErrorInitializationFailed;
    if (internal::InvalidSpirvRejectionsCount() == 0)
    {
        KLOG_WARN("subsystems/graphics",
                  "[selftest:graphics] expected SPIR-V validator to register at least one rejection");
        return VkResult::ErrorInitializationFailed;
    }
    if (internal::CommandRecordedCount() < 3)
    {
        KLOG_WARN_V("subsystems/graphics", "[selftest:graphics] command tape recorded fewer ops than expected",
                    internal::CommandRecordedCount());
        return VkResult::ErrorInitializationFailed;
    }
    if (internal::CommandReplayedCount() < 3)
    {
        KLOG_WARN_V("subsystems/graphics", "[selftest:graphics] command replay covered fewer ops than expected",
                    internal::CommandReplayedCount());
        return VkResult::ErrorInitializationFailed;
    }
    if (internal::SpirvModulesParsedCount() < 3)
    {
        KLOG_WARN_V("subsystems/graphics", "[selftest:graphics] SPIR-V parser covered fewer modules than expected",
                    internal::SpirvModulesParsedCount());
        return VkResult::ErrorInitializationFailed;
    }
    if (internal::SpirvEntryPointsSeenCount() == 0 || internal::SpirvCapabilitiesSeenCount() == 0)
    {
        KLOG_WARN("subsystems/graphics",
                  "[selftest:graphics] SPIR-V parser did not aggregate entry-points or capabilities");
        return VkResult::ErrorInitializationFailed;
    }
    KLOG_INFO_V("subsystems/graphics", "Vulkan ICD self-test passed; ops replayed", internal::CommandReplayedCount());
    return VkResult::Success;
}

} // namespace duetos::subsystems::graphics
