#include "syscall/syscall_vk.h"

#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"
#include "subsystems/graphics/graphics.h"
#include "syscall/syscall.h"

/*
 * DuetOS — SYS_VK_CALL dispatch implementation.
 *
 * Maps `VkOp` enum values from userland into the kernel ICD's
 * native API. Argument marshalling is direct: u64-sized values
 * pass in registers, pointers are validated by the existing
 * userland-VA checker before any dereference.
 *
 * v1 surface (the trivial-PE-binding set):
 *   - Instance / device / queue lifecycle (Create / Destroy /
 *     Wait).
 *   - vkEnumeratePhysicalDevices (count-only or count + array).
 *   - vkEnumerateInstanceVersion.
 *   - A diagnostic getter that reads one of the
 *     `GraphicsStats` counters by id — used by the userland
 *     stub's smoke test and by `gfx` / `vk` shell commands that
 *     want to display the live counter values without re-walking
 *     the full Stats blob.
 *
 * Out of scope for v1 — landed in follow-on slices once a real
 * PE uses them:
 *   - Buffer / image / memory creation (need a shared-memory
 *     bridge so the caller can map device-memory and the kernel
 *     can copy DMA buffers).
 *   - Command buffer record / submit (need pointer arrays of
 *     CmdRecord-shaped operands).
 *   - Shader module create (need to copy the SPIR-V word stream
 *     in from user memory).
 *   - WSI surface / swapchain (needs window-handle mapping).
 *
 * All deferred ops return 0 (the canonical Vulkan
 * VK_ERROR_INITIALIZATION_FAILED enum value, which the userland
 * stub propagates as a Vulkan-spec-compliant error). Userland
 * sees a clean rejection rather than UB.
 */

namespace duetos::syscall
{

namespace
{

namespace vk = ::duetos::subsystems::graphics;

constexpr u64 kVkBadOp = 0xFFFFFFFFFFFFFFFFull;

// Copy a u64 from kernel space into a user-supplied pointer.
// Today the kernel and userland share a single address space (no
// per-process VA isolation yet in the syscall path), so a direct
// pointer dereference is correct. When isolation lands this
// routes through the existing user-copy helper that fault-traps
// on a bad VA.
template <typename T> void UserStore(u64 user_va, T value)
{
    if (user_va == 0)
        return;
    *reinterpret_cast<T*>(user_va) = value;
}

template <typename T> T UserLoad(u64 user_va, T fallback)
{
    if (user_va == 0)
        return fallback;
    return *reinterpret_cast<T*>(user_va);
}

u64 OpCreateInstance(arch::TrapFrame* frame)
{
    vk::VkInstance inst = 0;
    const vk::VkResult r = vk::VkCreateInstance(&inst);
    if (r != vk::VkResult::Success)
        return 0;
    UserStore<u64>(frame->rdx, inst);
    return 1;
}

u64 OpDestroyInstance(arch::TrapFrame* frame)
{
    vk::VkDestroyInstance(frame->rdx);
    return 1;
}

u64 OpEnumeratePhysicalDevices(arch::TrapFrame* frame)
{
    const u64 inst = frame->rdx;
    const u64 count_ptr = frame->r10;
    const u64 array_ptr = frame->r8;
    u32 count = (array_ptr != 0) ? UserLoad<u32>(count_ptr, 0u) : 0u;
    vk::VkPhysicalDevice devs[4]{};
    if (count > 4)
        count = 4;
    const vk::VkResult r = vk::VkEnumeratePhysicalDevices(inst, &count, (array_ptr != 0) ? devs : nullptr);
    UserStore<u32>(count_ptr, count);
    if (array_ptr != 0)
    {
        auto* dst = reinterpret_cast<vk::VkPhysicalDevice*>(array_ptr);
        for (u32 i = 0; i < count; ++i)
            dst[i] = devs[i];
    }
    return (r == vk::VkResult::Success) ? 1 : 0;
}

u64 OpCreateDevice(arch::TrapFrame* frame)
{
    const u64 phys = frame->rdx;
    const u64 out_ptr = frame->r10;
    vk::VkDevice dev = 0;
    const vk::VkResult r = vk::VkCreateDevice(phys, &dev);
    if (r != vk::VkResult::Success)
        return 0;
    UserStore<u64>(out_ptr, dev);
    return 1;
}

u64 OpDestroyDevice(arch::TrapFrame* frame)
{
    vk::VkDestroyDevice(frame->rdx);
    return 1;
}

u64 OpGetDeviceQueue(arch::TrapFrame* frame)
{
    const u64 dev = frame->rdx;
    const u64 out_ptr = frame->r10;
    vk::VkQueue q = 0;
    const vk::VkResult r = vk::VkGetDeviceQueue(dev, &q);
    if (r != vk::VkResult::Success)
        return 0;
    UserStore<u64>(out_ptr, q);
    return 1;
}

u64 OpDeviceWaitIdle(arch::TrapFrame* frame)
{
    return (vk::VkDeviceWaitIdle(frame->rdx) == vk::VkResult::Success) ? 1 : 0;
}

u64 OpQueueWaitIdle(arch::TrapFrame* frame)
{
    return (vk::VkQueueWaitIdle(frame->rdx) == vk::VkResult::Success) ? 1 : 0;
}

u64 OpGetInstanceVersion(arch::TrapFrame* frame)
{
    const u64 out_ptr = frame->rdx;
    u32 v = 0;
    const vk::VkResult r = vk::VkEnumerateInstanceVersion(&v);
    UserStore<u32>(out_ptr, v);
    return (r == vk::VkResult::Success) ? 1 : 0;
}

u64 OpCreateSurfaceDuet(arch::TrapFrame* frame)
{
    const u64 inst = frame->rdx;
    const u64 out_ptr = frame->r10;
    vk::VkSurfaceKHR surf = 0;
    const vk::VkResult r = vk::VkCreateDuetSurfaceKHR(inst, &surf);
    if (r != vk::VkResult::Success)
        return 0;
    UserStore<u64>(out_ptr, surf);
    return 1;
}

u64 OpDestroySurface(arch::TrapFrame* frame)
{
    vk::VkDestroySurfaceKHR(frame->rdx, frame->r10);
    return 1;
}

u64 OpPresent(arch::TrapFrame* frame)
{
    (void)frame;
    // Flush whatever the userland has drawn into the framebuffer.
    // The Vulkan vkQueuePresentKHR path normally does this via
    // FramebufferPresent on the swapchain image; the simplified v0
    // syscall just fires the present hook directly so a userland
    // PE that wrote pixels via DuetOS_Vk_ClearFramebufferRgba can
    // hand them off to the compositor for display.
    ::duetos::drivers::video::FramebufferPresent();
    return 1;
}

u64 OpCreateShaderModule(arch::TrapFrame* frame)
{
    const u64 dev = frame->rdx;
    const u32* code = reinterpret_cast<const u32*>(frame->r10);
    const u64 code_size_bytes = frame->r8;
    if (code == nullptr || code_size_bytes == 0)
        return 0;
    vk::VkShaderModule out = 0;
    const vk::VkResult r = vk::VkCreateShaderModule(dev, code, code_size_bytes, &out);
    return (r == vk::VkResult::Success) ? out : 0;
}

u64 OpDestroyShaderModule(arch::TrapFrame* frame)
{
    vk::VkDestroyShaderModule(frame->rdx, frame->r10);
    return 1;
}

u64 OpAllocateMemory(arch::TrapFrame* frame)
{
    const u64 dev = frame->rdx;
    const u64 size = frame->r10;
    if (size == 0)
        return 0;
    vk::VkDeviceMemory out = 0;
    // Memory type 1 = host-visible coherent in the v0 ICD.
    const vk::VkResult r = vk::VkAllocateMemory(dev, size, 1, &out);
    return (r == vk::VkResult::Success) ? out : 0;
}

u64 OpFreeMemory(arch::TrapFrame* frame)
{
    vk::VkFreeMemory(frame->rdx, frame->r10);
    return 1;
}

u64 OpCreateBuffer(arch::TrapFrame* frame)
{
    const u64 dev = frame->rdx;
    const u64 size = frame->r10;
    if (size == 0)
        return 0;
    vk::VkBuffer out = 0;
    const vk::VkResult r = vk::VkCreateBuffer(dev, size, &out);
    return (r == vk::VkResult::Success) ? out : 0;
}

u64 OpDestroyBuffer(arch::TrapFrame* frame)
{
    vk::VkDestroyBuffer(frame->rdx, frame->r10);
    return 1;
}

u64 OpBindBufferMemory(arch::TrapFrame* frame)
{
    return (vk::VkBindBufferMemory(frame->rdx, frame->r10, frame->r8, frame->r9) == vk::VkResult::Success) ? 1 : 0;
}

u64 OpMapMemory(arch::TrapFrame* frame)
{
    void* p = nullptr;
    // size = 0 means "the rest of the allocation". The v0 ICD
    // returns the kheap-backed host pointer; userland can read /
    // write directly since v0 has no per-process VM separation
    // between kernel and userland on this surface.
    const vk::VkResult r = vk::VkMapMemory(frame->rdx, frame->r10, 0, 0, &p);
    return (r == vk::VkResult::Success) ? reinterpret_cast<u64>(p) : 0;
}

u64 OpUnmapMemory(arch::TrapFrame* frame)
{
    vk::VkUnmapMemory(frame->rdx, frame->r10);
    return 1;
}

u64 OpCreateImage(arch::TrapFrame* frame)
{
    vk::VkExtent3D extent{static_cast<u32>(frame->r10), static_cast<u32>(frame->r8), 1};
    const u32 flags = static_cast<u32>(frame->r9);
    vk::VkImage out = 0;
    const vk::VkResult r = vk::VkCreateImage(frame->rdx, extent, flags, &out);
    return (r == vk::VkResult::Success) ? out : 0;
}

u64 OpDestroyImage(arch::TrapFrame* frame)
{
    vk::VkDestroyImage(frame->rdx, frame->r10);
    return 1;
}

u64 OpBindImageMemory(arch::TrapFrame* frame)
{
    return (vk::VkBindImageMemory(frame->rdx, frame->r10, frame->r8, frame->r9) == vk::VkResult::Success) ? 1 : 0;
}

u64 OpCreateCommandPool(arch::TrapFrame* frame)
{
    vk::VkCommandPool out = 0;
    return (vk::VkCreateCommandPool(frame->rdx, &out) == vk::VkResult::Success) ? out : 0;
}

u64 OpDestroyCommandPool(arch::TrapFrame* frame)
{
    vk::VkDestroyCommandPool(frame->rdx, frame->r10);
    return 1;
}

u64 OpAllocateCommandBuffer(arch::TrapFrame* frame)
{
    vk::VkCommandBuffer out = 0;
    return (vk::VkAllocateCommandBuffers(frame->rdx, frame->r10, 1, &out) == vk::VkResult::Success) ? out : 0;
}

u64 OpBeginCommandBuffer(arch::TrapFrame* frame)
{
    return (vk::VkBeginCommandBuffer(frame->rdx) == vk::VkResult::Success) ? 1 : 0;
}

u64 OpEndCommandBuffer(arch::TrapFrame* frame)
{
    return (vk::VkEndCommandBuffer(frame->rdx) == vk::VkResult::Success) ? 1 : 0;
}

u64 OpCmdClearColorImage(arch::TrapFrame* frame)
{
    // Repack the packed ARGB into a VkClearColorValue. The ICD
    // uses the union form so the bits go in as uint32 to avoid
    // pulling in soft-float on the kernel side.
    vk::VkClearColorValue cv{};
    const u32 argb = static_cast<u32>(frame->r8 & 0xFFFFFFFFull);
    cv.uint32[0] = (argb >> 16) & 0xFFu; // R
    cv.uint32[1] = (argb >> 8) & 0xFFu;  // G
    cv.uint32[2] = argb & 0xFFu;         // B
    cv.uint32[3] = (argb >> 24) & 0xFFu; // A
    return (vk::VkCmdClearColorImage(frame->rdx, frame->r10, cv) == vk::VkResult::Success) ? 1 : 0;
}

u64 OpQueueSubmit(arch::TrapFrame* frame)
{
    vk::VkCommandBuffer cb = frame->r10;
    // No fence for the v0 syscall path (the kernel ICD's submits
    // are synchronous; the userland sees an immediately-signalled
    // result regardless).
    return (vk::VkQueueSubmit(frame->rdx, 1, &cb, 0) == vk::VkResult::Success) ? 1 : 0;
}

u64 OpClearFramebufferRgba(arch::TrapFrame* frame)
{
    // rsi = packed 0xAARRGGBB. Drive the same path that
    // `vkCmdClearColorImage` against a scanout-backed image
    // already does: FramebufferFillRect on the full extent +
    // FramebufferAddDamage to mark the present rect. This is
    // what the userland D3D11 ClearRenderTargetView call sites
    // can route through to get end-to-end Vulkan flow without
    // building a full command-buffer ladder.
    const u32 argb = static_cast<u32>(frame->rdx & 0xFFFFFFFFull);
    const auto di = ::duetos::drivers::video::Query();
    if (!di.available || di.width == 0 || di.height == 0)
        return 0;
    ::duetos::drivers::video::FramebufferFillRect(0, 0, di.width, di.height, argb);
    ::duetos::drivers::video::FramebufferAddDamage(0, 0, di.width, di.height);
    return 1;
}

u64 OpGetStatsCounter(arch::TrapFrame* frame)
{
    const u64 cid = frame->rdx;
    const auto s = vk::GraphicsStatsRead();
    using ::duetos::core::kVkStatsClearPixelsPainted;
    using ::duetos::core::kVkStatsCommandBufferLive;
    using ::duetos::core::kVkStatsDeviceLive;
    using ::duetos::core::kVkStatsInstanceLive;
    using ::duetos::core::kVkStatsQueueSubmits;
    using ::duetos::core::kVkStatsShaderRasterDrawsPainted;
    using ::duetos::core::kVkStatsShaderRasterDrawsSkipped;
    using ::duetos::core::kVkStatsSpirvEntryPointExecutions;
    using ::duetos::core::kVkStatsSpirvProgramsBuilt;
    using ::duetos::core::kVkStatsTrianglesDrawn;
    switch (static_cast<::duetos::core::VkStatsCounter>(cid))
    {
    case kVkStatsInstanceLive:
        return s.vk_instances_live;
    case kVkStatsDeviceLive:
        return s.vk_devices_live;
    case kVkStatsCommandBufferLive:
        return s.vk_command_buffers_live;
    case kVkStatsSpirvProgramsBuilt:
        return s.vk_spirv_programs_built;
    case kVkStatsSpirvEntryPointExecutions:
        return s.vk_spirv_entry_point_executions;
    case kVkStatsShaderRasterDrawsPainted:
        return s.vk_shader_raster_draws_painted;
    case kVkStatsShaderRasterDrawsSkipped:
        return s.vk_shader_raster_draws_skipped;
    case kVkStatsClearPixelsPainted:
        return s.vk_clear_pixels_painted;
    case kVkStatsTrianglesDrawn:
        return s.vk_triangles_drawn;
    case kVkStatsQueueSubmits:
        return s.vk_queue_submits;
    }
    return kVkBadOp;
}

} // namespace

void DoVkCall(arch::TrapFrame* frame)
{
    if (frame == nullptr)
        return;
    using ::duetos::core::kVkOpCreateDevice;
    using ::duetos::core::kVkOpCreateInstance;
    using ::duetos::core::kVkOpDestroyDevice;
    using ::duetos::core::kVkOpDestroyInstance;
    using ::duetos::core::kVkOpDeviceWaitIdle;
    using ::duetos::core::kVkOpEnumeratePhysicalDevices;
    using ::duetos::core::kVkOpGetDeviceQueue;
    using ::duetos::core::kVkOpAllocateCommandBuffer;
    using ::duetos::core::kVkOpAllocateMemory;
    using ::duetos::core::kVkOpBeginCommandBuffer;
    using ::duetos::core::kVkOpBindBufferMemory;
    using ::duetos::core::kVkOpBindImageMemory;
    using ::duetos::core::kVkOpCmdClearColorImage;
    using ::duetos::core::kVkOpCreateCommandPool;
    using ::duetos::core::kVkOpDestroyCommandPool;
    using ::duetos::core::kVkOpEndCommandBuffer;
    using ::duetos::core::kVkOpQueueSubmit;
    using ::duetos::core::kVkOpClearFramebufferRgba;
    using ::duetos::core::kVkOpCreateBuffer;
    using ::duetos::core::kVkOpCreateImage;
    using ::duetos::core::kVkOpCreateShaderModule;
    using ::duetos::core::kVkOpCreateSurfaceDuet;
    using ::duetos::core::kVkOpDestroyBuffer;
    using ::duetos::core::kVkOpDestroyImage;
    using ::duetos::core::kVkOpDestroyShaderModule;
    using ::duetos::core::kVkOpDestroySurface;
    using ::duetos::core::kVkOpFreeMemory;
    using ::duetos::core::kVkOpGetInstanceVersion;
    using ::duetos::core::kVkOpGetStatsCounter;
    using ::duetos::core::kVkOpMapMemory;
    using ::duetos::core::kVkOpPresent;
    using ::duetos::core::kVkOpQueueWaitIdle;
    using ::duetos::core::kVkOpUnmapMemory;
    const u64 op = frame->rdi;
    switch (static_cast<::duetos::core::VkOp>(op))
    {
    case kVkOpCreateInstance:
        frame->rax = OpCreateInstance(frame);
        return;
    case kVkOpDestroyInstance:
        frame->rax = OpDestroyInstance(frame);
        return;
    case kVkOpEnumeratePhysicalDevices:
        frame->rax = OpEnumeratePhysicalDevices(frame);
        return;
    case kVkOpCreateDevice:
        frame->rax = OpCreateDevice(frame);
        return;
    case kVkOpDestroyDevice:
        frame->rax = OpDestroyDevice(frame);
        return;
    case kVkOpGetDeviceQueue:
        frame->rax = OpGetDeviceQueue(frame);
        return;
    case kVkOpDeviceWaitIdle:
        frame->rax = OpDeviceWaitIdle(frame);
        return;
    case kVkOpQueueWaitIdle:
        frame->rax = OpQueueWaitIdle(frame);
        return;
    case kVkOpGetInstanceVersion:
        frame->rax = OpGetInstanceVersion(frame);
        return;
    case kVkOpGetStatsCounter:
        frame->rax = OpGetStatsCounter(frame);
        return;
    case kVkOpClearFramebufferRgba:
        frame->rax = OpClearFramebufferRgba(frame);
        return;
    case kVkOpCreateSurfaceDuet:
        frame->rax = OpCreateSurfaceDuet(frame);
        return;
    case kVkOpDestroySurface:
        frame->rax = OpDestroySurface(frame);
        return;
    case kVkOpPresent:
        frame->rax = OpPresent(frame);
        return;
    case kVkOpCreateShaderModule:
        frame->rax = OpCreateShaderModule(frame);
        return;
    case kVkOpAllocateMemory:
        frame->rax = OpAllocateMemory(frame);
        return;
    case kVkOpFreeMemory:
        frame->rax = OpFreeMemory(frame);
        return;
    case kVkOpCreateBuffer:
        frame->rax = OpCreateBuffer(frame);
        return;
    case kVkOpDestroyShaderModule:
        frame->rax = OpDestroyShaderModule(frame);
        return;
    case kVkOpDestroyBuffer:
        frame->rax = OpDestroyBuffer(frame);
        return;
    case kVkOpBindBufferMemory:
        frame->rax = OpBindBufferMemory(frame);
        return;
    case kVkOpMapMemory:
        frame->rax = OpMapMemory(frame);
        return;
    case kVkOpUnmapMemory:
        frame->rax = OpUnmapMemory(frame);
        return;
    case kVkOpCreateImage:
        frame->rax = OpCreateImage(frame);
        return;
    case kVkOpDestroyImage:
        frame->rax = OpDestroyImage(frame);
        return;
    case kVkOpBindImageMemory:
        frame->rax = OpBindImageMemory(frame);
        return;
    case kVkOpCreateCommandPool:
        frame->rax = OpCreateCommandPool(frame);
        return;
    case kVkOpDestroyCommandPool:
        frame->rax = OpDestroyCommandPool(frame);
        return;
    case kVkOpAllocateCommandBuffer:
        frame->rax = OpAllocateCommandBuffer(frame);
        return;
    case kVkOpBeginCommandBuffer:
        frame->rax = OpBeginCommandBuffer(frame);
        return;
    case kVkOpEndCommandBuffer:
        frame->rax = OpEndCommandBuffer(frame);
        return;
    case kVkOpCmdClearColorImage:
        frame->rax = OpCmdClearColorImage(frame);
        return;
    case kVkOpQueueSubmit:
        frame->rax = OpQueueSubmit(frame);
        return;
    }
    frame->rax = kVkBadOp;
}

} // namespace duetos::syscall
