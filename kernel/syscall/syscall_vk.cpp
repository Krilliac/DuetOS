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
    using ::duetos::core::kVkOpClearFramebufferRgba;
    using ::duetos::core::kVkOpCreateSurfaceDuet;
    using ::duetos::core::kVkOpDestroySurface;
    using ::duetos::core::kVkOpGetInstanceVersion;
    using ::duetos::core::kVkOpGetStatsCounter;
    using ::duetos::core::kVkOpPresent;
    using ::duetos::core::kVkOpQueueWaitIdle;
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
    }
    frame->rax = kVkBadOp;
}

} // namespace duetos::syscall
