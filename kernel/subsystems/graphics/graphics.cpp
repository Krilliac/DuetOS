#include "graphics.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../drivers/gpu/gpu.h"

namespace customos::subsystems::graphics
{

namespace
{

u64 g_next_handle = 0x1000;

// Rate-limit per-entry-point logs. Bitset keyed by a small enum.
enum EntryPointId
{
    EpVkCreateInstance,
    EpVkEnumeratePhysicalDevices,
    EpVkCreateDevice,
    EpVkGetDeviceQueue,
    EpVkQueueSubmit,
    EpVkDestroyInstance,
    EpVkDestroyDevice,
    EpD3d11Create,
    EpD3d12Create,
    EpDxgiCreate,
    EpCount
};
bool g_logged[EpCount] = {};

void LogOnce(EntryPointId id, const char* name)
{
    if (id < 0 || id >= EpCount)
        return;
    if (g_logged[id])
        return;
    g_logged[id] = true;
    arch::SerialWrite("[gfx] ");
    arch::SerialWrite(name);
    arch::SerialWrite(" called (skeleton — no real driver)\n");
}

u64 NewHandle()
{
    return ++g_next_handle;
}

} // namespace

void GraphicsIcdInit()
{
    KLOG_TRACE_SCOPE("subsystems/graphics", "GraphicsIcdInit");
    // Report what's available from the driver layer. These are the
    // "physical devices" a real ICD would enumerate.
    const u64 n = drivers::gpu::GpuCount();
    core::LogWithValue(core::LogLevel::Info, "subsystems/graphics", "physical devices visible to ICD", n);
    for (u64 i = 0; i < n; ++i)
    {
        const drivers::gpu::GpuInfo& g = drivers::gpu::Gpu(i);
        arch::SerialWrite("  gfx-dev ");
        arch::SerialWriteHex(i);
        arch::SerialWrite("  vendor=");
        arch::SerialWrite(g.vendor);
        arch::SerialWrite(" tier=");
        arch::SerialWrite(g.tier);
        if (g.family != nullptr)
        {
            arch::SerialWrite(" family=");
            arch::SerialWrite(g.family);
        }
        arch::SerialWrite("\n");
    }
    core::Log(core::LogLevel::Warn, "subsystems/graphics",
              "graphics ICD skeleton present; Vulkan/D3D entry points return ErrorIncompatibleDriver");
}

// -------------------------------------------------------------------
// Vulkan
// -------------------------------------------------------------------

VkResult VkCreateInstance(VkInstance* out)
{
    LogOnce(EpVkCreateInstance, "vkCreateInstance");
    if (out != nullptr)
        *out = NewHandle();
    // Tell the caller there's no real driver so their fallback
    // path activates cleanly. A real ICD returns Success here.
    return VkResult::ErrorIncompatibleDriver;
}

VkResult VkEnumeratePhysicalDevices(VkInstance inst, u32* count, VkPhysicalDevice* devs)
{
    LogOnce(EpVkEnumeratePhysicalDevices, "vkEnumeratePhysicalDevices");
    (void)inst;
    // Report the driver-layer GPU count. A real ICD would produce a
    // VkPhysicalDevice handle per actual device-backable queue.
    const u32 n = u32(drivers::gpu::GpuCount());
    if (count != nullptr)
        *count = n;
    if (devs != nullptr)
    {
        for (u32 i = 0; i < n; ++i)
            devs[i] = NewHandle();
    }
    return VkResult::Success;
}

VkResult VkCreateDevice(VkPhysicalDevice phys, VkDevice* out)
{
    LogOnce(EpVkCreateDevice, "vkCreateDevice");
    (void)phys;
    if (out != nullptr)
        *out = NewHandle();
    return VkResult::ErrorIncompatibleDriver;
}

VkResult VkGetDeviceQueue(VkDevice dev, VkQueue* out)
{
    LogOnce(EpVkGetDeviceQueue, "vkGetDeviceQueue");
    (void)dev;
    if (out != nullptr)
        *out = NewHandle();
    return VkResult::Success;
}

VkResult VkQueueSubmit(VkQueue q)
{
    LogOnce(EpVkQueueSubmit, "vkQueueSubmit");
    (void)q;
    // "Submit succeeded but nothing actually runs". Real ICD
    // forwards the batch to the driver's ring.
    return VkResult::Success;
}

void VkDestroyInstance(VkInstance inst)
{
    LogOnce(EpVkDestroyInstance, "vkDestroyInstance");
    (void)inst;
}

void VkDestroyDevice(VkDevice dev)
{
    LogOnce(EpVkDestroyDevice, "vkDestroyDevice");
    (void)dev;
}

// -------------------------------------------------------------------
// D3D translation stubs. Return the common Win32 HRESULT E_FAIL
// (0x80004005) so a caller's fallback-to-software path activates.
// -------------------------------------------------------------------

constexpr u32 kHresultEFail = 0x80004005;

u32 D3D11CreateDeviceStub()
{
    LogOnce(EpD3d11Create, "D3D11CreateDevice");
    return kHresultEFail;
}

u32 D3D12CreateDeviceStub()
{
    LogOnce(EpD3d12Create, "D3D12CreateDevice");
    return kHresultEFail;
}

u32 DxgiCreateFactoryStub()
{
    LogOnce(EpDxgiCreate, "CreateDXGIFactory");
    return kHresultEFail;
}

} // namespace customos::subsystems::graphics
