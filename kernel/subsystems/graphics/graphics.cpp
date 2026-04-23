#include "graphics.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../drivers/gpu/gpu.h"

namespace customos::subsystems::graphics
{

namespace
{

u64 g_next_handle = 0x1000;

// Tracked handle tables. Small fixed-size arrays so teardown is
// allocation-free. Each Create returns a handle in a distinct
// range so Destroy can validate by range.
constexpr u64 kInstanceBase = 0x1'0000;
constexpr u64 kDeviceBase = 0x2'0000;
constexpr u64 kD3dDeviceBase = 0x3'0000;
constexpr u64 kDxgiFactoryBase = 0x4'0000;
constexpr u64 kMaxPerKind = 8;

struct HandleTable
{
    u64 live_bitmap; // bit N = slot N live
    u32 live_count;
    u32 total_created;
    u32 total_destroyed;
};
HandleTable g_instances{};
HandleTable g_devices{};
HandleTable g_d3d_devices{};
HandleTable g_dxgi_factories{};

u64 AllocSlot(HandleTable& t, u64 base)
{
    for (u32 i = 0; i < kMaxPerKind; ++i)
    {
        const u64 bit = 1ULL << i;
        if ((t.live_bitmap & bit) == 0)
        {
            t.live_bitmap |= bit;
            ++t.live_count;
            ++t.total_created;
            return base + i;
        }
    }
    return 0; // table full
}

bool FreeSlot(HandleTable& t, u64 base, u64 handle)
{
    if (handle < base || handle >= base + kMaxPerKind)
        return false;
    const u64 bit = 1ULL << (handle - base);
    if ((t.live_bitmap & bit) == 0)
        return false;
    t.live_bitmap &= ~bit;
    --t.live_count;
    ++t.total_destroyed;
    return true;
}

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
    const u64 h = AllocSlot(g_instances, kInstanceBase);
    if (h == 0)
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = h;
    // Handle is real + tracked but there's no driver underneath, so
    // the result is still ErrorIncompatibleDriver — a caller that
    // ignores the return but later DestroyInstance's the handle
    // sees a matching free.
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
    const u64 h = AllocSlot(g_devices, kDeviceBase);
    if (h == 0)
        return VkResult::ErrorOutOfHostMemory;
    if (out != nullptr)
        *out = h;
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
    (void)FreeSlot(g_instances, kInstanceBase, inst);
}

void VkDestroyDevice(VkDevice dev)
{
    LogOnce(EpVkDestroyDevice, "vkDestroyDevice");
    (void)FreeSlot(g_devices, kDeviceBase, dev);
}

// -------------------------------------------------------------------
// D3D translation stubs. Return E_FAIL (0x80004005) — the caller's
// fallback-to-software path activates. The handle allocation is
// tracked so Destroy-side symmetry works if a future slice starts
// honouring these calls.
// -------------------------------------------------------------------

constexpr u32 kHresultEFail = 0x80004005;

u32 D3D11CreateDeviceStub()
{
    LogOnce(EpD3d11Create, "D3D11CreateDevice");
    (void)AllocSlot(g_d3d_devices, kD3dDeviceBase); // counted even on
                                                    // E_FAIL so stats
                                                    // reflect call rate
    return kHresultEFail;
}

u32 D3D12CreateDeviceStub()
{
    LogOnce(EpD3d12Create, "D3D12CreateDevice");
    (void)AllocSlot(g_d3d_devices, kD3dDeviceBase);
    return kHresultEFail;
}

u32 DxgiCreateFactoryStub()
{
    LogOnce(EpDxgiCreate, "CreateDXGIFactory");
    (void)AllocSlot(g_dxgi_factories, kDxgiFactoryBase);
    return kHresultEFail;
}

GraphicsStats GraphicsStatsRead()
{
    return GraphicsStats{
        .vk_instances_live = g_instances.live_count,
        .vk_instances_created = g_instances.total_created,
        .vk_instances_destroyed = g_instances.total_destroyed,
        .vk_devices_live = g_devices.live_count,
        .vk_devices_created = g_devices.total_created,
        .vk_devices_destroyed = g_devices.total_destroyed,
        .d3d_create_calls = g_d3d_devices.total_created,
        .dxgi_create_calls = g_dxgi_factories.total_created,
    };
}

} // namespace customos::subsystems::graphics
