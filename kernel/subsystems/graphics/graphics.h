#pragma once

#include "../../core/types.h"

/*
 * DuetOS — Graphics subsystem skeleton, v0.
 *
 * Where the pieces live in the final system:
 *
 *     userland application            (d3d / vulkan / opengl caller)
 *              |
 *              |  vulkan / d3d11 / d3d12 / opengl entry points
 *              v
 *     subsystems/graphics/ (user-mode)      <-- this file is the
 *     Vulkan ICD skeleton + D3D translation layer;  kernel-mode
 *     is a stand-in today because we don't yet have a user-mode
 *     graphics target.
 *              |
 *              |  command submission via kernel gate
 *              v
 *     kernel/drivers/gpu/<vendor>/  (drivers/gpu/gpu.cpp today)
 *              |
 *              |  direct MMIO + rings to hardware
 *              v
 *            GPU
 *
 * Right now this is a trace-only surface: each "API entry point"
 * logs "called" and returns an appropriate zero/null. It proves
 * the plumbing exists so a real Vulkan ICD slice can land
 * without restructuring the tree.
 *
 * Scope:
 *   - Vulkan ICD entry points: vkCreateInstance, vkEnumerate*,
 *     vkCreateDevice, vkGetDeviceQueue, vkQueueSubmit, vkDestroy*.
 *     Trace-only. Returns VK_ERROR_INCOMPATIBLE_DRIVER for
 *     any non-trivial call, so a caller's fallback path kicks in.
 *   - D3D11 → Vulkan translation entry points (stub).
 *   - D3D12 → Vulkan translation entry points (stub).
 *
 * Not in scope (real-work slices later):
 *   - Actually forwarding calls to a GPU driver.
 *   - Shader compilation / SPIR-V translation.
 *   - Descriptor table handling.
 *   - Swapchain / present.
 *
 * References to study when this becomes real work:
 *   ValveSoftware/wine (github)
 *     - dlls/wined3d/    — D3D9/10 support
 *     - dxvk/            — D3D9/10/11 → Vulkan
 *     - vkd3d-proton/    — D3D12 → Vulkan (used in Steam Play)
 *   These are the reference implementations for every translation
 *   layer we need. We won't fork them, but their IR lowering,
 *   descriptor-table handling, and swapchain logic are prior art
 *   worth studying.
 *
 * Context: kernel (temporary home). Moves to subsystems/graphics/
 * under a user-mode target when one exists.
 */

namespace duetos::subsystems::graphics
{

// -------------------------------------------------------------------
// Vulkan ICD surface (skeleton)
// -------------------------------------------------------------------
//
// Mirrors a small subset of the Vulkan 1.3 spec. Types are opaque
// u64 handles rather than structs — Vulkan itself defines them as
// dispatchable pointers, but for a skeleton u64 is enough to see
// "did vkCreateInstance get called, what followed".

using VkInstance = u64;
using VkPhysicalDevice = u64;
using VkDevice = u64;
using VkQueue = u64;
using VkCommandPool = u64;
using VkCommandBuffer = u64;

// Return codes (subset).
enum class VkResult : i32
{
    Success = 0,
    NotReady = 1,
    Timeout = 2,
    ErrorOutOfHostMemory = -1,
    ErrorInitializationFailed = -3,
    ErrorDeviceLost = -4,
    ErrorIncompatibleDriver = -9,
};

/// Bring up the graphics ICD skeleton. Currently logs "graphics
/// ICD present (v0 skeleton)" and registers the vendor enumerators
/// against `drivers::gpu`. Does not actually load a driver.
void GraphicsIcdInit();

// --- Vulkan entry points (skeleton) ---
//
// Each one logs a single `[vk] <name>` line the first time it's
// called (rate-limited). Returns either a trivial handle (a
// counter-generated u64) or VkResult::ErrorIncompatibleDriver to
// signal "no real driver available".

VkResult VkCreateInstance(VkInstance* out);
VkResult VkEnumeratePhysicalDevices(VkInstance inst, u32* count, VkPhysicalDevice* devs);
VkResult VkCreateDevice(VkPhysicalDevice phys, VkDevice* out);
VkResult VkGetDeviceQueue(VkDevice dev, VkQueue* out);
VkResult VkQueueSubmit(VkQueue q);
void VkDestroyInstance(VkInstance inst);
void VkDestroyDevice(VkDevice dev);

// -------------------------------------------------------------------
// D3D11 / D3D12 → Vulkan translation (skeleton)
// -------------------------------------------------------------------
//
// The Win32 subsystem (kernel/subsystems/win32/) patches PE IAT
// slots for d3d11/d3d12/dxgi imports. Those stubs currently all
// land on the miss-logger; a future slice will redirect them here.
// The entry points below are the shape those redirects will take.

/// D3D11: `HRESULT D3D11CreateDevice(IDXGIAdapter*, D3D_DRIVER_TYPE,
/// HMODULE, UINT flags, ...)`. Today: logs + returns E_FAIL.
u32 D3D11CreateDeviceStub();

/// D3D12: `HRESULT D3D12CreateDevice(IUnknown* adapter, D3D_FEATURE_LEVEL,
/// REFIID riid, void** ppDevice)`. Today: logs + returns E_FAIL.
u32 D3D12CreateDeviceStub();

/// DXGI: `HRESULT CreateDXGIFactory(REFIID, void**)`.
u32 DxgiCreateFactoryStub();

/// Diagnostic snapshot — handle-table counters for every kind of
/// object the ICD hands out. Covers a gap left by the logger-only
/// pattern: a future unit test of the vkCreate/vkDestroy round
/// trip can now assert that live counts return to zero.
struct GraphicsStats
{
    u32 vk_instances_live;
    u32 vk_instances_created;
    u32 vk_instances_destroyed;
    u32 vk_devices_live;
    u32 vk_devices_created;
    u32 vk_devices_destroyed;
    u32 d3d_create_calls;
    u32 dxgi_create_calls;
};
GraphicsStats GraphicsStatsRead();

} // namespace duetos::subsystems::graphics
