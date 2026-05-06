#include "subsystems/graphics/graphics.h"

#include "arch/x86_64/serial.h"
#include "drivers/gpu/gpu.h"
#include "log/klog.h"

namespace duetos::subsystems::graphics
{

// Implemented in graphics_vk.cpp.  Returns the live + cumulative
// counters maintained by the Vulkan-side handle pools so this TU
// (which still owns the D3D counters) can fill the rest of
// `GraphicsStats` without the two TUs having to share state.
GraphicsStats VkStatsSnapshot();

namespace
{

constexpr u32 kHresultEFail = 0x80004005;

// Per-API call counters for the DirectX peripheral DLLs (dinput8,
// xinput1_4, xaudio2_8, dsound, ddraw, d2d1, dwrite).  These DLLs
// hand out their own COM objects from heap; we only need the
// counter here so the `gfx` shell command can show "this DLL was
// used N times".
u32 g_d3d11_create_calls = 0;
u32 g_d3d12_create_calls = 0;
u32 g_dxgi_create_calls = 0;
u32 g_d3d9_create_calls = 0;
u32 g_dinput8_create_calls = 0;
u32 g_xinput_create_calls = 0;
u32 g_xaudio2_create_calls = 0;
u32 g_dsound_create_calls = 0;
u32 g_ddraw_create_calls = 0;
u32 g_d2d1_create_calls = 0;
u32 g_dwrite_create_calls = 0;

// Rate-limit per-entry-point logs.
enum EntryPointId
{
    EpD3d11Create,
    EpD3d12Create,
    EpDxgiCreate,
    EpD3d9Create,
    EpDinput8Create,
    EpXinputCreate,
    EpXaudio2Create,
    EpDsoundCreate,
    EpDdrawCreate,
    EpD2d1Create,
    EpDwriteCreate,
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
    arch::SerialWrite(" called (D3D translation skeleton — no real driver)\n");
}

} // namespace

void GraphicsIcdInit()
{
    KLOG_TRACE_SCOPE("subsystems/graphics", "GraphicsIcdInit");
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
    core::Log(core::LogLevel::Info, "subsystems/graphics",
              "graphics ICD v0 online; Vulkan instance/device/command lifecycle is functional, "
              "vkCmdClearColorImage paints scanout-backed images via the framebuffer; "
              "no GPU command-ring submission yet");
}

// -------------------------------------------------------------------
// D3D translation stubs.  Return E_FAIL (0x80004005) — the caller's
// fallback-to-software path activates.  The call counters are shown
// by the `gfx` shell command.
// -------------------------------------------------------------------

u32 D3D11CreateDeviceStub()
{
    LogOnce(EpD3d11Create, "D3D11CreateDevice");
    ++g_d3d11_create_calls;
    return kHresultEFail;
}

u32 D3D12CreateDeviceStub()
{
    LogOnce(EpD3d12Create, "D3D12CreateDevice");
    ++g_d3d12_create_calls;
    return kHresultEFail;
}

u32 DxgiCreateFactoryStub()
{
    LogOnce(EpDxgiCreate, "CreateDXGIFactory");
    ++g_dxgi_create_calls;
    return kHresultEFail;
}

u32 D3d9CreateStub()
{
    LogOnce(EpD3d9Create, "Direct3DCreate9");
    ++g_d3d9_create_calls;
    return kHresultEFail;
}
u32 Dinput8CreateStub()
{
    LogOnce(EpDinput8Create, "DirectInput8Create");
    ++g_dinput8_create_calls;
    return kHresultEFail;
}
u32 XinputCreateStub()
{
    LogOnce(EpXinputCreate, "XInputGetState");
    ++g_xinput_create_calls;
    return kHresultEFail;
}
u32 Xaudio2CreateStub()
{
    LogOnce(EpXaudio2Create, "XAudio2Create");
    ++g_xaudio2_create_calls;
    return kHresultEFail;
}
u32 DsoundCreateStub()
{
    LogOnce(EpDsoundCreate, "DirectSoundCreate");
    ++g_dsound_create_calls;
    return kHresultEFail;
}
u32 DdrawCreateStub()
{
    LogOnce(EpDdrawCreate, "DirectDrawCreate");
    ++g_ddraw_create_calls;
    return kHresultEFail;
}
u32 D2d1CreateStub()
{
    LogOnce(EpD2d1Create, "D2D1CreateFactory");
    ++g_d2d1_create_calls;
    return kHresultEFail;
}
u32 DwriteCreateStub()
{
    LogOnce(EpDwriteCreate, "DWriteCreateFactory");
    ++g_dwrite_create_calls;
    return kHresultEFail;
}

GraphicsStats GraphicsStatsRead()
{
    GraphicsStats s = VkStatsSnapshot();
    s.d3d_create_calls = g_d3d11_create_calls + g_d3d12_create_calls;
    s.dxgi_create_calls = g_dxgi_create_calls;
    s.d3d9_create_calls = g_d3d9_create_calls;
    s.dinput8_create_calls = g_dinput8_create_calls;
    s.xinput_create_calls = g_xinput_create_calls;
    s.xaudio2_create_calls = g_xaudio2_create_calls;
    s.dsound_create_calls = g_dsound_create_calls;
    s.ddraw_create_calls = g_ddraw_create_calls;
    s.d2d1_create_calls = g_d2d1_create_calls;
    s.dwrite_create_calls = g_dwrite_create_calls;
    return s;
}

} // namespace duetos::subsystems::graphics
