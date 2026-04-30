/*
 * d3d11_smoke — exercise the full D3D11 Clear+Present pipeline through
 * real COM vtable calls. Validates the userland/libs/d3d11/d3d11.c
 * implementation end-to-end:
 *
 *   D3D11CreateDeviceAndSwapChain
 *   IDXGISwapChain::GetBuffer(0, IID_ID3D11Texture2D, &tex)
 *   ID3D11Device::CreateRenderTargetView(tex, NULL, &rtv)
 *   ID3D11DeviceContext::OMSetRenderTargets(1, &rtv, NULL)
 *   ID3D11DeviceContext::ClearRenderTargetView(rtv, blue)
 *   IDXGISwapChain::Present(0, 0)
 *   ID3D11Device::CheckFeatureSupport
 *   ID3D11Device::GetFeatureLevel
 *   release everything
 *
 * Slot indices match D3D11SwapChainVtbl / ID3D11ContextVtbl /
 * ID3D11DeviceVtbl in userland/libs/d3d11/d3d11.c.
 */
#include <windows.h>

extern long D3D11CreateDeviceAndSwapChain(void* adapter, INT driver_type, void* sw, UINT flags, const void* fls,
                                          UINT nfls, UINT sdk, const void* desc, void** swap, void** dev,
                                          UINT* obtained, void** ctx);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

/* IID_ID3D11Texture2D = {6f15aaf2-d208-4e89-9ab4-489535d34f9c} */
static const GUID kIidTex2D = {0x6f15aaf2, 0xd208, 0x4e89, {0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c}};

/* DXGI_SWAP_CHAIN_DESC — 76 bytes packed as in dxgi.c:
 *   +0  Width           UINT
 *   +4  Height          UINT
 *   +8  RefreshRate     2x UINT
 *   +16 Format          UINT (87 = BGRA8_UNORM)
 *   +20 ScanlineOrdering UINT
 *   +24 Scaling         UINT
 *   +28 SampleDesc      Count(UINT) Quality(UINT)
 *   +36 BufferUsage     UINT
 *   +40 BufferCount     UINT
 *   +48 OutputWindow    HWND (8B aligned)
 *   +56 Windowed        BOOL
 *   +60 SwapEffect      UINT
 *   +64 Flags           UINT */
typedef struct
{
    UINT Width, Height;
    UINT RefreshNum, RefreshDen;
    UINT Format, ScanlineOrdering, Scaling;
    UINT SampleCount, SampleQuality;
    UINT BufferUsage;
    UINT BufferCount;
    UINT _pad;
    HWND OutputWindow;
    BOOL Windowed;
    UINT SwapEffect;
    UINT Flags;
} ScDesc;

void __cdecl mainCRTStartup(void)
{
    Out("[d3d11_smoke] starting\r\n");

    ScDesc desc;
    BYTE* p = (BYTE*)&desc;
    for (UINT i = 0; i < sizeof(desc); ++i)
        p[i] = 0;
    /* 32x32 BGRA8 = 4 KiB — fits in the 64 KiB Win32 heap with
     * room left for the COM objects + Texture2D wrapper + RTV. */
    desc.Width = 32;
    desc.Height = 32;
    desc.Format = 87; /* DXGI_FORMAT_B8G8R8A8_UNORM */
    desc.SampleCount = 1;
    desc.BufferUsage = 0x20; /* DXGI_USAGE_RENDER_TARGET_OUTPUT */
    desc.BufferCount = 1;
    desc.OutputWindow = NULL; /* offscreen Present */
    desc.Windowed = TRUE;

    void* sc = NULL;
    void* dev = NULL;
    void* ctx = NULL;
    UINT got_fl = 0;
    long hr = D3D11CreateDeviceAndSwapChain(NULL, 0, NULL, 0, NULL, 0, 0, &desc, &sc, &dev, &got_fl, &ctx);
    Out("[d3d11_smoke] CreateDeviceAndSwapChain = ");
    Out((hr == 0 && sc && dev && ctx) ? "PASS\r\n" : "FAIL\r\n");
    if (hr != 0 || !sc || !dev || !ctx)
    {
        Out("[d3d11_smoke] aborting\r\n");
        ExitProcess(1);
    }

    void** sc_vt = *(void***)sc;
    void** dev_vt = *(void***)dev;
    void** ctx_vt = *(void***)ctx;

    /* slot 9 = GetBuffer */
    void* tex = NULL;
    typedef long (*PFN_GetBuffer)(void*, UINT, const GUID*, void**);
    hr = ((PFN_GetBuffer)sc_vt[9])(sc, 0, &kIidTex2D, &tex);
    Out("[d3d11_smoke] SwapChain::GetBuffer    = ");
    Out((hr == 0 && tex) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 9 = CreateRenderTargetView (device) */
    void* rtv = NULL;
    typedef long (*PFN_CreateRTV)(void*, void*, const void*, void**);
    hr = ((PFN_CreateRTV)dev_vt[9])(dev, tex, NULL, &rtv);
    Out("[d3d11_smoke] Device::CreateRTV       = ");
    Out((hr == 0 && rtv) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 33 = OMSetRenderTargets (context) */
    void* rtvs[1] = {rtv};
    typedef void (*PFN_OMSet)(void*, UINT, void* const*, void*);
    ((PFN_OMSet)ctx_vt[33])(ctx, 1, rtvs, NULL);
    Out("[d3d11_smoke] Context::OMSetRT        = PASS (returned)\r\n");

    /* slot 50 = ClearRenderTargetView — bright blue */
    float blue[4] = {0.0f, 0.0f, 1.0f, 1.0f};
    typedef void (*PFN_ClearRTV)(void*, void*, const float*);
    ((PFN_ClearRTV)ctx_vt[50])(ctx, rtv, blue);
    Out("[d3d11_smoke] Context::ClearRTV       = PASS (returned)\r\n");

    /* slot 8 = Present */
    typedef long (*PFN_Present)(void*, UINT, UINT);
    hr = ((PFN_Present)sc_vt[8])(sc, 0, 0);
    Out("[d3d11_smoke] SwapChain::Present      = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 37 = GetFeatureLevel */
    typedef UINT (*PFN_GetFL)(void*);
    UINT fl = ((PFN_GetFL)dev_vt[37])(dev);
    Out("[d3d11_smoke] Device::GetFeatureLevel = ");
    Out((fl == 0xb000) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 29 = CheckFormatSupport */
    UINT fmt_supp = 0;
    typedef long (*PFN_CheckFmt)(void*, UINT, UINT*);
    hr = ((PFN_CheckFmt)dev_vt[29])(dev, 87, &fmt_supp);
    Out("[d3d11_smoke] Device::CheckFmt(BGRA8) = ");
    Out((hr == 0 && fmt_supp != 0) ? "PASS\r\n" : "FAIL\r\n");

    /* Release in reverse order. slot 2 = Release. */
    typedef unsigned long (*PFN_Release)(void*);
    ((PFN_Release)((void**)(*(void***)rtv))[2])(rtv);
    ((PFN_Release)((void**)(*(void***)tex))[2])(tex);
    ((PFN_Release)ctx_vt[2])(ctx);
    ((PFN_Release)sc_vt[2])(sc);
    ((PFN_Release)dev_vt[2])(dev);
    Out("[d3d11_smoke] Release chain           = PASS\r\n");

    Out("[d3d11_smoke] done\r\n");
    ExitProcess(0);
}
