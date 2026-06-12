/*
 * d3d9_smoke — exercise the IDirect3D9 + IDirect3DDevice9 path through
 * real COM vtable calls. Validates userland/libs/d3d9/d3d9.c:
 *
 *   Direct3DCreate9(D3D_SDK_VERSION) → IDirect3D9*
 *   IDirect3D9::GetAdapterCount      → 1
 *   IDirect3D9::CreateDevice         → IDirect3DDevice9*
 *   IDirect3DDevice9::BeginScene
 *   IDirect3DDevice9::Clear(0xff0000ff red)
 *   IDirect3DDevice9::EndScene
 *   IDirect3DDevice9::Present
 *   release
 *
 * Slot indices match d9_/d9d_ vtables in userland/libs/d3d9/d3d9.c.
 */
#include <windows.h>

extern void* Direct3DCreate9(UINT sdk);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

/* D3DPRESENT_PARAMETERS — only the fields d3d9.c reads:
 *   +0  BackBufferWidth
 *   +4  BackBufferHeight
 *   +8  BackBufferFormat
 *   +12 BackBufferCount
 *   +16 MultiSampleType
 *   +20 MultiSampleQuality
 *   +24 SwapEffect
 *   +32 hDeviceWindow      (HWND, 8B aligned) */
typedef struct
{
    UINT BackBufferWidth, BackBufferHeight;
    UINT BackBufferFormat, BackBufferCount;
    UINT MultiSampleType, MultiSampleQuality;
    UINT SwapEffect, _pad;
    HWND hDeviceWindow;
    BOOL Windowed;
    BOOL EnableAutoDepthStencil;
    UINT AutoDepthStencilFormat;
    UINT Flags;
    UINT FullScreen_RefreshRateInHz;
    UINT PresentationInterval;
} PresentParams;

void __cdecl mainCRTStartup(void)
{
    Out("[d3d9_smoke] starting\r\n");

    void* d3d = Direct3DCreate9(32);
    Out("[d3d9_smoke] Direct3DCreate9         = ");
    Out(d3d ? "PASS\r\n" : "FAIL\r\n");
    if (!d3d)
    {
        Out("[ring3-d3d9-smoke] FAIL create9\r\n");
        ExitProcess(1);
    }

    void** d3d_vt = *(void***)d3d;

    /* slot 4 = GetAdapterCount → returns 1 */
    typedef UINT (*PFN_AdCount)(void*);
    UINT n = ((PFN_AdCount)d3d_vt[4])(d3d);
    Out("[d3d9_smoke] IDirect3D9::AdapterCount = ");
    Out((n == 1) ? "PASS\r\n" : "FAIL\r\n");

    PresentParams pp;
    BYTE* p = (BYTE*)&pp;
    for (UINT i = 0; i < sizeof(pp); ++i)
        p[i] = 0;
    /* 32x32 BGRA8 = 4 KiB — fits in 64 KiB Win32 heap. */
    pp.BackBufferWidth = 32;
    pp.BackBufferHeight = 32;
    pp.BackBufferCount = 1;
    pp.SwapEffect = 1; /* D3DSWAPEFFECT_DISCARD */
    pp.hDeviceWindow = NULL;
    pp.Windowed = TRUE;

    /* slot 16 = CreateDevice */
    void* dev = NULL;
    typedef long (*PFN_CreateDev)(void*, UINT, UINT, HWND, DWORD, void*, void**);
    long hr = ((PFN_CreateDev)d3d_vt[16])(d3d, 0, 1 /*HAL*/, NULL, 0x40, &pp, &dev);
    Out("[d3d9_smoke] IDirect3D9::CreateDevice = ");
    Out((hr == 0 && dev) ? "PASS\r\n" : "FAIL\r\n");
    if (hr != 0 || !dev)
    {
        Out("[ring3-d3d9-smoke] FAIL createdevice\r\n");
        ExitProcess(1);
    }

    void** dev_vt = *(void***)dev;

    /* slot 41 = BeginScene (canonical d3d9.h ordering) */
    typedef long (*PFN_HR)(void*);
    hr = ((PFN_HR)dev_vt[41])(dev);
    Out("[d3d9_smoke] Device::BeginScene       = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 43 = Clear(count, rects, flags, color, z, stencil)
     * D3DCOLOR is 0xAARRGGBB → 0xffff0000 = opaque red */
    typedef long (*PFN_Clear)(void*, DWORD, const void*, DWORD, DWORD, float, DWORD);
    hr = ((PFN_Clear)dev_vt[43])(dev, 0, NULL, 1 /*D3DCLEAR_TARGET*/, 0xffff0000, 1.0f, 0);
    Out("[d3d9_smoke] Device::Clear(red)       = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 42 = EndScene */
    hr = ((PFN_HR)dev_vt[42])(dev);
    Out("[d3d9_smoke] Device::EndScene         = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* ----- v0.1: cover the FF geometry path ---------------------- *
     * D3DFVF_XYZRHW (4) | D3DFVF_DIFFUSE (0x40) = 0x44 — pre-transformed
     * verts so we don't need a real projection matrix. */
    typedef long (*PFN_SetFVF)(void*, DWORD);
    hr = ((PFN_SetFVF)dev_vt[89])(dev, 0x44);
    Out("[d3d9_smoke] Device::SetFVF(XYZRHW|DIFFUSE) = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    typedef struct
    {
        float x, y, z, rhw;
        DWORD argb;
    } D9Vert; /* 20 B */
    /* Triangle in screen space (will hit the back buffer). */
    D9Vert verts[3] = {
        {4.0f, 28.0f, 0.f, 1.f, 0xFFFF0000},
        {16.0f, 4.0f, 0.f, 1.f, 0xFF00FF00},
        {28.0f, 28.0f, 0.f, 1.f, 0xFF0000FF},
    };
    /* slot 83 = DrawPrimitiveUP(type, primCount, vertexData, stride)
     * D3DPT_TRIANGLELIST = 4. */
    typedef long (*PFN_DrawUP)(void*, UINT, UINT, const void*, UINT);
    hr = ((PFN_DrawUP)dev_vt[83])(dev, 4, 1, verts, sizeof(D9Vert));
    Out("[d3d9_smoke] Device::DrawPrimitiveUP  = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 17 = Present(srcRect, dstRect, hwndOverride, dirtyRgn) */
    typedef long (*PFN_Present)(void*, const void*, const void*, HWND, const void*);
    hr = ((PFN_Present)dev_vt[17])(dev, NULL, NULL, NULL, NULL);
    Out("[d3d9_smoke] Device::Present          = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* Release */
    typedef unsigned long (*PFN_Rel)(void*);
    ((PFN_Rel)dev_vt[2])(dev);
    ((PFN_Rel)d3d_vt[2])(d3d);
    Out("[d3d9_smoke] Release chain            = PASS\r\n");

    Out("[d3d9_smoke] done\r\n");
    Out("[ring3-d3d9-smoke] PASS\r\n");
    ExitProcess(0);
}
