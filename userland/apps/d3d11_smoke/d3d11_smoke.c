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

    /* ----- v0.1: cover the geometry path ------------------------- *
     * slot 3 = CreateBuffer(desc, init, **out)
     * D3D11_BUFFER_DESC: ByteWidth(0), Usage(4), BindFlags(8),
     *   CPUAccessFlags(12), MiscFlags(16), StructureByteStride(20).
     * D3D11_SUBRESOURCE_DATA: pSysMem(0), SysMemPitch(8), SysMemSlicePitch(12). */
    typedef struct
    {
        float x, y, z;
        DWORD argb;
    } Vert; /* 16 B per vertex */
    Vert verts[3] = {
        {-0.6f, -0.6f, 0.0f, 0xFFFF0000}, /* red bottom-left  */
        {0.0f, 0.6f, 0.0f, 0xFF00FF00},   /* green top        */
        {0.6f, -0.6f, 0.0f, 0xFF0000FF},  /* blue bottom-right */
    };
    BYTE bdesc[24] = {0};
    *(UINT*)(bdesc + 0) = sizeof(verts);
    *(UINT*)(bdesc + 8) = 0x1; /* D3D11_BIND_VERTEX_BUFFER */
    BYTE srd[16] = {0};
    *(const void**)(srd + 0) = (const void*)verts;
    void* vb = NULL;
    typedef long (*PFN_CreateBuf)(void*, const void*, const void*, void**);
    hr = ((PFN_CreateBuf)dev_vt[3])(dev, bdesc, srd, &vb);
    Out("[d3d11_smoke] Device::CreateBuffer    = ");
    Out((hr == 0 && vb) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 11 = CreateInputLayout(descs, n, vsCode, vsLen, **out)
     * D3D11_INPUT_ELEMENT_DESC (32 B):
     *   const char* SemanticName  (8)
     *   UINT SemanticIndex        (4)
     *   DXGI_FORMAT Format        (4)
     *   UINT InputSlot            (4)
     *   UINT AlignedByteOffset    (4)
     *   D3D11_INPUT_CLASSIFICATION (4)
     *   UINT InstanceDataStepRate (4) */
    static const char kPos[] = "POSITION";
    static const char kCol[] = "COLOR";
    BYTE ied[64];
    for (UINT i = 0; i < sizeof(ied); ++i)
        ied[i] = 0;
    *(const char**)(ied + 0) = kPos;
    *(UINT*)(ied + 12) = 6; /* DXGI_FORMAT_R32G32B32_FLOAT */
    *(UINT*)(ied + 20) = 0; /* offset 0 */
    *(const char**)(ied + 32) = kCol;
    *(UINT*)(ied + 44) = 87; /* DXGI_FORMAT_B8G8R8A8_UNORM */
    *(UINT*)(ied + 52) = 12; /* offset 12 (after xyz) */
    void* il = NULL;
    typedef long (*PFN_CreateIL)(void*, const void*, UINT, const void*, SIZE_T, void**);
    hr = ((PFN_CreateIL)dev_vt[11])(dev, ied, 2, NULL, 0, &il);
    Out("[d3d11_smoke] Device::CreateInputLay  = ");
    Out((hr == 0 && il) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 17 = IASetInputLayout(il) */
    typedef void (*PFN_IASetIL)(void*, void*);
    ((PFN_IASetIL)ctx_vt[17])(ctx, il);
    Out("[d3d11_smoke] Context::IASetIL        = PASS (returned)\r\n");

    /* slot 18 = IASetVertexBuffers(start, n, ppVB, pStride, pOffset) */
    void* vbs[1] = {vb};
    UINT strides[1] = {16};
    UINT offsets[1] = {0};
    typedef void (*PFN_IASetVB)(void*, UINT, UINT, void* const*, const UINT*, const UINT*);
    ((PFN_IASetVB)ctx_vt[18])(ctx, 0, 1, vbs, strides, offsets);
    Out("[d3d11_smoke] Context::IASetVB        = PASS (returned)\r\n");

    /* slot 24 = IASetPrimitiveTopology — TRIANGLELIST = 4 */
    typedef void (*PFN_IASetTopo)(void*, UINT);
    ((PFN_IASetTopo)ctx_vt[24])(ctx, 4);
    Out("[d3d11_smoke] Context::IASetTopo      = PASS (returned)\r\n");

    /* slot 44 = RSSetViewports — full back buffer */
    float vp[6] = {0.f, 0.f, 32.f, 32.f, 0.f, 1.f};
    typedef void (*PFN_RSSetVP)(void*, UINT, const void*);
    ((PFN_RSSetVP)ctx_vt[44])(ctx, 1, vp);
    Out("[d3d11_smoke] Context::RSSetVP        = PASS (returned)\r\n");

    /* slot 13 = Draw(VertexCount, StartVertex) — rasterizes the triangle */
    typedef void (*PFN_Draw)(void*, UINT, UINT);
    ((PFN_Draw)ctx_vt[13])(ctx, 3, 0);
    Out("[d3d11_smoke] Context::Draw(3)        = PASS (returned)\r\n");

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
    ((PFN_Release)((void**)(*(void***)il))[2])(il);
    ((PFN_Release)((void**)(*(void***)vb))[2])(vb);
    ((PFN_Release)((void**)(*(void***)rtv))[2])(rtv);
    ((PFN_Release)((void**)(*(void***)tex))[2])(tex);
    ((PFN_Release)ctx_vt[2])(ctx);
    ((PFN_Release)sc_vt[2])(sc);
    ((PFN_Release)dev_vt[2])(dev);
    Out("[d3d11_smoke] Release chain           = PASS\r\n");

    Out("[d3d11_smoke] done\r\n");
    ExitProcess(0);
}
