/*
 * userland/libs/dxgi/dxgi.c — DuetOS DXGI v0.
 *
 * Real IDXGIFactory / IDXGIFactory1 / IDXGIFactory2 that produce
 * an adapter ("DuetOS Software Adapter") and swap chains whose
 * Present() BitBlts a BGRA8 back buffer onto the owning HWND via
 * SYS_GDI_BITBLT. Good enough to let a real Win32 PE step through
 * the canonical "create factory → pick adapter → make swap chain
 * for HWND → clear → present" flow without a nullptr or E_FAIL.
 *
 * Build: tools/build-stub-dll.sh (base 0x10150000).
 */

#include "../dx_shared.h"

/* ---------------------------------------------------------------- *
 * IIDs we recognise in QueryInterface                              *
 * ---------------------------------------------------------------- */

static const DxGuid kIID_IDXGIObject = {0xaec22fb8, 0x76f1, 0x4780, {0xa5, 0xc6, 0x1d, 0xa2, 0xb0, 0xd6, 0x5d, 0xd5}};
static const DxGuid kIID_IDXGIFactory = {0x7b7166ec, 0x21c7, 0x44ae, {0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69}};
static const DxGuid kIID_IDXGIFactory1 = {0x770aae78, 0xf26f, 0x4dba, {0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}};
static const DxGuid kIID_IDXGIFactory2 = {0x50c83a1c, 0xe072, 0x4c48, {0x87, 0xb0, 0x36, 0x30, 0xfa, 0x36, 0xa6, 0xd0}};
static const DxGuid kIID_IDXGIAdapter = {0x2411e7e1, 0x12ac, 0x4ccf, {0xbd, 0x14, 0x97, 0x98, 0xe8, 0x53, 0x4d, 0xc0}};
static const DxGuid kIID_IDXGIAdapter1 = {0x29038f61, 0x3839, 0x4626, {0x91, 0xfd, 0x08, 0x68, 0x79, 0x01, 0x1a, 0x05}};
static const DxGuid kIID_IDXGIOutput = {0xae02eedb, 0xc735, 0x4690, {0x8d, 0x52, 0x5a, 0x8d, 0xc2, 0x02, 0x13, 0xaa}};
static const DxGuid kIID_IDXGISwapChain = {
    0x310d36a0, 0xd2e7, 0x4c0a, {0xaa, 0x04, 0x6a, 0x9d, 0x23, 0xb8, 0x88, 0x6a}};
static const DxGuid kIID_IDXGISwapChain1 = {
    0x790a45f7, 0x0d42, 0x4876, {0x98, 0x3a, 0x0a, 0x55, 0xcf, 0xe6, 0xf4, 0xaa}};

/* ---------------------------------------------------------------- *
 * Forward vtables                                                  *
 * ---------------------------------------------------------------- */

struct IDXGIObject;
struct IDXGIFactoryImpl;
struct IDXGIAdapterImpl;
struct IDXGIOutputImpl;
struct IDXGISwapChainImpl;

typedef struct IDXGIFactoryVtbl IDXGIFactoryVtbl;
typedef struct IDXGIAdapterVtbl IDXGIAdapterVtbl;
typedef struct IDXGIOutputVtbl IDXGIOutputVtbl;
typedef struct IDXGISwapChainVtbl IDXGISwapChainVtbl;

/* ---------------------------------------------------------------- *
 * IDXGISwapChain                                                   *
 * ---------------------------------------------------------------- */

typedef struct IDXGISwapChainImpl
{
    const IDXGISwapChainVtbl* lpVtbl;
    ULONG refcount;
    DxBackBuffer* bb;
} IDXGISwapChainImpl;

struct IDXGISwapChainVtbl
{
    /* IUnknown (0..2) */
    HRESULT (*QueryInterface)(IDXGISwapChainImpl*, REFIID, void**);
    ULONG (*AddRef)(IDXGISwapChainImpl*);
    ULONG (*Release)(IDXGISwapChainImpl*);
    /* IDXGIObject (3..6) */
    void* SetPrivateData;
    void* SetPrivateDataInterface;
    void* GetPrivateData;
    void* GetParent;
    /* IDXGIDeviceSubObject (7) */
    void* GetDevice;
    /* IDXGISwapChain (8..16) */
    HRESULT (*Present)(IDXGISwapChainImpl*, UINT sync, UINT flags);
    HRESULT (*GetBuffer)(IDXGISwapChainImpl*, UINT idx, REFIID riid, void** out);
    HRESULT (*SetFullscreenState)(IDXGISwapChainImpl*, BOOL, void*);
    HRESULT (*GetFullscreenState)(IDXGISwapChainImpl*, BOOL*, void**);
    HRESULT (*GetDesc)(IDXGISwapChainImpl*, void* desc);
    HRESULT (*ResizeBuffers)(IDXGISwapChainImpl*, UINT, UINT, UINT, DWORD, UINT);
    HRESULT (*ResizeTarget)(IDXGISwapChainImpl*, const void*);
    HRESULT (*GetContainingOutput)(IDXGISwapChainImpl*, void**);
    HRESULT (*GetFrameStatistics)(IDXGISwapChainImpl*, void*);
    HRESULT (*GetLastPresentCount)(IDXGISwapChainImpl*, UINT*);
};

static HRESULT sc_QueryInterface(IDXGISwapChainImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDXGIObject) ||
        dx_guid_eq(riid, &kIID_IDXGISwapChain) || dx_guid_eq(riid, &kIID_IDXGISwapChain1))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG sc_AddRef(IDXGISwapChainImpl* self)
{
    return ++self->refcount;
}
static ULONG sc_Release(IDXGISwapChainImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_bb_destroy(self->bb);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static HRESULT sc_Present(IDXGISwapChainImpl* self, UINT sync, UINT flags)
{
    (void)sync;
    (void)flags;
    if (!self || !self->bb)
        return DX_E_FAIL;
    dx_gfx_trace(3);
    dx_bb_present(self->bb);
    return DX_S_OK;
}

static HRESULT sc_GetBuffer(IDXGISwapChainImpl* self, UINT idx, REFIID riid, void** out)
{
    (void)idx;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    /* DXGI-only back buffer handle: return the raw DxBackBuffer* so
     * a DXGI-savvy caller can cast + read it. D3D11/D3D12 apps
     * expect a real ID3D11Texture2D / ID3D12Resource here; those
     * paths bypass DXGI by going through D3D11CreateDeviceAndSwap-
     * Chain / the D3D12 swap chain integration instead. */
    *out = self->bb;
    self->refcount++;
    return DX_S_OK;
}

static HRESULT sc_GetDesc(IDXGISwapChainImpl* self, void* desc)
{
    (void)self;
    (void)desc;
    /* Descriptor layout differs between Desc/Desc1; v0 zero-fills
     * a conservative 120-byte window (size of DXGI_SWAP_CHAIN_DESC1). */
    if (desc)
        dx_memzero(desc, 120);
    return DX_S_OK;
}

static HRESULT sc_ResizeBuffers(IDXGISwapChainImpl* self, UINT bufs, UINT w, UINT h, DWORD fmt, UINT flags)
{
    (void)bufs;
    (void)fmt;
    (void)flags;
    if (!self || !self->bb)
        return DX_E_FAIL;
    HWND hwnd = self->bb->hwnd;
    if (w == 0 || h == 0)
    {
        DxRect r;
        dx_memzero(&r, sizeof(r));
        if (hwnd && dx_win_get_rect(hwnd, &r))
        {
            if (r.right > r.left)
                w = (UINT)(r.right - r.left);
            if (r.bottom > r.top)
                h = (UINT)(r.bottom - r.top);
        }
        if (w == 0)
            w = self->bb->width;
        if (h == 0)
            h = self->bb->height;
    }
    dx_bb_destroy(self->bb);
    self->bb = dx_bb_create(hwnd, w, h);
    return self->bb ? DX_S_OK : DX_E_OUTOFMEMORY;
}

static const IDXGISwapChainVtbl g_sc_vtbl = {
    sc_QueryInterface,
    sc_AddRef,
    sc_Release,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB, /* IDXGIObject */
    DX_HSTUB, /* GetDevice */
    sc_Present,
    sc_GetBuffer,
    (HRESULT(*)(IDXGISwapChainImpl*, BOOL, void*))DX_HSTUB,
    (HRESULT(*)(IDXGISwapChainImpl*, BOOL*, void**))DX_HSTUB,
    sc_GetDesc,
    sc_ResizeBuffers,
    (HRESULT(*)(IDXGISwapChainImpl*, const void*))DX_HSTUB,
    (HRESULT(*)(IDXGISwapChainImpl*, void**))DX_HSTUB,
    (HRESULT(*)(IDXGISwapChainImpl*, void*))DX_HSTUB,
    (HRESULT(*)(IDXGISwapChainImpl*, UINT*))DX_HSTUB,
};

static IDXGISwapChainImpl* swap_chain_alloc(HWND hwnd, UINT w, UINT h)
{
    if (w == 0)
        w = 640;
    if (h == 0)
        h = 480;
    IDXGISwapChainImpl* sc = (IDXGISwapChainImpl*)dx_heap_alloc(sizeof(IDXGISwapChainImpl));
    if (!sc)
        return NULL;
    dx_memzero(sc, sizeof(*sc));
    sc->lpVtbl = &g_sc_vtbl;
    sc->refcount = 1;
    sc->bb = dx_bb_create(hwnd, w, h);
    if (!sc->bb)
    {
        dx_heap_free(sc);
        return NULL;
    }
    return sc;
}

/* ---------------------------------------------------------------- *
 * IDXGIOutput                                                      *
 * ---------------------------------------------------------------- */

typedef struct IDXGIOutputImpl
{
    const IDXGIOutputVtbl* lpVtbl;
    ULONG refcount;
} IDXGIOutputImpl;

struct IDXGIOutputVtbl
{
    HRESULT (*QueryInterface)(IDXGIOutputImpl*, REFIID, void**);
    ULONG (*AddRef)(IDXGIOutputImpl*);
    ULONG (*Release)(IDXGIOutputImpl*);
    void* SetPrivateData;
    void* SetPrivateDataInterface;
    void* GetPrivateData;
    void* GetParent;
    HRESULT (*GetDesc)(IDXGIOutputImpl*, void* desc);
    void* GetDisplayModeList;
    void* FindClosestMatchingMode;
    void* WaitForVBlank;
    void* TakeOwnership;
    void* ReleaseOwnership;
    void* GetGammaControlCapabilities;
    void* SetGammaControl;
    void* GetGammaControl;
    void* SetDisplaySurface;
    void* GetDisplaySurfaceData;
    void* GetFrameStatistics;
};

static HRESULT out_QueryInterface(IDXGIOutputImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDXGIObject) || dx_guid_eq(riid, &kIID_IDXGIOutput))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG out_AddRef(IDXGIOutputImpl* self)
{
    return ++self->refcount;
}
static ULONG out_Release(IDXGIOutputImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT out_GetDesc(IDXGIOutputImpl* self, void* desc)
{
    (void)self;
    /* DXGI_OUTPUT_DESC is 96 bytes; zero it. The DeviceName field
     * (first 32 bytes wchar_t[32]) is left as a NUL-terminated
     * empty string, which matches what a headless software output
     * would carry. */
    if (desc)
        dx_memzero(desc, 96);
    return DX_S_OK;
}

static const IDXGIOutputVtbl g_out_vtbl = {
    out_QueryInterface, out_AddRef, out_Release, DX_HSTUB, DX_HSTUB, DX_HSTUB, DX_HSTUB,
    out_GetDesc,        DX_HSTUB,   DX_HSTUB,    DX_HSTUB, DX_HSTUB, DX_HSTUB, DX_HSTUB,
    DX_HSTUB,           DX_HSTUB,   DX_HSTUB,    DX_HSTUB, DX_HSTUB,
};

static IDXGIOutputImpl* output_alloc(void)
{
    IDXGIOutputImpl* o = (IDXGIOutputImpl*)dx_heap_alloc(sizeof(IDXGIOutputImpl));
    if (!o)
        return NULL;
    o->lpVtbl = &g_out_vtbl;
    o->refcount = 1;
    return o;
}

/* ---------------------------------------------------------------- *
 * IDXGIAdapter / IDXGIAdapter1                                     *
 * ---------------------------------------------------------------- */

typedef struct IDXGIAdapterImpl
{
    const IDXGIAdapterVtbl* lpVtbl;
    ULONG refcount;
    BOOL output_enumerated;
} IDXGIAdapterImpl;

struct IDXGIAdapterVtbl
{
    HRESULT (*QueryInterface)(IDXGIAdapterImpl*, REFIID, void**);
    ULONG (*AddRef)(IDXGIAdapterImpl*);
    ULONG (*Release)(IDXGIAdapterImpl*);
    void* SetPrivateData;
    void* SetPrivateDataInterface;
    void* GetPrivateData;
    void* GetParent;
    HRESULT (*EnumOutputs)(IDXGIAdapterImpl*, UINT idx, void** out);
    HRESULT (*GetDesc)(IDXGIAdapterImpl*, void* desc);
    void* CheckInterfaceSupport;
    HRESULT (*GetDesc1)(IDXGIAdapterImpl*, void* desc);
};

static HRESULT ad_QueryInterface(IDXGIAdapterImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDXGIObject) ||
        dx_guid_eq(riid, &kIID_IDXGIAdapter) || dx_guid_eq(riid, &kIID_IDXGIAdapter1))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG ad_AddRef(IDXGIAdapterImpl* self)
{
    return ++self->refcount;
}
static ULONG ad_Release(IDXGIAdapterImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static HRESULT ad_EnumOutputs(IDXGIAdapterImpl* self, UINT idx, void** out)
{
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (idx != 0)
        return DXGI_ERROR_NOT_FOUND;
    IDXGIOutputImpl* o = output_alloc();
    if (!o)
        return DX_E_OUTOFMEMORY;
    *out = o;
    self->output_enumerated = 1;
    return DX_S_OK;
}

/* DXGI_ADAPTER_DESC layout (256 bytes total):
 *   wchar_t Description[128]    (256 bytes)
 *   UINT VendorId               (4)
 *   UINT DeviceId               (4)
 *   UINT SubSysId               (4)
 *   UINT Revision               (4)
 *   SIZE_T DedicatedVideoMemory (8)
 *   SIZE_T DedicatedSystemMemory(8)
 *   SIZE_T SharedSystemMemory   (8)
 *   LUID AdapterLuid            (8)
 * = 304 bytes; zero-fill is the safe path. */
static HRESULT ad_GetDesc(IDXGIAdapterImpl* self, void* desc)
{
    (void)self;
    if (!desc)
        return DX_E_POINTER;
    dx_memzero(desc, 304);
    /* "DuetOS Software Adapter" in UTF-16 LE, hand-encoded. */
    static const WORD kName[] = {'D', 'u', 'e', 't', 'O', 'S', ' ', 'S', 'o', 'f', 't', 'w',
                                 'a', 'r', 'e', ' ', 'A', 'd', 'a', 'p', 't', 'e', 'r', 0};
    WORD* dst = (WORD*)desc;
    for (UINT i = 0; i < (sizeof(kName) / sizeof(kName[0])) && i < 128; ++i)
        dst[i] = kName[i];
    return DX_S_OK;
}

static HRESULT ad_GetDesc1(IDXGIAdapterImpl* self, void* desc)
{
    /* DXGI_ADAPTER_DESC1 = DXGI_ADAPTER_DESC + UINT Flags (4 B). */
    return ad_GetDesc(self, desc);
}

static const IDXGIAdapterVtbl g_ad_vtbl = {
    ad_QueryInterface, ad_AddRef,      ad_Release, DX_HSTUB, DX_HSTUB,    DX_HSTUB,
    DX_HSTUB,          ad_EnumOutputs, ad_GetDesc, DX_HSTUB, ad_GetDesc1,
};

static IDXGIAdapterImpl* adapter_alloc(void)
{
    IDXGIAdapterImpl* a = (IDXGIAdapterImpl*)dx_heap_alloc(sizeof(IDXGIAdapterImpl));
    if (!a)
        return NULL;
    dx_memzero(a, sizeof(*a));
    a->lpVtbl = &g_ad_vtbl;
    a->refcount = 1;
    return a;
}

/* ---------------------------------------------------------------- *
 * IDXGIFactory / 1 / 2                                             *
 * ---------------------------------------------------------------- */

typedef struct IDXGIFactoryImpl
{
    const IDXGIFactoryVtbl* lpVtbl;
    ULONG refcount;
} IDXGIFactoryImpl;

struct IDXGIFactoryVtbl
{
    /* IUnknown + IDXGIObject (0..6) */
    HRESULT (*QueryInterface)(IDXGIFactoryImpl*, REFIID, void**);
    ULONG (*AddRef)(IDXGIFactoryImpl*);
    ULONG (*Release)(IDXGIFactoryImpl*);
    void* SetPrivateData;
    void* SetPrivateDataInterface;
    void* GetPrivateData;
    void* GetParent;
    /* IDXGIFactory (7..12) */
    HRESULT (*EnumAdapters)(IDXGIFactoryImpl*, UINT idx, void** out);
    void* MakeWindowAssociation;
    void* GetWindowAssociation;
    HRESULT (*CreateSwapChain)(IDXGIFactoryImpl*, void* device, void* desc, void** out);
    void* CreateSoftwareAdapter;
    /* IDXGIFactory1 (12..14) */
    HRESULT (*EnumAdapters1)(IDXGIFactoryImpl*, UINT idx, void** out);
    BOOL (*IsCurrent)(IDXGIFactoryImpl*);
    /* IDXGIFactory2 (14..27) */
    BOOL (*IsWindowedStereoEnabled)(IDXGIFactoryImpl*);
    HRESULT(*CreateSwapChainForHwnd)
    (IDXGIFactoryImpl*, void* device, HWND hwnd, const void* desc, const void* fsdesc, void* restrict_output,
     void** out);
    void* CreateSwapChainForCoreWindow;
    void* GetSharedResourceAdapterLuid;
    void* RegisterStereoStatusWindow;
    void* RegisterStereoStatusEvent;
    void* UnregisterStereoStatus;
    void* RegisterOcclusionStatusWindow;
    void* RegisterOcclusionStatusEvent;
    void* UnregisterOcclusionStatus;
    void* CreateSwapChainForComposition;
};

static HRESULT fac_QueryInterface(IDXGIFactoryImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDXGIObject) ||
        dx_guid_eq(riid, &kIID_IDXGIFactory) || dx_guid_eq(riid, &kIID_IDXGIFactory1) ||
        dx_guid_eq(riid, &kIID_IDXGIFactory2))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG fac_AddRef(IDXGIFactoryImpl* self)
{
    return ++self->refcount;
}
static ULONG fac_Release(IDXGIFactoryImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static HRESULT fac_EnumAdapters(IDXGIFactoryImpl* self, UINT idx, void** out)
{
    (void)self;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (idx != 0)
        return DXGI_ERROR_NOT_FOUND;
    IDXGIAdapterImpl* a = adapter_alloc();
    if (!a)
        return DX_E_OUTOFMEMORY;
    *out = a;
    return DX_S_OK;
}

/* DXGI_SWAP_CHAIN_DESC offsets (Win32 ABI):
 *   +0:  DXGI_MODE_DESC BufferDesc {
 *           UINT Width  (+0)
 *           UINT Height (+4)
 *           DXGI_RATIONAL RefreshRate (+8 +12)
 *           DXGI_FORMAT Format (+16)
 *           UINT ScanlineOrdering (+20)
 *           UINT Scaling (+24) }      = 28 bytes
 *   +28: DXGI_SAMPLE_DESC SampleDesc { UINT Count, Quality } = 8
 *   +36: DXGI_USAGE BufferUsage     = 4
 *   +40: UINT BufferCount           = 4
 *   +44: HWND OutputWindow          = 8 (after pad to 8)
 *      → struct is __declspec(align(8)) so OutputWindow lives at +48
 *   +48: HWND OutputWindow          = 8
 *   +56: BOOL Windowed              = 4
 *   +60: DXGI_SWAP_EFFECT SwapEffect= 4
 *   +64: UINT Flags                 = 4
 * Width/Height/HWND are what we need. */
static HRESULT fac_CreateSwapChain(IDXGIFactoryImpl* self, void* device, void* desc, void** out)
{
    (void)self;
    (void)device;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    UINT w = 0, h = 0;
    HWND hwnd = NULL;
    if (desc)
    {
        const BYTE* d = (const BYTE*)desc;
        w = *(const UINT*)(d + 0);
        h = *(const UINT*)(d + 4);
        hwnd = *(const HWND*)(d + 48);
    }
    IDXGISwapChainImpl* sc = swap_chain_alloc(hwnd, w, h);
    if (!sc)
        return DX_E_OUTOFMEMORY;
    *out = sc;
    return DX_S_OK;
}

/* DXGI_SWAP_CHAIN_DESC1: Width @0, Height @4, Format @8 ... no HWND
 * (HWND is the explicit hwnd param of CreateSwapChainForHwnd). */
static HRESULT fac_CreateSwapChainForHwnd(IDXGIFactoryImpl* self, void* device, HWND hwnd, const void* desc,
                                          const void* fsdesc, void* restrict_output, void** out)
{
    (void)self;
    (void)device;
    (void)fsdesc;
    (void)restrict_output;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    UINT w = 0, h = 0;
    if (desc)
    {
        const BYTE* d = (const BYTE*)desc;
        w = *(const UINT*)(d + 0);
        h = *(const UINT*)(d + 4);
    }
    IDXGISwapChainImpl* sc = swap_chain_alloc(hwnd, w, h);
    if (!sc)
        return DX_E_OUTOFMEMORY;
    *out = sc;
    return DX_S_OK;
}

static BOOL fac_IsCurrent(IDXGIFactoryImpl* self)
{
    (void)self;
    return 1;
}
static BOOL fac_IsWindowedStereoEnabled(IDXGIFactoryImpl* self)
{
    (void)self;
    return 0;
}

static const IDXGIFactoryVtbl g_fac_vtbl = {
    fac_QueryInterface,
    fac_AddRef,
    fac_Release,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB, /* IDXGIObject */
    fac_EnumAdapters,
    DX_HSTUB,
    DX_HSTUB,
    fac_CreateSwapChain,
    DX_HSTUB,
    fac_EnumAdapters,
    fac_IsCurrent, /* Factory1 */
    fac_IsWindowedStereoEnabled,
    fac_CreateSwapChainForHwnd, /* Factory2 */
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
};

static IDXGIFactoryImpl* factory_alloc(void)
{
    IDXGIFactoryImpl* f = (IDXGIFactoryImpl*)dx_heap_alloc(sizeof(IDXGIFactoryImpl));
    if (!f)
        return NULL;
    dx_memzero(f, sizeof(*f));
    f->lpVtbl = &g_fac_vtbl;
    f->refcount = 1;
    return f;
}

/* ---------------------------------------------------------------- *
 * Exported entry points                                            *
 * ---------------------------------------------------------------- */

__declspec(dllexport) HRESULT CreateDXGIFactory(REFIID riid, void** factory)
{
    (void)riid;
    dx_gfx_trace(3);
    if (!factory)
        return DX_E_POINTER;
    IDXGIFactoryImpl* f = factory_alloc();
    if (!f)
    {
        *factory = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *factory = f;
    return DX_S_OK;
}

__declspec(dllexport) HRESULT CreateDXGIFactory1(REFIID riid, void** factory)
{
    return CreateDXGIFactory(riid, factory);
}

__declspec(dllexport) HRESULT CreateDXGIFactory2(UINT flags, REFIID riid, void** factory)
{
    (void)flags;
    return CreateDXGIFactory(riid, factory);
}

/* DXGIGetDebugInterface{1} — many runtime tools probe these even
 * when DXGI debug isn't installed. Returning DXGI_ERROR_NOT_FOUND
 * matches Windows' behaviour on a system without the debug layer. */
__declspec(dllexport) HRESULT DXGIGetDebugInterface(REFIID riid, void** dbg)
{
    (void)riid;
    if (dbg)
        *dbg = NULL;
    return DXGI_ERROR_NOT_FOUND;
}

__declspec(dllexport) HRESULT DXGIGetDebugInterface1(UINT flags, REFIID riid, void** dbg)
{
    (void)flags;
    return DXGIGetDebugInterface(riid, dbg);
}

/* DXGIDeclareAdapterRemovalSupport — a no-op success on systems
 * with a single software adapter. */
__declspec(dllexport) HRESULT DXGIDeclareAdapterRemovalSupport(void)
{
    return DX_S_OK;
}
