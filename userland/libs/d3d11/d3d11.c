/*
 * userland/libs/d3d11/d3d11.c — DuetOS D3D11 v0.
 *
 * Real ID3D11Device + ID3D11DeviceContext that produce a working
 * Clear-and-Present pipeline:
 *   D3D11CreateDeviceAndSwapChain()
 *     → ID3D11Device, ID3D11DeviceContext, IDXGISwapChain
 *   IDXGISwapChain::GetBuffer(0, ID3D11Texture2D, ...)
 *     → ID3D11Texture2D wrapping the back buffer
 *   ID3D11Device::CreateRenderTargetView(tex, NULL, &rtv)
 *     → ID3D11RenderTargetView pointing at the back buffer
 *   ID3D11DeviceContext::ClearRenderTargetView(rtv, color)
 *     → fills the back buffer with `color`
 *   IDXGISwapChain::Present()
 *     → SYS_GDI_BITBLT to the owning HWND
 *
 * Higher-level drawing (vertex/pixel shaders, draw calls) is not
 * implemented in v0; those vtable slots return E_NOTIMPL via the
 * shared dx_stub_hresult so apps that only test the clear path
 * don't crash, and apps that try real rendering fail predictably.
 *
 * Build: tools/build/build-stub-dll.sh (base 0x10130000).
 */

#include "../dx_shared.h"

/* ---------------------------------------------------------------- *
 * IIDs                                                             *
 * ---------------------------------------------------------------- */

static const DxGuid kIID_ID3D11Device = {0xdb6f6ddb, 0xac77, 0x4e88, {0x82, 0x53, 0x81, 0x9d, 0xf9, 0xbb, 0xf1, 0x40}};
static const DxGuid kIID_ID3D11DeviceContext = {
    0xc0bfa96c, 0xe089, 0x44fb, {0x8e, 0xaf, 0x26, 0xf8, 0x79, 0x61, 0x90, 0xda}};
static const DxGuid kIID_ID3D11Resource = {
    0xdc8e63f3, 0xd12b, 0x4952, {0xb4, 0x7b, 0x5e, 0x45, 0x02, 0x6a, 0x86, 0x2d}};
static const DxGuid kIID_ID3D11Texture2D = {
    0x6f15aaf2, 0xd208, 0x4e89, {0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c}};
static const DxGuid kIID_ID3D11View = {0x839d1216, 0xbb2e, 0x412b, {0xb7, 0xf4, 0xa9, 0xdb, 0xeb, 0xe0, 0x8e, 0xd1}};
static const DxGuid kIID_ID3D11RenderTargetView = {
    0xdfdba067, 0x0b8d, 0x4865, {0x87, 0x5b, 0xd7, 0xb4, 0x51, 0x6c, 0xc1, 0x64}};
static const DxGuid kIID_IDXGISwapChain = {
    0x310d36a0, 0xd2e7, 0x4c0a, {0xaa, 0x04, 0x6a, 0x9d, 0x23, 0xb8, 0x88, 0x6a}};
static const DxGuid kIID_IDXGISwapChain1 = {
    0x790a45f7, 0x0d42, 0x4876, {0x98, 0x3a, 0x0a, 0x55, 0xcf, 0xe6, 0xf4, 0xaa}};

/* ---------------------------------------------------------------- *
 * Forward                                                          *
 * ---------------------------------------------------------------- */

typedef struct ID3D11Texture2DImpl ID3D11Texture2DImpl;
typedef struct ID3D11RTVImpl ID3D11RTVImpl;
typedef struct ID3D11DeviceImpl ID3D11DeviceImpl;
typedef struct ID3D11ContextImpl ID3D11ContextImpl;
typedef struct D3D11SwapChainImpl D3D11SwapChainImpl;

typedef struct ID3D11Texture2DVtbl ID3D11Texture2DVtbl;
typedef struct ID3D11RTVVtbl ID3D11RTVVtbl;
typedef struct ID3D11DeviceVtbl ID3D11DeviceVtbl;
typedef struct ID3D11ContextVtbl ID3D11ContextVtbl;
typedef struct D3D11SwapChainVtbl D3D11SwapChainVtbl;

/* ---------------------------------------------------------------- *
 * ID3D11Texture2D — wraps a DxBackBuffer.                          *
 * The vtable layout matches ID3D11Texture2D:                       *
 *   IUnknown(3) + ID3D11DeviceChild(1=GetDevice) +                  *
 *   ID3D11Resource(3=GetType,SetEvictionPriority,Get…) +            *
 *   ID3D11Texture2D(1=GetDesc).                                     *
 * ---------------------------------------------------------------- */

typedef struct ID3D11Texture2DImpl
{
    const ID3D11Texture2DVtbl* lpVtbl;
    ULONG refcount;
    DxBackBuffer* bb;
    BOOL owns_bb; /* if 1, dtor frees bb; otherwise it's owned by a swap chain */
    UINT format;  /* DXGI_FORMAT_B8G8R8A8_UNORM = 87 by default */
} ID3D11Texture2DImpl;

struct ID3D11Texture2DVtbl
{
    HRESULT (*QueryInterface)(ID3D11Texture2DImpl*, REFIID, void**);
    ULONG (*AddRef)(ID3D11Texture2DImpl*);
    ULONG (*Release)(ID3D11Texture2DImpl*);
    void* GetDevice;
    void* GetPrivateData;
    void* SetPrivateData;
    void* SetPrivateDataInterface;
    void (*GetType)(ID3D11Texture2DImpl*, UINT* type);
    void (*SetEvictionPriority)(ID3D11Texture2DImpl*, UINT);
    UINT (*GetEvictionPriority)(ID3D11Texture2DImpl*);
    void (*GetDesc)(ID3D11Texture2DImpl*, void* desc);
};

static HRESULT tx_QueryInterface(ID3D11Texture2DImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D11Resource) ||
        dx_guid_eq(riid, &kIID_ID3D11Texture2D))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG tx_AddRef(ID3D11Texture2DImpl* self)
{
    return ++self->refcount;
}
static ULONG tx_Release(ID3D11Texture2DImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->owns_bb && self->bb)
            dx_bb_destroy(self->bb);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static void tx_GetType(ID3D11Texture2DImpl* self, UINT* type)
{
    (void)self;
    if (type)
        *type = 3; /* D3D11_RESOURCE_DIMENSION_TEXTURE2D */
}
static UINT tx_GetEvictionPriority(ID3D11Texture2DImpl* self)
{
    (void)self;
    return 0;
}

/* D3D11_TEXTURE2D_DESC layout (44 bytes):
 *   UINT Width(0), Height(4), MipLevels(8), ArraySize(12),
 *   DXGI_FORMAT Format(16), DXGI_SAMPLE_DESC SampleDesc(20:Count, 24:Quality),
 *   D3D11_USAGE Usage(28), UINT BindFlags(32), CPUAccessFlags(36), MiscFlags(40). */
static void tx_GetDesc(ID3D11Texture2DImpl* self, void* desc)
{
    if (!desc)
        return;
    BYTE* d = (BYTE*)desc;
    dx_memzero(d, 44);
    UINT w = self->bb ? self->bb->width : 0;
    UINT h = self->bb ? self->bb->height : 0;
    *(UINT*)(d + 0) = w;
    *(UINT*)(d + 4) = h;
    *(UINT*)(d + 8) = 1;             /* MipLevels */
    *(UINT*)(d + 12) = 1;            /* ArraySize */
    *(UINT*)(d + 16) = self->format; /* Format */
    *(UINT*)(d + 20) = 1;            /* SampleCount */
    *(UINT*)(d + 28) = 0;            /* Usage = D3D11_USAGE_DEFAULT */
    *(UINT*)(d + 32) = 0x20;         /* BindFlags = D3D11_BIND_RENDER_TARGET */
}

static const ID3D11Texture2DVtbl g_tx_vtbl = {
    tx_QueryInterface,
    tx_AddRef,
    tx_Release,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    tx_GetType,
    (void (*)(ID3D11Texture2DImpl*, UINT))DX_VSTUB,
    tx_GetEvictionPriority,
    tx_GetDesc,
};

static ID3D11Texture2DImpl* tex_wrap(DxBackBuffer* bb, BOOL owns)
{
    ID3D11Texture2DImpl* t = (ID3D11Texture2DImpl*)dx_heap_alloc(sizeof(*t));
    if (!t)
        return NULL;
    dx_memzero(t, sizeof(*t));
    t->lpVtbl = &g_tx_vtbl;
    t->refcount = 1;
    t->bb = bb;
    t->owns_bb = owns;
    t->format = 87; /* DXGI_FORMAT_B8G8R8A8_UNORM */
    return t;
}

/* ---------------------------------------------------------------- *
 * ID3D11RenderTargetView                                           *
 * Vtable: IUnknown(3) + DeviceChild(1) + View(1=GetResource) + RTV(1=GetDesc) */
/* ---------------------------------------------------------------- */

typedef struct ID3D11RTVImpl
{
    const ID3D11RTVVtbl* lpVtbl;
    ULONG refcount;
    ID3D11Texture2DImpl* tex;
} ID3D11RTVImpl;

struct ID3D11RTVVtbl
{
    HRESULT (*QueryInterface)(ID3D11RTVImpl*, REFIID, void**);
    ULONG (*AddRef)(ID3D11RTVImpl*);
    ULONG (*Release)(ID3D11RTVImpl*);
    void* GetDevice;
    void* GetPrivateData;
    void* SetPrivateData;
    void* SetPrivateDataInterface;
    void (*GetResource)(ID3D11RTVImpl*, void** out);
    void (*GetDesc)(ID3D11RTVImpl*, void* desc);
};

static HRESULT rtv_QueryInterface(ID3D11RTVImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D11View) ||
        dx_guid_eq(riid, &kIID_ID3D11RenderTargetView))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG rtv_AddRef(ID3D11RTVImpl* self)
{
    return ++self->refcount;
}
static ULONG rtv_Release(ID3D11RTVImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->tex)
            tx_Release(self->tex);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static void rtv_GetResource(ID3D11RTVImpl* self, void** out)
{
    if (!out)
        return;
    if (self->tex)
        tx_AddRef(self->tex);
    *out = self->tex;
}
static void rtv_GetDesc(ID3D11RTVImpl* self, void* desc)
{
    if (!desc)
        return;
    /* D3D11_RENDER_TARGET_VIEW_DESC = 24 bytes; first 8 bytes are
     * Format + ViewDimension. */
    dx_memzero(desc, 24);
    *(UINT*)((BYTE*)desc + 0) = self->tex ? self->tex->format : 87;
    *(UINT*)((BYTE*)desc + 4) = 4; /* D3D11_RTV_DIMENSION_TEXTURE2D */
}

static const ID3D11RTVVtbl g_rtv_vtbl = {
    rtv_QueryInterface, rtv_AddRef, rtv_Release, DX_HSTUB, DX_HSTUB, DX_HSTUB, DX_HSTUB, rtv_GetResource, rtv_GetDesc,
};

static ID3D11RTVImpl* rtv_alloc(ID3D11Texture2DImpl* tex)
{
    ID3D11RTVImpl* r = (ID3D11RTVImpl*)dx_heap_alloc(sizeof(*r));
    if (!r)
        return NULL;
    dx_memzero(r, sizeof(*r));
    r->lpVtbl = &g_rtv_vtbl;
    r->refcount = 1;
    r->tex = tex;
    if (tex)
        tx_AddRef(tex);
    return r;
}

/* ---------------------------------------------------------------- *
 * IDXGISwapChain (D3D11-internal copy — same vtable layout as the *
 * one in dxgi.dll). Owns a DxBackBuffer and an ID3D11Texture2D    *
 * wrapping it; GetBuffer hands the texture back to the caller.    *
 * ---------------------------------------------------------------- */

typedef struct D3D11SwapChainImpl
{
    const D3D11SwapChainVtbl* lpVtbl;
    ULONG refcount;
    DxBackBuffer* bb;          /* owned */
    ID3D11Texture2DImpl* back; /* lazily created on first GetBuffer */
} D3D11SwapChainImpl;

struct D3D11SwapChainVtbl
{
    HRESULT (*QueryInterface)(D3D11SwapChainImpl*, REFIID, void**);
    ULONG (*AddRef)(D3D11SwapChainImpl*);
    ULONG (*Release)(D3D11SwapChainImpl*);
    void* SetPrivateData;
    void* SetPrivateDataInterface;
    void* GetPrivateData;
    void* GetParent;
    void* GetDevice;
    HRESULT (*Present)(D3D11SwapChainImpl*, UINT sync, UINT flags);
    HRESULT (*GetBuffer)(D3D11SwapChainImpl*, UINT idx, REFIID riid, void** out);
    HRESULT (*SetFullscreenState)(D3D11SwapChainImpl*, BOOL, void*);
    HRESULT (*GetFullscreenState)(D3D11SwapChainImpl*, BOOL*, void**);
    HRESULT (*GetDesc)(D3D11SwapChainImpl*, void* desc);
    HRESULT (*ResizeBuffers)(D3D11SwapChainImpl*, UINT, UINT, UINT, DWORD, UINT);
    HRESULT (*ResizeTarget)(D3D11SwapChainImpl*, const void*);
    HRESULT (*GetContainingOutput)(D3D11SwapChainImpl*, void**);
    HRESULT (*GetFrameStatistics)(D3D11SwapChainImpl*, void*);
    HRESULT (*GetLastPresentCount)(D3D11SwapChainImpl*, UINT*);
};

static HRESULT d3d11sc_QueryInterface(D3D11SwapChainImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDXGISwapChain) ||
        dx_guid_eq(riid, &kIID_IDXGISwapChain1))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG d3d11sc_AddRef(D3D11SwapChainImpl* self)
{
    return ++self->refcount;
}
static ULONG d3d11sc_Release(D3D11SwapChainImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->back)
            tx_Release(self->back);
        else if (self->bb)
            dx_bb_destroy(self->bb);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT d3d11sc_Present(D3D11SwapChainImpl* self, UINT sync, UINT flags)
{
    (void)sync;
    (void)flags;
    if (!self || !self->bb)
        return DX_E_FAIL;
    dx_gfx_trace(1);
    dx_bb_present(self->bb);
    return DX_S_OK;
}
static HRESULT d3d11sc_GetBuffer(D3D11SwapChainImpl* self, UINT idx, REFIID riid, void** out)
{
    (void)idx;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    if (!self->back)
    {
        self->back = tex_wrap(self->bb, /*owns_bb=*/1);
        if (!self->back)
        {
            *out = NULL;
            return DX_E_OUTOFMEMORY;
        }
    }
    tx_AddRef(self->back);
    *out = self->back;
    return DX_S_OK;
}
static HRESULT d3d11sc_GetDesc(D3D11SwapChainImpl* self, void* desc)
{
    (void)self;
    if (desc)
        dx_memzero(desc, 120);
    return DX_S_OK;
}
static HRESULT d3d11sc_ResizeBuffers(D3D11SwapChainImpl* self, UINT bufs, UINT w, UINT h, DWORD fmt, UINT flags)
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
    /* If a back-buffer texture has been handed out, the caller may
     * still hold refs; tell them to release first. */
    if (self->back)
        return DXGI_ERROR_INVALID_CALL;
    dx_bb_destroy(self->bb);
    self->bb = dx_bb_create(hwnd, w, h);
    return self->bb ? DX_S_OK : DX_E_OUTOFMEMORY;
}

static const D3D11SwapChainVtbl g_d3d11sc_vtbl = {
    d3d11sc_QueryInterface,
    d3d11sc_AddRef,
    d3d11sc_Release,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    DX_HSTUB,
    d3d11sc_Present,
    d3d11sc_GetBuffer,
    (HRESULT(*)(D3D11SwapChainImpl*, BOOL, void*))DX_HSTUB,
    (HRESULT(*)(D3D11SwapChainImpl*, BOOL*, void**))DX_HSTUB,
    d3d11sc_GetDesc,
    d3d11sc_ResizeBuffers,
    (HRESULT(*)(D3D11SwapChainImpl*, const void*))DX_HSTUB,
    (HRESULT(*)(D3D11SwapChainImpl*, void**))DX_HSTUB,
    (HRESULT(*)(D3D11SwapChainImpl*, void*))DX_HSTUB,
    (HRESULT(*)(D3D11SwapChainImpl*, UINT*))DX_HSTUB,
};

static D3D11SwapChainImpl* d3d11_swap_alloc(HWND hwnd, UINT w, UINT h)
{
    D3D11SwapChainImpl* s = (D3D11SwapChainImpl*)dx_heap_alloc(sizeof(*s));
    if (!s)
        return NULL;
    dx_memzero(s, sizeof(*s));
    s->lpVtbl = &g_d3d11sc_vtbl;
    s->refcount = 1;
    s->bb = dx_bb_create(hwnd, w ? w : 640, h ? h : 480);
    if (!s->bb)
    {
        dx_heap_free(s);
        return NULL;
    }
    return s;
}

/* ---------------------------------------------------------------- *
 * ID3D11DeviceContext                                              *
 *                                                                  *
 * Vtable layout: IUnknown(3) + DeviceChild(GetDevice,GetPrivate*)  *
 * + DeviceContext(108 methods). We implement enough that a clear  *
 * + present pipeline works:                                        *
 *   slot 50: ClearRenderTargetView                                 *
 *   slot 33: OMSetRenderTargets                                    *
 *   slot 44: RSSetViewports                                        *
 *   slot 51: ClearDepthStencilView (no-op success)                 *
 *   slot 110: Flush                                                *
 * Other slots → DX_HSTUB / DX_VSTUB.                                *
 * ---------------------------------------------------------------- */

#define CTX_VTBL_SLOTS 144 /* matches ID3D11DeviceContext1 size */

struct ID3D11ContextImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    ID3D11RTVImpl* current_rtv;
};

static HRESULT ctx_QueryInterface(ID3D11ContextImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D11DeviceContext))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG ctx_AddRef(ID3D11ContextImpl* self)
{
    return ++self->refcount;
}
static ULONG ctx_Release(ID3D11ContextImpl* self)
{
    if (self->refcount == 0)
        return 0;
    if (--self->refcount == 0)
    {
        if (self->current_rtv)
            rtv_Release(self->current_rtv);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

/* ClearRenderTargetView(rtv, const float color[4]) — slot index
 * matches ID3D11DeviceContext::ClearRenderTargetView at vtbl[50]. */
static void ctx_ClearRenderTargetView(ID3D11ContextImpl* self, ID3D11RTVImpl* rtv, const float color[4])
{
    (void)self;
    if (!rtv || !rtv->tex || !rtv->tex->bb || !color)
        return;
    dx_bb_clear_rgba(rtv->tex->bb, color[0], color[1], color[2], color[3]);
}

/* OMSetRenderTargets(numRTVs, ppRTV, pDSV) — slot 33. */
static void ctx_OMSetRenderTargets(ID3D11ContextImpl* self, UINT n, ID3D11RTVImpl* const* rtvs, void* dsv)
{
    (void)dsv;
    if (self->current_rtv)
    {
        rtv_Release(self->current_rtv);
        self->current_rtv = NULL;
    }
    if (n > 0 && rtvs && rtvs[0])
    {
        self->current_rtv = rtvs[0];
        rtv_AddRef(rtvs[0]);
    }
}

/* RSSetViewports(num, viewports) — slot 44. v0 stores nothing. */
static void ctx_RSSetViewports(ID3D11ContextImpl* self, UINT n, const void* vp)
{
    (void)self;
    (void)n;
    (void)vp;
}

/* Flush — slot 110. Software path: nothing to flush. */
static void ctx_Flush(ID3D11ContextImpl* self)
{
    (void)self;
}

/* GetType — slot 113: returns D3D11_DEVICE_CONTEXT_IMMEDIATE = 0. */
static UINT ctx_GetType(ID3D11ContextImpl* self)
{
    (void)self;
    return 0;
}

/* The MS x64 ABI lets us put the same `dx_stub_hresult` /
 * `dx_stub_void` pointer in any vtable slot since unused args are
 * just left in r8/r9/stack. We build the table with explicit
 * indices so the few slots we override land in the right place. */
static void* g_ctx_vtbl[CTX_VTBL_SLOTS];

static void ctx_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    /* Default: every slot returns E_NOTIMPL or void. ID3D11Device-
     * Context has a mix of return types; the HRESULT stub is the
     * safe default since callers handle E_NOTIMPL gracefully and
     * void-returning callers ignore rax. */
    for (int i = 0; i < CTX_VTBL_SLOTS; ++i)
        g_ctx_vtbl[i] = DX_VSTUB;
    g_ctx_vtbl[0] = (void*)ctx_QueryInterface;
    g_ctx_vtbl[1] = (void*)ctx_AddRef;
    g_ctx_vtbl[2] = (void*)ctx_Release;
    g_ctx_vtbl[33] = (void*)ctx_OMSetRenderTargets;
    g_ctx_vtbl[44] = (void*)ctx_RSSetViewports;
    g_ctx_vtbl[50] = (void*)ctx_ClearRenderTargetView;
    /* Flush */
    g_ctx_vtbl[110] = (void*)ctx_Flush;
    /* GetType */
    g_ctx_vtbl[113] = (void*)ctx_GetType;
}

static ID3D11ContextImpl* ctx_alloc(void)
{
    ctx_init_vtbl_once();
    ID3D11ContextImpl* c = (ID3D11ContextImpl*)dx_heap_alloc(sizeof(*c));
    if (!c)
        return NULL;
    dx_memzero(c, sizeof(*c));
    c->lpVtbl = g_ctx_vtbl;
    c->refcount = 1;
    return c;
}

/* ---------------------------------------------------------------- *
 * ID3D11Device                                                     *
 *                                                                  *
 * 43-method vtable. We implement:                                  *
 *   3   CreateBuffer                                               *
 *   5   CreateTexture2D                                            *
 *   9   CreateRenderTargetView                                     *
 *   29  CheckFormatSupport                                         *
 *   30  CheckMultisampleQualityLevels                              *
 *   33  CheckFeatureSupport                                        *
 *   37  GetFeatureLevel                                            *
 *   40  GetImmediateContext                                        *
 * Everything else returns E_NOTIMPL/0.                             *
 * ---------------------------------------------------------------- */

#define DEV_VTBL_SLOTS 43

struct ID3D11DeviceImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    ID3D11ContextImpl* immediate;
    UINT feature_level;
};

static HRESULT dev_QueryInterface(ID3D11DeviceImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D11Device))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG dev_AddRef(ID3D11DeviceImpl* self)
{
    return ++self->refcount;
}
static ULONG dev_Release(ID3D11DeviceImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->immediate)
            ctx_Release(self->immediate);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

/* CreateBuffer(desc, initial, ppBuffer) — slot 3. */
static HRESULT dev_CreateBuffer(ID3D11DeviceImpl* self, const void* desc, const void* init, void** out)
{
    (void)self;
    (void)init;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (!desc)
        return DX_E_INVALIDARG;
    /* D3D11_BUFFER_DESC: ByteWidth(0), Usage(4), BindFlags(8), ... */
    UINT bytes = *(const UINT*)desc;
    if (bytes == 0)
        return DX_E_INVALIDARG;
    /* Allocate a "buffer" object: refcount + size + payload. We use
     * the texture vtable as a generic resource container — the GUID
     * comparison gates make sure nothing tries to cast it to a tex2d. */
    BYTE* mem = (BYTE*)dx_heap_alloc(sizeof(ULONG) + sizeof(UINT) + bytes);
    if (!mem)
        return DX_E_OUTOFMEMORY;
    dx_memzero(mem, sizeof(ULONG) + sizeof(UINT));
    *(ULONG*)mem = 1;
    *(UINT*)(mem + sizeof(ULONG)) = bytes;
    *out = mem;
    return DX_S_OK;
}

/* CreateTexture2D(desc, initial, ppTexture) — slot 5. */
static HRESULT dev_CreateTexture2D(ID3D11DeviceImpl* self, const void* desc, const void* init, void** out)
{
    (void)self;
    (void)init;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (!desc)
        return DX_E_INVALIDARG;
    const BYTE* d = (const BYTE*)desc;
    UINT w = *(const UINT*)(d + 0);
    UINT h = *(const UINT*)(d + 4);
    DxBackBuffer* bb = dx_bb_create(NULL, w, h);
    if (!bb)
        return DX_E_OUTOFMEMORY;
    ID3D11Texture2DImpl* t = tex_wrap(bb, /*owns_bb=*/1);
    if (!t)
    {
        dx_bb_destroy(bb);
        return DX_E_OUTOFMEMORY;
    }
    *out = t;
    return DX_S_OK;
}

/* CreateRenderTargetView(resource, desc, ppRTV) — slot 9. */
static HRESULT dev_CreateRenderTargetView(ID3D11DeviceImpl* self, void* resource, const void* desc, void** out)
{
    (void)self;
    (void)desc;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (!resource)
        return DX_E_INVALIDARG;
    ID3D11Texture2DImpl* t = (ID3D11Texture2DImpl*)resource;
    /* Verify it's our texture vtable — defensive check. */
    if (t->lpVtbl != &g_tx_vtbl)
        return DX_E_INVALIDARG;
    ID3D11RTVImpl* r = rtv_alloc(t);
    if (!r)
        return DX_E_OUTOFMEMORY;
    *out = r;
    return DX_S_OK;
}

/* CheckFormatSupport — slot 29. Claim B8G8R8A8_UNORM works, others
 * fail. Format count constant in v0. */
static HRESULT dev_CheckFormatSupport(ID3D11DeviceImpl* self, UINT format, UINT* supp)
{
    (void)self;
    if (!supp)
        return DX_E_POINTER;
    if (format == 87 || format == 28) /* BGRA8 / RGBA8 */
    {
        *supp = 0x1 | 0x2 | 0x20; /* TEXTURE2D | RENDER_TARGET | BUFFER */
        return DX_S_OK;
    }
    *supp = 0;
    return DX_S_OK;
}

/* CheckMultisampleQualityLevels — slot 30. Count = 1, level = 0. */
static HRESULT dev_CheckMultisampleQualityLevels(ID3D11DeviceImpl* self, UINT fmt, UINT samples, UINT* levels)
{
    (void)self;
    (void)fmt;
    if (!levels)
        return DX_E_POINTER;
    *levels = (samples == 1) ? 1 : 0;
    return DX_S_OK;
}

/* CheckFeatureSupport — slot 33. Zero-fill the output and succeed
 * for any small request; many games gate features on what's
 * returned. */
static HRESULT dev_CheckFeatureSupport(ID3D11DeviceImpl* self, UINT feat, void* out, UINT n)
{
    (void)self;
    (void)feat;
    if (out && n > 0 && n < 4096)
        dx_memzero(out, n);
    return DX_S_OK;
}

/* GetFeatureLevel — slot 37. D3D_FEATURE_LEVEL_11_0 = 0xb000. */
static UINT dev_GetFeatureLevel(ID3D11DeviceImpl* self)
{
    return self ? self->feature_level : 0xb000;
}

/* GetImmediateContext — slot 40. Hands out the device's immediate
 * context, AddRef'd. */
static void dev_GetImmediateContext(ID3D11DeviceImpl* self, ID3D11ContextImpl** out)
{
    if (!out)
        return;
    if (self->immediate)
        ctx_AddRef(self->immediate);
    *out = self->immediate;
}

static void* g_dev_vtbl[DEV_VTBL_SLOTS];
static void dev_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DEV_VTBL_SLOTS; ++i)
        g_dev_vtbl[i] = DX_HSTUB;
    g_dev_vtbl[0] = (void*)dev_QueryInterface;
    g_dev_vtbl[1] = (void*)dev_AddRef;
    g_dev_vtbl[2] = (void*)dev_Release;
    g_dev_vtbl[3] = (void*)dev_CreateBuffer;
    g_dev_vtbl[5] = (void*)dev_CreateTexture2D;
    g_dev_vtbl[9] = (void*)dev_CreateRenderTargetView;
    g_dev_vtbl[29] = (void*)dev_CheckFormatSupport;
    g_dev_vtbl[30] = (void*)dev_CheckMultisampleQualityLevels;
    g_dev_vtbl[33] = (void*)dev_CheckFeatureSupport;
    g_dev_vtbl[37] = (void*)dev_GetFeatureLevel;
    g_dev_vtbl[40] = (void*)dev_GetImmediateContext;
}

static ID3D11DeviceImpl* dev_alloc(void)
{
    dev_init_vtbl_once();
    ID3D11DeviceImpl* d = (ID3D11DeviceImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return NULL;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_dev_vtbl;
    d->refcount = 1;
    d->feature_level = 0xb000;
    d->immediate = ctx_alloc();
    if (!d->immediate)
    {
        dx_heap_free(d);
        return NULL;
    }
    return d;
}

/* ---------------------------------------------------------------- *
 * Exported entry points                                            *
 * ---------------------------------------------------------------- */

__declspec(dllexport) HRESULT D3D11CreateDevice(void* adapter, INT driver_type, void* software, UINT flags,
                                                const void* feature_levels, UINT num_feature_levels, UINT sdk,
                                                void** device, UINT* obtained_fl, void** ctx)
{
    (void)adapter;
    (void)driver_type;
    (void)software;
    (void)flags;
    (void)feature_levels;
    (void)num_feature_levels;
    (void)sdk;
    dx_gfx_trace(1);
    ID3D11DeviceImpl* d = dev_alloc();
    if (!d)
    {
        if (device)
            *device = NULL;
        if (ctx)
            *ctx = NULL;
        return DX_E_OUTOFMEMORY;
    }
    if (device)
        *device = d;
    else
        dev_Release(d);
    if (obtained_fl)
        *obtained_fl = 0xb000;
    if (ctx)
    {
        if (d->immediate)
            ctx_AddRef(d->immediate);
        *ctx = d->immediate;
    }
    return DX_S_OK;
}

/* DXGI_SWAP_CHAIN_DESC offsets (see dxgi.c:fac_CreateSwapChain). */
__declspec(dllexport) HRESULT D3D11CreateDeviceAndSwapChain(void* adapter, INT driver_type, void* software, UINT flags,
                                                            const void* feature_levels, UINT num_feature_levels,
                                                            UINT sdk, const void* desc, void** swap_out,
                                                            void** device_out, UINT* obtained_fl, void** ctx_out)
{
    HRESULT hr = D3D11CreateDevice(adapter, driver_type, software, flags, feature_levels, num_feature_levels, sdk,
                                   device_out, obtained_fl, ctx_out);
    if (hr != DX_S_OK)
    {
        if (swap_out)
            *swap_out = NULL;
        return hr;
    }
    UINT w = 0, h = 0;
    HWND hwnd = NULL;
    if (desc)
    {
        const BYTE* d = (const BYTE*)desc;
        w = *(const UINT*)(d + 0);
        h = *(const UINT*)(d + 4);
        hwnd = *(const HWND*)(d + 48);
    }
    D3D11SwapChainImpl* sc = d3d11_swap_alloc(hwnd, w, h);
    if (!sc)
    {
        /* tear down what we created */
        if (device_out && *device_out)
        {
            dev_Release((ID3D11DeviceImpl*)*device_out);
            *device_out = NULL;
        }
        if (ctx_out && *ctx_out)
        {
            ctx_Release((ID3D11ContextImpl*)*ctx_out);
            *ctx_out = NULL;
        }
        if (swap_out)
            *swap_out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    if (swap_out)
        *swap_out = sc;
    else
        d3d11sc_Release(sc);
    return DX_S_OK;
}
