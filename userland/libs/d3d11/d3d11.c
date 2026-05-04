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
#include "../dx_raster.h"

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
 * ID3D11Buffer — vertex / index / constant buffer with backing     *
 * storage. The buffer's bytes live immediately after the COM head  *
 * so a single dx_heap_alloc owns both. CreateBuffer's optional     *
 * initial-data pointer (D3D11_SUBRESOURCE_DATA->pSysMem) is copied *
 * in at construction; UpdateSubresource paths write into the same  *
 * backing memory. Vtable layout:                                   *
 *   IUnknown(3) + ID3D11DeviceChild(4=GetDevice + 3 priv-data) +   *
 *   ID3D11Resource(3) + ID3D11Buffer(1=GetDesc). 12 slots.         *
 * ---------------------------------------------------------------- */

#define BUF_VTBL_SLOTS 12

static const DxGuid kIID_ID3D11Buffer = {0x48570b85, 0xd1ee, 0x4fcd, {0xa2, 0x50, 0xeb, 0x35, 0x07, 0x22, 0xb0, 0x37}};

typedef struct ID3D11BufferImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT bytes;
    UINT bind_flags;
    UINT cpu_access;
    BYTE storage[1]; /* `bytes` of payload follow the struct head */
} ID3D11BufferImpl;

static void* g_buf_vtbl[BUF_VTBL_SLOTS];

static HRESULT buf_QueryInterface(ID3D11BufferImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D11Resource) ||
        dx_guid_eq(riid, &kIID_ID3D11Buffer))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG buf_AddRef(ID3D11BufferImpl* self)
{
    return ++self->refcount;
}
static ULONG buf_Release(ID3D11BufferImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static void buf_GetType(ID3D11BufferImpl* self, UINT* type)
{
    (void)self;
    if (type)
        *type = 1; /* D3D11_RESOURCE_DIMENSION_BUFFER */
}
/* D3D11_BUFFER_DESC: ByteWidth(0), Usage(4), BindFlags(8),
 * CPUAccessFlags(12), MiscFlags(16), StructureByteStride(20). */
static void buf_GetDesc(ID3D11BufferImpl* self, void* desc)
{
    if (!desc)
        return;
    BYTE* d = (BYTE*)desc;
    dx_memzero(d, 24);
    *(UINT*)(d + 0) = self->bytes;
    *(UINT*)(d + 8) = self->bind_flags;
    *(UINT*)(d + 12) = self->cpu_access;
}

static void buf_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < BUF_VTBL_SLOTS; ++i)
        g_buf_vtbl[i] = DX_HSTUB;
    g_buf_vtbl[0] = (void*)buf_QueryInterface;
    g_buf_vtbl[1] = (void*)buf_AddRef;
    g_buf_vtbl[2] = (void*)buf_Release;
    g_buf_vtbl[7] = (void*)buf_GetType; /* ID3D11Resource::GetType */
    g_buf_vtbl[10] = (void*)DX_VSTUB;   /* SetEvictionPriority */
    g_buf_vtbl[11] = (void*)buf_GetDesc;
}

static ID3D11BufferImpl* buf_alloc(UINT bytes, UINT bind_flags, UINT cpu_access, const void* initial)
{
    buf_init_vtbl_once();
    if (bytes == 0)
        return NULL;
    ID3D11BufferImpl* b = (ID3D11BufferImpl*)dx_heap_alloc(sizeof(ID3D11BufferImpl) + bytes);
    if (!b)
        return NULL;
    dx_memzero(b, sizeof(ID3D11BufferImpl));
    b->lpVtbl = g_buf_vtbl;
    b->refcount = 1;
    b->bytes = bytes;
    b->bind_flags = bind_flags;
    b->cpu_access = cpu_access;
    if (initial)
        dx_memcpy(b->storage, initial, bytes);
    return b;
}

/* ---------------------------------------------------------------- *
 * ID3D11InputLayout — element descriptor table. Each element is    *
 * (semanticName, semanticIndex, format, inputSlot, alignedByteOff, *
 * inputSlotClass, instanceDataStepRate). v0 keeps just the offsets *
 * + format kind we need to decode positions and colours from a     *
 * vertex buffer:                                                   *
 *   - position_offset (0xFFFF = none)                              *
 *   - color_offset    (0xFFFF = none)                              *
 *   - color_kind      (0 = R32G32B32A32_FLOAT, 1 = B8G8R8A8_UNORM, *
 *                      2 = R8G8B8A8_UNORM)                         *
 * Stride is stored on the buffer side via IASetVertexBuffers.      *
 * ---------------------------------------------------------------- */

#define IL_VTBL_SLOTS 7

static const DxGuid kIID_ID3D11InputLayout = {
    0xe4819ddc, 0x4cf0, 0x4025, {0xbd, 0x26, 0x5d, 0xe8, 0x2a, 0x3e, 0x07, 0xb7}};

typedef struct ID3D11InputLayoutImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT position_offset;
    UINT color_offset;
    UINT color_kind;
} ID3D11InputLayoutImpl;

static void* g_il_vtbl[IL_VTBL_SLOTS];

static HRESULT il_QueryInterface(ID3D11InputLayoutImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D11InputLayout))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG il_AddRef(ID3D11InputLayoutImpl* self)
{
    return ++self->refcount;
}
static ULONG il_Release(ID3D11InputLayoutImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static void il_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < IL_VTBL_SLOTS; ++i)
        g_il_vtbl[i] = DX_HSTUB;
    g_il_vtbl[0] = (void*)il_QueryInterface;
    g_il_vtbl[1] = (void*)il_AddRef;
    g_il_vtbl[2] = (void*)il_Release;
}

/* Compare the SemanticName field (an ASCIIZ pointer in the
 * D3D11_INPUT_ELEMENT_DESC) without pulling in <string.h>. */
static int il_name_eq(const char* a, const char* b)
{
    if (!a || !b)
        return 0;
    while (*a && *b)
    {
        char ca = *a++, cb = *b++;
        if (ca >= 'a' && ca <= 'z')
            ca = (char)(ca - 32);
        if (cb >= 'a' && cb <= 'z')
            cb = (char)(cb - 32);
        if (ca != cb)
            return 0;
    }
    return *a == *b;
}

/* D3D11_INPUT_ELEMENT_DESC layout (32 bytes on x86_64):
 *   const char* SemanticName        (8)
 *   UINT SemanticIndex              (4)
 *   DXGI_FORMAT Format              (4)
 *   UINT InputSlot                  (4)
 *   UINT AlignedByteOffset          (4)
 *   D3D11_INPUT_CLASSIFICATION Cls  (4)
 *   UINT InstanceDataStepRate       (4) — pads to 32 with align(8). */
static ID3D11InputLayoutImpl* il_alloc_from_desc(const void* descs, UINT n)
{
    il_init_vtbl_once();
    ID3D11InputLayoutImpl* il = (ID3D11InputLayoutImpl*)dx_heap_alloc(sizeof(*il));
    if (!il)
        return NULL;
    dx_memzero(il, sizeof(*il));
    il->lpVtbl = g_il_vtbl;
    il->refcount = 1;
    il->position_offset = 0xFFFF;
    il->color_offset = 0xFFFF;
    il->color_kind = 0;
    if (descs)
    {
        const BYTE* p = (const BYTE*)descs;
        for (UINT i = 0; i < n; ++i)
        {
            const BYTE* e = p + (SIZE_T)i * 32;
            const char* name = *(const char* const*)(e + 0);
            UINT format = *(const UINT*)(e + 12);
            UINT offset = *(const UINT*)(e + 20);
            if (il_name_eq(name, "POSITION") || il_name_eq(name, "SV_POSITION"))
                il->position_offset = offset;
            else if (il_name_eq(name, "COLOR") || il_name_eq(name, "COLOUR"))
            {
                il->color_offset = offset;
                /* DXGI_FORMAT: 2 = R32G32B32A32_FLOAT, 28 = R8G8B8A8_UNORM,
                 * 87 = B8G8R8A8_UNORM. */
                if (format == 2)
                    il->color_kind = 0;
                else if (format == 87)
                    il->color_kind = 1;
                else
                    il->color_kind = 2;
            }
        }
    }
    return il;
}

/* ---------------------------------------------------------------- *
 * ID3D11VertexShader / ID3D11PixelShader — opaque shader handles.  *
 * v0 doesn't compile or run HLSL; we keep a single tag value so    *
 * callers can swap shaders and the bound shader pointer flows      *
 * through to Draw* (where it's currently ignored). 7 slot vtable.  *
 * ---------------------------------------------------------------- */

#define SHADER_VTBL_SLOTS 7

static const DxGuid kIID_ID3D11VertexShader = {
    0x3b301d64, 0xd678, 0x4289, {0x88, 0x97, 0x22, 0xf8, 0x92, 0x8b, 0x72, 0xf3}};
static const DxGuid kIID_ID3D11PixelShader = {
    0xea82e40d, 0x51dc, 0x4f33, {0x93, 0xd4, 0xdb, 0x7c, 0x91, 0x25, 0xae, 0x8c}};

typedef struct ID3D11ShaderImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT kind; /* 0 = VS, 1 = PS */
} ID3D11ShaderImpl;

static void* g_vs_vtbl[SHADER_VTBL_SLOTS];
static void* g_ps_vtbl[SHADER_VTBL_SLOTS];

static HRESULT shader_QueryInterface(ID3D11ShaderImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || (self->kind == 0 && dx_guid_eq(riid, &kIID_ID3D11VertexShader)) ||
        (self->kind == 1 && dx_guid_eq(riid, &kIID_ID3D11PixelShader)))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG shader_AddRef(ID3D11ShaderImpl* self)
{
    return ++self->refcount;
}
static ULONG shader_Release(ID3D11ShaderImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static void shader_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < SHADER_VTBL_SLOTS; ++i)
    {
        g_vs_vtbl[i] = DX_HSTUB;
        g_ps_vtbl[i] = DX_HSTUB;
    }
    g_vs_vtbl[0] = (void*)shader_QueryInterface;
    g_vs_vtbl[1] = (void*)shader_AddRef;
    g_vs_vtbl[2] = (void*)shader_Release;
    g_ps_vtbl[0] = (void*)shader_QueryInterface;
    g_ps_vtbl[1] = (void*)shader_AddRef;
    g_ps_vtbl[2] = (void*)shader_Release;
}

static ID3D11ShaderImpl* shader_alloc(UINT kind)
{
    shader_init_vtbl_once();
    ID3D11ShaderImpl* s = (ID3D11ShaderImpl*)dx_heap_alloc(sizeof(*s));
    if (!s)
        return NULL;
    dx_memzero(s, sizeof(*s));
    s->lpVtbl = (kind == 0) ? g_vs_vtbl : g_ps_vtbl;
    s->refcount = 1;
    s->kind = kind;
    return s;
}

/* ---------------------------------------------------------------- *
 * Pipeline state objects — RasterizerState / BlendState /          *
 * DepthStencilState / SamplerState. Opaque handles with refcounts; *
 * v0 stores no state since none of it changes the pure-software    *
 * raster path's behaviour. The COM shape is required so callers    *
 * can RSSetState(rs); rs->Release() without crashing.              *
 * ---------------------------------------------------------------- */

#define D11_STATE_VTBL_SLOTS 7

static const DxGuid kIID_ID3D11RasterizerState = {
    0x9bb4ab81, 0xab1a, 0x4d8f, {0xb5, 0x06, 0xfc, 0x04, 0x20, 0x0b, 0x6e, 0xe7}};
static const DxGuid kIID_ID3D11BlendState = {
    0x75b68faa, 0x347d, 0x4159, {0x8f, 0x45, 0xa0, 0x64, 0x0f, 0x01, 0xcd, 0x9a}};
static const DxGuid kIID_ID3D11DepthStencilState = {
    0x03823efb, 0x8d8f, 0x4e1c, {0x9a, 0xa2, 0xf6, 0x4b, 0xb2, 0xcb, 0xfd, 0xf1}};
static const DxGuid kIID_ID3D11SamplerState = {
    0xda6fea51, 0x564c, 0x4487, {0x98, 0x10, 0xf0, 0xd0, 0xf9, 0xb4, 0xe3, 0xa5}};

typedef struct ID3D11StateImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT kind; /* 0 = RS, 1 = BS, 2 = DSS, 3 = SS */
} ID3D11StateImpl;

static void* g_state_vtbl[D11_STATE_VTBL_SLOTS];

static HRESULT state_QueryInterface(ID3D11StateImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || (self->kind == 0 && dx_guid_eq(riid, &kIID_ID3D11RasterizerState)) ||
        (self->kind == 1 && dx_guid_eq(riid, &kIID_ID3D11BlendState)) ||
        (self->kind == 2 && dx_guid_eq(riid, &kIID_ID3D11DepthStencilState)) ||
        (self->kind == 3 && dx_guid_eq(riid, &kIID_ID3D11SamplerState)))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG state_AddRef(ID3D11StateImpl* self)
{
    return ++self->refcount;
}
static ULONG state_Release(ID3D11StateImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static void state_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < D11_STATE_VTBL_SLOTS; ++i)
        g_state_vtbl[i] = DX_HSTUB;
    g_state_vtbl[0] = (void*)state_QueryInterface;
    g_state_vtbl[1] = (void*)state_AddRef;
    g_state_vtbl[2] = (void*)state_Release;
}

static ID3D11StateImpl* state_alloc(UINT kind)
{
    state_init_vtbl_once();
    ID3D11StateImpl* s = (ID3D11StateImpl*)dx_heap_alloc(sizeof(*s));
    if (!s)
        return NULL;
    dx_memzero(s, sizeof(*s));
    s->lpVtbl = g_state_vtbl;
    s->refcount = 1;
    s->kind = kind;
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
 *                                                                  *
 * v0.1 adds a minimal vertex-buffer / draw path:                   *
 *   slot  9: PSSetShader                                           *
 *   slot 11: VSSetShader                                           *
 *   slot 12: DrawIndexed                                           *
 *   slot 13: Draw                                                  *
 *   slot 14: Map / 15: Unmap (write-discard on a buffer)           *
 *   slot 17: IASetInputLayout                                      *
 *   slot 18: IASetVertexBuffers                                    *
 *   slot 19: IASetIndexBuffer                                      *
 *   slot 20: DrawIndexedInstanced                                  *
 *   slot 21: DrawInstanced                                         *
 *   slot 24: IASetPrimitiveTopology                                *
 *   slot 35: OMSetBlendState   (no-op success)                     *
 *   slot 36: OMSetDepthStencilState (no-op success)                *
 *   slot 43: RSSetState        (no-op success)                     *
 *   slot 45: RSSetScissorRects (no-op success)                     *
 *   slot 48: UpdateSubresource (write into an ID3D11Buffer)        *
 * Other slots → DX_HSTUB / DX_VSTUB.                                *
 * ---------------------------------------------------------------- */

#define CTX_VTBL_SLOTS 144 /* matches ID3D11DeviceContext1 size */

struct ID3D11ContextImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    ID3D11RTVImpl* current_rtv;

    /* Pipeline state — set by IASet* / VSSetShader / RSSetViewports
     * and consumed by Draw / DrawIndexed. Refcounts on bound objects
     * are NOT taken; the caller is required to keep the resource
     * alive for the duration of the draw. (Real D3D11 does the same;
     * the device-context binding is "weak.") */
    ID3D11InputLayoutImpl* current_il;
    ID3D11ShaderImpl* current_vs;
    ID3D11ShaderImpl* current_ps;
    ID3D11BufferImpl* current_vb; /* slot 0 only — multi-stream is gated below the v0 cut-line */
    UINT current_vb_stride;
    UINT current_vb_offset;
    ID3D11BufferImpl* current_ib;
    UINT current_ib_offset;
    UINT current_ib_format; /* DXGI_FORMAT_R16_UINT = 57, R32_UINT = 42 */
    UINT current_topology;  /* D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST = 4, STRIP = 5 */

    /* Viewport from RSSetViewports — used by the rasterizer to map
     * NDC to pixels. Default to a sentinel so the first Draw before
     * RSSetViewports falls back to the back-buffer extents. */
    int viewport_x, viewport_y, viewport_w, viewport_h;
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

/* RSSetViewports(num, viewports) — slot 44. D3D11_VIEWPORT layout
 * (24 B): TopLeftX(0,f32), TopLeftY(4,f32), Width(8,f32), Height
 * (12,f32), MinDepth(16,f32), MaxDepth(20,f32). */
static void ctx_RSSetViewports(ID3D11ContextImpl* self, UINT n, const void* vp)
{
    if (!self || n == 0 || !vp)
        return;
    const float* v = (const float*)vp;
    self->viewport_x = (int)v[0];
    self->viewport_y = (int)v[1];
    self->viewport_w = (int)v[2];
    self->viewport_h = (int)v[3];
}

/* IASetInputLayout(layout) — slot 17. */
static void ctx_IASetInputLayout(ID3D11ContextImpl* self, ID3D11InputLayoutImpl* il)
{
    if (!self)
        return;
    self->current_il = (il && il->lpVtbl == g_il_vtbl) ? il : NULL;
}

/* IASetVertexBuffers(startSlot, numBuffers, ppVB, pStrides, pOffsets) — slot 18.
 * v0 only honours slot 0 (single-stream). */
static void ctx_IASetVertexBuffers(ID3D11ContextImpl* self, UINT start_slot, UINT n, ID3D11BufferImpl* const* buffers,
                                   const UINT* strides, const UINT* offsets)
{
    (void)start_slot;
    if (!self || n == 0 || !buffers)
        return;
    ID3D11BufferImpl* b = buffers[0];
    self->current_vb = (b && b->lpVtbl == g_buf_vtbl) ? b : NULL;
    self->current_vb_stride = strides ? strides[0] : 0;
    self->current_vb_offset = offsets ? offsets[0] : 0;
}

/* IASetIndexBuffer(buffer, format, offset) — slot 19. */
static void ctx_IASetIndexBuffer(ID3D11ContextImpl* self, ID3D11BufferImpl* buffer, UINT format, UINT offset)
{
    if (!self)
        return;
    self->current_ib = (buffer && buffer->lpVtbl == g_buf_vtbl) ? buffer : NULL;
    self->current_ib_format = format;
    self->current_ib_offset = offset;
}

/* IASetPrimitiveTopology(topology) — slot 24. */
static void ctx_IASetPrimitiveTopology(ID3D11ContextImpl* self, UINT topology)
{
    if (self)
        self->current_topology = topology;
}

/* VSSetShader / PSSetShader — slots 11 / 9. The class-instance + count
 * params are ignored; D3D11 class-linkage isn't a v0 feature. */
static void ctx_VSSetShader(ID3D11ContextImpl* self, ID3D11ShaderImpl* shader, void* class_instances, UINT n)
{
    (void)class_instances;
    (void)n;
    if (!self)
        return;
    self->current_vs = (shader && shader->lpVtbl == g_vs_vtbl) ? shader : NULL;
}
static void ctx_PSSetShader(ID3D11ContextImpl* self, ID3D11ShaderImpl* shader, void* class_instances, UINT n)
{
    (void)class_instances;
    (void)n;
    if (!self)
        return;
    self->current_ps = (shader && shader->lpVtbl == g_ps_vtbl) ? shader : NULL;
}

/* Pull (x, y) screen-space from a vertex via the bound input layout +
 * VB. Returns 0 if the layout / buffer / offset can't satisfy the
 * read; caller drops the triangle. dxr_project handles the NDC →
 * pixel map. */
static int ctx_read_vertex(ID3D11ContextImpl* self, UINT idx, int* out_x, int* out_y, DWORD* out_color)
{
    if (!self || !self->current_vb || !self->current_il || self->current_vb_stride == 0)
        return 0;
    ID3D11BufferImpl* vb = self->current_vb;
    SIZE_T base = (SIZE_T)self->current_vb_offset + (SIZE_T)idx * self->current_vb_stride;
    if (self->current_il->position_offset == 0xFFFF)
        return 0;
    SIZE_T pos_off = base + self->current_il->position_offset;
    if (pos_off + 12 > vb->bytes)
        return 0;
    float xyz[3];
    dx_memcpy(xyz, vb->storage + pos_off, 12);
    DxVec4 clip;
    clip.x = xyz[0];
    clip.y = xyz[1];
    clip.z = xyz[2];
    clip.w = 1.0f;
    int vp_x = self->viewport_x, vp_y = self->viewport_y;
    int vp_w = self->viewport_w, vp_h = self->viewport_h;
    if (vp_w <= 0 || vp_h <= 0)
    {
        /* No viewport set — fall back to the back buffer's full
         * extent so a Clear-then-Draw smoke test still hits visible
         * pixels. */
        DxBackBuffer* bb = self->current_rtv && self->current_rtv->tex ? self->current_rtv->tex->bb : NULL;
        if (!bb)
            return 0;
        vp_x = 0;
        vp_y = 0;
        vp_w = (int)bb->width;
        vp_h = (int)bb->height;
    }
    if (!dxr_project(&clip, vp_x, vp_y, vp_w, vp_h, out_x, out_y))
        return 0;
    if (out_color)
    {
        if (self->current_il->color_offset != 0xFFFF)
        {
            SIZE_T col_off = base + self->current_il->color_offset;
            if (self->current_il->color_kind == 0 && col_off + 16 <= vb->bytes)
            {
                float c[4];
                dx_memcpy(c, vb->storage + col_off, 16);
                *out_color = dxr_pack_rgba(c[0], c[1], c[2], c[3]);
            }
            else if (col_off + 4 <= vb->bytes)
            {
                DWORD c;
                dx_memcpy(&c, vb->storage + col_off, 4);
                if (self->current_il->color_kind == 1)
                    *out_color = c; /* already BGRA */
                else
                {
                    /* RGBA8 → BGRA8 byte-swap. */
                    BYTE r = (BYTE)(c & 0xFF);
                    BYTE g = (BYTE)((c >> 8) & 0xFF);
                    BYTE b = (BYTE)((c >> 16) & 0xFF);
                    BYTE a = (BYTE)((c >> 24) & 0xFF);
                    *out_color = ((DWORD)a << 24) | ((DWORD)r << 16) | ((DWORD)g << 8) | (DWORD)b;
                }
            }
            else
            {
                *out_color = 0xFFFFFFFFu;
            }
        }
        else
        {
            *out_color = 0xFFFFFFFFu; /* white */
        }
    }
    return 1;
}

/* Walk the bound IB and translate idx → vertex index, honouring the
 * 16/32-bit format and the buffer offset. base_vertex is added on
 * after the index lookup. Returns 0 on out-of-range. */
static int ctx_read_index(ID3D11ContextImpl* self, UINT idx, INT base_vertex, UINT* out_vertex_index)
{
    if (!self || !self->current_ib)
        return 0;
    ID3D11BufferImpl* ib = self->current_ib;
    UINT stride = (self->current_ib_format == 42) ? 4 : 2; /* R32_UINT vs R16_UINT */
    SIZE_T off = (SIZE_T)self->current_ib_offset + (SIZE_T)idx * stride;
    if (off + stride > ib->bytes)
        return 0;
    UINT v;
    if (stride == 4)
    {
        dx_memcpy(&v, ib->storage + off, 4);
    }
    else
    {
        WORD vw;
        dx_memcpy(&vw, ib->storage + off, 2);
        v = vw;
    }
    long long vi = (long long)v + (long long)base_vertex;
    if (vi < 0)
        return 0;
    if (out_vertex_index)
        *out_vertex_index = (UINT)vi;
    return 1;
}

/* Rasterize a single triangle from three vertex indices. */
static void ctx_emit_tri(ID3D11ContextImpl* self, UINT i0, UINT i1, UINT i2)
{
    int x0, y0, x1, y1, x2, y2;
    DWORD c0, c1, c2;
    if (!ctx_read_vertex(self, i0, &x0, &y0, &c0))
        return;
    if (!ctx_read_vertex(self, i1, &x1, &y1, &c1))
        return;
    if (!ctx_read_vertex(self, i2, &x2, &y2, &c2))
        return;
    if (!self->current_rtv || !self->current_rtv->tex || !self->current_rtv->tex->bb)
        return;
    DxBackBuffer* bb = self->current_rtv->tex->bb;
    if (c0 == c1 && c1 == c2)
        dxr_fill_tri(bb, x0, y0, x1, y1, x2, y2, c0);
    else
        dxr_shade_tri(bb, x0, y0, x1, y1, x2, y2, c0, c1, c2);
}

/* Draw(VertexCount, StartVertexLocation) — slot 13. v0 supports
 * triangle list (topology 4) and triangle strip (topology 5). Other
 * topologies fall through to "draw nothing" — matches the contract
 * for "primitive class we haven't wired in." */
static void ctx_Draw(ID3D11ContextImpl* self, UINT count, UINT start)
{
    if (!self || count == 0)
        return;
    if (self->current_topology == 4)
    {
        UINT triangles = count / 3;
        for (UINT t = 0; t < triangles; ++t)
            ctx_emit_tri(self, start + t * 3, start + t * 3 + 1, start + t * 3 + 2);
    }
    else if (self->current_topology == 5)
    {
        /* triangle strip: alternating winding */
        if (count < 3)
            return;
        for (UINT t = 0; t + 2 < count; ++t)
        {
            UINT a = start + t, b = start + t + 1, c = start + t + 2;
            if (t & 1)
            {
                UINT tmp = b;
                b = c;
                c = tmp;
            }
            ctx_emit_tri(self, a, b, c);
        }
    }
}

/* DrawIndexed(IndexCount, StartIndexLocation, BaseVertexLocation) — slot 12. */
static void ctx_DrawIndexed(ID3D11ContextImpl* self, UINT count, UINT start, INT base_vertex)
{
    if (!self || count == 0)
        return;
    if (self->current_topology == 4)
    {
        UINT triangles = count / 3;
        for (UINT t = 0; t < triangles; ++t)
        {
            UINT a, b, c;
            if (!ctx_read_index(self, start + t * 3, base_vertex, &a))
                continue;
            if (!ctx_read_index(self, start + t * 3 + 1, base_vertex, &b))
                continue;
            if (!ctx_read_index(self, start + t * 3 + 2, base_vertex, &c))
                continue;
            ctx_emit_tri(self, a, b, c);
        }
    }
    else if (self->current_topology == 5)
    {
        if (count < 3)
            return;
        for (UINT t = 0; t + 2 < count; ++t)
        {
            UINT a, b, c;
            if (!ctx_read_index(self, start + t, base_vertex, &a))
                continue;
            if (!ctx_read_index(self, start + t + 1, base_vertex, &b))
                continue;
            if (!ctx_read_index(self, start + t + 2, base_vertex, &c))
                continue;
            if (t & 1)
            {
                UINT tmp = b;
                b = c;
                c = tmp;
            }
            ctx_emit_tri(self, a, b, c);
        }
    }
}

/* DrawInstanced / DrawIndexedInstanced — slots 21 / 20. Per-instance
 * data isn't read from a stream-1 vertex buffer; we replay the same
 * draw N times so apps that do an instanced clear-test still see
 * something. */
static void ctx_DrawInstanced(ID3D11ContextImpl* self, UINT vcount, UINT icount, UINT vstart, UINT istart)
{
    (void)istart;
    for (UINT i = 0; i < icount; ++i)
        ctx_Draw(self, vcount, vstart);
}
static void ctx_DrawIndexedInstanced(ID3D11ContextImpl* self, UINT icount, UINT instance_count, UINT istart,
                                     INT base_vertex, UINT inst_start)
{
    (void)inst_start;
    for (UINT i = 0; i < instance_count; ++i)
        ctx_DrawIndexed(self, icount, istart, base_vertex);
}

/* Map(resource, sub, mapType, flags, mapped) — slot 14. v0 only
 * supports Map on an ID3D11Buffer; other resources return E_FAIL.
 * Mapped layout (D3D11_MAPPED_SUBRESOURCE = 24 B):
 *   void* pData (8) | UINT RowPitch (4) | UINT DepthPitch (4). */
static HRESULT ctx_Map(ID3D11ContextImpl* self, void* resource, UINT sub, UINT map_type, UINT flags, void* mapped)
{
    (void)self;
    (void)sub;
    (void)map_type;
    (void)flags;
    if (!mapped)
        return DX_E_POINTER;
    BYTE* m = (BYTE*)mapped;
    dx_memzero(m, 24);
    if (!resource)
        return DX_E_INVALIDARG;
    /* Sniff the vtable to decide buffer vs texture. lpVtbl is the
     * first 8 bytes of every COM impl in this DLL. */
    const void* vt = *(const void* const*)resource;
    if (vt == (const void*)g_buf_vtbl)
    {
        ID3D11BufferImpl* b = (ID3D11BufferImpl*)resource;
        *(void**)(m + 0) = b->storage;
        *(UINT*)(m + 8) = b->bytes;
        *(UINT*)(m + 12) = b->bytes;
        return DX_S_OK;
    }
    if (vt == (const void*)&g_tx_vtbl)
    {
        ID3D11Texture2DImpl* t = (ID3D11Texture2DImpl*)resource;
        if (!t->bb)
            return DX_E_FAIL;
        *(void**)(m + 0) = t->bb->pixels;
        *(UINT*)(m + 8) = t->bb->pitch_bytes;
        *(UINT*)(m + 12) = t->bb->buffer_bytes;
        return DX_S_OK;
    }
    return DX_E_INVALIDARG;
}
static void ctx_Unmap(ID3D11ContextImpl* self, void* resource, UINT sub)
{
    (void)self;
    (void)resource;
    (void)sub;
}

/* UpdateSubresource(resource, sub, box, src, srcRowPitch, srcDepthPitch) — slot 48.
 * Only ID3D11Buffer is honoured; box is ignored (full overwrite). */
static void ctx_UpdateSubresource(ID3D11ContextImpl* self, void* resource, UINT sub, const void* box, const void* src,
                                  UINT row_pitch, UINT depth_pitch)
{
    (void)self;
    (void)sub;
    (void)box;
    (void)row_pitch;
    (void)depth_pitch;
    if (!resource || !src)
        return;
    const void* vt = *(const void* const*)resource;
    if (vt == (const void*)g_buf_vtbl)
    {
        ID3D11BufferImpl* b = (ID3D11BufferImpl*)resource;
        dx_memcpy(b->storage, src, b->bytes);
    }
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
    g_ctx_vtbl[9] = (void*)ctx_PSSetShader;
    g_ctx_vtbl[11] = (void*)ctx_VSSetShader;
    g_ctx_vtbl[12] = (void*)ctx_DrawIndexed;
    g_ctx_vtbl[13] = (void*)ctx_Draw;
    g_ctx_vtbl[14] = (void*)ctx_Map;
    g_ctx_vtbl[15] = (void*)ctx_Unmap;
    g_ctx_vtbl[17] = (void*)ctx_IASetInputLayout;
    g_ctx_vtbl[18] = (void*)ctx_IASetVertexBuffers;
    g_ctx_vtbl[19] = (void*)ctx_IASetIndexBuffer;
    g_ctx_vtbl[20] = (void*)ctx_DrawIndexedInstanced;
    g_ctx_vtbl[21] = (void*)ctx_DrawInstanced;
    g_ctx_vtbl[24] = (void*)ctx_IASetPrimitiveTopology;
    g_ctx_vtbl[33] = (void*)ctx_OMSetRenderTargets;
    /* OMSetBlendState / OMSetDepthStencilState — bound objects are
     * tracked weakly; we don't expose them through Get*State, so the
     * simplest correct binding is to do nothing. */
    g_ctx_vtbl[35] = (void*)DX_VSTUB; /* OMSetBlendState */
    g_ctx_vtbl[36] = (void*)DX_VSTUB; /* OMSetDepthStencilState */
    g_ctx_vtbl[43] = (void*)DX_VSTUB; /* RSSetState */
    g_ctx_vtbl[44] = (void*)ctx_RSSetViewports;
    g_ctx_vtbl[45] = (void*)DX_VSTUB; /* RSSetScissorRects */
    g_ctx_vtbl[48] = (void*)ctx_UpdateSubresource;
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

/* CreateBuffer(desc, initial, ppBuffer) — slot 3.
 * D3D11_BUFFER_DESC: ByteWidth(0), Usage(4), BindFlags(8),
 * CPUAccessFlags(12), MiscFlags(16), StructureByteStride(20).
 * D3D11_SUBRESOURCE_DATA: pSysMem(0), SysMemPitch(8), SysMemSlicePitch(12). */
static HRESULT dev_CreateBuffer(ID3D11DeviceImpl* self, const void* desc, const void* init, void** out)
{
    (void)self;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (!desc)
        return DX_E_INVALIDARG;
    const BYTE* d = (const BYTE*)desc;
    UINT bytes = *(const UINT*)(d + 0);
    UINT bind_flags = *(const UINT*)(d + 8);
    UINT cpu_access = *(const UINT*)(d + 12);
    if (bytes == 0)
        return DX_E_INVALIDARG;
    const void* initial = NULL;
    if (init)
        initial = *(const void* const*)init; /* SUBRESOURCE_DATA::pSysMem */
    ID3D11BufferImpl* b = buf_alloc(bytes, bind_flags, cpu_access, initial);
    if (!b)
        return DX_E_OUTOFMEMORY;
    *out = b;
    return DX_S_OK;
}

/* CreateInputLayout(descs, n, vsBytecode, vsBytecodeLen, ppLayout) — slot 11.
 * v0 ignores the VS bytecode and only inspects the element descs to
 * pull POSITION + (optional) COLOR offsets. */
static HRESULT dev_CreateInputLayout(ID3D11DeviceImpl* self, const void* descs, UINT n, const void* vs, SIZE_T vs_len,
                                     void** out)
{
    (void)self;
    (void)vs;
    (void)vs_len;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    ID3D11InputLayoutImpl* il = il_alloc_from_desc(descs, n);
    if (!il)
        return DX_E_OUTOFMEMORY;
    *out = il;
    return DX_S_OK;
}

/* CreateVertexShader(byteCode, byteCodeLen, classLinkage, ppVS) — slot 12. */
static HRESULT dev_CreateVertexShader(ID3D11DeviceImpl* self, const void* code, SIZE_T code_len, void* linkage,
                                      void** out)
{
    (void)self;
    (void)code;
    (void)code_len;
    (void)linkage;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    ID3D11ShaderImpl* s = shader_alloc(0);
    if (!s)
        return DX_E_OUTOFMEMORY;
    *out = s;
    return DX_S_OK;
}

/* CreatePixelShader(byteCode, byteCodeLen, classLinkage, ppPS) — slot 15. */
static HRESULT dev_CreatePixelShader(ID3D11DeviceImpl* self, const void* code, SIZE_T code_len, void* linkage,
                                     void** out)
{
    (void)self;
    (void)code;
    (void)code_len;
    (void)linkage;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    ID3D11ShaderImpl* s = shader_alloc(1);
    if (!s)
        return DX_E_OUTOFMEMORY;
    *out = s;
    return DX_S_OK;
}

/* Pipeline state object factories — slots 20 / 21 / 22 / 23. The
 * descriptors are ignored; these are opaque tracking handles. */
static HRESULT dev_CreateBlendState(ID3D11DeviceImpl* self, const void* desc, void** out)
{
    (void)self;
    (void)desc;
    if (!out)
        return DX_E_POINTER;
    ID3D11StateImpl* s = state_alloc(1);
    if (!s)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = s;
    return DX_S_OK;
}
static HRESULT dev_CreateDepthStencilState(ID3D11DeviceImpl* self, const void* desc, void** out)
{
    (void)self;
    (void)desc;
    if (!out)
        return DX_E_POINTER;
    ID3D11StateImpl* s = state_alloc(2);
    if (!s)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = s;
    return DX_S_OK;
}
static HRESULT dev_CreateRasterizerState(ID3D11DeviceImpl* self, const void* desc, void** out)
{
    (void)self;
    (void)desc;
    if (!out)
        return DX_E_POINTER;
    ID3D11StateImpl* s = state_alloc(0);
    if (!s)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = s;
    return DX_S_OK;
}
static HRESULT dev_CreateSamplerState(ID3D11DeviceImpl* self, const void* desc, void** out)
{
    (void)self;
    (void)desc;
    if (!out)
        return DX_E_POINTER;
    ID3D11StateImpl* s = state_alloc(3);
    if (!s)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = s;
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
    g_dev_vtbl[11] = (void*)dev_CreateInputLayout;
    g_dev_vtbl[12] = (void*)dev_CreateVertexShader;
    g_dev_vtbl[15] = (void*)dev_CreatePixelShader;
    g_dev_vtbl[20] = (void*)dev_CreateBlendState;
    g_dev_vtbl[21] = (void*)dev_CreateDepthStencilState;
    g_dev_vtbl[22] = (void*)dev_CreateRasterizerState;
    g_dev_vtbl[23] = (void*)dev_CreateSamplerState;
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
