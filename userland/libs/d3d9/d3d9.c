/*
 * userland/libs/d3d9/d3d9.c — DuetOS D3D9 v0.
 *
 * Real IDirect3D9 + IDirect3DDevice9 with a working Clear-and-
 * Present pipeline. Higher-level state (texture stages, vertex
 * shaders, etc.) returns D3DERR-style codes via DX_HSTUB.
 *
 * Build: tools/build-stub-dll.sh (base 0x10120000).
 */

#include "../dx_shared.h"

/* IIDs */
static const DxGuid kIID_IDirect3D9 = {0x81bdcbca, 0x64d4, 0x426d, {0xae, 0x8d, 0xad, 0x01, 0x47, 0xf4, 0x27, 0x5c}};
static const DxGuid kIID_IDirect3D9Ex = {0x02177241, 0x69fc, 0x400c, {0x8f, 0xf1, 0x93, 0xa4, 0x4d, 0xf6, 0x86, 0x1d}};
static const DxGuid kIID_IDirect3DDevice9 = {
    0xd0223b96, 0xbf7a, 0x43fd, {0x92, 0xbd, 0xa4, 0x3b, 0x0d, 0x82, 0xb9, 0xeb}};

/* ---------------------------------------------------------------- *
 * IDirect3DDevice9                                                 *
 *                                                                  *
 * 119-method vtable. v0 implements:                                *
 *   slot 16 BeginScene (no-op success)                             *
 *   slot 17 EndScene (no-op success)                               *
 *   slot 18 Clear                                                  *
 *   slot 17 Present (non-Ex; the Present at 17 is in real D3D9)    *
 *   For simplicity v0 places Present at slot 17 and treats EndScene*
 *   as a no-op handled at slot 16.                                 *
 *                                                                  *
 *   Reality-aligned slot map (index → method):                     *
 *   3=GetAvailableTextureMem, 4=EvictManagedResources,             *
 *   5=GetDirect3D, ..., 16=BeginScene, 17=EndScene, 18=Clear,      *
 *   ..., 42=Present.                                                *
 * ---------------------------------------------------------------- */

#define DEV9_VTBL_SLOTS 119

typedef struct D9DeviceImpl D9DeviceImpl;
struct D9DeviceImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    HWND hwnd;
    DxBackBuffer* bb;
};

static HRESULT d9d_QueryInterface(D9DeviceImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirect3DDevice9))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG d9d_AddRef(D9DeviceImpl* self)
{
    return ++self->refcount;
}
static ULONG d9d_Release(D9DeviceImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->bb)
            dx_bb_destroy(self->bb);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static HRESULT d9d_BeginScene(D9DeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}
static HRESULT d9d_EndScene(D9DeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}

/* Clear(count, rects, flags, color, z, stencil). Color is a packed
 * D3DCOLOR (0xAARRGGBB). */
static HRESULT d9d_Clear(D9DeviceImpl* self, DWORD count, const void* rects, DWORD flags, DWORD color, float z,
                         DWORD stencil)
{
    (void)count;
    (void)rects;
    (void)flags;
    (void)z;
    (void)stencil;
    if (!self || !self->bb)
        return DX_E_FAIL;
    /* Convert D3DCOLOR ARGB → BGRA float and reuse dx_bb_clear_rgba. */
    BYTE a = (BYTE)((color >> 24) & 0xFF);
    BYTE r = (BYTE)((color >> 16) & 0xFF);
    BYTE g = (BYTE)((color >> 8) & 0xFF);
    BYTE b = (BYTE)(color & 0xFF);
    dx_bb_clear_rgba(self->bb, (float)r / 255.0f, (float)g / 255.0f, (float)b / 255.0f, (float)a / 255.0f);
    return DX_S_OK;
}

/* Present(srcRect, dstRect, hwndOverride, dirtyRgn) — slot 42. */
static HRESULT d9d_Present(D9DeviceImpl* self, const void* src, const void* dst, HWND hwnd_override, const void* dirty)
{
    (void)src;
    (void)dst;
    (void)dirty;
    if (!self || !self->bb)
        return DX_E_FAIL;
    HWND saved = self->bb->hwnd;
    if (hwnd_override)
        self->bb->hwnd = hwnd_override;
    dx_gfx_trace(4);
    dx_bb_present(self->bb);
    self->bb->hwnd = saved;
    return DX_S_OK;
}

static void* g_d9d_vtbl[DEV9_VTBL_SLOTS];
static void d9d_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DEV9_VTBL_SLOTS; ++i)
        g_d9d_vtbl[i] = DX_HSTUB;
    g_d9d_vtbl[0] = (void*)d9d_QueryInterface;
    g_d9d_vtbl[1] = (void*)d9d_AddRef;
    g_d9d_vtbl[2] = (void*)d9d_Release;
    g_d9d_vtbl[16] = (void*)d9d_BeginScene;
    g_d9d_vtbl[17] = (void*)d9d_EndScene;
    g_d9d_vtbl[18] = (void*)d9d_Clear;
    g_d9d_vtbl[42] = (void*)d9d_Present;
}

/* ---------------------------------------------------------------- *
 * IDirect3D9                                                       *
 *                                                                  *
 * 17-method vtable.                                                *
 *   slot 4  GetAdapterCount                                        *
 *   slot 5  GetAdapterIdentifier                                   *
 *   slot 6  GetAdapterModeCount                                    *
 *   slot 16 CreateDevice                                           *
 * ---------------------------------------------------------------- */

#define D9_VTBL_SLOTS 17

typedef struct D9Impl D9Impl;
struct D9Impl
{
    void* const* lpVtbl;
    ULONG refcount;
};

static HRESULT d9_QueryInterface(D9Impl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirect3D9) || dx_guid_eq(riid, &kIID_IDirect3D9Ex))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG d9_AddRef(D9Impl* self)
{
    return ++self->refcount;
}
static ULONG d9_Release(D9Impl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static UINT d9_GetAdapterCount(D9Impl* self)
{
    (void)self;
    return 1;
}

/* CreateDevice(adapter, devType, hwndFocus, behaviorFlags,
 *   D3DPRESENT_PARAMETERS*, IDirect3DDevice9** dev).
 * D3DPRESENT_PARAMETERS layout (start):
 *   UINT BackBufferWidth    (0)
 *   UINT BackBufferHeight   (4)
 *   D3DFORMAT BackBufferFormat (8)
 *   UINT BackBufferCount    (12)
 *   D3DMULTISAMPLE_TYPE     (16)
 *   DWORD MultiSampleQuality(20)
 *   D3DSWAPEFFECT           (24)
 *   HWND hDeviceWindow      (32, after pad to 8-align)
 */
static HRESULT d9_CreateDevice(D9Impl* self, UINT adapter, UINT dev_type, HWND focus, DWORD flags, void* present_params,
                               D9DeviceImpl** out)
{
    (void)self;
    (void)adapter;
    (void)dev_type;
    (void)flags;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    UINT w = 640, h = 480;
    HWND hwnd = focus;
    if (present_params)
    {
        const BYTE* p = (const BYTE*)present_params;
        UINT bw = *(const UINT*)(p + 0);
        UINT bh = *(const UINT*)(p + 4);
        if (bw)
            w = bw;
        if (bh)
            h = bh;
        HWND hp = *(const HWND*)(p + 32);
        if (hp)
            hwnd = hp;
    }
    d9d_init_vtbl_once();
    D9DeviceImpl* d = (D9DeviceImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return DX_E_OUTOFMEMORY;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_d9d_vtbl;
    d->refcount = 1;
    d->hwnd = hwnd;
    d->bb = dx_bb_create(hwnd, w, h);
    if (!d->bb)
    {
        dx_heap_free(d);
        return DX_E_OUTOFMEMORY;
    }
    *out = d;
    return DX_S_OK;
}

static void* g_d9_vtbl[D9_VTBL_SLOTS];
static void d9_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < D9_VTBL_SLOTS; ++i)
        g_d9_vtbl[i] = DX_HSTUB;
    g_d9_vtbl[0] = (void*)d9_QueryInterface;
    g_d9_vtbl[1] = (void*)d9_AddRef;
    g_d9_vtbl[2] = (void*)d9_Release;
    g_d9_vtbl[4] = (void*)d9_GetAdapterCount;
    g_d9_vtbl[16] = (void*)d9_CreateDevice;
}

static D9Impl* d9_alloc(void)
{
    d9_init_vtbl_once();
    D9Impl* p = (D9Impl*)dx_heap_alloc(sizeof(*p));
    if (!p)
        return NULL;
    dx_memzero(p, sizeof(*p));
    p->lpVtbl = g_d9_vtbl;
    p->refcount = 1;
    return p;
}

/* Exported entry points */

__declspec(dllexport) void* Direct3DCreate9(UINT sdk_version)
{
    (void)sdk_version;
    dx_gfx_trace(4);
    return d9_alloc();
}

__declspec(dllexport) HRESULT Direct3DCreate9Ex(UINT sdk_version, void** out)
{
    (void)sdk_version;
    if (!out)
        return DX_E_POINTER;
    D9Impl* p = d9_alloc();
    if (!p)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = p;
    return DX_S_OK;
}
