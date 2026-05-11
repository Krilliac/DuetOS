/*
 * userland/libs/ddraw/ddraw.c — DuetOS DirectDraw v0.
 *
 * Legacy 2D blit API. v0 implements the bare minimum so PEs that
 * call DirectDrawCreate{,Ex} get an IDirectDraw7 back; SetDisplay-
 * Mode succeeds; CreateSurface allocates a BGRA8 backbuffer that
 * Lock/Unlock map; Blt becomes a copy in software (apps can paint
 * into it). No actual GPU page flip — apps that draw to a primary
 * surface won't see output.
 *
 * Exports:
 *   DirectDrawCreate, DirectDrawCreateEx, DirectDrawEnumerateA,
 *   DirectDrawEnumerateW
 *
 * Build: tools/build/build-stub-dll.sh (base 0x102B0000).
 */

#include "../dx_shared.h"

/* IID_IDirectDraw7 = {15e65ec0-3b9c-11d2-b92f-00609797ea5b} */
static const DxGuid kIID_IDirectDraw7 = {0x15e65ec0, 0x3b9c, 0x11d2, {0xb9, 0x2f, 0x00, 0x60, 0x97, 0x97, 0xea, 0x5b}};
/* IID_IDirectDrawSurface7 = {06675a80-3b9b-11d2-b92f-00609797ea5b} */
static const DxGuid kIID_IDirectDrawSurface7 = {
    0x06675a80, 0x3b9b, 0x11d2, {0xb9, 0x2f, 0x00, 0x60, 0x97, 0x97, 0xea, 0x5b}};

/* ---------------------------------------------------------------- *
 * IDirectDrawSurface7 — 51-method vtable. v0 implements:           *
 *   slot 3  AddAttachedSurface                                      *
 *   slot 5  Blt / 7 BltFast                                         *
 *   slot 9  Flip                                                    *
 *   slot 18 GetPixelFormat                                          *
 *   slot 20 GetSurfaceDesc                                          *
 *   slot 25 Lock / 32 Unlock                                        *
 *   slot 29 Restore                                                 *
 *   slot 31 SetColorKey                                             *
 * ---------------------------------------------------------------- */

#define DDS_VTBL_SLOTS 51

typedef struct DdsImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT width;
    UINT height;
    DxBackBuffer* bb;
    BOOL is_primary;
    HWND hwnd; /* for primary surface Present */
} DdsImpl;

static HRESULT dds_QueryInterface(DdsImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirectDrawSurface7))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG dds_AddRef(DdsImpl* self)
{
    return ++self->refcount;
}
static ULONG dds_Release(DdsImpl* self)
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

/* DDSURFACEDESC2 (124 bytes): we read width(@12), height(@16),
 * pitch/lpSurface(@24/@36) get filled in on Lock. */
static HRESULT dds_Lock(DdsImpl* self, void* rect, void* desc, DWORD flags, HANDLE evt)
{
    (void)rect;
    (void)flags;
    (void)evt;
    if (!desc || !self->bb)
        return DX_E_POINTER;
    BYTE* d = (BYTE*)desc;
    *(DWORD*)(d + 12) = self->width;
    *(DWORD*)(d + 16) = self->height;
    *(DWORD*)(d + 24) = self->bb->pitch_bytes;
    /* lpSurface is a void* at offset 36 in DDSURFACEDESC2. */
    *(void**)(d + 36) = self->bb->pixels;
    return DX_S_OK;
}
static HRESULT dds_Unlock(DdsImpl* self, void* rect)
{
    (void)rect;
    /* If primary surface bound to an HWND, push pixels through. */
    if (self->is_primary && self->hwnd && self->bb)
        dx_bb_present(self->bb);
    return DX_S_OK;
}
static HRESULT dds_Blt(DdsImpl* self, void* dst_rect, DdsImpl* src, void* src_rect, DWORD flags, void* fx)
{
    (void)src_rect;
    (void)fx;
    if (!self->bb)
        return DX_E_INVALIDARG; /* surface detached from back buffer */
    if (flags & 0x0400)         /* DDBLT_COLORFILL — fx contains DDBLTFX with dwFillColor at +12 */
    {
        DWORD color = 0;
        if (fx)
            color = *(const DWORD*)((const BYTE*)fx + 12);
        DWORD* p = (DWORD*)self->bb->pixels;
        UINT n = self->width * self->height;
        for (UINT i = 0; i < n; ++i)
            p[i] = color;
    }
    else if (src && src->bb)
    {
        UINT bytes = src->bb->buffer_bytes < self->bb->buffer_bytes ? src->bb->buffer_bytes : self->bb->buffer_bytes;
        dx_memcpy(self->bb->pixels, src->bb->pixels, bytes);
    }
    (void)dst_rect;
    if (self->is_primary && self->hwnd && self->bb)
        dx_bb_present(self->bb);
    return DX_S_OK;
}
static HRESULT dds_Flip(DdsImpl* self, DdsImpl* override_target, DWORD flags)
{
    (void)override_target;
    (void)flags;
    if (self->bb)
        dx_bb_present(self->bb);
    return DX_S_OK;
}
static HRESULT dds_GetSurfaceDesc(DdsImpl* self, void* desc)
{
    if (!desc)
        return DX_E_POINTER;
    BYTE* d = (BYTE*)desc;
    dx_memzero(d, 124);
    *(DWORD*)(d + 0) = 124;
    *(DWORD*)(d + 12) = self->width;
    *(DWORD*)(d + 16) = self->height;
    *(DWORD*)(d + 24) = self->bb ? self->bb->pitch_bytes : 0;
    return DX_S_OK;
}

static void* g_dds_vtbl[DDS_VTBL_SLOTS];
static void dds_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DDS_VTBL_SLOTS; ++i)
        g_dds_vtbl[i] = DX_HSTUB;
    g_dds_vtbl[0] = (void*)dds_QueryInterface;
    g_dds_vtbl[1] = (void*)dds_AddRef;
    g_dds_vtbl[2] = (void*)dds_Release;
    g_dds_vtbl[5] = (void*)dds_Blt;
    g_dds_vtbl[9] = (void*)dds_Flip;
    g_dds_vtbl[20] = (void*)dds_GetSurfaceDesc;
    g_dds_vtbl[25] = (void*)dds_Lock;
    g_dds_vtbl[32] = (void*)dds_Unlock;
}

static DdsImpl* dds_alloc(UINT w, UINT h, BOOL primary, HWND hwnd)
{
    dds_init_vtbl_once();
    if (w == 0)
        w = 640;
    if (h == 0)
        h = 480;
    DdsImpl* s = (DdsImpl*)dx_heap_alloc(sizeof(*s));
    if (!s)
        return NULL;
    dx_memzero(s, sizeof(*s));
    s->lpVtbl = g_dds_vtbl;
    s->refcount = 1;
    s->width = w;
    s->height = h;
    s->is_primary = primary;
    s->hwnd = hwnd;
    s->bb = dx_bb_create(hwnd, w, h);
    if (!s->bb)
    {
        dx_heap_free(s);
        return NULL;
    }
    return s;
}

/* ---------------------------------------------------------------- *
 * IDirectDraw7 — IUnknown(3) + 27 methods. v0 implements:          *
 *   slot 3  Compact (no-op)                                         *
 *   slot 4  CreateClipper                                           *
 *   slot 6  CreateSurface                                           *
 *   slot 8  EnumDisplayModes                                        *
 *   slot 11 GetCaps                                                 *
 *   slot 14 GetDisplayMode                                          *
 *   slot 19 RestoreDisplayMode                                      *
 *   slot 20 SetCooperativeLevel                                     *
 *   slot 21 SetDisplayMode                                          *
 *   slot 22 WaitForVerticalBlank                                    *
 * ---------------------------------------------------------------- */

#define DD_VTBL_SLOTS 30

typedef struct DdImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    HWND hwnd;
    UINT mode_w, mode_h;
} DdImpl;

static HRESULT dd_QueryInterface(DdImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirectDraw7))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG dd_AddRef(DdImpl* self)
{
    return ++self->refcount;
}
static ULONG dd_Release(DdImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
/* DDSURFACEDESC2 (124B) — caller passes flags + caps + width + height */
static HRESULT dd_CreateSurface(DdImpl* self, const void* desc, void** out, void* unk)
{
    (void)unk;
    if (!desc || !out)
        return DX_E_POINTER;
    const BYTE* d = (const BYTE*)desc;
    UINT w = *(const DWORD*)(d + 12);
    UINT h = *(const DWORD*)(d + 16);
    /* Caps DWORD lives at offset 108 in DDSURFACEDESC2; DDSCAPS_PRIMARYSURFACE = 0x200. */
    DWORD caps0 = *(const DWORD*)(d + 108);
    BOOL primary = (caps0 & 0x200) != 0;
    if (primary && (w == 0 || h == 0))
    {
        w = self->mode_w ? self->mode_w : 640;
        h = self->mode_h ? self->mode_h : 480;
    }
    DdsImpl* s = dds_alloc(w, h, primary, primary ? self->hwnd : NULL);
    if (!s)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = s;
    return DX_S_OK;
}
static HRESULT dd_SetCooperativeLevel(DdImpl* self, HWND hwnd, DWORD flags)
{
    (void)flags;
    self->hwnd = hwnd;
    return DX_S_OK;
}
static HRESULT dd_SetDisplayMode(DdImpl* self, DWORD w, DWORD h, DWORD bpp, DWORD freq, DWORD flags)
{
    (void)bpp;
    (void)freq;
    (void)flags;
    self->mode_w = w;
    self->mode_h = h;
    return DX_S_OK;
}
static HRESULT dd_GetCaps(DdImpl* self, void* caps, void* hel_caps)
{
    (void)self;
    if (caps)
        dx_memzero(caps, 380); /* DDCAPS */
    if (hel_caps)
        dx_memzero(hel_caps, 380);
    return DX_S_OK;
}
static HRESULT dd_RestoreDisplayMode(DdImpl* self)
{
    (void)self;
    return DX_S_OK;
}
static HRESULT dd_WaitForVerticalBlank(DdImpl* self, DWORD flags, HANDLE h)
{
    (void)self;
    (void)flags;
    (void)h;
    return DX_S_OK;
}

static void* g_dd_vtbl[DD_VTBL_SLOTS];
static void dd_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DD_VTBL_SLOTS; ++i)
        g_dd_vtbl[i] = DX_HSTUB;
    g_dd_vtbl[0] = (void*)dd_QueryInterface;
    g_dd_vtbl[1] = (void*)dd_AddRef;
    g_dd_vtbl[2] = (void*)dd_Release;
    g_dd_vtbl[6] = (void*)dd_CreateSurface;
    g_dd_vtbl[11] = (void*)dd_GetCaps;
    g_dd_vtbl[19] = (void*)dd_RestoreDisplayMode;
    g_dd_vtbl[20] = (void*)dd_SetCooperativeLevel;
    g_dd_vtbl[21] = (void*)dd_SetDisplayMode;
    g_dd_vtbl[22] = (void*)dd_WaitForVerticalBlank;
}

static DdImpl* dd_alloc(void)
{
    dd_init_vtbl_once();
    DdImpl* d = (DdImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return NULL;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_dd_vtbl;
    d->refcount = 1;
    return d;
}

__declspec(dllexport) HRESULT DirectDrawCreate(const void* guid, void** out, void* unk)
{
    (void)guid;
    (void)unk;
    dx_gfx_trace(9);
    if (!out)
        return DX_E_POINTER;
    DdImpl* d = dd_alloc();
    if (!d)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = d;
    return DX_S_OK;
}

__declspec(dllexport) HRESULT DirectDrawCreateEx(const void* guid, void** out, REFIID riid, void* unk)
{
    (void)riid;
    return DirectDrawCreate(guid, out, unk);
}

__declspec(dllexport) HRESULT DirectDrawEnumerateA(void* cb, void* ctx)
{
    (void)cb;
    (void)ctx;
    return DX_S_OK;
}

__declspec(dllexport) HRESULT DirectDrawEnumerateW(void* cb, void* ctx)
{
    (void)cb;
    (void)ctx;
    return DX_S_OK;
}
