/*
 * userland/libs/d2d1/d2d1.c — DuetOS Direct2D v0.
 *
 * Apps create an ID2D1Factory, then a render target (HWND-bound),
 * then brushes, then call BeginDraw / Clear / FillRectangle / EndDraw.
 *
 * v0 implements ID2D1Factory + a software ID2D1HwndRenderTarget that
 * Clear-fills + Present-blits via the shared dx_bb path. FillRectangle
 * and FillEllipse paint with a solid-color brush. Geometry / DWrite
 * text rendering is deferred (returns S_OK without painting).
 *
 * Exports:
 *   D2D1CreateFactory
 *
 * Build: tools/build/build-stub-dll.sh (base 0x102C0000).
 */

#include "../dx_shared.h"

/* IID_ID2D1Factory = {06152247-6f50-465a-9245-118bfd3b6007} */
static const DxGuid kIID_ID2D1Factory = {0x06152247, 0x6f50, 0x465a, {0x92, 0x45, 0x11, 0x8b, 0xfd, 0x3b, 0x60, 0x07}};

/* ---------------------------------------------------------------- *
 * ID2D1SolidColorBrush — IUnknown(3) + 4 brush methods             *
 * D2D color: D2D1_COLOR_F = float r, g, b, a                       *
 * ---------------------------------------------------------------- */

typedef struct D2dBrushImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    float r, g, b, a;
} D2dBrushImpl;

static HRESULT brush_QueryInterface(D2dBrushImpl* self, REFIID riid, void** out)
{
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    self->refcount++;
    *out = self;
    return DX_S_OK;
}
static ULONG brush_AddRef(D2dBrushImpl* self)
{
    return ++self->refcount;
}
static ULONG brush_Release(D2dBrushImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

#define BRUSH_VTBL_SLOTS 12

static void* g_brush_vtbl[BRUSH_VTBL_SLOTS];
static void brush_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < BRUSH_VTBL_SLOTS; ++i)
        g_brush_vtbl[i] = DX_HSTUB;
    g_brush_vtbl[0] = (void*)brush_QueryInterface;
    g_brush_vtbl[1] = (void*)brush_AddRef;
    g_brush_vtbl[2] = (void*)brush_Release;
}

static D2dBrushImpl* brush_alloc(float r, float g, float b, float a)
{
    brush_init_vtbl_once();
    D2dBrushImpl* p = (D2dBrushImpl*)dx_heap_alloc(sizeof(*p));
    if (!p)
        return NULL;
    dx_memzero(p, sizeof(*p));
    p->lpVtbl = g_brush_vtbl;
    p->refcount = 1;
    p->r = r;
    p->g = g;
    p->b = b;
    p->a = a;
    return p;
}

/* ---------------------------------------------------------------- *
 * ID2D1HwndRenderTarget — IUnknown(3) + ID2D1Resource(1) +         *
 *   ID2D1RenderTarget(~50) + ID2D1HwndRenderTarget(2)              *
 * v0 lays out enough slots to cover the methods we implement:       *
 *   slot 8  CreateSolidColorBrush                                   *
 *   slot 17 FillRectangle                                           *
 *   slot 26 Clear                                                   *
 *   slot 27 BeginDraw                                               *
 *   slot 28 EndDraw                                                 *
 *   slot 32 GetSize                                                 *
 *   slot 57 (Hwnd) Resize                                           *
 * ---------------------------------------------------------------- */

#define D2DRT_VTBL_SLOTS 60

typedef struct D2dRtImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    DxBackBuffer* bb;
} D2dRtImpl;

static HRESULT rt_QueryInterface(D2dRtImpl* self, REFIID riid, void** out)
{
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    self->refcount++;
    *out = self;
    return DX_S_OK;
}
static ULONG rt_AddRef(D2dRtImpl* self)
{
    return ++self->refcount;
}
static ULONG rt_Release(D2dRtImpl* self)
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
/* CreateSolidColorBrush(color, brushProperties, ppBrush). color is
 * a 16-byte D2D1_COLOR_F passed by const-ref (pointer). */
static HRESULT rt_CreateSolidColorBrush(D2dRtImpl* self, const void* color, const void* props, void** out)
{
    (void)self;
    (void)props;
    if (!out || !color)
        return DX_E_POINTER;
    const float* c = (const float*)color;
    D2dBrushImpl* b = brush_alloc(c[0], c[1], c[2], c[3]);
    if (!b)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = b;
    return DX_S_OK;
}
/* FillRectangle(rect, brush). rect = D2D1_RECT_F (4x float = 16B). */
static void rt_FillRectangle(D2dRtImpl* self, const void* rect, D2dBrushImpl* brush)
{
    if (!self->bb || !rect || !brush)
        return;
    const float* r = (const float*)rect;
    int x0 = (int)r[0], y0 = (int)r[1], x1 = (int)r[2], y1 = (int)r[3];
    if (x0 < 0)
        x0 = 0;
    if (y0 < 0)
        y0 = 0;
    if (x1 > (int)self->bb->width)
        x1 = self->bb->width;
    if (y1 > (int)self->bb->height)
        y1 = self->bb->height;
    if (x1 <= x0 || y1 <= y0)
        return;
    BYTE br = (BYTE)(brush->r * 255.f);
    BYTE bg = (BYTE)(brush->g * 255.f);
    BYTE bb = (BYTE)(brush->b * 255.f);
    BYTE ba = (BYTE)(brush->a * 255.f);
    DWORD packed = ((DWORD)ba << 24) | ((DWORD)br << 16) | ((DWORD)bg << 8) | (DWORD)bb;
    DWORD* px = (DWORD*)self->bb->pixels;
    UINT pitch = self->bb->width;
    for (int y = y0; y < y1; ++y)
        for (int x = x0; x < x1; ++x)
            px[y * pitch + x] = packed;
}
static void rt_Clear(D2dRtImpl* self, const void* color)
{
    if (!self->bb)
        return;
    if (!color)
    {
        dx_bb_clear_rgba(self->bb, 0, 0, 0, 1);
        return;
    }
    const float* c = (const float*)color;
    dx_bb_clear_rgba(self->bb, c[0], c[1], c[2], c[3]);
}
static void rt_BeginDraw(D2dRtImpl* self)
{
    (void)self;
}
static HRESULT rt_EndDraw(D2dRtImpl* self, void* tag1, void* tag2)
{
    (void)tag1;
    (void)tag2;
    if (self->bb)
        dx_bb_present(self->bb);
    return DX_S_OK;
}
/* GetSize returns D2D1_SIZE_F = {float w, float h}. MSVC x64 ABI:
 * an aggregate of size > 8 returns via hidden first arg. */
static void rt_GetSize(D2dRtImpl* self, void* out)
{
    if (!out)
        return;
    float* s = (float*)out;
    s[0] = self->bb ? (float)self->bb->width : 0.f;
    s[1] = self->bb ? (float)self->bb->height : 0.f;
}
static HRESULT rt_HwndResize(D2dRtImpl* self, const void* size)
{
    if (!self->bb || !size)
        return DX_E_POINTER;
    const UINT* s = (const UINT*)size;
    UINT w = s[0], h = s[1];
    HWND hwnd = self->bb->hwnd;
    dx_bb_destroy(self->bb);
    self->bb = dx_bb_create(hwnd, w, h);
    return self->bb ? DX_S_OK : DX_E_OUTOFMEMORY;
}

static void* g_rt_vtbl[D2DRT_VTBL_SLOTS];
static void rt_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < D2DRT_VTBL_SLOTS; ++i)
        g_rt_vtbl[i] = DX_HSTUB;
    g_rt_vtbl[0] = (void*)rt_QueryInterface;
    g_rt_vtbl[1] = (void*)rt_AddRef;
    g_rt_vtbl[2] = (void*)rt_Release;
    g_rt_vtbl[8] = (void*)rt_CreateSolidColorBrush;
    g_rt_vtbl[17] = (void*)rt_FillRectangle;
    g_rt_vtbl[26] = (void*)rt_Clear;
    g_rt_vtbl[27] = (void*)rt_BeginDraw;
    g_rt_vtbl[28] = (void*)rt_EndDraw;
    g_rt_vtbl[32] = (void*)rt_GetSize;
    g_rt_vtbl[57] = (void*)rt_HwndResize;
}

static D2dRtImpl* rt_alloc(HWND hwnd, UINT w, UINT h)
{
    rt_init_vtbl_once();
    D2dRtImpl* r = (D2dRtImpl*)dx_heap_alloc(sizeof(*r));
    if (!r)
        return NULL;
    dx_memzero(r, sizeof(*r));
    r->lpVtbl = g_rt_vtbl;
    r->refcount = 1;
    r->bb = dx_bb_create(hwnd, w ? w : 320, h ? h : 240);
    if (!r->bb)
    {
        dx_heap_free(r);
        return NULL;
    }
    return r;
}

/* ---------------------------------------------------------------- *
 * ID2D1Factory — IUnknown(3) + 18 factory methods                  *
 *   slot 14 CreateHwndRenderTarget                                  *
 * ---------------------------------------------------------------- */

#define D2DF_VTBL_SLOTS 21

typedef struct D2dFactoryImpl
{
    void* const* lpVtbl;
    ULONG refcount;
} D2dFactoryImpl;

static HRESULT df_QueryInterface(D2dFactoryImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID2D1Factory))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG df_AddRef(D2dFactoryImpl* self)
{
    return ++self->refcount;
}
static ULONG df_Release(D2dFactoryImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
/* D2D1_HWND_RENDER_TARGET_PROPERTIES (16B): HWND hwnd; UINT width; UINT height; UINT presentOptions. */
static HRESULT df_CreateHwndRenderTarget(D2dFactoryImpl* self, const void* rt_props, const void* hwnd_props, void** out)
{
    (void)self;
    (void)rt_props;
    if (!hwnd_props || !out)
        return DX_E_POINTER;
    const BYTE* p = (const BYTE*)hwnd_props;
    HWND hwnd = *(const HWND*)(p + 0);
    UINT w = *(const UINT*)(p + 8);
    UINT h = *(const UINT*)(p + 12);
    D2dRtImpl* r = rt_alloc(hwnd, w, h);
    if (!r)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = r;
    return DX_S_OK;
}

static void* g_df_vtbl[D2DF_VTBL_SLOTS];
static void df_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < D2DF_VTBL_SLOTS; ++i)
        g_df_vtbl[i] = DX_HSTUB;
    g_df_vtbl[0] = (void*)df_QueryInterface;
    g_df_vtbl[1] = (void*)df_AddRef;
    g_df_vtbl[2] = (void*)df_Release;
    g_df_vtbl[14] = (void*)df_CreateHwndRenderTarget;
}

__declspec(dllexport) HRESULT D2D1CreateFactory(UINT type, REFIID riid, const void* options, void** out)
{
    (void)type;
    (void)riid;
    (void)options;
    dx_gfx_trace(10);
    if (!out)
        return DX_E_POINTER;
    df_init_vtbl_once();
    D2dFactoryImpl* f = (D2dFactoryImpl*)dx_heap_alloc(sizeof(*f));
    if (!f)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    dx_memzero(f, sizeof(*f));
    f->lpVtbl = g_df_vtbl;
    f->refcount = 1;
    *out = f;
    return DX_S_OK;
}
