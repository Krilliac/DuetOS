/*
 * userland/libs/d2d1/d2d1.c — DuetOS Direct2D v0.
 *
 * Apps create an ID2D1Factory, then a render target (HWND-bound),
 * then brushes, then call BeginDraw / Clear / FillRectangle / EndDraw.
 *
 * v0 implements ID2D1Factory + a software ID2D1HwndRenderTarget that
 * Clear-fills + Present-blits via the shared dx_bb path. Real
 * primitives: FillRectangle, FillEllipse, DrawRectangle (1px outline),
 * DrawEllipse (1px outline), DrawLine (Bresenham). Text rendering and
 * geometry/path objects deferred.
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
 *   slot 15 DrawLine                                                *
 *   slot 16 DrawRectangle (1px outline)                             *
 *   slot 17 FillRectangle                                           *
 *   slot 20 DrawEllipse  (1px outline)                              *
 *   slot 21 FillEllipse                                             *
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
static DWORD brush_pack_bgra(D2dBrushImpl* brush)
{
    BYTE br = (BYTE)(brush->r * 255.f);
    BYTE bg = (BYTE)(brush->g * 255.f);
    BYTE bb = (BYTE)(brush->b * 255.f);
    BYTE ba = (BYTE)(brush->a * 255.f);
    return ((DWORD)ba << 24) | ((DWORD)br << 16) | ((DWORD)bg << 8) | (DWORD)bb;
}

static inline void plot_clipped(DxBackBuffer* bb, int x, int y, DWORD packed)
{
    if (x < 0 || y < 0 || x >= (int)bb->width || y >= (int)bb->height)
        return;
    ((DWORD*)bb->pixels)[y * (int)bb->width + x] = packed;
}

/* Stamp a (2*hw+1) × (2*hw+1) filled square centred on (x,y) — the
 * stroke-width primitive every D2D1 outline path goes through. hw=0
 * degenerates to a single plot. Apps requesting fractional widths
 * (e.g. 1.5f) round to nearest pixel; sub-pixel coverage is the
 * antialiasing layer's job, which we don't have. */
static inline void plot_stamp(DxBackBuffer* bb, int x, int y, int hw, DWORD packed)
{
    if (hw <= 0)
    {
        plot_clipped(bb, x, y, packed);
        return;
    }
    for (int dy = -hw; dy <= hw; ++dy)
        for (int dx = -hw; dx <= hw; ++dx)
            plot_clipped(bb, x + dx, y + dy, packed);
}

/* Translate a D2D1 stroke_width (float pixels) to an integer half-
 * width radius for plot_stamp. D2D1 default is 1.0f; we round any
 * value <= 1.0f down to a single pixel (hw=0). 2.0f → hw=1, 3.0f →
 * hw=1, 4.0f → hw=2, etc. — i.e. the diameter is the requested
 * width, rounded down to odd. */
static inline int stroke_half_width(float stroke_width)
{
    if (stroke_width <= 1.5f)
        return 0;
    int w = (int)(stroke_width + 0.5f);
    if (w < 1)
        w = 1;
    return w / 2;
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
    DWORD packed = brush_pack_bgra(brush);
    DWORD* px = (DWORD*)self->bb->pixels;
    UINT pitch = self->bb->width;
    for (int y = y0; y < y1; ++y)
        for (int x = x0; x < x1; ++x)
            px[y * pitch + x] = packed;
}

/* DrawRectangle outlines the boundary at the requested stroke width
 * via plot_stamp. Style (dash / cap) still ignored — D2D1 stroke
 * styles are a separate object the smoke apps don't exercise. */
static void rt_DrawRectangle(D2dRtImpl* self, const void* rect, D2dBrushImpl* brush, float stroke_width, void* style)
{
    (void)style;
    if (!self->bb || !rect || !brush)
        return;
    const float* r = (const float*)rect;
    int x0 = (int)r[0], y0 = (int)r[1], x1 = (int)r[2] - 1, y1 = (int)r[3] - 1;
    if (x1 < x0 || y1 < y0)
        return;
    const int hw = stroke_half_width(stroke_width);
    DWORD packed = brush_pack_bgra(brush);
    for (int x = x0; x <= x1; ++x)
    {
        plot_stamp(self->bb, x, y0, hw, packed);
        plot_stamp(self->bb, x, y1, hw, packed);
    }
    for (int y = y0; y <= y1; ++y)
    {
        plot_stamp(self->bb, x0, y, hw, packed);
        plot_stamp(self->bb, x1, y, hw, packed);
    }
}

/* DrawLine(p0, p1, brush, strokeWidth, strokeStyle). MSVC x64 ABI:
 * D2D1_POINT_2F is 2x float = 8B, fits in a register, so each point
 * is passed by value in rdx/r8. Bresenham + plot_stamp for the
 * requested width; style ignored. */
static void rt_DrawLine(D2dRtImpl* self, ULONGLONG p0_packed, ULONGLONG p1_packed, D2dBrushImpl* brush,
                        float stroke_width, void* style)
{
    (void)style;
    if (!self->bb || !brush)
        return;
    float p0x, p0y, p1x, p1y;
    {
        DWORD lo = (DWORD)(p0_packed & 0xFFFFFFFFULL);
        DWORD hi = (DWORD)(p0_packed >> 32);
        dx_memcpy(&p0x, &lo, 4);
        dx_memcpy(&p0y, &hi, 4);
        lo = (DWORD)(p1_packed & 0xFFFFFFFFULL);
        hi = (DWORD)(p1_packed >> 32);
        dx_memcpy(&p1x, &lo, 4);
        dx_memcpy(&p1y, &hi, 4);
    }
    int x0 = (int)p0x, y0 = (int)p0y, x1 = (int)p1x, y1 = (int)p1y;
    int dx_ = x1 - x0, dy_ = y1 - y0;
    int sx = dx_ > 0 ? 1 : -1, sy = dy_ > 0 ? 1 : -1;
    if (dx_ < 0)
        dx_ = -dx_;
    if (dy_ < 0)
        dy_ = -dy_;
    const int hw = stroke_half_width(stroke_width);
    DWORD packed = brush_pack_bgra(brush);
    int err = dx_ - dy_;
    int x = x0, y = y0;
    int guard = 0;
    while (1)
    {
        plot_stamp(self->bb, x, y, hw, packed);
        if (x == x1 && y == y1)
            break;
        if (++guard > 65536) /* clamp on absurd line lengths */
            break;
        int e2 = 2 * err;
        if (e2 > -dy_)
        {
            err -= dy_;
            x += sx;
        }
        if (e2 < dx_)
        {
            err += dx_;
            y += sy;
        }
    }
}

/* D2D1_ELLIPSE = D2D1_POINT_2F point + float radiusX + float radiusY = 16B.
 *
 * Outline mode paints every pixel inside the outer ellipse but
 * outside the inner ellipse — a band of thickness 2*hw+1 along the
 * boundary. Fill mode (hw=-1 by convention, never reached via the
 * outline path) paints everything inside. */
static void ellipse_outline_or_fill(DxBackBuffer* bb, float cx, float cy, float rx, float ry, DWORD packed, int fill,
                                    int hw)
{
    if (rx <= 0 || ry <= 0)
        return;
    int icx = (int)cx, icy = (int)cy, irx = (int)rx, iry = (int)ry;
    /* Outer + inner radii for the band; the inner ellipse degenerates
     * to a point when hw >= min(irx, iry) — in that case every pixel
     * inside the outer ellipse passes the outline test. */
    int orx = irx + (fill ? 0 : hw);
    int ory = iry + (fill ? 0 : hw);
    int irx_in = (fill ? 0 : irx - hw - 1);
    int iry_in = (fill ? 0 : iry - hw - 1);
    if (irx_in < 0)
        irx_in = 0;
    if (iry_in < 0)
        iry_in = 0;
    long long orx2 = (long long)orx * orx;
    long long ory2 = (long long)ory * ory;
    long long irx2 = (long long)irx_in * irx_in;
    long long iry2 = (long long)iry_in * iry_in;
    if (orx2 == 0 || ory2 == 0)
        return;
    int x0 = icx - orx, x1 = icx + orx, y0 = icy - ory, y1 = icy + ory;
    for (int y = y0; y <= y1; ++y)
    {
        for (int x = x0; x <= x1; ++x)
        {
            long long dxd = (long long)(x - icx);
            long long dyd = (long long)(y - icy);
            /* Inside outer ellipse? */
            if (dxd * dxd * ory2 + dyd * dyd * orx2 > orx2 * ory2)
                continue;
            if (!fill && irx2 > 0 && iry2 > 0)
            {
                /* Strictly inside inner ellipse? Skip — that's the
                 * band's hollow interior. */
                if (dxd * dxd * iry2 + dyd * dyd * irx2 < irx2 * iry2)
                    continue;
            }
            plot_clipped(bb, x, y, packed);
        }
    }
}

static void rt_DrawEllipse(D2dRtImpl* self, const void* ellipse, D2dBrushImpl* brush, float stroke_width, void* style)
{
    (void)style;
    if (!self->bb || !ellipse || !brush)
        return;
    const float* e = (const float*)ellipse;
    const int hw = stroke_half_width(stroke_width);
    ellipse_outline_or_fill(self->bb, e[0], e[1], e[2], e[3], brush_pack_bgra(brush), 0, hw);
}

static void rt_FillEllipse(D2dRtImpl* self, const void* ellipse, D2dBrushImpl* brush)
{
    if (!self->bb || !ellipse || !brush)
        return;
    const float* e = (const float*)ellipse;
    ellipse_outline_or_fill(self->bb, e[0], e[1], e[2], e[3], brush_pack_bgra(brush), 1, 0);
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
    g_rt_vtbl[15] = (void*)rt_DrawLine;
    g_rt_vtbl[16] = (void*)rt_DrawRectangle;
    g_rt_vtbl[17] = (void*)rt_FillRectangle;
    g_rt_vtbl[20] = (void*)rt_DrawEllipse;
    g_rt_vtbl[21] = (void*)rt_FillEllipse;
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
