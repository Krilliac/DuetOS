/*
 * userland/libs/dwrite/dwrite.c — DuetOS DirectWrite v0.
 *
 * Apps create an IDWriteFactory, then a text format, then a text
 * layout. v0 hands out objects whose query methods return defaults
 * but no glyph rasterisation happens. ID2D1RenderTarget::DrawText
 * (when implemented) would consume the layout's geometry.
 *
 * Exports:
 *   DWriteCreateFactory
 *
 * Build: tools/build/build-stub-dll.sh (base 0x102D0000).
 */

#include "../dx_shared.h"

/* IID_IDWriteFactory = {b859ee5a-d838-4b5b-a2e8-1adc7d93db48} */
static const DxGuid kIID_IDWriteFactory = {
    0xb859ee5a, 0xd838, 0x4b5b, {0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}};
/* IID_IDWriteTextFormat = {9c906818-31d7-4fd3-a151-7c5e225db55a} */
static const DxGuid kIID_IDWriteTextFormat = {
    0x9c906818, 0x31d7, 0x4fd3, {0xa1, 0x51, 0x7c, 0x5e, 0x22, 0x5d, 0xb5, 0x5a}};
/* IID_IDWriteTextLayout = {53737037-6d14-410b-9bfe-0b182bb70961} */
static const DxGuid kIID_IDWriteTextLayout = {
    0x53737037, 0x6d14, 0x410b, {0x9b, 0xfe, 0x0b, 0x18, 0x2b, 0xb7, 0x09, 0x61}};

/* ---------------------------------------------------------------- *
 * IDWriteTextLayout — ~50-method vtable. v0:                        *
 *   slot 4  GetMaxWidth, 5 GetMaxHeight                             *
 *   slot 28 GetMetrics                                              *
 * ---------------------------------------------------------------- */

#define DW_LAYOUT_VTBL_SLOTS 60

typedef struct DwLayoutImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    float max_w, max_h;
    float font_size; /* points; from the source TextFormat */
    UINT text_len;   /* in UTF-16 code units */
} DwLayoutImpl;

static HRESULT layout_QueryInterface(DwLayoutImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDWriteTextLayout))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG layout_AddRef(DwLayoutImpl* self)
{
    return ++self->refcount;
}
static ULONG layout_Release(DwLayoutImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static float layout_GetMaxWidth(DwLayoutImpl* self)
{
    return self->max_w;
}
static float layout_GetMaxHeight(DwLayoutImpl* self)
{
    return self->max_h;
}
static HRESULT layout_GetMetrics(DwLayoutImpl* self, void* metrics)
{
    if (!metrics)
        return DX_E_POINTER;
    /* DWRITE_TEXT_METRICS = 7 FLOATs + 2 UINT32s = 36 bytes. We
     * populate it with a reasonable monospace approximation so apps
     * that gate on width > 0 / lineCount >= 1 proceed. Real glyph
     * metrics arrive when DirectWrite gains a font backend. */
    dx_memzero(metrics, 36);
    float fs = self->font_size > 0 ? self->font_size : 12.0f;
    float approx_w = (float)self->text_len * fs * 0.6f;
    float approx_h = fs * 1.2f;
    if (self->max_w > 0 && approx_w > self->max_w)
        approx_w = self->max_w;
    /* width / widthIncludingTrailingWhitespace */
    *(float*)((BYTE*)metrics + 8) = approx_w;
    *(float*)((BYTE*)metrics + 12) = approx_w;
    *(float*)((BYTE*)metrics + 16) = approx_h;    /* height */
    *(float*)((BYTE*)metrics + 20) = self->max_w; /* layoutWidth */
    *(float*)((BYTE*)metrics + 24) = self->max_h; /* layoutHeight */
    *(UINT*)((BYTE*)metrics + 32) = 1;            /* lineCount */
    return DX_S_OK;
}

static void* g_layout_vtbl[DW_LAYOUT_VTBL_SLOTS];
static void layout_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DW_LAYOUT_VTBL_SLOTS; ++i)
        g_layout_vtbl[i] = DX_HSTUB;
    g_layout_vtbl[0] = (void*)layout_QueryInterface;
    g_layout_vtbl[1] = (void*)layout_AddRef;
    g_layout_vtbl[2] = (void*)layout_Release;
    g_layout_vtbl[42] = (void*)layout_GetMaxWidth;
    g_layout_vtbl[43] = (void*)layout_GetMaxHeight;
    g_layout_vtbl[60 - 1] = DX_HSTUB; /* keep size legitimate */
    g_layout_vtbl[28] = (void*)layout_GetMetrics;
}

static DwLayoutImpl* layout_alloc(float w, float h, float font_size, UINT text_len)
{
    layout_init_vtbl_once();
    DwLayoutImpl* l = (DwLayoutImpl*)dx_heap_alloc(sizeof(*l));
    if (!l)
        return NULL;
    dx_memzero(l, sizeof(*l));
    l->lpVtbl = g_layout_vtbl;
    l->refcount = 1;
    l->max_w = w;
    l->max_h = h;
    l->font_size = font_size;
    l->text_len = text_len;
    return l;
}

/* ---------------------------------------------------------------- *
 * IDWriteTextFormat — IUnknown(3) + 18 methods                     *
 *   slot 18 GetFontSize                                             *
 * ---------------------------------------------------------------- */

#define DWFMT_VTBL_SLOTS 24

typedef struct DwFormatImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    float font_size;
} DwFormatImpl;

static HRESULT fmt_QueryInterface(DwFormatImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDWriteTextFormat))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG fmt_AddRef(DwFormatImpl* self)
{
    return ++self->refcount;
}
static ULONG fmt_Release(DwFormatImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static float fmt_GetFontSize(DwFormatImpl* self)
{
    return self->font_size;
}

static void* g_fmt_vtbl[DWFMT_VTBL_SLOTS];
static void fmt_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DWFMT_VTBL_SLOTS; ++i)
        g_fmt_vtbl[i] = DX_HSTUB;
    g_fmt_vtbl[0] = (void*)fmt_QueryInterface;
    g_fmt_vtbl[1] = (void*)fmt_AddRef;
    g_fmt_vtbl[2] = (void*)fmt_Release;
    g_fmt_vtbl[18] = (void*)fmt_GetFontSize;
}

static DwFormatImpl* fmt_alloc(float size)
{
    fmt_init_vtbl_once();
    DwFormatImpl* f = (DwFormatImpl*)dx_heap_alloc(sizeof(*f));
    if (!f)
        return NULL;
    dx_memzero(f, sizeof(*f));
    f->lpVtbl = g_fmt_vtbl;
    f->refcount = 1;
    f->font_size = size;
    return f;
}

/* ---------------------------------------------------------------- *
 * IDWriteFactory — IUnknown(3) + 13 methods                        *
 *   slot 15 CreateTextFormat                                        *
 *   slot 18 CreateTextLayout                                        *
 * ---------------------------------------------------------------- */

#define DWF_VTBL_SLOTS 20

typedef struct DwFactoryImpl
{
    void* const* lpVtbl;
    ULONG refcount;
} DwFactoryImpl;

static HRESULT dwf_QueryInterface(DwFactoryImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDWriteFactory))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG dwf_AddRef(DwFactoryImpl* self)
{
    return ++self->refcount;
}
static ULONG dwf_Release(DwFactoryImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT dwf_CreateTextFormat(DwFactoryImpl* self, const void* family, void* coll, UINT weight, UINT style,
                                    UINT stretch, float size, const void* locale, void** out)
{
    (void)self;
    (void)family;
    (void)coll;
    (void)weight;
    (void)style;
    (void)stretch;
    (void)locale;
    if (!out)
        return DX_E_POINTER;
    DwFormatImpl* f = fmt_alloc(size);
    if (!f)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = f;
    return DX_S_OK;
}
static HRESULT dwf_CreateTextLayout(DwFactoryImpl* self, const void* str, UINT n, void* fmt, float max_w, float max_h,
                                    void** out)
{
    (void)self;
    (void)str;
    if (!out)
        return DX_E_POINTER;
    float fs = 12.0f;
    if (fmt)
    {
        DwFormatImpl* fimpl = (DwFormatImpl*)fmt;
        if (fimpl->font_size > 0)
            fs = fimpl->font_size;
    }
    DwLayoutImpl* l = layout_alloc(max_w, max_h, fs, n);
    if (!l)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = l;
    return DX_S_OK;
}

static void* g_dwf_vtbl[DWF_VTBL_SLOTS];
static void dwf_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DWF_VTBL_SLOTS; ++i)
        g_dwf_vtbl[i] = DX_HSTUB;
    g_dwf_vtbl[0] = (void*)dwf_QueryInterface;
    g_dwf_vtbl[1] = (void*)dwf_AddRef;
    g_dwf_vtbl[2] = (void*)dwf_Release;
    g_dwf_vtbl[15] = (void*)dwf_CreateTextFormat;
    g_dwf_vtbl[18] = (void*)dwf_CreateTextLayout;
}

__declspec(dllexport) HRESULT DWriteCreateFactory(UINT type, REFIID riid, void** out)
{
    (void)type;
    (void)riid;
    dx_gfx_trace(11);
    if (!out)
        return DX_E_POINTER;
    dwf_init_vtbl_once();
    DwFactoryImpl* f = (DwFactoryImpl*)dx_heap_alloc(sizeof(*f));
    if (!f)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    dx_memzero(f, sizeof(*f));
    f->lpVtbl = g_dwf_vtbl;
    f->refcount = 1;
    *out = f;
    return DX_S_OK;
}
