/* uxtheme.dll — visual styles. No theming; all stubs. */
typedef int BOOL;
typedef unsigned long DWORD;
typedef int INT;
typedef void* HANDLE;
typedef unsigned long HRESULT;
typedef unsigned short wchar_t16;

#define S_OK 0UL

__declspec(dllexport) HANDLE OpenThemeData(HANDLE wnd, const wchar_t16* class_list)
{
    (void)wnd;
    (void)class_list;
    return (HANDLE)0;
}
__declspec(dllexport) HRESULT CloseThemeData(HANDLE theme)
{
    (void)theme;
    return S_OK;
}
__declspec(dllexport) BOOL IsThemeActive(void)
{
    return 0;
}
__declspec(dllexport) BOOL IsAppThemed(void)
{
    return 0;
}
__declspec(dllexport) HRESULT SetWindowTheme(HANDLE wnd, const wchar_t16* sub, const wchar_t16* id)
{
    (void)wnd;
    (void)sub;
    (void)id;
    return S_OK;
}
__declspec(dllexport) HRESULT GetThemeSysFont(HANDLE theme, INT font_id, void* lf)
{
    (void)theme;
    (void)font_id;
    (void)lf;
    return S_OK;
}
__declspec(dllexport) HRESULT DrawThemeBackground(HANDLE theme, HANDLE dc, INT part, INT state, const void* rect,
                                                  const void* clip)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)rect;
    (void)clip;
    return S_OK;
}
__declspec(dllexport) HRESULT DrawThemeText(HANDLE theme, HANDLE dc, INT part, INT state, const wchar_t16* text,
                                            INT char_count, DWORD flags, DWORD flags2, const void* rect)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)text;
    (void)char_count;
    (void)flags;
    (void)flags2;
    (void)rect;
    return S_OK;
}

/* GetThemeColor / GetThemeMargins / GetThemeFont / GetThemeMetric:
 * caller queries individual properties. With no theme engine, fill
 * the output with zero/default and return S_OK so paint loops
 * proceed without trapping into "theme broken" fallbacks. */
__declspec(dllexport) HRESULT GetThemeColor(HANDLE theme, INT part, INT state, INT prop, DWORD* color)
{
    (void)theme;
    (void)part;
    (void)state;
    (void)prop;
    if (color)
        *color = 0; /* RGB(0,0,0) */
    return S_OK;
}

__declspec(dllexport) HRESULT GetThemeMargins(HANDLE theme, HANDLE dc, INT part, INT state, INT prop, const void* rect,
                                              void* margins)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)prop;
    (void)rect;
    if (margins)
    {
        unsigned char* m = (unsigned char*)margins;
        for (int i = 0; i < 16; ++i) /* MARGINS = 4 LONGs */
            m[i] = 0;
    }
    return S_OK;
}

__declspec(dllexport) HRESULT GetThemeFont(HANDLE theme, HANDLE dc, INT part, INT state, INT prop, void* lf)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)prop;
    if (lf)
    {
        unsigned char* p = (unsigned char*)lf;
        for (int i = 0; i < 92; ++i) /* LOGFONTW size */
            p[i] = 0;
    }
    return S_OK;
}

__declspec(dllexport) HRESULT GetThemeMetric(HANDLE theme, HANDLE dc, INT part, INT state, INT prop, INT* val)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)prop;
    if (val)
        *val = 0;
    return S_OK;
}

__declspec(dllexport) HRESULT GetThemePartSize(HANDLE theme, HANDLE dc, INT part, INT state, const void* rect, int kind,
                                               void* sz)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)rect;
    (void)kind;
    if (sz)
    {
        unsigned char* p = (unsigned char*)sz;
        for (int i = 0; i < 8; ++i) /* SIZE = 2 LONGs */
            p[i] = 0;
    }
    return S_OK;
}

__declspec(dllexport) HRESULT GetCurrentThemeName(wchar_t16* name, int name_max, wchar_t16* color, int color_max,
                                                  wchar_t16* size, int size_max)
{
    static const wchar_t16 kName[] = {'A', 'e', 'r', 'o', 0};
    static const wchar_t16 kColor[] = {'N', 'o', 'r', 'm', 'a', 'l', 'C', 'o', 'l', 'o', 'r', 0};
    static const wchar_t16 kSize[] = {'N', 'o', 'r', 'm', 'a', 'l', 'S', 'i', 'z', 'e', 0};
    if (name && name_max > 0)
    {
        int i = 0;
        while (i < name_max - 1 && kName[i] != 0)
        {
            name[i] = kName[i];
            ++i;
        }
        name[i] = 0;
    }
    if (color && color_max > 0)
    {
        int i = 0;
        while (i < color_max - 1 && kColor[i] != 0)
        {
            color[i] = kColor[i];
            ++i;
        }
        color[i] = 0;
    }
    if (size && size_max > 0)
    {
        int i = 0;
        while (i < size_max - 1 && kSize[i] != 0)
        {
            size[i] = kSize[i];
            ++i;
        }
        size[i] = 0;
    }
    return 0; /* S_OK */
}

__declspec(dllexport) BOOL IsThemePartDefined(HANDLE theme, INT part, INT state)
{
    (void)theme;
    (void)part;
    (void)state;
    return 0;
}

__declspec(dllexport) HRESULT EnableThemeDialogTexture(HANDLE wnd, DWORD flags)
{
    (void)wnd;
    (void)flags;
    return S_OK;
}

__declspec(dllexport) BOOL IsThemeDialogTextureEnabled(HANDLE wnd)
{
    (void)wnd;
    return 0;
}

#define E_NOTIMPL 0x80004001UL

/* SetWindowThemeAttribute — modern attribute setter
 * (e.g. WTNCA_NODRAWCAPTION). v0 silently accepts. */
__declspec(dllexport) HRESULT SetWindowThemeAttribute(HANDLE wnd, int attr, void* data, DWORD size)
{
    (void)wnd;
    (void)attr;
    (void)data;
    (void)size;
    return S_OK;
}

/* GetThemeBitmap — fetch a theme part's bitmap. With no theme
 * engine, return NULL handle + S_OK so the caller treats the
 * part as "no bitmap defined" (the standard fallback). */
__declspec(dllexport) HRESULT GetThemeBitmap(HANDLE theme, INT part, INT state, INT prop, DWORD flags, HANDLE* bmp)
{
    (void)theme;
    (void)part;
    (void)state;
    (void)prop;
    (void)flags;
    if (bmp)
        *bmp = (HANDLE)0;
    return S_OK;
}

/* DrawThemeParentBackground / DrawThemeParentBackgroundEx —
 * paint the parent's background under a transparent control.
 * v0 has no theme paint; succeed quietly so the caller's
 * subsequent foreground paint is correctly stacked. */
__declspec(dllexport) HRESULT DrawThemeParentBackground(HANDLE wnd, HANDLE dc, const void* rect)
{
    (void)wnd;
    (void)dc;
    (void)rect;
    return S_OK;
}

__declspec(dllexport) HRESULT DrawThemeParentBackgroundEx(HANDLE wnd, HANDLE dc, DWORD flags, const void* rect)
{
    (void)wnd;
    (void)dc;
    (void)flags;
    (void)rect;
    return S_OK;
}

/* BufferedPaint{Init,UnInit} — buffered paint API. Counted
 * call: each Init balanced by UnInit. v0 has no buffer pool —
 * succeed both. */
__declspec(dllexport) HRESULT BufferedPaintInit(void)
{
    return S_OK;
}

__declspec(dllexport) HRESULT BufferedPaintUnInit(void)
{
    return S_OK;
}

/* BeginBufferedPaint — would create an off-screen buffer and
 * return its DC. v0 returns NULL handle; callers fall back to
 * direct-DC paint. */
__declspec(dllexport) HANDLE BeginBufferedPaint(HANDLE target_dc, const void* target_rect, DWORD format, void* params,
                                                HANDLE* buffer_dc)
{
    (void)target_dc;
    (void)target_rect;
    (void)format;
    (void)params;
    if (buffer_dc)
        *buffer_dc = (HANDLE)0;
    return (HANDLE)0;
}

__declspec(dllexport) HRESULT EndBufferedPaint(HANDLE buffer, BOOL update)
{
    (void)buffer;
    (void)update;
    return S_OK;
}

/* BufferedPaintClear — clear a buffer region. */
__declspec(dllexport) HRESULT BufferedPaintClear(HANDLE buffer, const void* rect)
{
    (void)buffer;
    (void)rect;
    return S_OK;
}

/* BufferedPaintSetAlpha — alpha post-process. */
__declspec(dllexport) HRESULT BufferedPaintSetAlpha(HANDLE buffer, const void* rect, unsigned char alpha)
{
    (void)buffer;
    (void)rect;
    (void)alpha;
    return S_OK;
}

/* GetThemeInt / GetThemeBool / GetThemeRect — small theme
 * property getters. Return zero / FALSE / empty rect + S_OK so
 * callers proceed with their fallback values. */
__declspec(dllexport) HRESULT GetThemeInt(HANDLE theme, INT part, INT state, INT prop, INT* val)
{
    (void)theme;
    (void)part;
    (void)state;
    (void)prop;
    if (val)
        *val = 0;
    return S_OK;
}

__declspec(dllexport) HRESULT GetThemeBool(HANDLE theme, INT part, INT state, INT prop, BOOL* val)
{
    (void)theme;
    (void)part;
    (void)state;
    (void)prop;
    if (val)
        *val = 0;
    return S_OK;
}

__declspec(dllexport) HRESULT GetThemeRect(HANDLE theme, INT part, INT state, INT prop, void* rect)
{
    (void)theme;
    (void)part;
    (void)state;
    (void)prop;
    if (rect)
    {
        unsigned char* p = (unsigned char*)rect;
        for (int i = 0; i < 16; ++i) /* RECT = 4 LONGs */
            p[i] = 0;
    }
    return S_OK;
}

/* GetThemeBackgroundContentRect — content area inside a part. */
__declspec(dllexport) HRESULT GetThemeBackgroundContentRect(HANDLE theme, HANDLE dc, INT part, INT state,
                                                            const void* bound_rect, void* content_rect)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    if (content_rect)
    {
        if (bound_rect)
        {
            const unsigned char* src = (const unsigned char*)bound_rect;
            unsigned char* dst = (unsigned char*)content_rect;
            for (int i = 0; i < 16; ++i)
                dst[i] = src[i];
        }
        else
        {
            unsigned char* p = (unsigned char*)content_rect;
            for (int i = 0; i < 16; ++i)
                p[i] = 0;
        }
    }
    return S_OK;
}

/* GetThemeTextExtent / GetThemeTextMetrics — text measurement.
 * v0 returns zero metrics + S_OK so callers fall back to
 * GDI-direct measurement (which we do support). */
__declspec(dllexport) HRESULT GetThemeTextExtent(HANDLE theme, HANDLE dc, INT part, INT state, const void* text,
                                                 INT chars, DWORD flags, const void* bound_rect, void* extent_rect)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)text;
    (void)chars;
    (void)flags;
    (void)bound_rect;
    if (extent_rect)
    {
        unsigned char* p = (unsigned char*)extent_rect;
        for (int i = 0; i < 16; ++i)
            p[i] = 0;
    }
    return S_OK;
}

__declspec(dllexport) HRESULT GetThemeTextMetrics(HANDLE theme, HANDLE dc, INT part, INT state, void* metrics)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    if (metrics)
    {
        unsigned char* p = (unsigned char*)metrics;
        for (int i = 0; i < 60; ++i) /* TEXTMETRIC */
            p[i] = 0;
    }
    return S_OK;
}

/* HitTestThemeBackground — hit-test a part region. v0 reports
 * "miss" so callers default to client-area dispatch. */
__declspec(dllexport) HRESULT HitTestThemeBackground(HANDLE theme, HANDLE dc, INT part, INT state, DWORD options,
                                                     const void* rect, HANDLE clip, void* point, unsigned short* code)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)options;
    (void)rect;
    (void)clip;
    (void)point;
    if (code)
        *code = 1; /* HTNOWHERE */
    return S_OK;
}

/* DrawThemeEdge / DrawThemeIcon — common painters. Succeed
 * silently so paint chains continue. */
__declspec(dllexport) HRESULT DrawThemeEdge(HANDLE theme, HANDLE dc, INT part, INT state, const void* rect,
                                            unsigned int edge, unsigned int flags, void* content_rect)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)rect;
    (void)edge;
    (void)flags;
    (void)content_rect;
    return S_OK;
}

__declspec(dllexport) HRESULT DrawThemeIcon(HANDLE theme, HANDLE dc, INT part, INT state, const void* rect, HANDLE list,
                                            INT image_index)
{
    (void)theme;
    (void)dc;
    (void)part;
    (void)state;
    (void)rect;
    (void)list;
    (void)image_index;
    return S_OK;
}

/* GetThemeFilename / GetThemeStream — file-path getters. v0
 * returns empty + S_OK. */
__declspec(dllexport) HRESULT GetThemeFilename(HANDLE theme, INT part, INT state, INT prop, wchar_t16* file,
                                               INT file_max)
{
    (void)theme;
    (void)part;
    (void)state;
    (void)prop;
    if (file && file_max > 0)
        file[0] = 0;
    return S_OK;
}

__declspec(dllexport) HRESULT GetThemeStream(HANDLE theme, INT part, INT state, INT prop, void** stream, DWORD* size,
                                             HANDLE inst)
{
    (void)theme;
    (void)part;
    (void)state;
    (void)prop;
    (void)inst;
    if (stream)
        *stream = (void*)0;
    if (size)
        *size = 0;
    return E_NOTIMPL;
}

/* BeginPanningFeedback / EndPanningFeedback / UpdatePanningFeedback —
 * touch panning UX. v0 reports success; no visual feedback. */
__declspec(dllexport) BOOL BeginPanningFeedback(HANDLE wnd)
{
    (void)wnd;
    return 1;
}

__declspec(dllexport) BOOL EndPanningFeedback(HANDLE wnd, BOOL animate)
{
    (void)wnd;
    (void)animate;
    return 1;
}

__declspec(dllexport) BOOL UpdatePanningFeedback(HANDLE wnd, long dx, long dy, BOOL in_inertia)
{
    (void)wnd;
    (void)dx;
    (void)dy;
    (void)in_inertia;
    return 1;
}
