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
