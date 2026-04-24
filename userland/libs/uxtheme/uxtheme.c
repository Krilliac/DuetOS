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
