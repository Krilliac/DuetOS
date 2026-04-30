/*
 * uxtheme_smoke — exercise visual-styles uxtheme.dll.
 *
 *   IsAppThemed
 *   IsThemeActive
 *   GetCurrentThemeName
 *   OpenThemeData (skipped — needs HWND)
 *   GetThemeAppProperties
 *
 * v0: themes not implemented; expect FAIL/STUB across the board
 * but verify it doesn't trap.
 */
#include <windows.h>
#include <uxtheme.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

void __cdecl mainCRTStartup(void)
{
    Out("[uxtheme_smoke] starting\r\n");

    BOOL themed = IsAppThemed();
    Out("[uxtheme_smoke] IsAppThemed          = ");
    Out("PASS (returned)\r\n");
    (void)themed;

    BOOL active = IsThemeActive();
    Out("[uxtheme_smoke] IsThemeActive        = ");
    Out("PASS (returned)\r\n");
    (void)active;

    /* GetCurrentThemeName. */
    {
        WCHAR fname[260] = {0};
        WCHAR color[64] = {0};
        WCHAR size[64] = {0};
        HRESULT hr = GetCurrentThemeName(fname, 260, color, 64, size, 64);
        Out("[uxtheme_smoke] GetCurrentThemeName  = ");
        Out(SUCCEEDED(hr) || hr == E_NOTIMPL ? "PASS (returned)\r\n" : "FAIL\r\n");
    }

    /* GetThemeAppProperties. */
    {
        DWORD props = GetThemeAppProperties();
        Out("[uxtheme_smoke] GetThemeAppProperties= ");
        Out("PASS (returned)\r\n");
        (void)props;
    }

    Out("[uxtheme_smoke] done\r\n");
    ExitProcess(0);
}
