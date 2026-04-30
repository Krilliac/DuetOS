/*
 * disp_smoke — display-mode / monitor enumeration APIs.
 *
 *   EnumDisplaySettingsW
 *   ChangeDisplaySettingsW (skipped — would change display)
 *   GetSystemMetricsForDpi (Win10+)
 *   GetDpiForSystem
 *   GetDpiForWindow (skipped — needs window)
 */
#include <windows.h>

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
    Out("[disp_smoke] starting\r\n");

    /* EnumDisplaySettingsW for current mode. */
    {
        DEVMODEW dm = {0};
        dm.dmSize = sizeof(dm);
        BOOL ok = EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dm);
        Out("[disp_smoke] EnumDisplaySettingsW = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetDpiForSystem. */
    {
        UINT dpi = GetDpiForSystem();
        Out("[disp_smoke] GetDpiForSystem      = ");
        Out(dpi > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[disp_smoke] done\r\n");
    ExitProcess(0);
}
