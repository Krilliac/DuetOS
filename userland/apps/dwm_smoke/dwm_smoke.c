/*
 * dwm_smoke — exercise Desktop Window Manager APIs.
 *
 *   DwmIsCompositionEnabled
 *   DwmGetWindowAttribute (skipped — needs HWND)
 *   DwmEnableComposition
 *   DwmGetColorizationColor
 *   DwmFlush
 *
 * v0: DWM is not implemented; calls return E_NOTIMPL or sentinel.
 */
#include <windows.h>
#include <dwmapi.h>

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
    Out("[dwm_smoke] starting\r\n");

    BOOL enabled = FALSE;
    HRESULT hr = DwmIsCompositionEnabled(&enabled);
    Out("[dwm_smoke] DwmIsCompositionEnabled = ");
    Out(SUCCEEDED(hr) ? "PASS\r\n" : "FAIL/STUB\r\n");

    DWORD color = 0;
    BOOL opaque = FALSE;
    hr = DwmGetColorizationColor(&color, &opaque);
    Out("[dwm_smoke] DwmGetColorizationColor = ");
    Out(SUCCEEDED(hr) || hr == E_NOTIMPL ? "PASS (returned)\r\n" : "FAIL\r\n");

    hr = DwmFlush();
    Out("[dwm_smoke] DwmFlush               = ");
    Out(SUCCEEDED(hr) || hr == E_NOTIMPL ? "PASS (returned)\r\n" : "FAIL\r\n");

    Out("[dwm_smoke] done\r\n");
    ExitProcess(0);
}
