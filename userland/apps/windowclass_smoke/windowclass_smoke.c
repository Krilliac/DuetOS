/*
 * windowclass_smoke — exercise window-class registration APIs.
 *
 * Probes the WNDCLASS plumbing every Win32 GUI app uses to
 * register window classes before CreateWindow:
 *   RegisterClassW (returns ATOM)
 *   GetClassInfoW
 *   UnregisterClassW
 *   GetClassNameW   (skipped — needs window)
 *
 * v0: real RegisterClass routes through SYS_WIN_REGISTER_CLASS
 * which exists for windowed_hello. Should mostly PASS here.
 */
#include <windows.h>

static LRESULT CALLBACK SmokeWndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    return DefWindowProcW(h, m, w, l);
}

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
    Out("[windowclass_smoke] starting\r\n");

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = SmokeWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"DuetOSSmokeClass";
    ATOM a = RegisterClassW(&wc);
    Out("[windowclass_smoke] RegisterClassW       = ");
    Out(a != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* GetClassInfoW on the just-registered class. */
    {
        WNDCLASSW info = {0};
        BOOL ok = GetClassInfoW(GetModuleHandleW(NULL), L"DuetOSSmokeClass", &info);
        Out("[windowclass_smoke] GetClassInfoW (own)  = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetClassInfoW on an unknown class — should return FALSE. */
    {
        WNDCLASSW info = {0};
        BOOL ok = GetClassInfoW(GetModuleHandleW(NULL), L"DuetOSDefinitelyMissingClass", &info);
        Out("[windowclass_smoke] GetClassInfoW(?)     = ");
        Out(!ok ? "PASS (FALSE, as expected)\r\n" : "FAIL\r\n");
    }

    /* UnregisterClassW. */
    if (a != 0)
    {
        BOOL un = UnregisterClassW(L"DuetOSSmokeClass", GetModuleHandleW(NULL));
        Out("[windowclass_smoke] UnregisterClassW     = ");
        Out(un ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[windowclass_smoke] done\r\n");
    ExitProcess(0);
}
