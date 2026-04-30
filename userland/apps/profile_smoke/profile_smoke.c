/*
 * profile_smoke — exercise legacy INI-file profile APIs.
 *
 * Win32 still ships the INI-file API for backwards compat with
 * Windows 3.1 era programs. It writes to %WINDIR%\\$file.ini:
 *   GetPrivateProfileStringA / W
 *   WritePrivateProfileStringA
 *   GetPrivateProfileIntA
 *   GetProfileStringA (system win.ini)
 *
 * v0 likely STUB across the board — registry replaced this in
 * the 2000s and DuetOS doesn't have win.ini. Smoke value =
 * "doesn't trap, returns sane sentinels".
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
    Out("[profile_smoke] starting\r\n");

    /* GetPrivateProfileString on missing INI → returns default. */
    {
        char buf[64] = {0};
        DWORD n = GetPrivateProfileStringA("section", "key", "DEFAULT", buf, 64, "C:\\does\\not\\exist.ini");
        Out("[profile_smoke] GetPrivateProfileStringA = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetPrivateProfileIntA on missing INI → returns the supplied default. */
    {
        UINT v = GetPrivateProfileIntA("section", "key", 42, "C:\\nope.ini");
        Out("[profile_smoke] GetPrivateProfileIntA    = ");
        Out(v == 42 ? "PASS (default returned)\r\n" : "FAIL/STUB\r\n");
    }

    /* GetProfileStringA (win.ini fallback). */
    {
        char buf[64] = {0};
        DWORD n = GetProfileStringA("section", "key", "DEFAULT", buf, 64);
        Out("[profile_smoke] GetProfileStringA        = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[profile_smoke] done\r\n");
    ExitProcess(0);
}
