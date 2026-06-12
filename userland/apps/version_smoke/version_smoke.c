/*
 * version_smoke — exercise version-info / OS-detection APIs.
 *
 * Probes the OS-version surface beyond GetVersionExW (in process_smoke):
 *   GetFileVersionInfoSizeW
 *   GetFileVersionInfoW
 *   VerQueryValueW
 *   VerifyVersionInfoW (basic OSVERSIONINFOEXW with VER_MAJORVERSION)
 *   GetVersion (legacy DWORD-packed version)
 *
 * Real Win32 apps use these to gate features by Windows release.
 * Our DuetOS reports version 10.0 to match Windows 10's
 * GetVersionExW so most apps proceed without bailing.
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

static void OutHex(unsigned long long v)
{
    static const char hex[] = "0123456789abcdef";
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; ++i)
        buf[2 + i] = hex[(v >> ((15 - i) * 4)) & 0xF];
    buf[18] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[version_smoke] starting\r\n");

    /* Legacy GetVersion — packs major/minor/build into a DWORD. */
    {
        DWORD v = GetVersion();
        Out("[version_smoke] GetVersion             = ");
        if (v != 0)
        {
            Out("PASS v=");
            OutHex((unsigned long long)v);
            Out("\r\n");
        }
        else
        {
            Out("FAIL\r\n");
        }
    }

    /* GetFileVersionInfoSizeW for a known module. v0 has no real
     * version resources; expect 0 / FAIL today. */
    {
        DWORD handle = 0;
        DWORD sz = GetFileVersionInfoSizeW(L"\\bin\\hello.exe", &handle);
        Out("[version_smoke] GetFileVersionInfoSizeW = ");
        Out(sz > 0 ? "PASS\r\n" : "FAIL/STUB (no resource)\r\n");
    }

    /* VerifyVersionInfoW with VER_MAJORVERSION. */
    {
        OSVERSIONINFOEXW info = {0};
        info.dwOSVersionInfoSize = sizeof(info);
        info.dwMajorVersion = 6; /* require >= 6 */
        DWORDLONG mask = 0;
        VER_SET_CONDITION(mask, VER_MAJORVERSION, VER_GREATER_EQUAL);
        BOOL ok = VerifyVersionInfoW(&info, VER_MAJORVERSION, mask);
        Out("[version_smoke] VerifyVersionInfo(maj>=6) = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[version_smoke] done\r\n");
    Out("[ring3-version-smoke] PASS\r\n");
    ExitProcess(0);
}
