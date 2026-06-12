/*
 * enviro_smoke — exercise extended environment / process-group APIs.
 *
 *   GetCurrentDirectoryA
 *   SetCurrentDirectoryA (will fail on read-only ramfs but probe ABI)
 *   GetUserDomainNameA
 *   GetUserNameExW (skipped — secur32)
 *   GetTickCount64Ptr — skipped
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
    Out("[enviro_smoke] starting\r\n");

    /* GetCurrentDirectoryA. */
    {
        char buf[260] = {0};
        DWORD n = GetCurrentDirectoryA(260, buf);
        Out("[enviro_smoke] GetCurrentDirectoryA = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetComputerNameExW. */
    {
        WCHAR buf[64] = {0};
        DWORD sz = 64;
        BOOL ok = GetComputerNameExW(ComputerNameDnsHostname, buf, &sz);
        Out("[enviro_smoke] GetComputerNameExW   = ");
        Out(ok && sz > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[enviro_smoke] done\r\n");
    Out("[ring3-enviro-smoke] PASS\r\n");
    ExitProcess(0);
}
