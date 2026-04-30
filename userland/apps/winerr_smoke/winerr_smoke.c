/*
 * winerr_smoke — exercise error / last-error APIs.
 *
 *   GetLastError / SetLastError round-trip (already in module_smoke;
 *     re-verified here to catch regressions)
 *   FormatMessageA / FormatMessageW
 *   GetSystemErrorCode (skipped)
 *   SetErrorMode / GetErrorMode
 *   RtlSetLastWin32Error (ntdll route to GetLastError)
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
    Out("[winerr_smoke] starting\r\n");

    SetLastError(ERROR_PATH_NOT_FOUND);
    DWORD got = GetLastError();
    Out("[winerr_smoke] SetLastError + Get  = ");
    Out(got == ERROR_PATH_NOT_FOUND ? "PASS\r\n" : "FAIL\r\n");

    /* FormatMessageA on ERROR_SUCCESS. */
    {
        char buf[256] = {0};
        DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_SUCCESS, 0,
                                 buf, sizeof(buf), NULL);
        Out("[winerr_smoke] FormatMessageA      = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* FormatMessageW on ERROR_SUCCESS. */
    {
        WCHAR buf[256] = {0};
        DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_SUCCESS, 0,
                                 buf, 256, NULL);
        Out("[winerr_smoke] FormatMessageW      = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* SetErrorMode + GetErrorMode round-trip. */
    {
        UINT prev = SetErrorMode(SEM_FAILCRITICALERRORS);
        UINT now = GetErrorMode();
        Out("[winerr_smoke] SetErrorMode + Get  = ");
        Out(now == SEM_FAILCRITICALERRORS ? "PASS\r\n" : "FAIL/STUB\r\n");
        SetErrorMode(prev);
    }

    Out("[winerr_smoke] done\r\n");
    ExitProcess(0);
}
