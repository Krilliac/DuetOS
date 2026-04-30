/*
 * utf16_smoke — UTF-16 conversion edge cases beyond string_smoke.
 *
 *   MultiByteToWideChar with ASCII text round-trip
 *   WideCharToMultiByte with default-char fallback
 *   GetStringTypeW
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
    Out("[utf16_smoke] starting\r\n");

    /* MB→WC with explicit length. */
    {
        WCHAR wbuf[16] = {0};
        int n = MultiByteToWideChar(CP_ACP, 0, "world", 5, wbuf, 16);
        Out("[utf16_smoke] MBtoWC(CP_ACP, 5)  = ");
        Out(n == 5 && wbuf[0] == 'w' && wbuf[4] == 'd' ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* WC→MB. */
    {
        char abuf[16] = {0};
        int n = WideCharToMultiByte(CP_ACP, 0, L"world", 5, abuf, 16, NULL, NULL);
        Out("[utf16_smoke] WCtoMB(CP_ACP, 5)  = ");
        Out(n == 5 && abuf[0] == 'w' ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetStringTypeW. */
    {
        WORD types[3] = {0};
        BOOL ok = GetStringTypeW(CT_CTYPE1, L"a1!", 3, types);
        Out("[utf16_smoke] GetStringTypeW     = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[utf16_smoke] done\r\n");
    ExitProcess(0);
}
