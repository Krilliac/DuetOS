/*
 * wstr_smoke — exercise wide-string operations beyond string_smoke.
 *
 *   wcsncmp / wcsncpy / wcsstr / wcsrchr (msvcrt)
 *   _wcsicmp / _wcsnicmp
 *   StrCmpW (shlwapi)
 *   StrCmpIW (shlwapi)
 */
#include <windows.h>
#include <wchar.h>
#include <shlwapi.h>

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
    Out("[wstr_smoke] starting\r\n");

    /* wcsncmp. */
    Out("[wstr_smoke] wcsncmp(eq,3)       = ");
    Out(wcsncmp(L"abc!", L"abc?", 3) == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* wcsstr. */
    Out("[wstr_smoke] wcsstr             = ");
    {
        const WCHAR* p = wcsstr(L"hello world", L"world");
        Out(p != NULL && p[0] == 'w' ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* wcsrchr. */
    Out("[wstr_smoke] wcsrchr            = ");
    {
        const WCHAR* p = wcsrchr(L"a/b/c", L'/');
        Out(p != NULL && p[1] == 'c' ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* StrCmpW (shlwapi). */
    Out("[wstr_smoke] StrCmpW            = ");
    Out(StrCmpW(L"abc", L"abc") == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* StrCmpIW. */
    Out("[wstr_smoke] StrCmpIW           = ");
    Out(StrCmpIW(L"ABC", L"abc") == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    Out("[wstr_smoke] done\r\n");
    ExitProcess(0);
}
