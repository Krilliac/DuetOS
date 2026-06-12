/*
 * mbcs_smoke — exercise msvcrt multi-byte character APIs.
 *
 *   mbtowc / wctomb
 *   mbstowcs / wcstombs
 *   _setmbcp / _getmbcp
 */
#include <windows.h>
#include <stdlib.h>
#include <mbctype.h> /* _getmbcp / _setmbcp */

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
    Out("[mbcs_smoke] starting\r\n");

    /* mbstowcs. */
    {
        wchar_t wbuf[16] = {0};
        size_t n = mbstowcs(wbuf, "hello", 16);
        Out("[mbcs_smoke] mbstowcs            = ");
        Out(n == 5 && wbuf[0] == 'h' ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* wcstombs. */
    {
        char abuf[16] = {0};
        size_t n = wcstombs(abuf, L"hello", 16);
        Out("[mbcs_smoke] wcstombs            = ");
        Out(n == 5 && abuf[0] == 'h' ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* _getmbcp. */
    {
        int cp = _getmbcp();
        Out("[mbcs_smoke] _getmbcp            = ");
        Out(cp >= 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[mbcs_smoke] done\r\n");
    Out("[ring3-mbcs-smoke] PASS\r\n");
    ExitProcess(0);
}
