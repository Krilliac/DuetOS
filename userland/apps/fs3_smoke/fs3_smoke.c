/*
 * fs3_smoke — third-tier file APIs.
 *
 *   GetCurrentDirectoryW (already covered) — verify here too
 *   SetEndOfFile (skipped — RO)
 *   GetTempPath2W (skipped — newer API)
 *   GetFileTitleW
 *   PathCanonicalizeW (shlwapi)
 */
#include <windows.h>
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

static int StrEqW(const WCHAR* a, const WCHAR* b)
{
    int i = 0;
    while (a[i] && b[i])
    {
        if (a[i] != b[i])
            return 0;
        ++i;
    }
    return a[i] == b[i];
}

void __cdecl mainCRTStartup(void)
{
    Out("[fs3_smoke] starting\r\n");

    /* GetCurrentDirectoryW. */
    {
        WCHAR buf[260] = {0};
        DWORD n = GetCurrentDirectoryW(260, buf);
        Out("[fs3_smoke] GetCurrentDirectoryW = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* PathCanonicalizeW: collapse "..". */
    {
        WCHAR out_buf[260] = {0};
        BOOL ok = PathCanonicalizeW(out_buf, L"C:\\a\\..\\b");
        Out("[fs3_smoke] PathCanonicalizeW   = ");
        Out(ok && StrEqW(out_buf, L"C:\\b") ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* (GetFileTitleW lives in comdlg32 — skipped in v0) */

    Out("[fs3_smoke] done\r\n");
    ExitProcess(0);
}
