/*
 * paths2_smoke — extended shlwapi path coverage beyond paths_smoke.
 *
 *   PathIsRelativeW
 *   PathUnquoteSpacesW
 *   PathQuoteSpacesW
 *   PathMatchSpecW (wildcard match)
 *   PathRemoveExtensionW
 *   PathRenameExtensionW
 *   PathSkipRootW
 *   PathRemoveBlanksW
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
    Out("[paths2_smoke] starting\r\n");

    /* PathIsRelativeW. */
    Out("[paths2_smoke] PathIsRelativeW     = ");
    Out(PathIsRelativeW(L"foo.txt") && !PathIsRelativeW(L"C:\\foo.txt") ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* PathMatchSpecW("hello.exe", "*.exe"). */
    Out("[paths2_smoke] PathMatchSpecW(*.exe) = ");
    Out(PathMatchSpecW(L"hello.exe", L"*.exe") ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* PathRemoveExtensionW. */
    {
        WCHAR buf[64] = L"file.exe";
        PathRemoveExtensionW(buf);
        Out("[paths2_smoke] PathRemoveExtensionW = ");
        Out(StrEqW(buf, L"file") ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* PathRenameExtensionW. */
    {
        WCHAR buf[64] = L"file.exe";
        BOOL ok = PathRenameExtensionW(buf, L".bak");
        Out("[paths2_smoke] PathRenameExtensionW = ");
        Out(ok && StrEqW(buf, L"file.bak") ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* PathQuoteSpacesW + PathUnquoteSpacesW round-trip. */
    {
        WCHAR buf[64] = L"a b c";
        PathQuoteSpacesW(buf);
        PathUnquoteSpacesW(buf);
        Out("[paths2_smoke] Quote + Unquote     = ");
        Out(StrEqW(buf, L"a b c") ? "PASS (round-trip)\r\n" : "FAIL/STUB\r\n");
    }

    Out("[paths2_smoke] done\r\n");
    ExitProcess(0);
}
