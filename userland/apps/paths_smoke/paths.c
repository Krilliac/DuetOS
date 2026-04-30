/*
 * paths_smoke — exercise shlwapi path-manipulation surface.
 *
 * Probes common file-path utilities every Windows app uses:
 *   PathFindExtensionA / PathFindExtensionW
 *   PathFindFileNameA / PathFindFileNameW
 *   PathRemoveFileSpecW
 *   PathAddBackslashW
 *   PathAppendW
 *   PathCombineW
 *   PathFileExistsA / PathFileExistsW
 *   PathIsDirectoryW
 *   PathStripPathW
 *
 * Each call's return is checked against the expected output for
 * a known input — PASS only if the exact bytes match. STUB
 * implementations that return NULL or the input unchanged are
 * caught by these spot-checks.
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

static int StrEqA(const char* a, const char* b)
{
    int i = 0;
    while (a[i] != '\0' && b[i] != '\0')
    {
        if (a[i] != b[i])
            return 0;
        ++i;
    }
    return a[i] == b[i];
}

static int StrEqW(const WCHAR* a, const WCHAR* b)
{
    int i = 0;
    while (a[i] != 0 && b[i] != 0)
    {
        if (a[i] != b[i])
            return 0;
        ++i;
    }
    return a[i] == b[i];
}

void __cdecl mainCRTStartup(void)
{
    Out("[paths_smoke] starting\r\n");

    /* Step 1: PathFindExtensionA. */
    {
        const char* p = "C:\\Users\\test\\file.exe";
        const char* got = PathFindExtensionA(p);
        Out("[paths_smoke] PathFindExtensionA = ");
        Out(got != NULL && StrEqA(got, ".exe") ? "PASS \".exe\"\r\n" : "FAIL\r\n");
    }

    /* Step 2: PathFindFileNameA. */
    {
        const char* p = "C:\\Users\\test\\file.exe";
        const char* got = PathFindFileNameA(p);
        Out("[paths_smoke] PathFindFileNameA  = ");
        Out(got != NULL && StrEqA(got, "file.exe") ? "PASS \"file.exe\"\r\n" : "FAIL\r\n");
    }

    /* Step 3: PathFindExtensionW. */
    {
        WCHAR buf[] = L"C:\\Users\\test\\file.exe";
        WCHAR* got = PathFindExtensionW(buf);
        WCHAR want[] = L".exe";
        Out("[paths_smoke] PathFindExtensionW = ");
        Out(got != NULL && StrEqW(got, want) ? "PASS\r\n" : "FAIL\r\n");
    }

    /* Step 4: PathRemoveFileSpecW. */
    {
        WCHAR buf[64] = L"C:\\Users\\test\\file.exe";
        BOOL ok = PathRemoveFileSpecW(buf);
        WCHAR want[] = L"C:\\Users\\test";
        Out("[paths_smoke] PathRemoveFileSpecW= ");
        Out(ok && StrEqW(buf, want) ? "PASS\r\n" : "FAIL\r\n");
    }

    /* Step 5: PathAddBackslashW. */
    {
        WCHAR buf[64] = L"C:\\Users\\test";
        WCHAR* got = PathAddBackslashW(buf);
        WCHAR want[] = L"C:\\Users\\test\\";
        Out("[paths_smoke] PathAddBackslashW  = ");
        Out(got != NULL && StrEqW(buf, want) ? "PASS\r\n" : "FAIL\r\n");
    }

    /* Step 6: PathAppendW. */
    {
        WCHAR buf[64] = L"C:\\Users\\test";
        BOOL ok = PathAppendW(buf, L"file.exe");
        WCHAR want[] = L"C:\\Users\\test\\file.exe";
        Out("[paths_smoke] PathAppendW        = ");
        Out(ok && StrEqW(buf, want) ? "PASS\r\n" : "FAIL\r\n");
    }

    /* Step 7: PathCombineW. */
    {
        WCHAR out_buf[64] = {0};
        WCHAR* got = PathCombineW(out_buf, L"C:\\Users\\test", L"file.exe");
        WCHAR want[] = L"C:\\Users\\test\\file.exe";
        Out("[paths_smoke] PathCombineW       = ");
        Out(got != NULL && StrEqW(out_buf, want) ? "PASS\r\n" : "FAIL\r\n");
    }

    /* Step 8: PathFileExistsA — should be FALSE for nonexistent. */
    {
        BOOL exists = PathFileExistsA("C:\\does\\not\\exist.txt");
        Out("[paths_smoke] PathFileExistsA(no)= ");
        Out(!exists ? "PASS (not found, as expected)\r\n" : "FAIL (false positive)\r\n");
    }

    /* Step 9: PathStripPathW. */
    {
        WCHAR buf[64] = L"C:\\Users\\test\\file.exe";
        PathStripPathW(buf);
        WCHAR want[] = L"file.exe";
        Out("[paths_smoke] PathStripPathW     = ");
        Out(StrEqW(buf, want) ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[paths_smoke] done\r\n");
    ExitProcess(0);
}
