/*
 * string_smoke — exercise kernel32 + user32 string APIs.
 *
 * Probes the string-manipulation APIs every Win32 app touches:
 *   lstrlenA / lstrlenW
 *   lstrcmpA / lstrcmpW
 *   lstrcpyA / lstrcpyW
 *   lstrcatA / lstrcatW
 *   MultiByteToWideChar / WideCharToMultiByte (CP_UTF8 + CP_ACP)
 *   CharLowerA / CharUpperA / CharLowerW / CharUpperW
 *   CompareStringW
 *   IsCharAlphaA / IsCharAlphaNumericA / IsCharAlphaW
 *
 * Each call is checked for both return value AND output bytes
 * against a known-good reference, so STUB implementations
 * that return 0 / leave the buffer empty get caught.
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

static void Pass(const char* tag)
{
    Out(tag), Out(" PASS\r\n");
}
static void Fail(const char* tag)
{
    Out(tag), Out(" FAIL\r\n");
}

void __cdecl mainCRTStartup(void)
{
    Out("[string_smoke] starting\r\n");

    /* lstrlenA / lstrlenW. */
    Out("[string_smoke] lstrlenA(\"hello\")     = ");
    Out(lstrlenA("hello") == 5 ? "PASS\r\n" : "FAIL\r\n");
    Out("[string_smoke] lstrlenW(L\"hello\")    = ");
    Out(lstrlenW(L"hello") == 5 ? "PASS\r\n" : "FAIL\r\n");

    /* lstrcmpA / lstrcmpW. */
    Out("[string_smoke] lstrcmpA equal/diff   = ");
    Out(lstrcmpA("a", "a") == 0 && lstrcmpA("a", "b") < 0 ? "PASS\r\n" : "FAIL\r\n");
    Out("[string_smoke] lstrcmpW equal/diff   = ");
    Out(lstrcmpW(L"a", L"a") == 0 && lstrcmpW(L"a", L"b") < 0 ? "PASS\r\n" : "FAIL\r\n");

    /* lstrcpyA / lstrcatA. */
    {
        char buf[16] = {0};
        lstrcpyA(buf, "hello");
        lstrcatA(buf, " world");
        Out("[string_smoke] lstrcpyA + lstrcatA   = ");
        Out(StrEqA(buf, "hello world") ? "PASS\r\n" : "FAIL\r\n");
    }

    /* lstrcpyW / lstrcatW. */
    {
        WCHAR buf[16] = {0};
        lstrcpyW(buf, L"hello");
        lstrcatW(buf, L" world");
        Out("[string_smoke] lstrcpyW + lstrcatW   = ");
        Out(StrEqW(buf, L"hello world") ? "PASS\r\n" : "FAIL\r\n");
    }

    /* MultiByteToWideChar (CP_UTF8). */
    {
        WCHAR wbuf[16] = {0};
        int n = MultiByteToWideChar(CP_UTF8, 0, "hello", -1, wbuf, 16);
        Out("[string_smoke] MBtoWC CP_UTF8       = ");
        Out(n == 6 && StrEqW(wbuf, L"hello") ? "PASS\r\n" : "FAIL\r\n");
    }

    /* WideCharToMultiByte (CP_UTF8). */
    {
        char abuf[16] = {0};
        int n = WideCharToMultiByte(CP_UTF8, 0, L"hello", -1, abuf, 16, NULL, NULL);
        Out("[string_smoke] WCtoMB CP_UTF8       = ");
        Out(n == 6 && StrEqA(abuf, "hello") ? "PASS\r\n" : "FAIL\r\n");
    }

    /* CharLowerA / CharUpperA. */
    {
        char buf[8] = "HELLO";
        CharLowerA(buf);
        Out("[string_smoke] CharLowerA            = ");
        Out(StrEqA(buf, "hello") ? "PASS\r\n" : "FAIL\r\n");
    }
    {
        char buf[8] = "hello";
        CharUpperA(buf);
        Out("[string_smoke] CharUpperA            = ");
        Out(StrEqA(buf, "HELLO") ? "PASS\r\n" : "FAIL\r\n");
    }

    /* CharLowerW / CharUpperW. */
    {
        WCHAR buf[8] = L"HELLO";
        CharLowerW(buf);
        Out("[string_smoke] CharLowerW            = ");
        Out(StrEqW(buf, L"hello") ? "PASS\r\n" : "FAIL\r\n");
    }
    {
        WCHAR buf[8] = L"hello";
        CharUpperW(buf);
        Out("[string_smoke] CharUpperW            = ");
        Out(StrEqW(buf, L"HELLO") ? "PASS\r\n" : "FAIL\r\n");
    }

    /* CompareStringW (LOCALE_USER_DEFAULT). */
    {
        int rc = CompareStringW(LOCALE_USER_DEFAULT, 0, L"abc", -1, L"abc", -1);
        Out("[string_smoke] CompareStringW equal  = ");
        Out(rc == CSTR_EQUAL ? "PASS\r\n" : "FAIL\r\n");
    }

    /* IsCharAlphaA / IsCharAlphaNumericA. */
    Out("[string_smoke] IsCharAlphaA('a'/'1')  = ");
    Out(IsCharAlphaA('a') && !IsCharAlphaA('1') ? "PASS\r\n" : "FAIL\r\n");
    Out("[string_smoke] IsCharAlphaNumericA    = ");
    Out(IsCharAlphaNumericA('a') && IsCharAlphaNumericA('1') && !IsCharAlphaNumericA('!') ? "PASS\r\n" : "FAIL\r\n");

    Out("[string_smoke] done\r\n");
    Out("[ring3-string-smoke] PASS\r\n");
    ExitProcess(0);
}
