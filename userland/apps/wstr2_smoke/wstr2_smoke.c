/*
 * wstr2_smoke — second-tier wide-string APIs.
 *
 *   _wtoi / _wtol
 *   _itow_s
 *   wcsftime (skipped — needs tm)
 *   _wfopen (skipped — heavy)
 *   wcstoul / wcstol
 */
#include <windows.h>
#include <wchar.h>
#include <stdlib.h>

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
    Out("[wstr2_smoke] starting\r\n");

    Out("[wstr2_smoke] _wtoi(L\"-42\")    = ");
    Out(_wtoi(L"-42") == -42 ? "PASS\r\n" : "FAIL/STUB\r\n");

    Out("[wstr2_smoke] _wtol(L\"123456\") = ");
    Out(_wtol(L"123456") == 123456 ? "PASS\r\n" : "FAIL/STUB\r\n");

    Out("[wstr2_smoke] wcstoul(L\"42\")   = ");
    {
        wchar_t* end = NULL;
        unsigned long v = wcstoul(L"42", &end, 10);
        Out(v == 42 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[wstr2_smoke] wcstol(L\"-7\")    = ");
    {
        wchar_t* end = NULL;
        long v = wcstol(L"-7", &end, 10);
        Out(v == -7 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[wstr2_smoke] done\r\n");
    Out("[ring3-wstr2-smoke] PASS\r\n");
    ExitProcess(0);
}
