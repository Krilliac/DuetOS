/*
 * datetime_smoke — exercise date / time conversion APIs.
 *
 * Probes the conversion paths between FILETIME, SYSTEMTIME, and
 * tick counters. Real Win32 apps shuffle these constantly when
 * formatting timestamps:
 *   GetSystemTime / GetLocalTime
 *   SystemTimeToFileTime / FileTimeToSystemTime
 *   GetSystemTimeAsFileTime
 *   FileTimeToLocalFileTime / LocalFileTimeToFileTime
 *   CompareFileTime
 *   GetTimeZoneInformation
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

static void OutDec(unsigned long long v)
{
    char buf[24];
    int len = 0;
    if (v == 0)
        buf[len++] = '0';
    else
    {
        char rev[24];
        int r = 0;
        while (v != 0)
        {
            rev[r++] = (char)('0' + (v % 10));
            v /= 10;
        }
        for (int j = 0; j < r; ++j)
            buf[len++] = rev[r - 1 - j];
    }
    buf[len] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[datetime_smoke] starting\r\n");

    /* GetSystemTime — UTC SYSTEMTIME. */
    SYSTEMTIME st = {0};
    GetSystemTime(&st);
    Out("[datetime_smoke] GetSystemTime         = ");
    if (st.wYear > 1900 && st.wMonth >= 1 && st.wMonth <= 12)
    {
        Out("PASS Y=");
        OutDec((unsigned long long)st.wYear);
        Out(" M=");
        OutDec((unsigned long long)st.wMonth);
        Out(" D=");
        OutDec((unsigned long long)st.wDay);
        Out("\r\n");
    }
    else
    {
        Out("FAIL/STUB\r\n");
    }

    /* GetLocalTime — should match in DuetOS (no time zone yet). */
    SYSTEMTIME lt = {0};
    GetLocalTime(&lt);
    Out("[datetime_smoke] GetLocalTime          = ");
    Out(lt.wYear > 1900 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* SystemTimeToFileTime + FileTimeToSystemTime round-trip. */
    {
        FILETIME ft = {0};
        BOOL ok = SystemTimeToFileTime(&st, &ft);
        Out("[datetime_smoke] SystemTimeToFileTime  = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

        if (ok)
        {
            SYSTEMTIME st2 = {0};
            BOOL ok2 = FileTimeToSystemTime(&ft, &st2);
            Out("[datetime_smoke] FileTimeToSystemTime  = ");
            Out(ok2 && st2.wYear == st.wYear && st2.wMonth == st.wMonth ? "PASS (round-trip)\r\n" : "FAIL/STUB\r\n");
        }
    }

    /* CompareFileTime — compare ft to itself = 0. */
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        FILETIME ft_copy = ft;
        LONG r = CompareFileTime(&ft, &ft_copy);
        Out("[datetime_smoke] CompareFileTime self  = ");
        Out(r == 0 ? "PASS (equal)\r\n" : "FAIL/STUB\r\n");
    }

    /* GetTimeZoneInformation. */
    {
        TIME_ZONE_INFORMATION tzi = {0};
        DWORD r = GetTimeZoneInformation(&tzi);
        Out("[datetime_smoke] GetTimeZoneInformation= ");
        Out(r != TIME_ZONE_ID_INVALID ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[datetime_smoke] done\r\n");
    ExitProcess(0);
}
