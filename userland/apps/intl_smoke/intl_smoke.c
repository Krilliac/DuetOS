/*
 * intl_smoke — international format APIs.
 *
 *   GetUserGeoID / GetSystemGeoID
 *   EnumLanguageGroupLocalesW (skipped)
 *   GetGeoInfoW
 *   GetCalendarInfoEx
 *   IdnToAscii (skipped)
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
    Out("[intl_smoke] starting\r\n");

    GEOID g = GetUserGeoID(GEOCLASS_NATION);
    Out("[intl_smoke] GetUserGeoID         = ");
    Out(g != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* GetGeoInfoW for ISO 3166 country code. */
    {
        WCHAR buf[16] = {0};
        int n = GetGeoInfoW(g, GEO_ISO2, buf, 16, 0);
        Out("[intl_smoke] GetGeoInfoW(ISO2)    = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetCalendarInfoEx. */
    {
        WCHAR buf[64] = {0};
        int n = GetCalendarInfoEx(L"en-US", CAL_GREGORIAN, NULL, CAL_SCALNAME, buf, 64, NULL);
        Out("[intl_smoke] GetCalendarInfoEx    = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[intl_smoke] done\r\n");
    ExitProcess(0);
}
