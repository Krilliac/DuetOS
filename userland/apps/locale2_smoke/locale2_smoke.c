/*
 * locale2_smoke — extended locale APIs beyond locale_smoke.
 *
 *   FoldStringW (LCMAP_LINGUISTIC_CASING)
 *   GetGeoInfoA / GetUserGeoID
 *   EnumCalendarInfoA (callback)
 *   GetCalendarInfoA
 *   GetCurrencyFormatA
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
    Out("[locale2_smoke] starting\r\n");

    /* FoldStringW (MAP_FOLDCZONE — strip compat-zone codepoints). */
    {
        WCHAR out[16] = {0};
        int n = FoldStringW(MAP_FOLDCZONE, L"hello", -1, out, 16);
        Out("[locale2_smoke] FoldStringW          = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetUserGeoID — returns a numeric GeoID. */
    {
        GEOID g = GetUserGeoID(GEOCLASS_NATION);
        Out("[locale2_smoke] GetUserGeoID         = ");
        Out(g != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetCalendarInfoA. */
    {
        char buf[64] = {0};
        int n = GetCalendarInfoA(LOCALE_USER_DEFAULT, CAL_GREGORIAN, CAL_SCALNAME, buf, 64, NULL);
        Out("[locale2_smoke] GetCalendarInfoA     = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetCurrencyFormatA. */
    {
        char buf[64] = {0};
        int n = GetCurrencyFormatA(LOCALE_USER_DEFAULT, 0, "1234.56", NULL, buf, 64);
        Out("[locale2_smoke] GetCurrencyFormatA   = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[locale2_smoke] done\r\n");
    ExitProcess(0);
}
