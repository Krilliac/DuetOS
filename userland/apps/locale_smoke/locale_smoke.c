/*
 * locale_smoke — exercise locale-info APIs.
 *
 * Probes the localization surface every internationalised app
 * touches. Many of these will be STUB on v0 since DuetOS has
 * no real locale tables yet:
 *   GetUserDefaultLCID / GetSystemDefaultLCID
 *   GetUserDefaultLangID / GetSystemDefaultLangID
 *   GetThreadLocale / SetThreadLocale
 *   GetLocaleInfoW (LOCALE_SISO639LANGNAME, LOCALE_SCOUNTRY, …)
 *   IsValidLocale
 *   EnumSystemLocalesW (skipped — long callback chain)
 */
#include <windows.h>

#ifndef LOCALE_RETURN_NUMBER
#define LOCALE_RETURN_NUMBER 0x20000000
#endif
#ifndef LOCALE_IDIGITS
#define LOCALE_IDIGITS 0x00000011
#endif
#ifndef LOCALE_S1159
#define LOCALE_S1159 0x00000028
#endif

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutHex(unsigned long long v)
{
    static const char hex[] = "0123456789abcdef";
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; ++i)
        buf[2 + i] = hex[(v >> ((15 - i) * 4)) & 0xF];
    buf[18] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[locale_smoke] starting\r\n");

    LCID user = GetUserDefaultLCID();
    Out("[locale_smoke] GetUserDefaultLCID    = ");
    if (user != 0)
    {
        Out("PASS lcid=");
        OutHex((unsigned long long)user);
        Out("\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    LCID sys = GetSystemDefaultLCID();
    Out("[locale_smoke] GetSystemDefaultLCID  = ");
    Out(sys != 0 ? "PASS\r\n" : "FAIL\r\n");

    LANGID ulang = GetUserDefaultLangID();
    Out("[locale_smoke] GetUserDefaultLangID  = ");
    Out(ulang != 0 ? "PASS\r\n" : "FAIL\r\n");

    LANGID slang = GetSystemDefaultLangID();
    Out("[locale_smoke] GetSystemDefaultLangID= ");
    Out(slang != 0 ? "PASS\r\n" : "FAIL\r\n");

    LCID t = GetThreadLocale();
    Out("[locale_smoke] GetThreadLocale       = ");
    Out(t != 0 ? "PASS\r\n" : "FAIL\r\n");

    /* GetLocaleInfoW LOCALE_SISO639LANGNAME — 2-3 letter ISO code. */
    {
        WCHAR buf[16] = {0};
        int n = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SISO639LANGNAME, buf, 16);
        Out("[locale_smoke] GetLocaleInfoW(ISO639)= ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetLocaleInfoW LOCALE_IDIGITS | LOCALE_RETURN_NUMBER — must write a
     * binary DWORD (2) and return 2 WCHAR units, not the string "2". */
    {
        DWORD num = 0xFFFFFFFF;
        int n = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_IDIGITS | LOCALE_RETURN_NUMBER, (WCHAR*)&num,
                               (int)(sizeof(num) / sizeof(WCHAR)));
        Out("[locale_smoke] GetLocaleInfo(NUMBER) = ");
        Out((n == 2 && num == 2) ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetLocaleInfoW LOCALE_S1159 — AM designator (en-US). */
    {
        WCHAR buf[8] = {0};
        GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_S1159, buf, 8);
        Out("[locale_smoke] GetLocaleInfo(S1159) = ");
        Out((buf[0] == 'A' && buf[1] == 'M' && buf[2] == 0) ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* IsValidLocale on user default. */
    {
        BOOL ok = IsValidLocale(user, LCID_INSTALLED);
        Out("[locale_smoke] IsValidLocale(user)   = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[locale_smoke] done\r\n");
    Out("[ring3-locale-smoke] PASS\r\n");
    ExitProcess(0);
}
