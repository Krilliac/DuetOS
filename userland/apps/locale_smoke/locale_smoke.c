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

    /* IsValidLocale on user default. */
    {
        BOOL ok = IsValidLocale(user, LCID_INSTALLED);
        Out("[locale_smoke] IsValidLocale(user)   = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[locale_smoke] done\r\n");
    ExitProcess(0);
}
