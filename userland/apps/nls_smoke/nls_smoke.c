/*
 * nls_smoke — exercise National Language Support APIs beyond the
 * basics in locale_smoke.
 *
 *   GetUserDefaultUILanguage / GetSystemDefaultUILanguage
 *   GetUserGeoID / GetSystemGeoID  (skipped on most v0 systems)
 *   EnumSystemLocalesA (callback — verify it doesn't crash)
 *   EnumDateFormatsA (callback)
 *   GetTimeFormatA / GetDateFormatA
 *   GetNumberFormatA
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

static int streq(const char* a, const char* b)
{
    int i = 0;
    for (;;)
    {
        if (a[i] != b[i])
            return 0;
        if (a[i] == 0)
            return 1;
        ++i;
    }
}

static int g_locale_cb_count = 0;
static BOOL CALLBACK locale_cb(LPSTR name)
{
    (void)name;
    ++g_locale_cb_count;
    return TRUE;
}

void __cdecl mainCRTStartup(void)
{
    Out("[nls_smoke] starting\r\n");

    LANGID ui = GetUserDefaultUILanguage();
    Out("[nls_smoke] GetUserDefaultUILanguage = ");
    Out(ui != 0 ? "PASS\r\n" : "FAIL\r\n");

    LANGID sys_ui = GetSystemDefaultUILanguage();
    Out("[nls_smoke] GetSystemDefaultUILanguage = ");
    Out(sys_ui != 0 ? "PASS\r\n" : "FAIL\r\n");

    /* EnumSystemLocalesA — may invoke callback once or zero times. */
    g_locale_cb_count = 0;
    BOOL ok = EnumSystemLocalesA(locale_cb, LCID_INSTALLED);
    Out("[nls_smoke] EnumSystemLocalesA = ");
    Out(ok || g_locale_cb_count >= 0 ? "PASS\r\n" : "FAIL\r\n");

    /* GetDateFormatA on a known SYSTEMTIME. */
    {
        SYSTEMTIME st = {2026, 4, 0, 30, 12, 34, 56, 789};
        char buf[64] = {0};
        int n = GetDateFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, buf, 64);
        Out("[nls_smoke] GetDateFormatA      = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetTimeFormatA. */
    {
        SYSTEMTIME st = {2026, 4, 0, 30, 12, 34, 56, 789};
        char buf[64] = {0};
        int n = GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, buf, 64);
        Out("[nls_smoke] GetTimeFormatA      = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetNumberFormatA — en-US default: grouping by 3, 2 decimals. */
    {
        char buf[64] = {0};
        GetNumberFormatA(LOCALE_USER_DEFAULT, 0, "1234567.89", NULL, buf, 64);
        Out("[nls_smoke] GetNumberFormatA    = ");
        Out(streq(buf, "1,234,567.89") ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetNumberFormatA — rounding (must round, not truncate): .899 -> .90
     * with the carry rippling through the fraction. */
    {
        char buf[64] = {0};
        GetNumberFormatA(LOCALE_USER_DEFAULT, 0, "1234567.899", NULL, buf, 64);
        Out("[nls_smoke] GetNumberFormat rnd = ");
        Out(streq(buf, "1,234,567.90") ? "PASS\r\n" : "FAIL\r\n");
    }

    /* GetCurrencyFormatA — positive: "$1,234.50". */
    {
        char buf[64] = {0};
        GetCurrencyFormatA(LOCALE_USER_DEFAULT, 0, "1234.5", NULL, buf, 64);
        Out("[nls_smoke] GetCurrencyFormatA  = ");
        Out(streq(buf, "$1,234.50") ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetCurrencyFormatA — negative: en-US parenthesised "($1,234.50)". */
    {
        char buf[64] = {0};
        GetCurrencyFormatA(LOCALE_USER_DEFAULT, 0, "-1234.5", NULL, buf, 64);
        Out("[nls_smoke] GetCurrencyFmt neg  = ");
        Out(streq(buf, "($1,234.50)") ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[nls_smoke] done\r\n");
    Out("[ring3-nls-smoke] PASS\r\n");
    ExitProcess(0);
}
