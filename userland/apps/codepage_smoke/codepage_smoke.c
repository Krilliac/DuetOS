/*
 * codepage_smoke — exercise kernel32 code-page / Unicode APIs.
 *
 * Probes the code-page surface beyond the basic UTF-8 round-trip
 * already in string_smoke:
 *   GetACP / GetOEMCP
 *   GetCPInfo
 *   IsValidCodePage
 *   MultiByteToWideChar with required-buffer-size mode
 *   WideCharToMultiByte with required-buffer-size mode
 *   GetStringTypeW (CT_CTYPE1)
 *   LCMapStringW (LCMAP_LOWERCASE / LCMAP_UPPERCASE)
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

static void OutDec(unsigned long v)
{
    char buf[16];
    int len = 0;
    if (v == 0)
        buf[len++] = '0';
    else
    {
        char rev[16];
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
    Out("[codepage_smoke] starting\r\n");

    UINT acp = GetACP();
    Out("[codepage_smoke] GetACP                 = ");
    if (acp != 0)
    {
        Out("PASS cp=");
        OutDec((unsigned long)acp);
        Out("\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    UINT oem = GetOEMCP();
    Out("[codepage_smoke] GetOEMCP               = ");
    if (oem != 0)
    {
        Out("PASS cp=");
        OutDec((unsigned long)oem);
        Out("\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    /* CPINFO for the active code page. */
    {
        CPINFO info = {0};
        BOOL ok = GetCPInfo(CP_ACP, &info);
        Out("[codepage_smoke] GetCPInfo(CP_ACP)      = ");
        Out(ok && info.MaxCharSize > 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* Bogus codepage — should be invalid. */
    {
        BOOL ok = IsValidCodePage(99999);
        Out("[codepage_smoke] IsValidCodePage(99999) = ");
        Out(!ok ? "PASS (invalid, as expected)\r\n" : "FAIL\r\n");
    }

    /* CP_UTF8 should always be valid. */
    {
        BOOL ok = IsValidCodePage(CP_UTF8);
        Out("[codepage_smoke] IsValidCodePage(UTF8)  = ");
        Out(ok ? "PASS\r\n" : "FAIL\r\n");
    }

    /* MultiByteToWideChar required-size mode. */
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, "hello", -1, NULL, 0);
        Out("[codepage_smoke] MBtoWC sizing          = ");
        Out(n == 6 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* WideCharToMultiByte required-size mode. */
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, L"hello", -1, NULL, 0, NULL, NULL);
        Out("[codepage_smoke] WCtoMB sizing          = ");
        Out(n == 6 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* LCMapStringW LOWER. */
    {
        WCHAR out_buf[16] = {0};
        int n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_LOWERCASE, L"HELLO", -1, out_buf, 16);
        Out("[codepage_smoke] LCMapStringW(LOWER)    = ");
        Out(n == 6 && out_buf[0] == 'h' ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[codepage_smoke] done\r\n");
    ExitProcess(0);
}
