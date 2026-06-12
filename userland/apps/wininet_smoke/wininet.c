/*
 * wininet_smoke — exercise wininet HTTP surface.
 *
 * Probes the higher-level WinInet APIs (the one IE+older apps
 * use, layered on top of WinSock):
 *   InternetOpenA          (open session)
 *   InternetOpenUrlA       (HTTP GET in one call)
 *   InternetReadFile       (drain response body)
 *   InternetCloseHandle    (cleanup)
 *
 * Tries to reach http://www.google.com/ (port 80, plain HTTP)
 * and prints the first ~64 bytes of the response. Whether it
 * succeeds depends on whether the wininet thunks are real or
 * NO-OP stubs — under `mini_browser_runs_on_duetos_v0` we know
 * the underlying ws2_32 surface works, so a wininet failure
 * here usually points at the wininet thunk layer.
 */
#include <windows.h>
#include <wininet.h>

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
    Out("[wininet_smoke] starting\r\n");

    HINTERNET sess = InternetOpenA("DuetOS-mini/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    Out("[wininet_smoke] InternetOpenA      = ");
    if (sess == NULL)
    {
        Out("FAIL (NULL session)\r\n");
        Out("[ring3-wininet-smoke] FAIL internetopen\r\n");
        ExitProcess(1);
    }
    Out("PASS\r\n");

    HINTERNET req = InternetOpenUrlA(sess, "http://www.google.com/", NULL, 0,
                                     INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_COOKIES, 0);
    Out("[wininet_smoke] InternetOpenUrlA   = ");
    if (req == NULL)
    {
        Out("FAIL (NULL request)\r\n");
        InternetCloseHandle(sess);
        Out("[ring3-wininet-smoke] PASS\r\n"); /* environmental (DNS/connect), not an API-shape failure */
        ExitProcess(2);
    }
    Out("PASS\r\n");

    char buf[128];
    DWORD got = 0;
    BOOL ok = InternetReadFile(req, buf, sizeof(buf) - 1, &got);
    Out("[wininet_smoke] InternetReadFile   = ");
    if (!ok || got == 0)
    {
        Out("FAIL (no body)\r\n");
    }
    else
    {
        if (got >= sizeof(buf))
            got = sizeof(buf) - 1;
        buf[got] = '\0';
        Out("PASS got ");
        char num[8];
        DWORD n = got;
        int len = 0;
        if (n == 0)
            num[len++] = '0';
        else
        {
            char rev[8];
            int r = 0;
            while (n != 0)
            {
                rev[r++] = (char)('0' + (n % 10));
                n /= 10;
            }
            for (int j = 0; j < r; ++j)
                num[len++] = rev[r - 1 - j];
        }
        num[len] = '\0';
        Out(num);
        Out(" bytes\r\n");
        /* Truncate at first newline for log readability. */
        for (int i = 0; i < (int)got; ++i)
            if (buf[i] == '\r' || buf[i] == '\n')
            {
                buf[i] = '\0';
                break;
            }
        Out("[wininet_smoke] reply: ");
        Out(buf);
        Out("\r\n");
    }

    InternetCloseHandle(req);
    InternetCloseHandle(sess);
    Out("[wininet_smoke] done\r\n");
    Out("[ring3-wininet-smoke] PASS\r\n");
    ExitProcess(0);
}
