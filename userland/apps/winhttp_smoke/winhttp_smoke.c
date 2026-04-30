/*
 * winhttp_smoke — exercise winhttp HTTP client surface.
 *
 * WinHTTP is the modern Windows HTTP/HTTPS client (the one Visual
 * Studio's "Connected Services" path uses). Wire-level different
 * from WinInet despite similar shape:
 *   WinHttpOpen     (session)
 *   WinHttpConnect  (session→server)
 *   WinHttpOpenRequest
 *   WinHttpSendRequest
 *   WinHttpReceiveResponse
 *   WinHttpReadData
 *   WinHttpCloseHandle
 *
 * Targets www.google.com:80 plain HTTP (TLS not yet implemented).
 * Same expected response as mini_browser: HTTP 426 Upgrade Required.
 */
#include <windows.h>
#include <winhttp.h>

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
    Out("[winhttp_smoke] starting\r\n");

    HINTERNET sess = WinHttpOpen(L"DuetOS-winhttp/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                                 WINHTTP_NO_PROXY_BYPASS, 0);
    Out("[winhttp_smoke] WinHttpOpen          = ");
    if (sess == NULL)
    {
        Out("FAIL (NULL)\r\n");
        Out("[winhttp_smoke] done\r\n");
        ExitProcess(1);
    }
    Out("PASS\r\n");

    HINTERNET conn = WinHttpConnect(sess, L"www.google.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    Out("[winhttp_smoke] WinHttpConnect       = ");
    if (conn == NULL)
    {
        Out("FAIL\r\n");
        WinHttpCloseHandle(sess);
        Out("[winhttp_smoke] done\r\n");
        ExitProcess(2);
    }
    Out("PASS\r\n");

    HINTERNET req =
        WinHttpOpenRequest(conn, L"GET", L"/", L"HTTP/1.0", WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    Out("[winhttp_smoke] WinHttpOpenRequest   = ");
    if (req == NULL)
    {
        Out("FAIL\r\n");
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        Out("[winhttp_smoke] done\r\n");
        ExitProcess(3);
    }
    Out("PASS\r\n");

    BOOL ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    Out("[winhttp_smoke] WinHttpSendRequest   = ");
    Out(ok ? "PASS\r\n" : "FAIL\r\n");

    if (ok)
    {
        ok = WinHttpReceiveResponse(req, NULL);
        Out("[winhttp_smoke] WinHttpReceiveResponse = ");
        Out(ok ? "PASS\r\n" : "FAIL\r\n");

        if (ok)
        {
            char buf[128] = {0};
            DWORD got = 0;
            ok = WinHttpReadData(req, buf, sizeof(buf) - 1, &got);
            Out("[winhttp_smoke] WinHttpReadData      = ");
            if (ok && got > 0)
            {
                buf[got] = '\0';
                /* Truncate at first newline. */
                for (DWORD i = 0; i < got; ++i)
                    if (buf[i] == '\r' || buf[i] == '\n')
                    {
                        buf[i] = '\0';
                        break;
                    }
                Out("PASS reply: ");
                Out(buf);
                Out("\r\n");
            }
            else
            {
                Out("FAIL\r\n");
            }
        }
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(sess);

    Out("[winhttp_smoke] done\r\n");
    ExitProcess(0);
}
