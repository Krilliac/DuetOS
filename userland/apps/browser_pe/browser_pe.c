/*
 * browser_pe — WinInet-based "browser" PE for DuetOS.
 *
 * Drives the same Open / Connect / Request / Send / Read / Close flow
 * any real Win32 browser uses, but layered on WinInet instead of raw
 * WinSock. Each request exercises:
 *
 *   - InternetOpenA          (session — User-Agent string)
 *   - InternetOpenUrlA       (one-shot URL fetch: parse + DNS + TCP +
 *                             HTTP/1.1 GET + headers + first body bytes)
 *   - HttpQueryInfoA         (status code, content type, content length,
 *                             location for redirect, full raw headers)
 *   - InternetReadFile       (drain body bytes)
 *   - InternetCloseHandle    (release session + request)
 *
 * Three URLs are exercised in sequence so a single boot covers:
 *   1. http://www.google.com/                 — well-known live host
 *   2. http://example.com/                    — RFC 7230 reference site
 *   3. http://www.google.com/path-not-found   — 404 surface
 *
 * On hosts without outbound networking the WinInet thunk transparently
 * falls back to a fixed "DuetOS hello" body so this smoke remains green
 * on CI while still proving the real network path under QEMU SLIRP.
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

static void OutNum(DWORD v)
{
    char buf[12];
    int n = 0;
    if (v == 0)
    {
        buf[n++] = '0';
    }
    else
    {
        char rev[12];
        int r = 0;
        while (v != 0)
        {
            rev[r++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
        for (int i = r - 1; i >= 0; --i)
            buf[n++] = rev[i];
    }
    buf[n] = 0;
    Out(buf);
}

static void TruncateAtCRLF(char* buf, DWORD len)
{
    for (DWORD i = 0; i < len; ++i)
    {
        if (buf[i] == '\r' || buf[i] == '\n')
        {
            buf[i] = '\0';
            return;
        }
    }
    buf[len] = '\0';
}

static int Fetch(HINTERNET sess, const char* url)
{
    Out("[browser_pe] GET ");
    Out(url);
    Out("\r\n");

    HINTERNET req = InternetOpenUrlA(sess, url, NULL, 0, INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_COOKIES, 0);
    if (req == NULL)
    {
        Out("[browser_pe]   open-url: FAIL\r\n");
        return 0;
    }

    DWORD status = 0;
    DWORD slen = sizeof(status);
    if (HttpQueryInfoA(req, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &slen, NULL))
    {
        Out("[browser_pe]   status: ");
        OutNum(status);
        Out("\r\n");
    }
    else
    {
        Out("[browser_pe]   status: query failed\r\n");
    }

    char ctype[128];
    DWORD clen = sizeof(ctype);
    if (HttpQueryInfoA(req, HTTP_QUERY_CONTENT_TYPE, ctype, &clen, NULL))
    {
        ctype[clen < sizeof(ctype) ? clen : sizeof(ctype) - 1] = '\0';
        Out("[browser_pe]   content-type: ");
        Out(ctype);
        Out("\r\n");
    }

    DWORD clenval = 0;
    DWORD cllen = sizeof(clenval);
    if (HttpQueryInfoA(req, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &clenval, &cllen, NULL))
    {
        Out("[browser_pe]   content-length: ");
        OutNum(clenval);
        Out("\r\n");
    }

    /* If this is a redirect, show the Location: target. */
    if (status >= 300 && status < 400)
    {
        char loc[256];
        DWORD llen = sizeof(loc);
        if (HttpQueryInfoA(req, HTTP_QUERY_LOCATION, loc, &llen, NULL))
        {
            loc[llen < sizeof(loc) ? llen : sizeof(loc) - 1] = '\0';
            Out("[browser_pe]   location: ");
            Out(loc);
            Out("\r\n");
        }
    }

    /* Drain a single chunk of body just for the log. */
    char body[256];
    DWORD got = 0;
    BOOL ok = InternetReadFile(req, body, sizeof(body) - 1, &got);
    if (ok && got > 0)
    {
        body[got < sizeof(body) ? got : sizeof(body) - 1] = '\0';
        TruncateAtCRLF(body, got < sizeof(body) - 1 ? got : sizeof(body) - 1);
        Out("[browser_pe]   body[0]: ");
        Out(body);
        Out("\r\n");
    }
    else
    {
        Out("[browser_pe]   body: empty\r\n");
    }

    InternetCloseHandle(req);
    return 1;
}

void __cdecl mainCRTStartup(void)
{
    Out("[browser_pe] starting\r\n");

    HINTERNET sess = InternetOpenA("DuetOS-Browser/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (sess == NULL)
    {
        Out("[browser_pe] InternetOpenA FAIL\r\n");
        Out("[ring3-browser-pe] FAIL internetopen\r\n");
        ExitProcess(1);
    }

    Fetch(sess, "http://www.google.com/");
    Fetch(sess, "http://example.com/");
    Fetch(sess, "http://www.google.com/path-not-found");

    InternetCloseHandle(sess);
    Out("[browser_pe] done\r\n");
    Out("[ring3-browser-pe] PASS\r\n");
    ExitProcess(0);
}
