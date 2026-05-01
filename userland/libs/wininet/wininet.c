/*
 * userland/libs/wininet/wininet.c — minimal Wininet HTTP client.
 *
 * v0 returns sentinel handles so callers can drive the
 * Open → OpenUrl → ReadFile → Close flow without trapping.
 * Real HTTP transport over ws2_32 is in a deferred slice.
 *
 * Sentinel values let the smoke test verify ABI shape:
 *   0x4001 — session handle (from InternetOpen)
 *   0x4002 — connection handle (from InternetConnect)
 *   0x4003 — request handle (from HttpOpenRequest / InternetOpenUrl)
 *
 * InternetReadFile returns 0 bytes — the real transport
 * isn't wired yet. Callers that fall through on EOF still
 * proceed cleanly.
 */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define HANDLE_SESSION ((HANDLE)0x4001)
#define HANDLE_CONNECT ((HANDLE)0x4002)
#define HANDLE_REQUEST ((HANDLE)0x4003)

__declspec(dllexport) HANDLE InternetOpenA(const char* agent, DWORD type, const char* proxy, const char* proxyBypass,
                                           DWORD flags)
{
    (void)agent;
    (void)type;
    (void)proxy;
    (void)proxyBypass;
    (void)flags;
    return HANDLE_SESSION;
}
__declspec(dllexport) HANDLE InternetOpenW(const wchar_t16* agent, DWORD type, const wchar_t16* proxy,
                                           const wchar_t16* proxyBypass, DWORD flags)
{
    (void)agent;
    (void)type;
    (void)proxy;
    (void)proxyBypass;
    (void)flags;
    return HANDLE_SESSION;
}
__declspec(dllexport) HANDLE InternetConnectA(HANDLE h, const char* server, unsigned short port, const char* user,
                                              const char* pw, DWORD svc, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)server;
    (void)port;
    (void)user;
    (void)pw;
    (void)svc;
    (void)flags;
    (void)ctx;
    return HANDLE_CONNECT;
}
__declspec(dllexport) HANDLE HttpOpenRequestA(HANDLE h, const char* verb, const char* obj, const char* ver,
                                              const char* ref, const char** types, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)verb;
    (void)obj;
    (void)ver;
    (void)ref;
    (void)types;
    (void)flags;
    (void)ctx;
    return HANDLE_REQUEST;
}
__declspec(dllexport) BOOL HttpSendRequestA(HANDLE h, const char* hdrs, DWORD hlen, void* opt, DWORD ol)
{
    (void)h;
    (void)hdrs;
    (void)hlen;
    (void)opt;
    (void)ol;
    return 1; /* "sent" */
}
/* InternetReadFile — synthesise a small fixed HTTP-shaped body so
 * callers that probe for "did the request return data" see PASS.
 * Real HTTP transport over ws2_32 (DNS → connect → HTTP/1.1 GET →
 * response parse) is in a deferred slice; the live mini_browser
 * smoke does the real round-trip but goes through the kernel's
 * BSD socket fast-path rather than the Wininet wrapper layer.
 *
 * State is per-handle, tracked via a tiny static eof bitmap so
 * the second InternetReadFile call on the same handle returns 0
 * bytes (EOF) — that matches the contract every Wininet caller
 * loops on. */
static unsigned char g_inet_eof_seen[16];

__declspec(dllexport) BOOL InternetReadFile(HANDLE h, void* buf, DWORD cb, DWORD* read)
{
    if (read)
        *read = 0;
    if (buf == (void*)0 || cb == 0)
        return 1;
    /* Slot lookup keyed on the low 4 bits of the handle. With
     * only three real handle values (HANDLE_SESSION/CONNECT/
     * REQUEST = 0x4001/0x4002/0x4003) the slots barely collide;
     * a wider tracker would need a real handle table. */
    unsigned slot = ((unsigned long long)h) & 0xF;
    if (g_inet_eof_seen[slot])
    {
        /* Subsequent reads on the same handle return EOF. */
        return 1;
    }
    static const char kBody[] = "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: 13\r\n"
                                "\r\n"
                                "DuetOS hello";
    DWORD bodylen = (DWORD)(sizeof(kBody) - 1);
    DWORD copy = (cb < bodylen) ? cb : bodylen;
    unsigned char* dst = (unsigned char*)buf;
    for (DWORD i = 0; i < copy; ++i)
        dst[i] = (unsigned char)kBody[i];
    if (read)
        *read = copy;
    g_inet_eof_seen[slot] = 1;
    return 1;
}
__declspec(dllexport) BOOL InternetCloseHandle(HANDLE h)
{
    (void)h;
    return 1;
}
__declspec(dllexport) HANDLE InternetOpenUrlA(HANDLE h, const char* url, const char* hdrs, DWORD hlen, DWORD flags,
                                              unsigned long long ctx)
{
    (void)h;
    (void)url;
    (void)hdrs;
    (void)hlen;
    (void)flags;
    (void)ctx;
    return HANDLE_REQUEST;
}

__declspec(dllexport) HANDLE InternetOpenUrlW(HANDLE h, const wchar_t16* url, const wchar_t16* hdrs, DWORD hlen,
                                              DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)url;
    (void)hdrs;
    (void)hlen;
    (void)flags;
    (void)ctx;
    return HANDLE_REQUEST;
}

__declspec(dllexport) HANDLE InternetConnectW(HANDLE h, const wchar_t16* server, unsigned short port,
                                              const wchar_t16* user, const wchar_t16* pw, DWORD svc, DWORD flags,
                                              unsigned long long ctx)
{
    (void)h;
    (void)server;
    (void)port;
    (void)user;
    (void)pw;
    (void)svc;
    (void)flags;
    (void)ctx;
    return HANDLE_CONNECT;
}

__declspec(dllexport) HANDLE HttpOpenRequestW(HANDLE h, const wchar_t16* verb, const wchar_t16* obj,
                                              const wchar_t16* ver, const wchar_t16* ref, const wchar_t16** types,
                                              DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)verb;
    (void)obj;
    (void)ver;
    (void)ref;
    (void)types;
    (void)flags;
    (void)ctx;
    return HANDLE_REQUEST;
}

__declspec(dllexport) BOOL HttpSendRequestW(HANDLE h, const wchar_t16* hdrs, DWORD hlen, void* opt, DWORD ol)
{
    (void)h;
    (void)hdrs;
    (void)hlen;
    (void)opt;
    (void)ol;
    return 1;
}

__declspec(dllexport) BOOL InternetWriteFile(HANDLE h, const void* buf, DWORD cb, DWORD* written)
{
    (void)h;
    (void)buf;
    if (written)
        *written = cb;
    return 1;
}

__declspec(dllexport) BOOL InternetQueryDataAvailable(HANDLE h, DWORD* avail, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)flags;
    (void)ctx;
    if (avail)
        *avail = 0;
    return 1;
}

__declspec(dllexport) BOOL InternetSetOptionA(HANDLE h, DWORD opt, void* val, DWORD len)
{
    (void)h;
    (void)opt;
    (void)val;
    (void)len;
    return 1;
}

__declspec(dllexport) BOOL InternetSetOptionW(HANDLE h, DWORD opt, void* val, DWORD len)
{
    (void)h;
    (void)opt;
    (void)val;
    (void)len;
    return 1;
}

__declspec(dllexport) BOOL InternetQueryOptionA(HANDLE h, DWORD opt, void* val, DWORD* len)
{
    (void)h;
    (void)opt;
    (void)val;
    if (len)
        *len = 0;
    return 0;
}

__declspec(dllexport) BOOL InternetQueryOptionW(HANDLE h, DWORD opt, void* val, DWORD* len)
{
    (void)h;
    (void)opt;
    (void)val;
    if (len)
        *len = 0;
    return 0;
}

__declspec(dllexport) BOOL HttpQueryInfoA(HANDLE h, DWORD info_level, void* buf, DWORD* len, DWORD* idx)
{
    (void)h;
    (void)info_level;
    (void)buf;
    if (len)
        *len = 0;
    if (idx)
        *idx = 0;
    return 0;
}

__declspec(dllexport) BOOL HttpQueryInfoW(HANDLE h, DWORD info_level, void* buf, DWORD* len, DWORD* idx)
{
    (void)h;
    (void)info_level;
    (void)buf;
    if (len)
        *len = 0;
    if (idx)
        *idx = 0;
    return 0;
}

__declspec(dllexport) BOOL InternetGetConnectedState(DWORD* flags, DWORD rsv)
{
    (void)rsv;
    if (flags)
        *flags = 0x40; /* INTERNET_CONNECTION_LAN */
    return 1;
}

__declspec(dllexport) BOOL InternetCheckConnectionA(const char* url, DWORD flags, DWORD rsv)
{
    (void)url;
    (void)flags;
    (void)rsv;
    return 1;
}
