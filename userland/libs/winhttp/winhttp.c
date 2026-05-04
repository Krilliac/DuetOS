/*
 * winhttp.dll — modern HTTP client. v0 returns sentinel handles
 * so callers can drive Open → Connect → Request → Send → Receive
 * → Read → Close without trapping. Real HTTP transport over
 * ws2_32 deferred to a later slice.
 *
 * Sentinel values:
 *   0x5001 — session
 *   0x5002 — connection
 *   0x5003 — request
 */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define WHTTP_SESSION ((HANDLE)0x5001)
#define WHTTP_CONNECT ((HANDLE)0x5002)
#define WHTTP_REQUEST ((HANDLE)0x5003)

__declspec(dllexport) HANDLE WinHttpOpen(const wchar_t16* agent, DWORD accessType, const wchar_t16* proxy,
                                         const wchar_t16* bypass, DWORD flags)
{
    (void)agent;
    (void)accessType;
    (void)proxy;
    (void)bypass;
    (void)flags;
    return WHTTP_SESSION;
}
__declspec(dllexport) HANDLE WinHttpConnect(HANDLE h, const wchar_t16* server, unsigned short port, DWORD rsv)
{
    (void)h;
    (void)server;
    (void)port;
    (void)rsv;
    return WHTTP_CONNECT;
}
__declspec(dllexport) HANDLE WinHttpOpenRequest(HANDLE h, const wchar_t16* verb, const wchar_t16* obj,
                                                const wchar_t16* ver, const wchar_t16* ref, const wchar_t16** types,
                                                DWORD flags)
{
    (void)h;
    (void)verb;
    (void)obj;
    (void)ver;
    (void)ref;
    (void)types;
    (void)flags;
    return WHTTP_REQUEST;
}
__declspec(dllexport) BOOL WinHttpSendRequest(HANDLE h, const wchar_t16* hdrs, DWORD hlen, void* opt, DWORD ol,
                                              DWORD total, unsigned long long ctx)
{
    (void)h;
    (void)hdrs;
    (void)hlen;
    (void)opt;
    (void)ol;
    (void)total;
    (void)ctx;
    return 1;
}
__declspec(dllexport) BOOL WinHttpReceiveResponse(HANDLE h, void* rsv)
{
    (void)h;
    (void)rsv;
    return 1;
}
/* WinHttpReadData — synthesise a small fixed body on the first
 * read of each handle, EOF on subsequent reads. Mirrors the
 * Wininet equivalent; real WinHttp transport over ws2_32 lands
 * with the same slice that wires Wininet for real. */
static unsigned char g_winhttp_eof_seen[16];

__declspec(dllexport) BOOL WinHttpReadData(HANDLE h, void* buf, DWORD cb, DWORD* read)
{
    if (read)
        *read = 0;
    if (buf == (void*)0 || cb == 0)
        return 1;
    unsigned slot = ((unsigned long long)h) & 0xF;
    if (g_winhttp_eof_seen[slot])
        return 1;
    static const char kBody[] = "DuetOS WinHttp hello";
    DWORD bodylen = (DWORD)(sizeof(kBody) - 1);
    DWORD copy = (cb < bodylen) ? cb : bodylen;
    unsigned char* dst = (unsigned char*)buf;
    for (DWORD i = 0; i < copy; ++i)
        dst[i] = (unsigned char)kBody[i];
    if (read)
        *read = copy;
    g_winhttp_eof_seen[slot] = 1;
    return 1;
}
__declspec(dllexport) BOOL WinHttpCloseHandle(HANDLE h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL WinHttpQueryDataAvailable(HANDLE h, DWORD* avail)
{
    (void)h;
    if (avail)
        *avail = 0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpQueryHeaders(HANDLE h, DWORD info_level, const wchar_t16* name, void* buf, DWORD* len,
                                               DWORD* idx)
{
    (void)h;
    (void)info_level;
    (void)name;
    (void)buf;
    if (len)
        *len = 0;
    if (idx)
        *idx = 0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpAddRequestHeaders(HANDLE h, const wchar_t16* hdrs, DWORD len, DWORD modifiers)
{
    (void)h;
    (void)hdrs;
    (void)len;
    (void)modifiers;
    return 1;
}

__declspec(dllexport) BOOL WinHttpSetOption(HANDLE h, DWORD opt, const void* val, DWORD len)
{
    (void)h;
    (void)opt;
    (void)val;
    (void)len;
    return 1;
}

__declspec(dllexport) BOOL WinHttpQueryOption(HANDLE h, DWORD opt, void* val, DWORD* len)
{
    (void)h;
    (void)opt;
    (void)val;
    if (len)
        *len = 0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpSetTimeouts(HANDLE h, int resolve, int connect, int send, int receive)
{
    (void)h;
    (void)resolve;
    (void)connect;
    (void)send;
    (void)receive;
    return 1;
}

__declspec(dllexport) BOOL WinHttpSetStatusCallback(HANDLE h, void* cb, DWORD flags, unsigned long long rsv)
{
    (void)h;
    (void)cb;
    (void)flags;
    (void)rsv;
    return 1;
}

__declspec(dllexport) BOOL WinHttpCheckPlatform(void)
{
    return 1;
}

__declspec(dllexport) BOOL WinHttpCrackUrl(const wchar_t16* url, DWORD len, DWORD flags, void* components)
{
    (void)url;
    (void)len;
    (void)flags;
    (void)components;
    return 0;
}

/* WinHttpQueryAuthSchemes — auth-mechanism probe. v0 reports
 * "no auth schemes" so callers fall through to anonymous. */
__declspec(dllexport) BOOL WinHttpQueryAuthSchemes(HANDLE h, DWORD* supported, DWORD* first, DWORD* target)
{
    (void)h;
    if (supported)
        *supported = 0;
    if (first)
        *first = 0;
    if (target)
        *target = 0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpSetCredentials(HANDLE h, DWORD auth_targets, DWORD auth_scheme, const wchar_t16* user,
                                                 const wchar_t16* pass, void* p_auth_params)
{
    (void)h;
    (void)auth_targets;
    (void)auth_scheme;
    (void)user;
    (void)pass;
    (void)p_auth_params;
    return 1;
}

__declspec(dllexport) BOOL WinHttpDetectAutoProxyConfigUrl(DWORD detect_flags, wchar_t16** url)
{
    (void)detect_flags;
    if (url)
        *url = (wchar_t16*)0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpGetIEProxyConfigForCurrentUser(void* config)
{
    if (config)
    {
        unsigned char* p = (unsigned char*)config;
        for (int i = 0; i < 32; ++i)
            p[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL WinHttpGetProxyForUrl(HANDLE session, const wchar_t16* url, void* p_auto_proxy_options,
                                                 void* p_proxy_info)
{
    (void)session;
    (void)url;
    (void)p_auto_proxy_options;
    if (p_proxy_info)
    {
        unsigned char* p = (unsigned char*)p_proxy_info;
        for (int i = 0; i < 24; ++i)
            p[i] = 0;
    }
    return 0;
}

__declspec(dllexport) BOOL WinHttpGetDefaultProxyConfiguration(void* p_proxy_info)
{
    if (p_proxy_info)
    {
        unsigned char* p = (unsigned char*)p_proxy_info;
        for (int i = 0; i < 24; ++i)
            p[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL WinHttpSetDefaultProxyConfiguration(void* p_proxy_info)
{
    (void)p_proxy_info;
    return 1;
}

__declspec(dllexport) BOOL WinHttpResetAutoProxy(HANDLE session, DWORD flags)
{
    (void)session;
    (void)flags;
    return 1;
}

/* WinHttpCreateUrl — assemble URL from components. v0 reports
 * 0-length / failure. */
__declspec(dllexport) BOOL WinHttpCreateUrl(void* components, DWORD flags, wchar_t16* url, DWORD* url_len)
{
    (void)components;
    (void)flags;
    if (url && url_len && *url_len > 0)
        url[0] = 0;
    if (url_len)
        *url_len = 0;
    return 0;
}

/* WinHttpTimeFromSystemTime / WinHttpTimeToSystemTime — RFC 1123
 * date conversion. v0 returns failure. */
__declspec(dllexport) BOOL WinHttpTimeFromSystemTime(const void* time_st, wchar_t16* http_time)
{
    (void)time_st;
    if (http_time)
        http_time[0] = 0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpTimeToSystemTime(const wchar_t16* http_time, void* time_st)
{
    (void)http_time;
    if (time_st)
    {
        unsigned char* p = (unsigned char*)time_st;
        for (int i = 0; i < 16; ++i) /* SYSTEMTIME = 8 WORDs */
            p[i] = 0;
    }
    return 0;
}

/* WinHttpReadDataEx — extended read variant. */
__declspec(dllexport) DWORD WinHttpReadDataEx(HANDLE h, void* buf, DWORD cb, DWORD* read, unsigned long long flags,
                                              DWORD prop_buf_size, const void* prop_buf)
{
    (void)flags;
    (void)prop_buf_size;
    (void)prop_buf;
    return WinHttpReadData(h, buf, cb, read) ? 0 : 1;
}

/* WinHttpWriteData — POST body bytes. v0 reports success
 * regardless of whether the bytes go anywhere. */
__declspec(dllexport) BOOL WinHttpWriteData(HANDLE h, const void* buf, DWORD cb, DWORD* written)
{
    (void)h;
    (void)buf;
    if (written)
        *written = cb;
    return 1;
}

__declspec(dllexport) BOOL WinHttpQueryDataAvailable2(HANDLE h, DWORD* avail)
{
    (void)h;
    if (avail)
        *avail = 0;
    return 1;
}

/* WinHttpWebSocketCompleteUpgrade etc. — WebSocket support. v0
 * has no WS layer; report failure. */
__declspec(dllexport) HANDLE WinHttpWebSocketCompleteUpgrade(HANDLE h, unsigned long long ctx)
{
    (void)h;
    (void)ctx;
    return (HANDLE)0;
}

__declspec(dllexport) DWORD WinHttpWebSocketSend(HANDLE h, int buf_type, void* buf, DWORD cb)
{
    (void)h;
    (void)buf_type;
    (void)buf;
    (void)cb;
    return 0xC0000002UL;
}

__declspec(dllexport) DWORD WinHttpWebSocketReceive(HANDLE h, void* buf, DWORD cb, DWORD* read, int* buf_type)
{
    (void)h;
    (void)buf;
    (void)cb;
    if (read)
        *read = 0;
    if (buf_type)
        *buf_type = 0;
    return 0xC0000002UL;
}

__declspec(dllexport) DWORD WinHttpWebSocketClose(HANDLE h, unsigned short status, void* reason, DWORD reason_len)
{
    (void)h;
    (void)status;
    (void)reason;
    (void)reason_len;
    return 0;
}

__declspec(dllexport) DWORD WinHttpWebSocketShutdown(HANDLE h, unsigned short status, void* reason, DWORD reason_len)
{
    (void)h;
    (void)status;
    (void)reason;
    (void)reason_len;
    return 0;
}
