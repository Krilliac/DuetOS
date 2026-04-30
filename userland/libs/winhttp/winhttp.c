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
__declspec(dllexport) BOOL WinHttpReadData(HANDLE h, void* buf, DWORD cb, DWORD* read)
{
    (void)h;
    (void)buf;
    (void)cb;
    /* No transport yet — return TRUE with 0 bytes (EOF). */
    if (read)
        *read = 0;
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
