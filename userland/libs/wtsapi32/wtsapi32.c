/* wtsapi32.dll — Remote Desktop / Terminal Services. v0 reports a
 * single console session (id 1) belonging to "user" on "duetos".
 * Allocates the returned buffers from a small static pool because
 * the v0 ring-3 heap doesn't have a per-DLL allocator; WTSFreeMemory
 * recognises pool-resident pointers and clears the in-use flag. */
typedef int BOOL;
typedef unsigned long DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define WTS_CURRENT_SERVER_HANDLE ((HANDLE)0)

/* WTS_INFO_CLASS values we recognise. The Windows enum is much
 * larger; everything not listed here falls through to FALSE. */
enum
{
    WTSInitialProgram = 0,
    WTSApplicationName = 1,
    WTSWorkingDirectory = 2,
    WTSOEMId = 3,
    WTSSessionId = 4,
    WTSUserName = 5,
    WTSWinStationName = 6,
    WTSDomainName = 7,
    WTSConnectState = 8,
    WTSClientName = 10,
    WTSClientProtocolType = 16,
};

/* Static pool: 8 slots, 64 bytes each — large enough for the
 * known-string responses below (max 16 wide chars + NUL = 34
 * bytes). Each slot has a u32 in-use flag at offset 0; the
 * caller-visible pointer is offset 8 to keep alignment + room
 * for the flag word. */
#define WTS_POOL_SLOTS 8
#define WTS_POOL_SLOT_BYTES 64
static unsigned char g_wts_pool[WTS_POOL_SLOTS][WTS_POOL_SLOT_BYTES];
static unsigned int g_wts_pool_inuse[WTS_POOL_SLOTS];

static unsigned char* wts_pool_alloc(void)
{
    for (int i = 0; i < WTS_POOL_SLOTS; ++i)
    {
        if (!g_wts_pool_inuse[i])
        {
            g_wts_pool_inuse[i] = 1;
            return &g_wts_pool[i][8];
        }
    }
    return (unsigned char*)0;
}

static int wts_pool_free(void* p)
{
    if (!p)
        return 0;
    unsigned char* base = (unsigned char*)p - 8;
    for (int i = 0; i < WTS_POOL_SLOTS; ++i)
    {
        if (base == &g_wts_pool[i][0])
        {
            g_wts_pool_inuse[i] = 0;
            return 1;
        }
    }
    return 0;
}

/* ASCII string write into a pool-allocated buf; returns NUL-included
 * byte count or 0 if pool exhausted. */
static unsigned long wts_write_a(const char* s, char** out_buf)
{
    unsigned long n = 0;
    while (s[n])
        ++n;
    unsigned char* p = wts_pool_alloc();
    if (!p)
        return 0;
    for (unsigned long i = 0; i <= n; ++i)
        p[i] = (unsigned char)s[i];
    *out_buf = (char*)p;
    return n + 1;
}

/* UTF-16LE write; same return convention (byte count, not char count). */
static unsigned long wts_write_w(const char* s, wchar_t16** out_buf)
{
    unsigned long n = 0;
    while (s[n])
        ++n;
    unsigned char* p = wts_pool_alloc();
    if (!p)
        return 0;
    wchar_t16* w = (wchar_t16*)p;
    for (unsigned long i = 0; i <= n; ++i)
        w[i] = (wchar_t16)(unsigned char)s[i];
    *out_buf = w;
    return (n + 1) * 2;
}

/* DWORD pool write — for SessionId / ConnectState / ClientProtocolType. */
static unsigned long wts_write_dword(DWORD v, char** out_buf)
{
    unsigned char* p = wts_pool_alloc();
    if (!p)
        return 0;
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
    *out_buf = (char*)p;
    return 4;
}

__declspec(dllexport) BOOL WTSQuerySessionInformationA(HANDLE server, DWORD session, int info_class, char** buf,
                                                       DWORD* len)
{
    (void)server;
    (void)session;
    if (!buf)
        return 0;
    *buf = (char*)0;
    if (len)
        *len = 0;
    unsigned long n = 0;
    switch (info_class)
    {
    case WTSUserName:
        n = wts_write_a("user", buf);
        break;
    case WTSWinStationName:
    case WTSClientName:
        n = wts_write_a("Console", buf);
        break;
    case WTSDomainName:
        n = wts_write_a("DUETOS", buf);
        break;
    case WTSInitialProgram:
    case WTSApplicationName:
    case WTSWorkingDirectory:
    case WTSOEMId:
        n = wts_write_a("", buf);
        break;
    case WTSSessionId:
        n = wts_write_dword(1, buf);
        break;
    case WTSConnectState:
        /* WTSActive = 0 */
        n = wts_write_dword(0, buf);
        break;
    case WTSClientProtocolType:
        /* 0 = console */
        n = wts_write_dword(0, buf);
        break;
    default:
        return 0;
    }
    if (n == 0)
        return 0;
    if (len)
        *len = (DWORD)n;
    return 1;
}
__declspec(dllexport) BOOL WTSQuerySessionInformationW(HANDLE server, DWORD session, int info_class, wchar_t16** buf,
                                                       DWORD* len)
{
    (void)server;
    (void)session;
    if (!buf)
        return 0;
    *buf = (wchar_t16*)0;
    if (len)
        *len = 0;
    unsigned long n = 0;
    switch (info_class)
    {
    case WTSUserName:
        n = wts_write_w("user", buf);
        break;
    case WTSWinStationName:
    case WTSClientName:
        n = wts_write_w("Console", buf);
        break;
    case WTSDomainName:
        n = wts_write_w("DUETOS", buf);
        break;
    case WTSInitialProgram:
    case WTSApplicationName:
    case WTSWorkingDirectory:
    case WTSOEMId:
        n = wts_write_w("", buf);
        break;
    case WTSSessionId:
        n = wts_write_dword(1, (char**)buf);
        break;
    case WTSConnectState:
        n = wts_write_dword(0, (char**)buf);
        break;
    case WTSClientProtocolType:
        n = wts_write_dword(0, (char**)buf);
        break;
    default:
        return 0;
    }
    if (n == 0)
        return 0;
    if (len)
        *len = (DWORD)n;
    return 1;
}
__declspec(dllexport) void WTSFreeMemory(void* mem)
{
    (void)wts_pool_free(mem);
}
__declspec(dllexport) BOOL WTSEnumerateSessionsW(HANDLE server, DWORD rsv, DWORD ver, void** sess_info, DWORD* count)
{
    (void)server;
    (void)rsv;
    (void)ver;
    if (sess_info)
        *sess_info = (void*)0;
    if (count)
        *count = 0;
    return 0;
}
__declspec(dllexport) BOOL WTSRegisterSessionNotification(HANDLE wnd, DWORD flags)
{
    (void)wnd;
    (void)flags;
    return 0;
}
__declspec(dllexport) BOOL WTSUnRegisterSessionNotification(HANDLE wnd)
{
    (void)wnd;
    return 1;
}

/* WTSGetActiveConsoleSessionId — current console session. v0
 * runs as a single-user single-session system, so report
 * session 1 (matches Windows default for the local console). */
__declspec(dllexport) DWORD WTSGetActiveConsoleSessionId(void)
{
    return 1;
}

/* WTSQueryUserToken — get the access token for a session. v0
 * has no token model; report failure so callers fall through
 * to GetCurrentProcessToken. */
__declspec(dllexport) BOOL WTSQueryUserToken(DWORD session_id, HANDLE* token)
{
    (void)session_id;
    if (token)
        *token = (HANDLE)0;
    return 0;
}

/* WTSEnumerateSessionsA — same canned "no sessions" answer as
 * the W variant. */
__declspec(dllexport) BOOL WTSEnumerateSessionsA(HANDLE server, DWORD rsv, DWORD ver, void** sess_info, DWORD* count)
{
    (void)server;
    (void)rsv;
    (void)ver;
    if (sess_info)
        *sess_info = (void*)0;
    if (count)
        *count = 0;
    return 0;
}

/* WTSEnumerateProcessesA / W — empty enum. */
__declspec(dllexport) BOOL WTSEnumerateProcessesA(HANDLE server, DWORD rsv, DWORD ver, void** proc_info, DWORD* count)
{
    (void)server;
    (void)rsv;
    (void)ver;
    if (proc_info)
        *proc_info = (void*)0;
    if (count)
        *count = 0;
    return 0;
}

__declspec(dllexport) BOOL WTSEnumerateProcessesW(HANDLE server, DWORD rsv, DWORD ver, void** proc_info, DWORD* count)
{
    (void)server;
    (void)rsv;
    (void)ver;
    if (proc_info)
        *proc_info = (void*)0;
    if (count)
        *count = 0;
    return 0;
}

/* WTSWaitSystemEvent — block on a session-state change. v0
 * never reports an event so callers see the timeout / abort
 * paths. */
__declspec(dllexport) BOOL WTSWaitSystemEvent(HANDLE server, DWORD event_mask, DWORD* events_out)
{
    (void)server;
    (void)event_mask;
    if (events_out)
        *events_out = 0;
    return 0;
}

/* WTSOpenServerA / W — return the local-server sentinel
 * regardless of input. WTSCloseServer is a no-op. */
__declspec(dllexport) HANDLE WTSOpenServerA(const char* server)
{
    (void)server;
    return WTS_CURRENT_SERVER_HANDLE;
}

__declspec(dllexport) HANDLE WTSOpenServerW(const wchar_t16* server)
{
    (void)server;
    return WTS_CURRENT_SERVER_HANDLE;
}

__declspec(dllexport) void WTSCloseServer(HANDLE server)
{
    (void)server;
}

/* WTSDisconnectSession / WTSLogoffSession — session control.
 * v0 has no session model; report success but do nothing. */
__declspec(dllexport) BOOL WTSDisconnectSession(HANDLE server, DWORD session_id, BOOL wait)
{
    (void)server;
    (void)session_id;
    (void)wait;
    return 1;
}

__declspec(dllexport) BOOL WTSLogoffSession(HANDLE server, DWORD session_id, BOOL wait)
{
    (void)server;
    (void)session_id;
    (void)wait;
    return 1;
}

/* WTSSendMessageA / W — message-box-style notification. v0
 * doesn't display messages; report user "OK" so the caller
 * proceeds. */
__declspec(dllexport) BOOL WTSSendMessageA(HANDLE server, DWORD session, char* title, DWORD title_len, char* msg,
                                           DWORD msg_len, DWORD style, DWORD timeout, DWORD* response, BOOL wait)
{
    (void)server;
    (void)session;
    (void)title;
    (void)title_len;
    (void)msg;
    (void)msg_len;
    (void)style;
    (void)timeout;
    (void)wait;
    if (response)
        *response = 1; /* IDOK */
    return 1;
}

__declspec(dllexport) BOOL WTSSendMessageW(HANDLE server, DWORD session, wchar_t16* title, DWORD title_len,
                                           wchar_t16* msg, DWORD msg_len, DWORD style, DWORD timeout, DWORD* response,
                                           BOOL wait)
{
    (void)server;
    (void)session;
    (void)title;
    (void)title_len;
    (void)msg;
    (void)msg_len;
    (void)style;
    (void)timeout;
    (void)wait;
    if (response)
        *response = 1;
    return 1;
}

/* ProcessIdToSessionId — map any PID to session 1. */
__declspec(dllexport) BOOL ProcessIdToSessionId(DWORD pid, DWORD* session_id)
{
    (void)pid;
    if (session_id)
        *session_id = 1;
    return 1;
}
