/* wtsapi32.dll — Remote Desktop / Terminal Services. All stubs. */
typedef int BOOL;
typedef unsigned long DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define WTS_CURRENT_SERVER_HANDLE ((HANDLE)0)

__declspec(dllexport) BOOL WTSQuerySessionInformationA(HANDLE server, DWORD session, int info_class, char** buf,
                                                       DWORD* len)
{
    (void)server;
    (void)session;
    (void)info_class;
    if (buf)
        *buf = (char*)0;
    if (len)
        *len = 0;
    return 0;
}
__declspec(dllexport) BOOL WTSQuerySessionInformationW(HANDLE server, DWORD session, int info_class, wchar_t16** buf,
                                                       DWORD* len)
{
    (void)server;
    (void)session;
    (void)info_class;
    if (buf)
        *buf = (wchar_t16*)0;
    if (len)
        *len = 0;
    return 0;
}
__declspec(dllexport) void WTSFreeMemory(void* mem)
{
    (void)mem;
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
