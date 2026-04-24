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
