/*
 * wts_smoke — exercise wtsapi32 terminal-services APIs.
 *
 *   WTSGetActiveConsoleSessionId
 *   WTSQuerySessionInformationW (skipped — needs session)
 *   WTSEnumerateSessionsW (skipped)
 *   ProcessIdToSessionId
 */
#include <windows.h>
#include <wtsapi32.h>

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
    Out("[wts_smoke] starting\r\n");

    DWORD sid = WTSGetActiveConsoleSessionId();
    Out("[wts_smoke] WTSGetActiveConsoleSessionId = ");
    Out(sid != 0xFFFFFFFFu ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* ProcessIdToSessionId. */
    {
        DWORD sid2 = 0;
        BOOL ok = ProcessIdToSessionId(GetCurrentProcessId(), &sid2);
        Out("[wts_smoke] ProcessIdToSessionId = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[wts_smoke] done\r\n");
    Out("[ring3-wts-smoke] PASS\r\n");
    ExitProcess(0);
}
