/*
 * eventlog_smoke — exercise advapi32 Windows Event Log APIs.
 *
 *   RegisterEventSourceW
 *   ReportEventW
 *   DeregisterEventSource
 *
 * v0: no event-log database; calls likely return success
 * sentinels but don't actually persist. The smoke value is
 * verifying that crash-reporting paths through event log
 * don't trap.
 */
#include <windows.h>

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
    Out("[eventlog_smoke] starting\r\n");

    HANDLE src = RegisterEventSourceW(NULL, L"DuetOSSmoke");
    Out("[eventlog_smoke] RegisterEventSourceW = ");
    Out(src != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (src != NULL)
    {
        const WCHAR* msg = L"smoke test";
        const WCHAR* msgs[1] = {msg};
        BOOL ok = ReportEventW(src, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, msgs, NULL);
        Out("[eventlog_smoke] ReportEventW         = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

        BOOL d = DeregisterEventSource(src);
        Out("[eventlog_smoke] DeregisterEventSource= ");
        Out(d ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[eventlog_smoke] done\r\n");
    Out("[ring3-eventlog-smoke] PASS\r\n");
    ExitProcess(0);
}
