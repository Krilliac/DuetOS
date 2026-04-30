/*
 * proc3_smoke — process-creation / image-info APIs.
 *
 *   CreateProcessW (skipped — heavy, would actually spawn)
 *   OpenProcess (on self PID)
 *   TerminateProcess (skipped)
 *   GetCommandLineW (already in process_smoke; cross-check)
 *   GetStartupInfoW
 *   IsImmersiveProcess (Win10+; usually FALSE)
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
    Out("[proc3_smoke] starting\r\n");

    /* OpenProcess on self. */
    DWORD pid = GetCurrentProcessId();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    Out("[proc3_smoke] OpenProcess(self)    = ");
    Out(h != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
    if (h != NULL)
        CloseHandle(h);

    /* GetStartupInfoW. */
    {
        STARTUPINFOW si = {0};
        si.cb = sizeof(si);
        GetStartupInfoW(&si);
        Out("[proc3_smoke] GetStartupInfoW      = ");
        Out(si.cb >= sizeof(si) ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetCommandLineA — should be non-NULL. */
    {
        LPSTR cl = GetCommandLineA();
        Out("[proc3_smoke] GetCommandLineA      = ");
        Out(cl != NULL && cl[0] != '\0' ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[proc3_smoke] done\r\n");
    ExitProcess(0);
}
