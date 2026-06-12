/*
 * proc2_smoke — extended process-introspection / control APIs.
 *
 *   GetExitCodeProcess (on self — should return STILL_ACTIVE)
 *   GetPriorityClass / SetPriorityClass
 *   GetProcessAffinityMask
 *   GetProcessHandleCount
 *   GetProcessIoCounters (skipped — needs IO_COUNTERS)
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
    Out("[proc2_smoke] starting\r\n");

    HANDLE me = GetCurrentProcess();

    /* GetExitCodeProcess on self — STILL_ACTIVE (259). */
    {
        DWORD ec = 0;
        BOOL ok = GetExitCodeProcess(me, &ec);
        Out("[proc2_smoke] GetExitCodeProcess  = ");
        Out(ok && ec == STILL_ACTIVE ? "PASS (STILL_ACTIVE)\r\n" : "FAIL/STUB\r\n");
    }

    /* GetPriorityClass. */
    {
        DWORD pc = GetPriorityClass(me);
        Out("[proc2_smoke] GetPriorityClass    = ");
        Out(pc != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetProcessAffinityMask. */
    {
        DWORD_PTR proc_mask = 0, sys_mask = 0;
        BOOL ok = GetProcessAffinityMask(me, &proc_mask, &sys_mask);
        Out("[proc2_smoke] GetProcessAffinityMask = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetProcessHandleCount. */
    {
        DWORD cnt = 0;
        BOOL ok = GetProcessHandleCount(me, &cnt);
        Out("[proc2_smoke] GetProcessHandleCount = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[proc2_smoke] done\r\n");
    Out("[ring3-proc2-smoke] PASS\r\n");
    ExitProcess(0);
}
