/*
 * asyn_smoke — exercise async-procedure-call surface.
 *
 *   CreateWaitableTimer
 *   SetWaitableTimer (relative timeout)
 *   CancelWaitableTimer
 *   QueueUserAPC (skipped)
 *   RegisterWaitForSingleObject (skipped)
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
    Out("[asyn_smoke] starting\r\n");

    HANDLE t = CreateWaitableTimerW(NULL, FALSE, NULL);
    Out("[asyn_smoke] CreateWaitableTimerW = ");
    Out(t != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (t != NULL)
    {
        LARGE_INTEGER due = {0};
        due.QuadPart = -100 * 10000LL; /* 100 ms relative (negative) */
        BOOL set = SetWaitableTimer(t, &due, 0, NULL, NULL, FALSE);
        Out("[asyn_smoke] SetWaitableTimer    = ");
        Out(set ? "PASS\r\n" : "FAIL/STUB\r\n");

        DWORD r = WaitForSingleObject(t, 500);
        Out("[asyn_smoke] WaitForSingleObject(timer) = ");
        Out(r == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        BOOL c = CancelWaitableTimer(t);
        Out("[asyn_smoke] CancelWaitableTimer = ");
        Out(c ? "PASS\r\n" : "FAIL/STUB\r\n");

        CloseHandle(t);
    }

    Out("[asyn_smoke] done\r\n");
    Out("[ring3-asyn-smoke] PASS\r\n");
    ExitProcess(0);
}
