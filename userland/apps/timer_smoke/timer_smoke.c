/*
 * timer_smoke — exercise SetTimer / KillTimer (window timers)
 * and CreateTimerQueue / CreateTimerQueueTimer.
 *
 *   SetTimer (NULL hwnd — system queue)
 *   KillTimer
 *   CreateTimerQueue
 *   CreateTimerQueueTimer (skipped — needs callback)
 *   DeleteTimerQueue
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
    Out("[timer_smoke] starting\r\n");

    /* SetTimer(NULL, 0, ms, NULL) — schedules a WM_TIMER msg. */
    UINT_PTR id = SetTimer(NULL, 0, 100, NULL);
    Out("[timer_smoke] SetTimer            = ");
    Out(id != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (id != 0)
    {
        BOOL k = KillTimer(NULL, id);
        Out("[timer_smoke] KillTimer           = ");
        Out(k ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* CreateTimerQueue. */
    {
        HANDLE q = CreateTimerQueue();
        Out("[timer_smoke] CreateTimerQueue    = ");
        Out(q != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (q != NULL)
        {
            BOOL d = DeleteTimerQueue(q);
            Out("[timer_smoke] DeleteTimerQueue    = ");
            Out(d ? "PASS\r\n" : "FAIL/STUB\r\n");
        }
    }

    Out("[timer_smoke] done\r\n");
    ExitProcess(0);
}
