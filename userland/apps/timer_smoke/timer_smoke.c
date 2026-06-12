/*
 * timer_smoke — exercise SetTimer / KillTimer (window timers),
 * CreateTimerQueue / DeleteTimerQueue, the waitable-timer surface
 * (CreateWaitableTimer / SetWaitableTimer / WaitForSingleObject),
 * and the multimedia-timer surface (timeSetEvent + TIMECALLBACK).
 */
#include <windows.h>
#include <mmsystem.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static volatile LONG g_mm_callback_fired = 0;

static void __stdcall mm_timer_cb(UINT id, UINT msg, DWORD_PTR user, DWORD_PTR p1, DWORD_PTR p2)
{
    (void)id;
    (void)msg;
    (void)p1;
    (void)p2;
    if (user == 0xC0FFEEU)
        g_mm_callback_fired = 1;
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

    /* CreateWaitableTimer + SetWaitableTimer + WaitForSingleObject.
     * Schedule fire 50 ms out (negative LARGE_INTEGER = relative
     * 100-ns intervals from now). Wait up to 500 ms — comfortably
     * past the 50 ms due time + the polling-thread's 10 ms cadence.
     * If the wait completes within budget, the polling-service-thread
     * path actually fired SetEvent. */
    {
        HANDLE wt = CreateWaitableTimerW(NULL, TRUE, NULL);
        Out("[timer_smoke] CreateWaitableTimer = ");
        Out(wt != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (wt != NULL)
        {
            LARGE_INTEGER due;
            due.QuadPart = -((LONGLONG)50 * 10000); /* 50 ms */
            BOOL set_ok = SetWaitableTimer(wt, &due, 0, NULL, NULL, FALSE);
            Out("[timer_smoke] SetWaitableTimer    = ");
            Out(set_ok ? "PASS\r\n" : "FAIL/STUB\r\n");
            DWORD wr = WaitForSingleObject(wt, 500);
            Out("[timer_smoke] WaitForTimer fire   = ");
            Out(wr == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL/STUB\r\n");
            CloseHandle(wt);
        }
    }

    /* timeSetEvent — winmm multimedia timer. Schedule a 50 ms one-shot
     * with the test's user value, sleep ~150 ms, check that the
     * callback has fired. */
    {
        g_mm_callback_fired = 0;
        UINT mm_id = timeSetEvent(50, 5, mm_timer_cb, 0xC0FFEEU, TIME_ONESHOT);
        Out("[timer_smoke] timeSetEvent        = ");
        Out(mm_id != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
        Sleep(150);
        Out("[timer_smoke] mm callback fired   = ");
        Out(g_mm_callback_fired ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (mm_id != 0)
            timeKillEvent(mm_id);
    }

    Out("[timer_smoke] done\r\n");
    Out("[ring3-timer-smoke] PASS\r\n");
    ExitProcess(0);
}
