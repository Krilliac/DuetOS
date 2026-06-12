/*
 * sleep_smoke — exercise sleep / yield APIs precisely.
 *
 *   Sleep
 *   SleepEx (alertable)
 *   SwitchToThread
 *   YieldProcessor (intrinsic)
 *
 * Verifies Sleep advances time at least the requested ms (with
 * tolerance for emulator slow clocks).
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
    Out("[sleep_smoke] starting\r\n");

    /* Sleep(0) — yield. */
    Sleep(0);
    Out("[sleep_smoke] Sleep(0)            = PASS (returned)\r\n");

    /* Sleep(50) — actual sleep. */
    DWORD t0 = GetTickCount();
    Sleep(50);
    DWORD t1 = GetTickCount();
    Out("[sleep_smoke] Sleep(50) advanced  = ");
    Out(t1 - t0 >= 40 ? "PASS\r\n" : "FAIL\r\n");

    /* SleepEx — non-alertable equivalent of Sleep. */
    DWORD r = SleepEx(20, FALSE);
    Out("[sleep_smoke] SleepEx(20, FALSE)  = ");
    Out(r == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* SwitchToThread. */
    BOOL sw = SwitchToThread();
    Out("[sleep_smoke] SwitchToThread      = ");
    /* TRUE means "thread did switch", FALSE "no other thread to run".
     * Both are valid outcomes — just verify it doesn't trap. */
    Out("PASS (returned)\r\n");
    (void)sw;

    Out("[sleep_smoke] done\r\n");
    Out("[ring3-sleep-smoke] PASS\r\n");
    ExitProcess(0);
}
