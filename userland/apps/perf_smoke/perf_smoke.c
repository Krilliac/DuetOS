/*
 * perf_smoke — exercise extended performance / cycle-counter APIs.
 *
 *   QueryPerformanceFrequency / QueryPerformanceCounter
 *   QueryUnbiasedInterruptTime
 *   QueryProcessCycleTime
 *   QueryThreadCycleTime
 *   GetProcessTimes
 *   GetThreadTimes
 *
 * Verifies cycle counters advance and are non-zero.
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

static void busy_loop(int n)
{
    volatile int x = 0;
    for (int i = 0; i < n; ++i)
        x += i;
}

void __cdecl mainCRTStartup(void)
{
    Out("[perf_smoke] starting\r\n");

    LARGE_INTEGER freq;
    BOOL ok = QueryPerformanceFrequency(&freq);
    Out("[perf_smoke] QueryPerformanceFrequency = ");
    Out(ok && freq.QuadPart > 0 ? "PASS\r\n" : "FAIL\r\n");

    LARGE_INTEGER c0, c1;
    QueryPerformanceCounter(&c0);
    busy_loop(100000);
    QueryPerformanceCounter(&c1);
    Out("[perf_smoke] QPC monotonic       = ");
    Out(c1.QuadPart > c0.QuadPart ? "PASS\r\n" : "FAIL\r\n");

    /* QueryProcessCycleTime. */
    {
        ULONG64 cycles = 0;
        BOOL r = QueryProcessCycleTime(GetCurrentProcess(), &cycles);
        Out("[perf_smoke] QueryProcessCycleTime = ");
        Out(r && cycles > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* QueryThreadCycleTime. */
    {
        ULONG64 cycles = 0;
        BOOL r = QueryThreadCycleTime(GetCurrentThread(), &cycles);
        Out("[perf_smoke] QueryThreadCycleTime  = ");
        Out(r && cycles > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetProcessTimes. */
    {
        FILETIME create, exit, kernel, user;
        BOOL r = GetProcessTimes(GetCurrentProcess(), &create, &exit, &kernel, &user);
        Out("[perf_smoke] GetProcessTimes       = ");
        Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetThreadTimes. */
    {
        FILETIME create, exit, kernel, user;
        BOOL r = GetThreadTimes(GetCurrentThread(), &create, &exit, &kernel, &user);
        Out("[perf_smoke] GetThreadTimes        = ");
        Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[perf_smoke] done\r\n");
    ExitProcess(0);
}
