/*
 * fiber_smoke — exercise fiber + Fiber-Local Storage APIs.
 *
 * Fibers are user-mode cooperatively scheduled lightweight
 * threads — heavily used by C++ coroutines and the Windows
 * Runtime. Most of these likely STUB on v0:
 *   ConvertThreadToFiber / ConvertFiberToThread
 *   CreateFiber / DeleteFiber
 *   SwitchToFiber  (skipped — would not return cleanly)
 *   FlsAlloc / FlsSetValue / FlsGetValue / FlsFree
 *   IsThreadAFiber
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
    Out("[fiber_smoke] starting\r\n");

    /* IsThreadAFiber — should be FALSE before ConvertThreadToFiber. */
    BOOL isf = IsThreadAFiber();
    Out("[fiber_smoke] IsThreadAFiber(no)  = ");
    Out(!isf ? "PASS (FALSE)\r\n" : "FAIL/STUB\r\n");

    /* FlsAlloc / FlsSetValue / FlsGetValue / FlsFree. */
    DWORD slot = FlsAlloc(NULL);
    Out("[fiber_smoke] FlsAlloc             = ");
    Out(slot != FLS_OUT_OF_INDEXES ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (slot != FLS_OUT_OF_INDEXES)
    {
        BOOL set_ok = FlsSetValue(slot, (PVOID)0x1234ABCD);
        Out("[fiber_smoke] FlsSetValue          = ");
        Out(set_ok ? "PASS\r\n" : "FAIL\r\n");

        PVOID v = FlsGetValue(slot);
        Out("[fiber_smoke] FlsGetValue          = ");
        Out((unsigned long long)v == 0x1234ABCDUL ? "PASS\r\n" : "FAIL\r\n");

        BOOL free_ok = FlsFree(slot);
        Out("[fiber_smoke] FlsFree              = ");
        Out(free_ok ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[fiber_smoke] done\r\n");
    Out("[ring3-fiber-smoke] PASS\r\n");
    ExitProcess(0);
}
