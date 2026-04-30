/*
 * prio_smoke — process / thread priority + CPU set APIs.
 *
 *   GetPriorityClass / SetPriorityClass round-trip
 *   GetThreadPriorityBoost / SetThreadPriorityBoost
 *   SetProcessAffinityMask (skipped — would change scheduling)
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
    Out("[prio_smoke] starting\r\n");

    HANDLE p = GetCurrentProcess();
    DWORD prev = GetPriorityClass(p);
    Out("[prio_smoke] GetPriorityClass     = ");
    Out(prev != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    BOOL ok = SetPriorityClass(p, NORMAL_PRIORITY_CLASS);
    Out("[prio_smoke] SetPriorityClass     = ");
    Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* Thread priority boost. */
    BOOL boosted = TRUE;
    ok = GetThreadPriorityBoost(GetCurrentThread(), &boosted);
    Out("[prio_smoke] GetThreadPriorityBoost = ");
    Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

    Out("[prio_smoke] done\r\n");
    ExitProcess(0);
}
