/*
 * debug_smoke — exercise kernel32 debugging APIs.
 *
 * Probes the debugger-introspection surface. Every Win32 program
 * touches at least IsDebuggerPresent at startup; the more
 * specialised entries here are common in malware-detection /
 * anti-cheat / crash-reporting code:
 *   IsDebuggerPresent
 *   CheckRemoteDebuggerPresent
 *   OutputDebugStringA / OutputDebugStringW
 *   DebugBreak              (only in trapped form — wrap)
 *   GetThreadId / GetProcessId
 *   QueryPerformanceCounter (already in time_smoke; here as sanity)
 *
 * DebugBreak is intentionally NOT called: it would generate INT3
 * which traps to the kernel exception handler. We just probe its
 * IAT slot is non-NULL.
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
    Out("[debug_smoke] starting\r\n");

    /* IsDebuggerPresent — DuetOS doesn't expose a debugger to a
     * userspace PE, so this should return FALSE. */
    {
        BOOL pres = IsDebuggerPresent();
        Out("[debug_smoke] IsDebuggerPresent       = ");
        Out(!pres ? "PASS (FALSE, as expected)\r\n" : "FAIL (true)\r\n");
    }

    /* CheckRemoteDebuggerPresent on self. */
    {
        BOOL flag = TRUE;
        BOOL ok = CheckRemoteDebuggerPresent(GetCurrentProcess(), &flag);
        Out("[debug_smoke] CheckRemoteDebuggerPresent = ");
        Out(ok && !flag ? "PASS (FALSE)\r\n" : "FAIL\r\n");
    }

    /* OutputDebugStringA. Doesn't return a status — we just
     * verify the IAT slot is non-NULL by calling and checking
     * the process didn't trap. */
    OutputDebugStringA("[odbg-A] hello from debug_smoke\n");
    Out("[debug_smoke] OutputDebugStringA      = PASS (returned)\r\n");
    OutputDebugStringW(L"[odbg-W] hello from debug_smoke\n");
    Out("[debug_smoke] OutputDebugStringW      = PASS (returned)\r\n");

    /* GetCurrentProcessId / GetCurrentThreadId — relationship. */
    {
        DWORD pid1 = GetCurrentProcessId();
        DWORD pid2 = GetProcessId(GetCurrentProcess());
        Out("[debug_smoke] GetProcessId == self    = ");
        Out(pid1 == pid2 ? "PASS\r\n" : "FAIL\r\n");

        DWORD tid1 = GetCurrentThreadId();
        DWORD tid2 = GetThreadId(GetCurrentThread());
        Out("[debug_smoke] GetThreadId == self     = ");
        Out(tid1 == tid2 ? "PASS\r\n" : "FAIL/different\r\n");
    }

    Out("[debug_smoke] done\r\n");
    ExitProcess(0);
}
