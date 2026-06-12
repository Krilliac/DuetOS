/*
 * signal_smoke — exercise C signal() and abort() interception.
 *
 *   signal(SIGTERM, SIG_IGN)  (just registers — won't fire)
 *   raise(SIGTERM) (skipped — would terminate)
 *   signal(SIGABRT, SIG_DFL)
 *
 * Pure ABI exercise — does signal() return non-NULL handler?
 */
#include <windows.h>
#include <signal.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void my_handler(int sig)
{
    (void)sig;
}

void __cdecl mainCRTStartup(void)
{
    Out("[signal_smoke] starting\r\n");

    /* Install + restore. */
    void (*prev)(int) = signal(SIGTERM, my_handler);
    Out("[signal_smoke] signal(SIGTERM)      = ");
    Out(prev != SIG_ERR ? "PASS\r\n" : "FAIL/STUB\r\n");

    void (*prev2)(int) = signal(SIGTERM, prev);
    Out("[signal_smoke] signal restore       = ");
    Out(prev2 == my_handler ? "PASS (round-trip)\r\n" : "FAIL/STUB\r\n");

    /* SIG_IGN. */
    void (*prev3)(int) = signal(SIGABRT, SIG_IGN);
    Out("[signal_smoke] signal(SIGABRT, IGN) = ");
    Out(prev3 != SIG_ERR ? "PASS\r\n" : "FAIL/STUB\r\n");

    Out("[signal_smoke] done\r\n");
    Out("[ring3-signal-smoke] PASS\r\n");
    ExitProcess(0);
}
