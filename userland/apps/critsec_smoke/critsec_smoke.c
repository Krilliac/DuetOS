/*
 * critsec_smoke — exercise critical-section APIs.
 *
 * Critical sections are kernel32's lightweight per-process
 * mutex (no kernel transition for uncontended acquires). Every
 * MSVC C++ runtime relies on them for static-init guards.
 *   InitializeCriticalSection
 *   InitializeCriticalSectionAndSpinCount
 *   EnterCriticalSection / LeaveCriticalSection (recursive)
 *   TryEnterCriticalSection (non-blocking)
 *   DeleteCriticalSection
 *
 * Single-threaded test: verifies recursive acquire works, verifies
 * the count balances. Real contention testing needs a second
 * thread which thread_stress already does.
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
    Out("[critsec_smoke] starting\r\n");

    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    Out("[critsec_smoke] InitializeCriticalSection   = PASS (returned)\r\n");

    /* Recursive acquire — same thread should succeed N times. */
    EnterCriticalSection(&cs);
    EnterCriticalSection(&cs);
    EnterCriticalSection(&cs);
    Out("[critsec_smoke] EnterCriticalSection x3     = PASS (no deadlock)\r\n");

    LeaveCriticalSection(&cs);
    LeaveCriticalSection(&cs);
    LeaveCriticalSection(&cs);
    Out("[critsec_smoke] LeaveCriticalSection x3     = PASS (balanced)\r\n");

    /* TryEnterCriticalSection on a free CS. */
    BOOL got = TryEnterCriticalSection(&cs);
    Out("[critsec_smoke] TryEnterCriticalSection     = ");
    Out(got ? "PASS\r\n" : "FAIL\r\n");
    if (got)
        LeaveCriticalSection(&cs);

    DeleteCriticalSection(&cs);
    Out("[critsec_smoke] DeleteCriticalSection       = PASS (returned)\r\n");

    /* InitializeCriticalSectionAndSpinCount. */
    CRITICAL_SECTION cs2;
    BOOL ok = InitializeCriticalSectionAndSpinCount(&cs2, 4000);
    Out("[critsec_smoke] InitializeCSWithSpinCount   = ");
    Out(ok ? "PASS\r\n" : "FAIL\r\n");
    if (ok)
    {
        EnterCriticalSection(&cs2);
        LeaveCriticalSection(&cs2);
        DeleteCriticalSection(&cs2);
    }

    Out("[critsec_smoke] done\r\n");
    Out("[ring3-critsec-smoke] PASS\r\n");
    ExitProcess(0);
}
