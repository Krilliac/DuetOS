/*
 * sync_smoke — exercises the Win32 synchronization primitives V8 /
 * Chrome thread pools depend on, end-to-end across real threads:
 *
 *   A. CRITICAL_SECTION + CONDITION_VARIABLE producer/consumer
 *      (SleepConditionVariableCS / WakeConditionVariable).
 *   B. WaitOnAddress / WakeByAddressSingle handshake — the kernel
 *      SYS_WAIT_ON_ADDRESS / SYS_WAKE_BY_ADDRESS futex.
 *   C. InitOnceBeginInitialize / InitOnceComplete two-call form.
 *
 * All built on the kernel address-keyed wait. Exit 0 = full PASS.
 */
#define _WIN32_WINNT 0x0A00 /* Win10: WaitOnAddress + condition vars */
#include <windows.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

/* ---- A. CONDITION_VARIABLE + CRITICAL_SECTION ---- */
static CRITICAL_SECTION g_cs;
static CONDITION_VARIABLE g_cv;
static volatile int g_ready;
static volatile int g_consumed;

static DWORD WINAPI consumer(LPVOID arg)
{
    (void)arg;
    EnterCriticalSection(&g_cs);
    while (!g_ready)
        SleepConditionVariableCS(&g_cv, &g_cs, INFINITE);
    g_consumed = 1;
    LeaveCriticalSection(&g_cs);
    return 0;
}

static int test_condvar(void)
{
    InitializeCriticalSection(&g_cs);
    InitializeConditionVariable(&g_cv);
    g_ready = 0;
    g_consumed = 0;
    HANDLE t = CreateThread(0, 0, consumer, 0, 0, 0);
    if (t == 0)
    {
        Out("[sync_smoke] condvar: FAIL (CreateThread)\r\n");
        return 1;
    }
    Sleep(50); /* let the consumer reach the wait */
    EnterCriticalSection(&g_cs);
    g_ready = 1;
    LeaveCriticalSection(&g_cs);
    WakeConditionVariable(&g_cv);
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    if (g_consumed == 1)
    {
        Out("[sync_smoke] condvar: PASS\r\n");
        return 0;
    }
    Out("[sync_smoke] condvar: FAIL (not consumed)\r\n");
    return 1;
}

/* ---- B. WaitOnAddress / WakeByAddressSingle ---- */
static volatile LONG g_word;
static volatile int g_waiter_done;

static DWORD WINAPI waiter(LPVOID arg)
{
    (void)arg;
    LONG zero = 0;
    while (g_word == 0)
        WaitOnAddress((volatile void*)&g_word, &zero, sizeof(LONG), INFINITE);
    g_waiter_done = 1;
    return 0;
}

static int test_waitonaddr(void)
{
    g_word = 0;
    g_waiter_done = 0;
    HANDLE t = CreateThread(0, 0, waiter, 0, 0, 0);
    if (t == 0)
    {
        Out("[sync_smoke] waitonaddr: FAIL (CreateThread)\r\n");
        return 1;
    }
    Sleep(50);
    InterlockedExchange(&g_word, 1);
    WakeByAddressSingle((PVOID)&g_word);
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    if (g_waiter_done == 1 && g_word == 1)
    {
        Out("[sync_smoke] waitonaddr: PASS\r\n");
        return 0;
    }
    Out("[sync_smoke] waitonaddr: FAIL\r\n");
    return 1;
}

/* ---- C. InitOnceBeginInitialize / InitOnceComplete ---- */
static int test_initonce(void)
{
    INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    BOOL pending = FALSE;
    void* ctx = (void*)0;
    if (!InitOnceBeginInitialize(&once, 0, &pending, &ctx) || !pending)
    {
        Out("[sync_smoke] initonce: FAIL (first begin)\r\n");
        return 1;
    }
    if (!InitOnceComplete(&once, 0, (void*)0))
    {
        Out("[sync_smoke] initonce: FAIL (complete)\r\n");
        return 1;
    }
    pending = TRUE;
    if (!InitOnceBeginInitialize(&once, 0, &pending, &ctx) || pending)
    {
        Out("[sync_smoke] initonce: FAIL (second begin should not be pending)\r\n");
        return 1;
    }
    Out("[sync_smoke] initonce: PASS\r\n");
    return 0;
}

void __cdecl mainCRTStartup(void)
{
    Out("[sync_smoke] starting\r\n");
    int fail = 0;
    fail |= test_condvar();
    fail |= test_waitonaddr();
    fail |= test_initonce();
    Out(fail ? "[sync_smoke] RESULT FAIL\r\n" : "[sync_smoke] RESULT PASS\r\n");
    Out("[sync_smoke] done\r\n");
    ExitProcess(fail ? 1u : 0u);
}
