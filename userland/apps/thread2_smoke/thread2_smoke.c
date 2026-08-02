/*
 * thread2_smoke — extended threading-API coverage beyond
 * handle_smoke (which covers Event/Mutex/Sem) and the original
 * thread_stress (which is throughput-oriented).
 *
 *   GetThreadPriority / SetThreadPriority
 *   SuspendThread / ResumeThread (on a child thread)
 *   GetExitCodeThread
 *   Closed-thread handle rejection before slot reuse
 *   GetExitCodeThread out-parameter width/preservation
 *   QueueUserAPC (skipped — needs alertable wait)
 *   InitializeConditionVariable / SleepConditionVariableCS (skipped)
 *   InitializeSRWLock / AcquireSRWLockExclusive / Release
 *   InitOnceExecuteOnce
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

typedef struct ExitCodeCanary
{
    DWORD before;
    DWORD value;
    DWORD after;
} ExitCodeCanary;

#define EXIT_CANARY_BEFORE 0xC13FA11Du
#define EXIT_CANARY_AFTER 0x91E0BEEFu
#define EXIT_CANARY_UNTOUCHED 0xD00DFEEDu

static HANDLE g_worker_release = NULL;
static HANDLE g_replacement_release = NULL;
static volatile int g_started = 0;
static volatile int g_ran = 0;

static DWORD WINAPI worker(LPVOID p)
{
    (void)p;
    g_started = 1;
    if (WaitForSingleObject(g_worker_release, 5000) != WAIT_OBJECT_0)
        return 0xE1;
    g_ran = 1;
    return 0x42;
}

static DWORD WINAPI replacement_worker(LPVOID p)
{
    (void)p;
    if (WaitForSingleObject(g_replacement_release, 5000) != WAIT_OBJECT_0)
        return 0xE2;
    return 0x24;
}

static BOOL ExitCodeCanariesIntact(const ExitCodeCanary* probe)
{
    return probe->before == EXIT_CANARY_BEFORE && probe->after == EXIT_CANARY_AFTER;
}

static BOOL CALLBACK init_once_fn(PINIT_ONCE io, PVOID p, PVOID* ctx)
{
    (void)io;
    (void)p;
    (void)ctx;
    return TRUE;
}

void __cdecl mainCRTStartup(void)
{
    BOOL retirement_ok = TRUE;
    Out("[thread2_smoke] starting\r\n");

    /*
     * Keep the worker live until the main thread has observed
     * STILL_ACTIVE. This makes the exit-code check deterministic and
     * gives its adjacent words a width canary.
     */
    g_worker_release = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (g_worker_release == NULL)
        retirement_ok = FALSE;

    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    Out("[thread2_smoke] CreateThread          = ");
    Out(t != NULL ? "PASS\r\n" : "FAIL\r\n");
    if (t == NULL)
        retirement_ok = FALSE;

    if (t != NULL)
    {
        DWORD start_budget = 5000;
        while (g_started == 0 && start_budget-- != 0)
            Sleep(1);

        ExitCodeCanary active = {EXIT_CANARY_BEFORE, EXIT_CANARY_UNTOUCHED, EXIT_CANARY_AFTER};
        BOOL active_ok = g_started != 0 && GetExitCodeThread(t, &active.value) && active.value == STILL_ACTIVE &&
                         ExitCodeCanariesIntact(&active);
        Out("[thread2_smoke] active exit-code canary= ");
        Out(active_ok ? "PASS\r\n" : "FAIL\r\n");
        if (!active_ok)
            retirement_ok = FALSE;

        /* GetThreadPriority. */
        int pri = GetThreadPriority(t);
        Out("[thread2_smoke] GetThreadPriority     = ");
        Out(pri != THREAD_PRIORITY_ERROR_RETURN ? "PASS\r\n" : "FAIL/STUB\r\n");

        /* SetThreadPriority. */
        BOOL sp = SetThreadPriority(t, THREAD_PRIORITY_NORMAL);
        Out("[thread2_smoke] SetThreadPriority     = ");
        Out(sp ? "PASS\r\n" : "FAIL/STUB\r\n");

        if (g_worker_release == NULL || !SetEvent(g_worker_release))
            retirement_ok = FALSE;

        /* Wait for finish. */
        DWORD r = WaitForSingleObject(t, 5000);
        Out("[thread2_smoke] WaitForSingleObject(t)= ");
        Out(r == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (r != WAIT_OBJECT_0)
            retirement_ok = FALSE;

        /* GetExitCodeThread. Emit the verdict in ONE Out() call: the
         * smoke harness greps for the exact contiguous line, and the
         * old two-call split let a concurrently-logging CPU interleave
         * a kernel line between prefix and verdict, breaking the match
         * on an otherwise-passing run (observed 2026-08-02). */
        ExitCodeCanary completed = {EXIT_CANARY_BEFORE, EXIT_CANARY_UNTOUCHED, EXIT_CANARY_AFTER};
        BOOL gec = GetExitCodeThread(t, &completed.value);
        Out(gec && completed.value == 0x42 && ExitCodeCanariesIntact(&completed)
                ? "[thread2_smoke] GetExitCodeThread     = PASS (0x42)\r\n"
                : "[thread2_smoke] GetExitCodeThread     = FAIL/STUB\r\n");
        if (!gec || completed.value != 0x42 || !ExitCodeCanariesIntact(&completed) || g_ran == 0)
            retirement_ok = FALSE;

        HANDLE stale = t;
        CloseHandle(t);

        /*
         * Before another thread can reuse this slot, the closed public
         * value must be rejected and a failed exit-code query must not
         * touch any part of the caller's output object. Public handles
         * are intentionally slot-only in v0, so no assertion is made
         * about an old numeric value after the slot is reused.
         */
        ExitCodeCanary stale_probe = {EXIT_CANARY_BEFORE, EXIT_CANARY_UNTOUCHED, EXIT_CANARY_AFTER};
        BOOL stale_rejected = WaitForSingleObject(stale, 0) == WAIT_FAILED &&
                              !GetExitCodeThread(stale, &stale_probe.value) &&
                              stale_probe.value == EXIT_CANARY_UNTOUCHED && ExitCodeCanariesIntact(&stale_probe);
        Out("[thread2_smoke] stale handle + canary = ");
        Out(stale_rejected ? "PASS\r\n" : "FAIL\r\n");
        if (!stale_rejected)
            retirement_ok = FALSE;

        /* A fresh create must still be able to reclaim the closed row. */
        g_replacement_release = CreateEventA(NULL, TRUE, FALSE, NULL);
        HANDLE replacement = CreateThread(NULL, 0, replacement_worker, NULL, 0, NULL);
        if (replacement == NULL || g_replacement_release == NULL || !SetEvent(g_replacement_release))
        {
            retirement_ok = FALSE;
            if (replacement != NULL)
            {
                (void)WaitForSingleObject(replacement, 5000);
                CloseHandle(replacement);
            }
        }
        else
        {
            ExitCodeCanary replacement_exit = {EXIT_CANARY_BEFORE, EXIT_CANARY_UNTOUCHED, EXIT_CANARY_AFTER};
            BOOL replacement_ok = WaitForSingleObject(replacement, 5000) == WAIT_OBJECT_0 &&
                                  GetExitCodeThread(replacement, &replacement_exit.value) &&
                                  replacement_exit.value == 0x24 && ExitCodeCanariesIntact(&replacement_exit);
            Out("[thread2_smoke] closed row reclaimed = ");
            Out(replacement_ok ? "PASS\r\n" : "FAIL\r\n");
            if (!replacement_ok)
                retirement_ok = FALSE;
            CloseHandle(replacement);
        }
    }

    if (g_worker_release != NULL)
        CloseHandle(g_worker_release);
    if (g_replacement_release != NULL)
        CloseHandle(g_replacement_release);

    /* SRWLock. */
    {
        SRWLOCK l;
        InitializeSRWLock(&l);
        AcquireSRWLockExclusive(&l);
        ReleaseSRWLockExclusive(&l);
        Out("[thread2_smoke] SRWLock cycle         = PASS (returned)\r\n");
    }

    /* InitOnceExecuteOnce. */
    {
        INIT_ONCE io = INIT_ONCE_STATIC_INIT;
        BOOL ran = InitOnceExecuteOnce(&io, init_once_fn, NULL, NULL);
        Out("[thread2_smoke] InitOnceExecuteOnce   = ");
        Out(ran ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[thread2_smoke] done\r\n");
    Out(retirement_ok ? "[ring3-thread2-smoke] PASS\r\n" : "[ring3-thread2-smoke] FAIL\r\n");
    ExitProcess(retirement_ok ? 0 : 1);
}
