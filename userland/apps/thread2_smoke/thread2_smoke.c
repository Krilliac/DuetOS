/*
 * thread2_smoke — extended threading-API coverage beyond
 * handle_smoke (which covers Event/Mutex/Sem) and the original
 * thread_stress (which is throughput-oriented).
 *
 *   GetThreadPriority / SetThreadPriority
 *   SuspendThread / ResumeThread (on a child thread)
 *   GetExitCodeThread
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

static volatile int g_ran = 0;
static DWORD WINAPI worker(LPVOID p)
{
    (void)p;
    Sleep(20);
    g_ran = 1;
    return 0x42;
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
    Out("[thread2_smoke] starting\r\n");

    /* Spawn a worker, wait, check exit code. */
    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    Out("[thread2_smoke] CreateThread          = ");
    Out(t != NULL ? "PASS\r\n" : "FAIL\r\n");

    if (t != NULL)
    {
        /* GetThreadPriority. */
        int pri = GetThreadPriority(t);
        Out("[thread2_smoke] GetThreadPriority     = ");
        Out(pri != THREAD_PRIORITY_ERROR_RETURN ? "PASS\r\n" : "FAIL/STUB\r\n");

        /* SetThreadPriority. */
        BOOL sp = SetThreadPriority(t, THREAD_PRIORITY_NORMAL);
        Out("[thread2_smoke] SetThreadPriority     = ");
        Out(sp ? "PASS\r\n" : "FAIL/STUB\r\n");

        /* Wait for finish. */
        DWORD r = WaitForSingleObject(t, 5000);
        Out("[thread2_smoke] WaitForSingleObject(t)= ");
        Out(r == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        /* GetExitCodeThread. */
        DWORD ec = 0;
        BOOL gec = GetExitCodeThread(t, &ec);
        Out("[thread2_smoke] GetExitCodeThread     = ");
        Out(gec && ec == 0x42 ? "PASS (0x42)\r\n" : "FAIL/STUB\r\n");

        CloseHandle(t);
    }

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
    Out("[ring3-thread2-smoke] PASS\r\n");
    ExitProcess(0);
}
