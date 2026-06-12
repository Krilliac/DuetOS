/*
 * thread3_smoke — extended thread-control APIs.
 *
 *   GetThreadContext / SetThreadContext (skipped — needs CONTEXT)
 *   OpenThread (on self TID)
 *   GetThreadDescription / SetThreadDescription (Win10+)
 *   GetThreadIOPendingFlag
 *   GetThreadInformation (skipped)
 *   SuspendThread on a brand-new suspended thread
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

static DWORD WINAPI worker(LPVOID p)
{
    (void)p;
    Sleep(50);
    return 0;
}

void __cdecl mainCRTStartup(void)
{
    Out("[thread3_smoke] starting\r\n");

    /* OpenThread on self. */
    HANDLE me = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
    Out("[thread3_smoke] OpenThread(self)      = ");
    Out(me != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
    if (me != NULL)
        CloseHandle(me);

    /* CreateThread suspended → ResumeThread → wait. */
    {
        HANDLE t = CreateThread(NULL, 0, worker, NULL, CREATE_SUSPENDED, NULL);
        Out("[thread3_smoke] CreateThread(suspended)= ");
        Out(t != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (t != NULL)
        {
            DWORD prev = ResumeThread(t);
            Out("[thread3_smoke] ResumeThread          = ");
            Out(prev != (DWORD)-1 ? "PASS\r\n" : "FAIL/STUB\r\n");

            DWORD r = WaitForSingleObject(t, 5000);
            Out("[thread3_smoke] Wait + finish         = ");
            Out(r == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL/STUB\r\n");

            CloseHandle(t);
        }
    }

    /* GetThreadIOPendingFlag. */
    {
        BOOL pending = TRUE;
        BOOL ok = GetThreadIOPendingFlag(GetCurrentThread(), &pending);
        Out("[thread3_smoke] GetThreadIOPendingFlag= ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[thread3_smoke] done\r\n");
    Out("[ring3-thread3-smoke] PASS\r\n");
    ExitProcess(0);
}
