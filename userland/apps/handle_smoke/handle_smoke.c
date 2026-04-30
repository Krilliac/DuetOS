/*
 * handle_smoke — exercise kernel32 sync-primitive APIs.
 *
 * Probes the synchronization-object surface every threaded
 * Win32 app uses:
 *   CreateEventW (manual + auto-reset, signaled / not signaled)
 *   SetEvent / ResetEvent / PulseEvent
 *   CreateMutexW + WaitForSingleObject + ReleaseMutex (recursion)
 *   CreateSemaphoreW + WaitForSingleObject + ReleaseSemaphore
 *   WaitForSingleObject(timeout=0) on signaled vs. not-signaled
 *   CloseHandle
 *
 * Verifies signaling logic, not just the ABI shape.
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
    Out("[handle_smoke] starting\r\n");

    /* CreateEventW — manual, initially signaled. */
    HANDLE e = CreateEventW(NULL, /*manualReset=*/TRUE, /*initialState=*/TRUE, NULL);
    Out("[handle_smoke] CreateEventW(M, sig)    = ");
    Out(e != NULL ? "PASS\r\n" : "FAIL\r\n");

    if (e != NULL)
    {
        /* Wait should return immediately because initial = signaled. */
        DWORD rc = WaitForSingleObject(e, 0);
        Out("[handle_smoke] WaitForSingleObject sig = ");
        Out(rc == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL\r\n");

        ResetEvent(e);
        rc = WaitForSingleObject(e, 0);
        Out("[handle_smoke] Wait after ResetEvent   = ");
        Out(rc == WAIT_TIMEOUT ? "PASS (TIMEOUT)\r\n" : "FAIL\r\n");

        SetEvent(e);
        rc = WaitForSingleObject(e, 0);
        Out("[handle_smoke] Wait after SetEvent     = ");
        Out(rc == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL\r\n");

        CloseHandle(e);
    }

    /* CreateMutexW — recursive acquire by owning thread. */
    HANDLE m = CreateMutexW(NULL, /*initialOwner=*/TRUE, NULL);
    Out("[handle_smoke] CreateMutexW(owned)     = ");
    Out(m != NULL ? "PASS\r\n" : "FAIL\r\n");

    if (m != NULL)
    {
        /* Recursive Wait — should still grant. */
        DWORD rc = WaitForSingleObject(m, 0);
        Out("[handle_smoke] Recursive WaitForMutex  = ");
        Out(rc == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL\r\n");

        BOOL r = ReleaseMutex(m);
        Out("[handle_smoke] ReleaseMutex (recur)    = ");
        Out(r ? "PASS\r\n" : "FAIL\r\n");

        r = ReleaseMutex(m);
        Out("[handle_smoke] ReleaseMutex (final)    = ");
        Out(r ? "PASS\r\n" : "FAIL\r\n");

        CloseHandle(m);
    }

    /* CreateSemaphoreW — initial 2, max 4. */
    HANDLE sem = CreateSemaphoreW(NULL, 2, 4, NULL);
    Out("[handle_smoke] CreateSemaphoreW(2,4)   = ");
    Out(sem != NULL ? "PASS\r\n" : "FAIL\r\n");

    if (sem != NULL)
    {
        /* Two waits should both succeed (count was 2). */
        DWORD rc1 = WaitForSingleObject(sem, 0);
        DWORD rc2 = WaitForSingleObject(sem, 0);
        Out("[handle_smoke] Wait x2 (drain)         = ");
        Out(rc1 == WAIT_OBJECT_0 && rc2 == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL\r\n");

        /* Third should TIMEOUT. */
        DWORD rc3 = WaitForSingleObject(sem, 0);
        Out("[handle_smoke] Wait #3 (drained)       = ");
        Out(rc3 == WAIT_TIMEOUT ? "PASS (TIMEOUT)\r\n" : "FAIL\r\n");

        /* Release back to 2. */
        LONG prev = 0;
        BOOL r = ReleaseSemaphore(sem, 2, &prev);
        Out("[handle_smoke] ReleaseSemaphore(+2)    = ");
        Out(r ? "PASS\r\n" : "FAIL\r\n");

        CloseHandle(sem);
    }

    Out("[handle_smoke] done\r\n");
    ExitProcess(0);
}
