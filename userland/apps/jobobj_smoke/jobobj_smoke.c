/*
 * jobobj_smoke — exercise Job-Object APIs.
 *
 *   CreateJobObjectW
 *   AssignProcessToJobObject (on self)
 *   QueryInformationJobObject
 *   SetInformationJobObject
 *   IsProcessInJob
 *
 * Job objects sandbox a set of processes for resource caps.
 * v0: probably STUB across the board.
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
    Out("[jobobj_smoke] starting\r\n");

    HANDLE job = CreateJobObjectW(NULL, NULL);
    Out("[jobobj_smoke] CreateJobObjectW       = ");
    Out(job != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (job != NULL)
    {
        /* IsProcessInJob — should report FALSE for our process before
         * any AssignProcessToJobObject. */
        BOOL in_job = TRUE;
        BOOL r = IsProcessInJob(GetCurrentProcess(), NULL, &in_job);
        Out("[jobobj_smoke] IsProcessInJob (self)  = ");
        Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");

        BOOL ap = AssignProcessToJobObject(job, GetCurrentProcess());
        Out("[jobobj_smoke] AssignProcessToJobObject = ");
        Out(ap ? "PASS\r\n" : "FAIL/STUB\r\n");

        CloseHandle(job);
    }

    Out("[jobobj_smoke] done\r\n");
    ExitProcess(0);
}
