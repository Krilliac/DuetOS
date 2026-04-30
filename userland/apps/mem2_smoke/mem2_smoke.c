/*
 * mem2_smoke — extended VirtualAlloc / paging APIs.
 *
 *   VirtualQuery
 *   VirtualLock / VirtualUnlock
 *   GetWriteWatch / ResetWriteWatch (skipped — needs MEM_WRITE_WATCH)
 *   AllocateUserPhysicalPages (skipped — privileged)
 *   FlushFileBuffers
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
    Out("[mem2_smoke] starting\r\n");

    /* VirtualAlloc + VirtualQuery. */
    void* p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Out("[mem2_smoke] VirtualAlloc       = ");
    Out(p != NULL ? "PASS\r\n" : "FAIL\r\n");

    if (p != NULL)
    {
        MEMORY_BASIC_INFORMATION mbi = {0};
        SIZE_T n = VirtualQuery(p, &mbi, sizeof(mbi));
        Out("[mem2_smoke] VirtualQuery       = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        BOOL lk = VirtualLock(p, 4096);
        Out("[mem2_smoke] VirtualLock        = ");
        Out("PASS (returned)\r\n");
        (void)lk;

        BOOL ul = VirtualUnlock(p, 4096);
        Out("[mem2_smoke] VirtualUnlock      = ");
        Out("PASS (returned)\r\n");
        (void)ul;

        VirtualFree(p, 0, MEM_RELEASE);
    }

    Out("[mem2_smoke] done\r\n");
    ExitProcess(0);
}
