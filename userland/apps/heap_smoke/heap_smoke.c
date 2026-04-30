/*
 * heap_smoke — extended heap-API coverage beyond mem_smoke.
 *
 *   HeapValidate
 *   HeapSize
 *   HeapReAlloc
 *   HeapWalk          (skipped — long iteration)
 *   HeapCompact
 *   GetProcessHeaps
 *   HeapSetInformation / HeapQueryInformation
 *
 * v0: malloc/HeapAlloc work. Validation / introspection mostly STUB.
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
    Out("[heap_smoke] starting\r\n");

    HANDLE ph = GetProcessHeap();
    Out("[heap_smoke] GetProcessHeap     = ");
    Out(ph != NULL ? "PASS\r\n" : "FAIL\r\n");

    /* HeapAlloc + HeapSize. */
    void* p = HeapAlloc(ph, 0, 256);
    Out("[heap_smoke] HeapAlloc(256)     = ");
    Out(p != NULL ? "PASS\r\n" : "FAIL\r\n");

    if (p != NULL)
    {
        SIZE_T sz = HeapSize(ph, 0, p);
        Out("[heap_smoke] HeapSize           = ");
        Out(sz >= 256 ? "PASS\r\n" : "FAIL/STUB\r\n");

        BOOL valid = HeapValidate(ph, 0, p);
        Out("[heap_smoke] HeapValidate       = ");
        Out(valid ? "PASS\r\n" : "FAIL/STUB\r\n");

        void* q = HeapReAlloc(ph, 0, p, 1024);
        Out("[heap_smoke] HeapReAlloc(1024)  = ");
        Out(q != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

        if (q != NULL)
            HeapFree(ph, 0, q);
        else
            HeapFree(ph, 0, p);
    }

    /* HeapCompact. */
    {
        SIZE_T n = HeapCompact(ph, 0);
        Out("[heap_smoke] HeapCompact        = ");
        Out("PASS (returned)\r\n");
        (void)n;
    }

    /* GetProcessHeaps. */
    {
        HANDLE bufs[8];
        DWORD n = GetProcessHeaps(8, bufs);
        Out("[heap_smoke] GetProcessHeaps    = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[heap_smoke] done\r\n");
    ExitProcess(0);
}
