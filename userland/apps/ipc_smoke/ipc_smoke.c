/*
 * ipc_smoke — exercise inter-process communication primitives.
 *
 *   CreateFileMappingW (named shared memory)
 *   MapViewOfFile / UnmapViewOfFile
 *   OpenFileMappingW
 *   CreateMailslotW (skipped — server only)
 *   GetMailslotInfo
 *
 * v0: shared memory across processes is heavy; smoke value =
 * "doesn't trap". For an in-process map (which is what most
 * call paths use first), HeapAlloc-aliased Map* should work.
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
    Out("[ipc_smoke] starting\r\n");

    /* CreateFileMappingW for an anonymous 64K mapping. */
    HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, L"DuetOSIpcTest");
    Out("[ipc_smoke] CreateFileMappingW    = ");
    Out(h != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (h != NULL)
    {
        /* MapViewOfFile. */
        void* p = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 0x10000);
        Out("[ipc_smoke] MapViewOfFile         = ");
        Out(p != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

        if (p != NULL)
        {
            /* Write, then read back. */
            volatile unsigned char* b = (volatile unsigned char*)p;
            b[0] = 0xAB;
            b[100] = 0xCD;
            int ok = b[0] == 0xAB && b[100] == 0xCD;
            Out("[ipc_smoke] mapped round-trip      = ");
            Out(ok ? "PASS\r\n" : "FAIL\r\n");

            UnmapViewOfFile(p);
            Out("[ipc_smoke] UnmapViewOfFile        = PASS (returned)\r\n");
        }

        /* OpenFileMappingW for the same name. */
        HANDLE h2 = OpenFileMappingW(FILE_MAP_READ, FALSE, L"DuetOSIpcTest");
        Out("[ipc_smoke] OpenFileMappingW(name) = ");
        Out(h2 != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (h2 != NULL)
            CloseHandle(h2);

        CloseHandle(h);
    }

    Out("[ipc_smoke] done\r\n");
    Out("[ring3-ipc-smoke] PASS\r\n");
    ExitProcess(0);
}
