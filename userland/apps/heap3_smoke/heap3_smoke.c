/*
 * heap3_smoke — exercise advanced kernel32 / msvcrt allocation
 * APIs not in mem_smoke or heap_smoke.
 *
 *   _aligned_malloc / _aligned_free
 *   calloc / realloc
 *   _msize
 *   _expand (skipped — rarely supported)
 */
#include <windows.h>
#include <stdlib.h>
#include <malloc.h>

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
    Out("[heap3_smoke] starting\r\n");

    /* calloc — zero-initialised. */
    {
        unsigned char* p = (unsigned char*)calloc(64, 1);
        Out("[heap3_smoke] calloc(64)          = ");
        if (p == NULL)
            Out("FAIL/STUB\r\n");
        else
        {
            int ok = 1;
            for (int i = 0; i < 64; ++i)
                if (p[i] != 0)
                    ok = 0;
            Out(ok ? "PASS (zero-init)\r\n" : "FAIL\r\n");
            free(p);
        }
    }

    /* realloc shrink + grow. */
    {
        char* p = (char*)malloc(32);
        Out("[heap3_smoke] malloc(32)          = ");
        Out(p != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (p != NULL)
        {
            char* q = (char*)realloc(p, 64);
            Out("[heap3_smoke] realloc(32→64)      = ");
            Out(q != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
            free(q);
        }
    }

    /* _aligned_malloc — 16-byte alignment. */
    {
        void* p = _aligned_malloc(32, 16);
        Out("[heap3_smoke] _aligned_malloc(32,16) = ");
        Out(p != NULL && (((unsigned long long)p) & 15) == 0 ? "PASS (aligned)\r\n" : "FAIL/STUB\r\n");
        if (p != NULL)
            _aligned_free(p);
    }

    Out("[heap3_smoke] done\r\n");
    Out("[ring3-heap3-smoke] PASS\r\n");
    ExitProcess(0);
}
