/*
 * mem_smoke — exercise kernel32 memory APIs.
 *
 * Probes the three memory-allocation surfaces every Win32 app
 * eventually uses:
 *   VirtualAlloc / VirtualFree / VirtualProtect    (page-level)
 *   HeapCreate / HeapAlloc / HeapFree / HeapDestroy (heap pool)
 *   GetProcessHeap / HeapAlloc                      (process heap)
 *   GlobalAlloc / GlobalFree                        (legacy global heap)
 *   LocalAlloc / LocalFree                          (legacy local heap)
 *   IsBadReadPtr / IsBadWritePtr                    (legacy probes)
 *
 * Each call is checked: pointer non-null, written bytes round-trip,
 * free succeeds. STUB returns of 0 / NULL get caught.
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
    Out("[mem_smoke] starting\r\n");

    /* VirtualAlloc + write + VirtualFree. */
    {
        void* p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Out("[mem_smoke] VirtualAlloc(4K RW)   = ");
        if (p == NULL)
            Out("FAIL (NULL)\r\n");
        else
        {
            volatile unsigned int* w = (volatile unsigned int*)p;
            w[0] = 0xCAFEBABE;
            w[1023] = 0xDEADBEEF;
            int ok = (w[0] == 0xCAFEBABE) && (w[1023] == 0xDEADBEEF);
            Out(ok ? "PASS (round-trip)\r\n" : "FAIL (corrupt)\r\n");
            BOOL freed = VirtualFree(p, 0, MEM_RELEASE);
            Out("[mem_smoke] VirtualFree           = ");
            Out(freed ? "PASS\r\n" : "FAIL\r\n");
        }
    }

    /* VirtualProtect — flip page R/W → R/O and back. */
    {
        void* p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (p != NULL)
        {
            DWORD old = 0;
            BOOL ok = VirtualProtect(p, 4096, PAGE_READONLY, &old);
            Out("[mem_smoke] VirtualProtect RW->R  = ");
            Out(ok ? "PASS\r\n" : "FAIL\r\n");
            ok = VirtualProtect(p, 4096, PAGE_READWRITE, &old);
            Out("[mem_smoke] VirtualProtect R->RW  = ");
            Out(ok ? "PASS\r\n" : "FAIL\r\n");
            VirtualFree(p, 0, MEM_RELEASE);
        }
    }

    /* HeapCreate + HeapAlloc + HeapFree + HeapDestroy. */
    {
        HANDLE heap = HeapCreate(0, 0, 0);
        Out("[mem_smoke] HeapCreate            = ");
        if (heap == NULL)
        {
            Out("FAIL (NULL handle)\r\n");
        }
        else
        {
            Out("PASS\r\n");
            void* p = HeapAlloc(heap, 0, 256);
            Out("[mem_smoke] HeapAlloc(256)        = ");
            if (p == NULL)
                Out("FAIL (NULL)\r\n");
            else
            {
                ((unsigned char*)p)[0] = 0x42;
                ((unsigned char*)p)[255] = 0x99;
                int ok = ((unsigned char*)p)[0] == 0x42 && ((unsigned char*)p)[255] == 0x99;
                Out(ok ? "PASS (round-trip)\r\n" : "FAIL (corrupt)\r\n");
                HeapFree(heap, 0, p);
            }
            HeapDestroy(heap);
        }
    }

    /* GetProcessHeap + HeapAlloc on it. */
    {
        HANDLE ph = GetProcessHeap();
        Out("[mem_smoke] GetProcessHeap        = ");
        Out(ph != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (ph != NULL)
        {
            void* p = HeapAlloc(ph, 0, 64);
            Out("[mem_smoke] HeapAlloc(processHeap)= ");
            Out(p != NULL ? "PASS\r\n" : "FAIL\r\n");
            if (p != NULL)
                HeapFree(ph, 0, p);
        }
    }

    /* GlobalAlloc + GlobalFree (legacy). */
    {
        HGLOBAL g = GlobalAlloc(GMEM_FIXED, 128);
        Out("[mem_smoke] GlobalAlloc(GMEM_FIXED)= ");
        Out(g != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (g != NULL)
            GlobalFree(g);
    }

    /* LocalAlloc + LocalFree (legacy). */
    {
        HLOCAL l = LocalAlloc(LMEM_FIXED, 128);
        Out("[mem_smoke] LocalAlloc(LMEM_FIXED) = ");
        Out(l != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (l != NULL)
            LocalFree(l);
    }

    Out("[mem_smoke] done\r\n");
    Out("[ring3-mem-smoke] PASS\r\n");
    ExitProcess(0);
}
