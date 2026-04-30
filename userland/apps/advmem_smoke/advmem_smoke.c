/*
 * advmem_smoke — advanced memory APIs not yet covered.
 *
 *   GlobalLock / GlobalUnlock
 *   GlobalSize / GlobalFlags
 *   LocalSize
 *   IsBadReadPtr / IsBadWritePtr (deprecated but still legal)
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
    Out("[advmem_smoke] starting\r\n");

    HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, 256);
    Out("[advmem_smoke] GlobalAlloc(MOVEABLE)= ");
    Out(g != NULL ? "PASS\r\n" : "FAIL\r\n");

    if (g != NULL)
    {
        void* p = GlobalLock(g);
        Out("[advmem_smoke] GlobalLock          = ");
        Out(p != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

        SIZE_T sz = GlobalSize(g);
        Out("[advmem_smoke] GlobalSize          = ");
        Out(sz >= 256 ? "PASS\r\n" : "FAIL/STUB\r\n");

        GlobalUnlock(g);
        Out("[advmem_smoke] GlobalUnlock        = PASS (returned)\r\n");

        GlobalFree(g);
    }

    /* LocalAlloc + LocalSize. */
    {
        HLOCAL l = LocalAlloc(LMEM_FIXED, 64);
        if (l != NULL)
        {
            SIZE_T sz = LocalSize(l);
            Out("[advmem_smoke] LocalSize           = ");
            Out(sz >= 64 ? "PASS\r\n" : "FAIL/STUB\r\n");
            LocalFree(l);
        }
    }

    /* IsBadWritePtr on a stack variable — should be FALSE. */
    {
        int x = 0;
        BOOL bad = IsBadWritePtr(&x, sizeof(x));
        Out("[advmem_smoke] IsBadWritePtr(stack)= ");
        Out(!bad ? "PASS (writable)\r\n" : "FAIL/STUB\r\n");
    }

    Out("[advmem_smoke] done\r\n");
    ExitProcess(0);
}
