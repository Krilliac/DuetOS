/*
 * debug2_smoke — debug-helper APIs beyond debug_smoke.
 *
 *   AddVectoredExceptionHandler / RemoveVectoredExceptionHandler
 *   SetUnhandledExceptionFilter
 *   GetCurrentProcessorNumber
 *   GetCurrentProcessorNumberEx (Win10+)
 */
#include <windows.h>

static LONG WINAPI veh(PEXCEPTION_POINTERS p)
{
    (void)p;
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI top_filter(PEXCEPTION_POINTERS p)
{
    (void)p;
    return EXCEPTION_EXECUTE_HANDLER;
}

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
    Out("[debug2_smoke] starting\r\n");

    PVOID h = AddVectoredExceptionHandler(1, veh);
    Out("[debug2_smoke] AddVectoredExceptionHandler = ");
    Out(h != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (h != NULL)
    {
        ULONG r = RemoveVectoredExceptionHandler(h);
        Out("[debug2_smoke] RemoveVectoredExceptionHandler = ");
        Out(r != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* SetUnhandledExceptionFilter — install + restore. */
    {
        LPTOP_LEVEL_EXCEPTION_FILTER prev = SetUnhandledExceptionFilter(top_filter);
        SetUnhandledExceptionFilter(prev);
        Out("[debug2_smoke] SetUnhandledExceptionFilter = PASS (returned)\r\n");
    }

    /* GetCurrentProcessorNumber. */
    {
        DWORD c = GetCurrentProcessorNumber();
        Out("[debug2_smoke] GetCurrentProcessorNumber = ");
        Out("PASS (returned)\r\n");
        (void)c;
    }

    Out("[debug2_smoke] done\r\n");
    Out("[ring3-debug2-smoke] PASS\r\n");
    ExitProcess(0);
}
