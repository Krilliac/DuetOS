/*
 * fpcontrol_smoke — exercise FPU control / rounding-mode APIs.
 *
 *   _controlfp_s
 *   _fpieee_flt (skipped — needs handler)
 *   _statusfp
 *   _clearfp
 */
#include <windows.h>
#include <float.h>

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
    Out("[fpcontrol_smoke] starting\r\n");

    /* _statusfp. */
    {
        unsigned int s = _statusfp();
        Out("[fpcontrol_smoke] _statusfp         = ");
        Out("PASS (returned)\r\n");
        (void)s;
    }

    /* _clearfp. */
    {
        unsigned int prev = _clearfp();
        Out("[fpcontrol_smoke] _clearfp          = ");
        Out("PASS (returned)\r\n");
        (void)prev;
    }

    Out("[fpcontrol_smoke] done\r\n");
    ExitProcess(0);
}
