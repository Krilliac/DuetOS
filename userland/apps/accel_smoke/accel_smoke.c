/*
 * accel_smoke — exercise user32 keyboard-accelerator APIs.
 *
 *   LoadAcceleratorsW (skipped — needs resource)
 *   CreateAcceleratorTableW
 *   CopyAcceleratorTableW
 *   DestroyAcceleratorTable
 *   TranslateAcceleratorW (skipped — needs window + msg)
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
    Out("[accel_smoke] starting\r\n");

    ACCEL accels[2] = {
        {FCONTROL | FVIRTKEY, 'C', 1001},
        {FCONTROL | FVIRTKEY, 'V', 1002},
    };
    HACCEL h = CreateAcceleratorTableW(accels, 2);
    Out("[accel_smoke] CreateAcceleratorTableW = ");
    Out(h != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (h != NULL)
    {
        ACCEL out_buf[2] = {0};
        int n = CopyAcceleratorTableW(h, out_buf, 2);
        Out("[accel_smoke] CopyAcceleratorTableW = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        BOOL d = DestroyAcceleratorTable(h);
        Out("[accel_smoke] DestroyAcceleratorTable = ");
        Out(d ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[accel_smoke] done\r\n");
    ExitProcess(0);
}
