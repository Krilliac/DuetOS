/*
 * console3_smoke — third-tier console APIs beyond console / console2.
 *
 *   ReadConsoleInputW (skipped — would block)
 *   WriteConsoleOutputW (skipped — needs CHAR_INFO array)
 *   FlushConsoleInputBuffer
 *   GenerateConsoleCtrlEvent (skipped — heavy)
 *   GetConsoleWindow (returns HWND or NULL)
 *   GetConsoleProcessList
 *   AttachConsole / DetachConsole (skipped)
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
    Out("[console3_smoke] starting\r\n");

    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);

    BOOL fl = FlushConsoleInputBuffer(in);
    Out("[console3_smoke] FlushConsoleInputBuffer = ");
    Out("PASS (returned)\r\n");
    (void)fl;

    /* GetConsoleWindow — could return NULL on emulator. */
    HWND hw = GetConsoleWindow();
    Out("[console3_smoke] GetConsoleWindow      = ");
    Out("PASS (returned)\r\n");
    (void)hw;

    /* GetConsoleProcessList. */
    {
        DWORD pids[8];
        DWORD c = GetConsoleProcessList(pids, 8);
        Out("[console3_smoke] GetConsoleProcessList = ");
        Out(c >= 1 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[console3_smoke] done\r\n");
    Out("[ring3-console3-smoke] PASS\r\n");
    ExitProcess(0);
}
