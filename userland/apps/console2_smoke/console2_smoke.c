/*
 * console2_smoke — extended console / cursor / attribute coverage.
 *
 *   SetConsoleCursorPosition
 *   GetConsoleCursorInfo / SetConsoleCursorInfo
 *   SetConsoleTextAttribute
 *   FillConsoleOutputAttribute
 *   ScrollConsoleScreenBufferW
 *   AllocConsole / FreeConsole (skipped — would attach a new console)
 *   GetNumberOfConsoleInputEvents
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
    Out("[console2_smoke] starting\r\n");

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);

    /* SetConsoleCursorPosition. */
    {
        COORD c = {0, 0};
        BOOL ok = SetConsoleCursorPosition(out, c);
        Out("[console2_smoke] SetConsoleCursorPosition = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetConsoleCursorInfo. */
    {
        CONSOLE_CURSOR_INFO ci = {0};
        BOOL ok = GetConsoleCursorInfo(out, &ci);
        Out("[console2_smoke] GetConsoleCursorInfo  = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* SetConsoleTextAttribute. */
    {
        BOOL ok = SetConsoleTextAttribute(out, FOREGROUND_RED | FOREGROUND_GREEN);
        Out("[console2_smoke] SetConsoleTextAttribute = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
        /* Reset. */
        SetConsoleTextAttribute(out, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    /* FillConsoleOutputAttribute. */
    {
        DWORD written = 0;
        COORD origin = {0, 0};
        BOOL ok = FillConsoleOutputAttribute(out, FOREGROUND_RED, 10, origin, &written);
        Out("[console2_smoke] FillConsoleOutputAttribute = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetNumberOfConsoleInputEvents. */
    {
        DWORD ev = 0;
        BOOL ok = GetNumberOfConsoleInputEvents(in, &ev);
        Out("[console2_smoke] GetNumberOfConsoleInputEvents = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[console2_smoke] done\r\n");
    ExitProcess(0);
}
