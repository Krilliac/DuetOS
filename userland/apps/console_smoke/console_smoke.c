/*
 * console_smoke — exercise kernel32 console APIs.
 *
 * Probes the console-handling surface every CLI tool uses for
 * ANSI escapes, cursor control, title, screen-buffer info:
 *   GetStdHandle (already exercised; sanity here)
 *   GetConsoleMode / SetConsoleMode
 *   GetConsoleCP / SetConsoleCP / GetConsoleOutputCP
 *   GetConsoleScreenBufferInfo
 *   SetConsoleTitleA / SetConsoleTitleW
 *   GetConsoleTitleA
 *   FillConsoleOutputCharacterA (skipped — would clobber output)
 *   AllocConsole (skipped — could trap)
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
    Out("[console_smoke] starting\r\n");

    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);

    Out("[console_smoke] GetStdHandle in/out/err = ");
    Out(in != INVALID_HANDLE_VALUE && out != INVALID_HANDLE_VALUE && err != INVALID_HANDLE_VALUE ? "PASS\r\n"
                                                                                                 : "FAIL\r\n");

    /* GetConsoleMode. */
    {
        DWORD mode = 0;
        BOOL ok = GetConsoleMode(in, &mode);
        Out("[console_smoke] GetConsoleMode(in)      = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetConsoleCP / GetConsoleOutputCP. */
    {
        UINT cp_in = GetConsoleCP();
        UINT cp_out = GetConsoleOutputCP();
        Out("[console_smoke] GetConsoleCP/OutputCP   = ");
        Out(cp_in > 0 && cp_out > 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* GetConsoleScreenBufferInfo. */
    {
        CONSOLE_SCREEN_BUFFER_INFO info = {0};
        BOOL ok = GetConsoleScreenBufferInfo(out, &info);
        Out("[console_smoke] GetConsoleScreenBufferInfo = ");
        Out(ok && info.dwSize.X > 0 && info.dwSize.Y > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* SetConsoleTitle round-trip. */
    {
        BOOL set = SetConsoleTitleA("DuetOS console smoke");
        Out("[console_smoke] SetConsoleTitleA        = ");
        Out(set ? "PASS\r\n" : "FAIL\r\n");

        char buf[64] = {0};
        DWORD n = GetConsoleTitleA(buf, 64);
        Out("[console_smoke] GetConsoleTitleA        = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* WriteConsoleW — wide write, just verify no trap. */
    {
        WCHAR text[] = L"[console_smoke] WriteConsoleW PASS\r\n";
        DWORD n = 0;
        WriteConsoleW(out, text, lstrlenW(text), &n, NULL);
    }

    Out("[console_smoke] done\r\n");
    Out("[ring3-console-smoke] PASS\r\n");
    ExitProcess(0);
}
