/*
 * conio_smoke — exercise msvcrt console-I/O conio.h APIs.
 *
 *   _getch (skipped — would block)
 *   _kbhit
 *   _putch / _putwch
 *   _cputs (legacy)
 */
#include <windows.h>
#include <conio.h>

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
    Out("[conio_smoke] starting\r\n");

    /* _kbhit — should return 0 (no key pending). */
    int kh = _kbhit();
    Out("[conio_smoke] _kbhit              = ");
    Out(kh == 0 ? "PASS (0, no key)\r\n" : "FAIL\r\n");

    /* _putch — write a single character. */
    int rc = _putch('X');
    Out("[conio_smoke] _putch              = ");
    Out(rc == 'X' ? "PASS\r\n" : "FAIL/STUB\r\n");
    _putch('\n');

    /* _cputs (legacy const-char* version). */
    rc = _cputs("[conio_smoke] _cputs hello\n");
    Out("[conio_smoke] _cputs              = ");
    Out(rc == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    Out("[conio_smoke] done\r\n");
    ExitProcess(0);
}
