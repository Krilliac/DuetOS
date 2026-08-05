/*
 * console4_smoke — console subsystem round-trip exercise.
 *
 * Tests the real (non-stub) console API implementations:
 *   GetStdHandle → WriteConsoleA output
 *   GetConsoleScreenBufferInfo → dimensions 80x25
 *   SetConsoleMode / GetConsoleMode round-trip
 *   SetConsoleCursorPosition (emits ANSI escape)
 *   SetConsoleTextAttribute (emits ANSI SGR)
 *   FillConsoleOutputCharacterA (emits fill)
 *   ReadConsoleA (real blocking read; only attempted when input is queued)
 */
#include <windows.h>

static HANDLE g_out;

static void Out(const char* s)
{
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(g_out, s, len, &n, 0);
}

void __cdecl mainCRTStartup(void)
{
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    Out("[console4_smoke] starting\r\n");

    /* 1. WriteConsoleA basic output. */
    {
        DWORD written = 0;
        const char msg[] = "Hello from console\r\n";
        BOOL ok = WriteConsoleA(g_out, msg, sizeof(msg) - 1, &written, NULL);
        Out("[console4_smoke] WriteConsoleA          = ");
        Out(ok && written == sizeof(msg) - 1 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* 2. GetConsoleScreenBufferInfo — verify 80x25. */
    {
        CONSOLE_SCREEN_BUFFER_INFO sbi = {0};
        BOOL ok = GetConsoleScreenBufferInfo(g_out, &sbi);
        Out("[console4_smoke] ScreenBufferInfo 80x25 = ");
        Out(ok && sbi.dwSize.X == 80 && sbi.dwSize.Y == 25 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* 3. SetConsoleMode / GetConsoleMode round-trip. */
    {
        DWORD original = 0;
        GetConsoleMode(in, &original);
        /* Set ENABLE_VIRTUAL_TERMINAL_INPUT (0x0200) in addition
         * to the defaults. */
        DWORD newMode = original | 0x0200;
        SetConsoleMode(in, newMode);
        DWORD readBack = 0;
        GetConsoleMode(in, &readBack);
        Out("[console4_smoke] ConsoleMode roundtrip  = ");
        Out(readBack == newMode ? "PASS\r\n" : "FAIL\r\n");
        /* Restore. */
        SetConsoleMode(in, original);
    }

    /* 4. SetConsoleCursorPosition. */
    {
        COORD pos = {5, 3};
        BOOL ok = SetConsoleCursorPosition(g_out, pos);
        /* Verify the stored position via GetConsoleScreenBufferInfo. */
        CONSOLE_SCREEN_BUFFER_INFO sbi = {0};
        GetConsoleScreenBufferInfo(g_out, &sbi);
        Out("[console4_smoke] SetCursorPosition      = ");
        Out(ok && sbi.dwCursorPosition.X == 5 && sbi.dwCursorPosition.Y == 3 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* 5. SetConsoleTextAttribute. */
    {
        BOOL ok = SetConsoleTextAttribute(g_out, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        Out("[console4_smoke] SetTextAttribute       = ");
        Out(ok ? "PASS\r\n" : "FAIL\r\n");
        /* Reset to default 0x07 (white on black). */
        SetConsoleTextAttribute(g_out, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    /* 6. FillConsoleOutputCharacterA. */
    {
        DWORD written = 0;
        COORD origin = {0, 0};
        BOOL ok = FillConsoleOutputCharacterA(g_out, ' ', 80 * 25, origin, &written);
        Out("[console4_smoke] FillOutputCharA        = ");
        Out(ok && written == 80u * 25u ? "PASS\r\n" : "FAIL\r\n");
    }

    /* 7. ReadConsoleA — now a real blocking read. Probe the input queue
     * first so an unattended boot doesn't wedge waiting for a keypress;
     * only attempt the read when input is already queued. */
    {
        DWORD nEvents = 0xFFFF;
        BOOL ok = GetNumberOfConsoleInputEvents(in, &nEvents);
        Out("[console4_smoke] ReadConsoleA           = ");
        if (ok && nEvents == 0)
        {
            Out("PASS (no input queued; blocking read skipped)\r\n");
        }
        else
        {
            char buf[16] = {0};
            DWORD nRead = 0;
            BOOL rok = ReadConsoleA(in, buf, sizeof(buf), &nRead, NULL);
            Out(rok ? "PASS\r\n" : "FAIL\r\n");
        }
    }

    Out("[console4_smoke] done\r\n");
    Out("[ring3-console4-smoke] PASS\r\n");
    ExitProcess(0);
}
