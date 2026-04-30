/*
 * find_smoke — exercise FindXxx file/dir search APIs in depth.
 *
 *   FindFirstFileExW
 *   FindFirstFileW
 *   FindNextFileW (multi-iteration)
 *   FindFirstFileNameW (skipped — needs hardlinks)
 *   FindClose
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

static void OutDec(unsigned int v)
{
    char buf[16];
    int len = 0;
    if (v == 0)
        buf[len++] = '0';
    else
    {
        char rev[16];
        int r = 0;
        while (v != 0)
        {
            rev[r++] = (char)('0' + (v % 10));
            v /= 10;
        }
        for (int j = 0; j < r; ++j)
            buf[len++] = rev[r - 1 - j];
    }
    buf[len] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[find_smoke] starting\r\n");

    /* FindFirstFileW + FindNextFileW iteration. */
    {
        WIN32_FIND_DATAW fd = {0};
        HANDLE h = FindFirstFileW(L"/etc/*", &fd);
        Out("[find_smoke] FindFirstFileW(/etc) = ");
        if (h == INVALID_HANDLE_VALUE)
        {
            Out("FAIL\r\n");
        }
        else
        {
            int count = 1;
            while (FindNextFileW(h, &fd))
                ++count;
            Out("PASS entries=");
            OutDec((unsigned int)count);
            Out("\r\n");
            FindClose(h);
        }
    }

    /* FindFirstFileExW. */
    {
        WIN32_FIND_DATAW fd = {0};
        HANDLE h = FindFirstFileExW(L"/etc/*", FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
        Out("[find_smoke] FindFirstFileExW    = ");
        Out(h != INVALID_HANDLE_VALUE ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (h != INVALID_HANDLE_VALUE)
            FindClose(h);
    }

    /* Find on missing pattern. */
    {
        WIN32_FIND_DATAW fd = {0};
        HANDLE h = FindFirstFileW(L"/does/not/exist/*", &fd);
        Out("[find_smoke] FindFirstFileW(?)    = ");
        Out(h == INVALID_HANDLE_VALUE ? "PASS (INVALID, as expected)\r\n" : "FAIL\r\n");
        if (h != INVALID_HANDLE_VALUE)
            FindClose(h);
    }

    Out("[find_smoke] done\r\n");
    ExitProcess(0);
}
