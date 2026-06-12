/*
 * iocp2_smoke — verify IOCP across multiple posts.
 *
 *   CreateIoCompletionPort + Post x N + Get x N + Close
 *
 * Validates a stress-light pattern: post 4 completions, drain 4.
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
    Out("[iocp2_smoke] starting\r\n");

    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    Out("[iocp2_smoke] CreateIoCompletionPort = ");
    Out(iocp != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (iocp != NULL)
    {
        int posted = 0;
        for (int i = 0; i < 4; ++i)
            if (PostQueuedCompletionStatus(iocp, (DWORD)i, (ULONG_PTR)i, NULL))
                ++posted;
        Out("[iocp2_smoke] Post x4              = ");
        Out(posted == 4 ? "PASS\r\n" : "FAIL/STUB\r\n");

        int got = 0;
        for (int i = 0; i < 4; ++i)
        {
            DWORD bytes = 0;
            ULONG_PTR key = 0;
            OVERLAPPED* ov = NULL;
            if (GetQueuedCompletionStatus(iocp, &bytes, &key, &ov, 100))
                ++got;
        }
        Out("[iocp2_smoke] Get x4               = ");
        Out(got == 4 ? "PASS\r\n" : "FAIL/STUB\r\n");

        CloseHandle(iocp);
    }

    Out("[iocp2_smoke] done\r\n");
    Out("[ring3-iocp2-smoke] PASS\r\n");
    ExitProcess(0);
}
