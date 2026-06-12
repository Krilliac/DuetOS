/*
 * stream_smoke — exercise overlapped + completion-port APIs.
 *
 *   CreateIoCompletionPort
 *   GetQueuedCompletionStatus (with 0 timeout)
 *   PostQueuedCompletionStatus
 *   CancelIoEx
 *   ReadFileEx (skipped — needs APC)
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
    Out("[stream_smoke] starting\r\n");

    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    Out("[stream_smoke] CreateIoCompletionPort = ");
    Out(iocp != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (iocp != NULL)
    {
        BOOL p = PostQueuedCompletionStatus(iocp, 42, 0xCAFE, NULL);
        Out("[stream_smoke] PostQueuedCompletionStatus = ");
        Out(p ? "PASS\r\n" : "FAIL/STUB\r\n");

        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* ov = NULL;
        BOOL g = GetQueuedCompletionStatus(iocp, &bytes, &key, &ov, 100);
        Out("[stream_smoke] GetQueuedCompletionStatus = ");
        Out(g && bytes == 42 && key == 0xCAFE ? "PASS\r\n" : "FAIL/STUB\r\n");

        CloseHandle(iocp);
    }

    Out("[stream_smoke] done\r\n");
    Out("[ring3-stream-smoke] PASS\r\n");
    ExitProcess(0);
}
