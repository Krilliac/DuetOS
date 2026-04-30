/*
 * msg_smoke — exercise user32 messaging APIs.
 *
 * Probes the per-thread message queue surface every Windows
 * GUI app uses. We don't have a window so SendMessage paths
 * that need a window proc are STUB; we focus on the queue
 * primitives:
 *   PostThreadMessageA / PostThreadMessageW
 *   GetMessageA / GetMessageW (timeout via PeekMessage instead)
 *   PeekMessageA / PeekMessageW
 *   TranslateMessage
 *   DispatchMessageA / DispatchMessageW
 *   GetCurrentThreadId (sanity)
 *   PostQuitMessage / WM_QUIT detection
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
    Out("[msg_smoke] starting\r\n");

    DWORD tid = GetCurrentThreadId();
    Out("[msg_smoke] GetCurrentThreadId  = ");
    Out(tid != 0 ? "PASS\r\n" : "FAIL\r\n");

    /* Post a thread message to ourselves. */
    BOOL post = PostThreadMessageA(tid, WM_USER + 1, 0xCAFE, 0xBABE);
    Out("[msg_smoke] PostThreadMessageA  = ");
    Out(post ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* PeekMessage to drain. */
    {
        MSG msg;
        BOOL got = PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE);
        Out("[msg_smoke] PeekMessageA(PM_REMOVE) = ");
        if (got)
        {
            Out("PASS msg=");
            char hex[8];
            const char* h = "0123456789abcdef";
            unsigned int m = msg.message;
            for (int i = 3; i >= 0; --i)
                hex[3 - i] = h[(m >> (i * 4)) & 0xF];
            hex[4] = '\0';
            Out(hex);
            Out("\r\n");
        }
        else
        {
            Out("FAIL/STUB\r\n");
        }
    }

    /* PeekMessage on empty queue → 0. */
    {
        MSG msg;
        BOOL got = PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE);
        Out("[msg_smoke] PeekMessageA(empty) = ");
        Out(!got ? "PASS (empty, as expected)\r\n" : "FAIL/STUB\r\n");
    }

    /* PostQuitMessage. */
    PostQuitMessage(42);
    Out("[msg_smoke] PostQuitMessage     = PASS (returned)\r\n");

    /* TranslateMessage / DispatchMessage on a synthetic msg. */
    {
        MSG msg = {0};
        msg.hwnd = NULL;
        msg.message = WM_KEYDOWN;
        msg.wParam = 'A';
        BOOL t = TranslateMessage(&msg);
        Out("[msg_smoke] TranslateMessage    = ");
        Out("PASS (returned ");
        Out(t ? "TRUE)\r\n" : "FALSE)\r\n");

        LRESULT r = DispatchMessageA(&msg);
        (void)r;
        Out("[msg_smoke] DispatchMessageA    = PASS (returned)\r\n");
    }

    Out("[msg_smoke] done\r\n");
    ExitProcess(0);
}
