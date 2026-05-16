/*
 * select_smoke — exercise WinSock select / WSAEventSelect surface.
 *
 *   select on a fresh socket (should return 0 — no events)
 *   WSACreateEvent / WSACloseEvent
 *   WSAEventSelect (skipped — heavy)
 *   FD_ZERO / FD_SET (macros — pure logic)
 */
#include <winsock2.h>
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
    Out("[select_smoke] starting\r\n");

    WSADATA wsa = {0};
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    Out("[select_smoke] WSAStartup          = ");
    Out(rc == 0 ? "PASS\r\n" : "FAIL\r\n");

    /* FD_ZERO / FD_SET / FD_ISSET — pure logic. */
    {
        fd_set s;
        FD_ZERO(&s);
        FD_SET((SOCKET)42, &s);
        Out("[select_smoke] FD_ZERO + FD_SET    = ");
        Out(FD_ISSET((SOCKET)42, &s) ? "PASS\r\n" : "FAIL\r\n");
    }

    /* select with empty fdsets and 0 timeout. */
    {
        struct timeval tv = {0, 0};
        int n = select(0, NULL, NULL, NULL, &tv);
        Out("[select_smoke] select empty        = ");
        Out(n == 0 ? "PASS (0)\r\n" : "FAIL/STUB\r\n");
    }

    /* WSACreateEvent / WSACloseEvent. */
    {
        WSAEVENT e = WSACreateEvent();
        Out("[select_smoke] WSACreateEvent      = ");
        Out(e != WSA_INVALID_EVENT ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (e != WSA_INVALID_EVENT)
        {
            BOOL c = WSACloseEvent(e);
            Out("[select_smoke] WSACloseEvent       = ");
            Out(c ? "PASS\r\n" : "FAIL/STUB\r\n");
        }
    }

    WSACleanup();
    Out("[select_smoke] done\r\n");
    ExitProcess(0);
}
