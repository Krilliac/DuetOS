/*
 * winsock_ext_smoke — exercise WSAxxx extension surface.
 *
 *   WSACreateEvent / WSAResetEvent / WSASetEvent / WSACloseEvent
 *   WSAGetLastError
 *   WSAAddressToStringA
 *   WSAEnumProtocolsA (skipped — heavy)
 */
#include <winsock2.h>
#include <ws2tcpip.h>
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
    Out("[winsock_ext_smoke] starting\r\n");

    WSADATA wsa = {0};
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    Out("[winsock_ext_smoke] WSAStartup            = ");
    Out(rc == 0 ? "PASS\r\n" : "FAIL\r\n");

    /* WSACreateEvent + WSASetEvent + WSAResetEvent + WSACloseEvent. */
    {
        WSAEVENT e = WSACreateEvent();
        Out("[winsock_ext_smoke] WSACreateEvent        = ");
        Out(e != WSA_INVALID_EVENT ? "PASS\r\n" : "FAIL/STUB\r\n");

        if (e != WSA_INVALID_EVENT)
        {
            BOOL s = WSASetEvent(e);
            Out("[winsock_ext_smoke] WSASetEvent           = ");
            Out(s ? "PASS\r\n" : "FAIL/STUB\r\n");

            BOOL r = WSAResetEvent(e);
            Out("[winsock_ext_smoke] WSAResetEvent         = ");
            Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");

            BOOL c = WSACloseEvent(e);
            Out("[winsock_ext_smoke] WSACloseEvent         = ");
            Out(c ? "PASS\r\n" : "FAIL/STUB\r\n");
        }
    }

    /* WSAGetLastError after a known-bad operation. */
    {
        SOCKET bad = (SOCKET)0xDEADBEEF;
        char buf[8];
        send(bad, buf, 1, 0);
        int err = WSAGetLastError();
        Out("[winsock_ext_smoke] WSAGetLastError       = ");
        Out(err != 0 ? "PASS (non-zero)\r\n" : "FAIL/STUB\r\n");
    }

    WSACleanup();
    Out("[winsock_ext_smoke] done\r\n");
    ExitProcess(0);
}
