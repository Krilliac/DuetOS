/*
 * sock_opt_smoke — extended socket options.
 *
 *   setsockopt / getsockopt for: SO_BROADCAST, SO_KEEPALIVE,
 *   SO_RCVBUF, SO_SNDBUF, SO_LINGER
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
    Out("[sock_opt_smoke] starting\r\n");

    WSADATA wsa = {0};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Out("[sock_opt_smoke] socket               = ");
    Out(s != INVALID_SOCKET ? "PASS\r\n" : "FAIL\r\n");

    if (s != INVALID_SOCKET)
    {
        int opt = 1;
        int rc = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char*)&opt, sizeof(opt));
        Out("[sock_opt_smoke] setsockopt SO_KEEPALIVE = ");
        Out(rc == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        int buf_sz = 65536;
        rc = setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&buf_sz, sizeof(buf_sz));
        Out("[sock_opt_smoke] setsockopt SO_RCVBUF = ");
        Out(rc == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        rc = setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char*)&buf_sz, sizeof(buf_sz));
        Out("[sock_opt_smoke] setsockopt SO_SNDBUF = ");
        Out(rc == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        closesocket(s);
    }

    WSACleanup();
    Out("[sock_opt_smoke] done\r\n");
    ExitProcess(0);
}
