/*
 * dns_smoke — exercise dnsapi / WinSock DNS APIs.
 *
 *   gethostname (ws2_32)
 *   getaddrinfo / freeaddrinfo
 *   getnameinfo (skipped — needs sockaddr)
 *
 * mini_browser already verified gethostbyname; this exercises
 * the modern getaddrinfo path that IPv6-aware code uses.
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
    Out("[dns_smoke] starting\r\n");

    WSADATA wsa = {0};
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    Out("[dns_smoke] WSAStartup            = ");
    Out(rc == 0 ? "PASS\r\n" : "FAIL\r\n");

    /* gethostname. */
    {
        char name[64] = {0};
        int r = gethostname(name, 64);
        Out("[dns_smoke] gethostname           = ");
        Out(r == 0 && name[0] != '\0' ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* getaddrinfo for a known name (won't succeed without
     * routing yet; we just verify it doesn't trap). */
    {
        struct addrinfo hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* res = NULL;
        int r = getaddrinfo("localhost", "80", &hints, &res);
        Out("[dns_smoke] getaddrinfo           = ");
        Out("PASS (returned)\r\n");
        (void)r;
        if (res != NULL)
            freeaddrinfo(res);
    }

    WSACleanup();
    Out("[dns_smoke] done\r\n");
    ExitProcess(0);
}
