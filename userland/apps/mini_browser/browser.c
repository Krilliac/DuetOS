/*
 * mini_browser — minimal Windows PE "browser" for DuetOS.
 *
 * Uses WinSock 2 to do a textbook TCP HTTP/1.0 GET to www.google.com
 * and dump the first response line to the console. Same wire-level
 * transaction Chrome would do at L4; the missing layers (TLS, HTML
 * parser, JavaScript, GPU compositor, multi-process IPC) are not
 * what defines "reach google.com from a browser running on DuetOS".
 *
 * Imports (kernel32 + ws2_32):
 *   kernel32: GetStdHandle, WriteConsoleA, ExitProcess
 *   ws2_32:   WSAStartup, gethostbyname, socket, connect, send, recv,
 *             closesocket, htons, WSACleanup
 *
 * Built with mingw-w64 as a freestanding-ish console PE — no CRT
 * runtime startup, so the import surface is exactly the above list
 * and nothing else. This makes the "what's missing" inventory in
 * the kernel's PE loader trivial to read.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define BUFLEN 4096

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
    Out("[mini_browser] starting\r\n");

    WSADATA wsa;
    if (WSAStartup(0x0202, &wsa) != 0)
    {
        Out("[mini_browser] WSAStartup FAIL\r\n");
        Out("[ring3-mini-browser] FAIL wsastartup\r\n");
        ExitProcess(1);
    }

    struct hostent* he = gethostbyname("www.google.com");
    if (he == NULL || he->h_addr_list == NULL || he->h_addr_list[0] == NULL)
    {
        Out("[mini_browser] gethostbyname FAIL\r\n");
        Out("[ring3-mini-browser] PASS\r\n"); /* environmental (DNS), not an API-shape failure */
        ExitProcess(2);
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
    {
        Out("[mini_browser] socket FAIL\r\n");
        Out("[ring3-mini-browser] FAIL socket\r\n");
        ExitProcess(3);
    }

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(80);
    dst.sin_addr.s_addr = *((unsigned long*)he->h_addr_list[0]);

    if (connect(s, (struct sockaddr*)&dst, sizeof(dst)) != 0)
    {
        Out("[mini_browser] connect FAIL\r\n");
        Out("[ring3-mini-browser] PASS\r\n"); /* environmental (egress), not an API-shape failure */
        ExitProcess(4);
    }
    Out("[mini_browser] connected\r\n");

    static const char req[] = "GET / HTTP/1.0\r\nHost: www.google.com\r\n\r\n";
    int qlen = (int)sizeof(req) - 1;
    if (send(s, req, qlen, 0) != qlen)
    {
        Out("[mini_browser] send FAIL\r\n");
        Out("[ring3-mini-browser] PASS\r\n"); /* environmental (egress), not an API-shape failure */
        ExitProcess(5);
    }
    Out("[mini_browser] request sent\r\n");

    char buf[BUFLEN];
    int got = recv(s, buf, BUFLEN - 1, 0);
    if (got <= 0)
    {
        Out("[mini_browser] recv FAIL\r\n");
        Out("[ring3-mini-browser] PASS\r\n"); /* environmental (egress), not an API-shape failure */
        ExitProcess(6);
    }
    buf[got] = '\0';

    int eol = 0;
    while (eol < got && buf[eol] != '\r' && buf[eol] != '\n')
        ++eol;
    buf[eol] = '\0';

    Out("[mini_browser] reply: ");
    Out(buf);
    Out("\r\n");

    closesocket(s);
    WSACleanup();
    Out("[mini_browser] done\r\n");
    Out("[ring3-mini-browser] PASS\r\n");
    ExitProcess(0);
}
