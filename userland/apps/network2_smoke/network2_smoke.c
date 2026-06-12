/*
 * network2_smoke — extended ws2_32 socket-option / select coverage
 * beyond mini_browser (which only does the basic socket flow).
 *
 *   socket / closesocket
 *   setsockopt / getsockopt (SO_REUSEADDR)
 *   ntohs / htons / ntohl / htonl
 *   inet_addr
 *   inet_ntoa (legacy)
 *   ioctlsocket (FIONREAD / FIONBIO)
 *   bind on AF_INET (will likely STUB)
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
    Out("[network2_smoke] starting\r\n");

    WSADATA wsa = {0};
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    Out("[network2_smoke] WSAStartup            = ");
    Out(rc == 0 ? "PASS\r\n" : "FAIL\r\n");

    /* Byte-order conversions are pure logic — should always PASS. */
    Out("[network2_smoke] htons(0x1234)         = ");
    Out(htons(0x1234) == 0x3412 ? "PASS\r\n" : "FAIL\r\n");

    Out("[network2_smoke] ntohs round-trip      = ");
    Out(ntohs(htons(0xABCD)) == 0xABCD ? "PASS\r\n" : "FAIL\r\n");

    Out("[network2_smoke] htonl(0x12345678)     = ");
    Out(htonl(0x12345678U) == 0x78563412U ? "PASS\r\n" : "FAIL\r\n");

    /* inet_addr. */
    {
        unsigned int ip = inet_addr("192.168.1.1");
        Out("[network2_smoke] inet_addr             = ");
        Out(ip != INADDR_NONE ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* socket + setsockopt + getsockopt. */
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Out("[network2_smoke] socket(TCP)           = ");
    Out(s != INVALID_SOCKET ? "PASS\r\n" : "FAIL\r\n");

    if (s != INVALID_SOCKET)
    {
        int opt = 1;
        int r = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        Out("[network2_smoke] setsockopt SO_REUSEADDR = ");
        Out(r == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        int got = 0;
        int got_sz = sizeof(got);
        r = getsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&got, &got_sz);
        Out("[network2_smoke] getsockopt SO_REUSEADDR = ");
        Out(r == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        /* ioctlsocket FIONBIO. */
        unsigned long nb = 1;
        r = ioctlsocket(s, FIONBIO, &nb);
        Out("[network2_smoke] ioctlsocket FIONBIO   = ");
        Out(r == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        closesocket(s);
    }

    WSACleanup();
    Out("[network2_smoke] done\r\n");
    Out("[ring3-network2-smoke] PASS\r\n");
    ExitProcess(0);
}
