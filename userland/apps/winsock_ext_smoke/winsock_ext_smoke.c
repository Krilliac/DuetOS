/*
 * winsock_ext_smoke — exercise WSAxxx extension surface.
 *
 *   WSACreateEvent / WSAResetEvent / WSASetEvent / WSACloseEvent
 *   WSAGetLastError
 *   WSAAsyncSelect (loopback listener + connector, FD_ACCEPT / FD_READ
 *                   delivered as window messages through a PeekMessage pump)
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

    /* WSAAsyncSelect — end-to-end over loopback. A hidden window receives
     * WM_USER+1 from ws2_32's poller thread: FD_ACCEPT when the connector's
     * connect lands on the listener, then FD_READ on the accepted socket
     * when the connector's payload arrives. wParam must carry the socket,
     * LOWORD(lParam) the single FD_* event (WSAMAKESELECTREPLY shape). */
    {
        const UINT kSockMsg = WM_USER + 1;
        WNDCLASSA wc = {0};
        wc.lpfnWndProc = DefWindowProcA;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.lpszClassName = "WsaAsyncSmokeCls";
        RegisterClassA(&wc);
        HWND hwnd = CreateWindowExA(0, "WsaAsyncSmokeCls", "wsaasync", 0, 0, 0, 32, 32, NULL, NULL, wc.hInstance, NULL);
        Out("[winsock_ext_smoke] CreateWindowExA       = ");
        Out(hwnd != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

        SOCKET listener = socket(AF_INET, SOCK_STREAM, 0);
        SOCKET connector = socket(AF_INET, SOCK_STREAM, 0);
        SOCKET accepted = INVALID_SOCKET;
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(7791);
        sa.sin_addr.s_addr = htonl(0x7F000001u);
        int net_ok = (hwnd != NULL) && (listener != INVALID_SOCKET) && (connector != INVALID_SOCKET) &&
                     bind(listener, (struct sockaddr*)&sa, sizeof(sa)) == 0 && listen(listener, 1) == 0;

        int reg = net_ok ? WSAAsyncSelect(listener, hwnd, kSockMsg, FD_ACCEPT) : SOCKET_ERROR;
        Out("[winsock_ext_smoke] WSAAsyncSelect reg    = ");
        Out(reg == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        if (reg == 0 && connect(connector, (struct sockaddr*)&sa, sizeof(sa)) == 0)
        {
            int got_accept = 0;
            int got_read = 0;
            /* Pump with a hard iteration cap so a missing message FAILs the
             * step instead of wedging the smoke (~8 s worst case). */
            for (int iter = 0; iter < 800 && !(got_accept && got_read); ++iter)
            {
                MSG m;
                if (!PeekMessageA(&m, hwnd, 0, 0, PM_REMOVE))
                {
                    Sleep(10);
                    continue;
                }
                if (m.message != kSockMsg)
                    continue;
                const int ev = WSAGETSELECTEVENT(m.lParam);
                if (ev == FD_ACCEPT && (SOCKET)m.wParam == listener && !got_accept)
                {
                    got_accept = 1;
                    accepted = accept(listener, NULL, NULL);
                    if (accepted != INVALID_SOCKET)
                    {
                        WSAAsyncSelect(accepted, hwnd, kSockMsg, FD_READ | FD_CLOSE);
                        send(connector, "ping", 4, 0);
                    }
                }
                else if (ev == FD_READ && (SOCKET)m.wParam == accepted)
                {
                    char rb[8];
                    if (recv(accepted, rb, sizeof(rb), 0) == 4)
                        got_read = 1;
                }
            }
            Out("[winsock_ext_smoke] WSAAsyncSelect FD_ACCEPT = ");
            Out(got_accept ? "PASS\r\n" : "FAIL/STUB (timeout)\r\n");
            Out("[winsock_ext_smoke] WSAAsyncSelect FD_READ   = ");
            Out(got_read ? "PASS\r\n" : "FAIL/STUB (timeout)\r\n");
            Out("[winsock_ext_smoke] WSAAsyncSelect = ");
            Out(got_accept && got_read ? "PASS\r\n" : "FAIL\r\n");
        }
        else
        {
            Out("[winsock_ext_smoke] WSAAsyncSelect = FAIL (setup)\r\n");
        }

        if (accepted != INVALID_SOCKET)
            closesocket(accepted);
        if (connector != INVALID_SOCKET)
            closesocket(connector);
        if (listener != INVALID_SOCKET)
            closesocket(listener);
    }

    WSACleanup();
    Out("[winsock_ext_smoke] done\r\n");
    ExitProcess(0);
}
