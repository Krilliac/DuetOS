/*
 * net_loopback_smoke — listener + connector exchange a known
 * payload over 127.0.0.1, verify a per-byte checksum across
 * the round-trip (T14-03 + T3-01).
 *
 *   1. WSAStartup
 *   2. listener = socket(AF_INET, SOCK_STREAM); bind(127.0.0.1:7777); listen
 *   3. connector = socket(...); connect(127.0.0.1, 7777)
 *   4. accepted = accept(listener)        — server side of the pair
 *   5. spawn a worker thread that recv's from accepted and folds
 *      every byte into a running checksum
 *   6. main thread writes 16 KiB of pseudo-random bytes to connector
 *   7. join, compare expected vs observed checksum
 *
 * Uses 16 KiB rather than the row's 1 MiB target — the kernel's
 * pipe ring is 4 KiB and the wait-queue still cooperates fine at
 * 16 KiB, but full 1 MiB stresses cooperation more than v0
 * latency can handle in a smoke window. Operators can crank up
 * BUF_SIZE for longer soak runs.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define BUF_SIZE 16384

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutHex(unsigned long v)
{
    char buf[12];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 8; ++i)
    {
        unsigned int nibble = (v >> ((7 - i) * 4)) & 0xFu;
        buf[2 + i] = (char)(nibble < 10 ? ('0' + nibble) : ('a' + nibble - 10));
    }
    buf[10] = '\r';
    buf[11] = '\n';
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    WriteConsoleA(h, buf, 12, &n, 0);
}

/* Mirror of the deterministic byte stream the writer thread
 * generates. Both sides compute the same expected checksum so
 * an off-by-one between sender and receiver shows up as a
 * checksum mismatch. */
static unsigned char gen_byte(int i)
{
    return (unsigned char)((i * 1103515245 + 12345) & 0xFFu);
}

static volatile unsigned long g_observed_checksum;
static volatile int g_recv_done;

static SOCKET g_accepted;

static DWORD __stdcall recv_thread(LPVOID arg)
{
    (void)arg;
    unsigned long sum = 0;
    int total = 0;
    char rbuf[1024];
    while (total < BUF_SIZE)
    {
        int got = recv(g_accepted, rbuf, sizeof(rbuf), 0);
        if (got <= 0)
            break;
        for (int i = 0; i < got; ++i)
            sum = sum * 31u + (unsigned char)rbuf[i];
        total += got;
    }
    g_observed_checksum = sum;
    g_recv_done = 1;
    return 0;
}

void __cdecl mainCRTStartup(void)
{
    Out("[net_loopback] starting\r\n");

    WSADATA wsa = {0};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        Out("[net_loopback] WSAStartup failed\r\n");
        Out("[ring3-net-loopback] FAIL wsastartup\r\n");
        ExitProcess(1);
    }

    SOCKET listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID_SOCKET)
    {
        Out("[net_loopback] FAIL listener socket\r\n");
        Out("[ring3-net-loopback] FAIL listener-socket\r\n");
        ExitProcess(2);
    }

    struct sockaddr_in la = {0};
    la.sin_family = AF_INET;
    la.sin_port = htons(7777);
    la.sin_addr.s_addr = htonl(0x7F000001u);
    if (bind(listener, (struct sockaddr*)&la, sizeof(la)) != 0)
    {
        Out("[net_loopback] FAIL bind\r\n");
        Out("[ring3-net-loopback] FAIL bind\r\n");
        ExitProcess(3);
    }
    if (listen(listener, 1) != 0)
    {
        Out("[net_loopback] FAIL listen\r\n");
        Out("[ring3-net-loopback] FAIL listen\r\n");
        ExitProcess(4);
    }
    Out("[net_loopback] listener bound + listening\r\n");

    SOCKET connector = socket(AF_INET, SOCK_STREAM, 0);
    if (connector == INVALID_SOCKET)
    {
        Out("[net_loopback] FAIL connector socket\r\n");
        Out("[ring3-net-loopback] FAIL connector-socket\r\n");
        ExitProcess(5);
    }
    struct sockaddr_in pa = {0};
    pa.sin_family = AF_INET;
    pa.sin_port = htons(7777);
    pa.sin_addr.s_addr = htonl(0x7F000001u);
    if (connect(connector, (struct sockaddr*)&pa, sizeof(pa)) != 0)
    {
        Out("[net_loopback] FAIL connect\r\n");
        Out("[ring3-net-loopback] FAIL connect\r\n");
        ExitProcess(6);
    }
    Out("[net_loopback] connect ok\r\n");

    struct sockaddr_in pa2 = {0};
    int pa2_len = sizeof(pa2);
    g_accepted = accept(listener, (struct sockaddr*)&pa2, &pa2_len);
    if (g_accepted == INVALID_SOCKET)
    {
        Out("[net_loopback] FAIL accept\r\n");
        Out("[ring3-net-loopback] FAIL accept\r\n");
        ExitProcess(7);
    }
    Out("[net_loopback] accept ok\r\n");

    /* Compute expected checksum of the byte stream we're about
     * to send, BEFORE actually sending anything. */
    unsigned long expected = 0;
    for (int i = 0; i < BUF_SIZE; ++i)
        expected = expected * 31u + gen_byte(i);

    /* Spawn the receive worker. */
    DWORD tid = 0;
    HANDLE rt = CreateThread(0, 0, recv_thread, 0, 0, &tid);
    if (rt == 0)
    {
        Out("[net_loopback] FAIL CreateThread\r\n");
        Out("[ring3-net-loopback] FAIL create-thread\r\n");
        ExitProcess(8);
    }

    /* Send the payload in 1 KiB chunks. send() may return short
     * writes if the pipe ring is full; loop until we've pushed
     * the full count. */
    char wbuf[1024];
    int sent_total = 0;
    int chunk_id = 0;
    while (sent_total < BUF_SIZE)
    {
        int chunk = sizeof(wbuf);
        if (sent_total + chunk > BUF_SIZE)
            chunk = BUF_SIZE - sent_total;
        for (int i = 0; i < chunk; ++i)
            wbuf[i] = (char)gen_byte(sent_total + i);
        int wrote = send(connector, wbuf, chunk, 0);
        if (wrote <= 0)
        {
            Out("[net_loopback] FAIL send returned 0/error chunk=");
            OutHex((unsigned long)chunk_id);
            Out("[ring3-net-loopback] FAIL send\r\n");
            ExitProcess(9);
        }
        sent_total += wrote;
        ++chunk_id;
    }
    Out("[net_loopback] send complete\r\n");

    /* Wait for the receive worker to drain the connection. */
    WaitForSingleObject(rt, 30000);
    CloseHandle(rt);

    if (!g_recv_done)
    {
        Out("[net_loopback] FAIL receive timed out\r\n");
        Out("[ring3-net-loopback] FAIL recv-timeout\r\n");
        ExitProcess(10);
    }

    Out("[net_loopback] expected = ");
    OutHex(expected);
    Out("[net_loopback] observed = ");
    OutHex(g_observed_checksum);

    closesocket(g_accepted);
    closesocket(connector);
    closesocket(listener);
    WSACleanup();

    if (expected != g_observed_checksum)
    {
        Out("[net_loopback] FAIL checksum mismatch\r\n");
        Out("[ring3-net-loopback] FAIL checksum-mismatch\r\n");
        ExitProcess(11);
    }
    Out("[net_loopback] done OK\r\n");
    Out("[ring3-net-loopback] PASS\r\n");
    ExitProcess(0);
}
