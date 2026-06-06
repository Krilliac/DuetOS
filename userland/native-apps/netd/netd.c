/*
 * DuetOS — netd, the first resident userland network daemon, v0.
 *
 * A long-running TCP server: bind INADDR_ANY:7777, listen, then loop
 * forever accepting connections and echoing bytes back (with a one-
 * line banner on connect). It is DuetOS's first userland program that
 * is a network *server* rather than a run-once smoke — and the first
 * service the kernel service manager runs with restart=Always
 * (kernel/core/service.cpp). Two things it proves end-to-end:
 *
 *   1. The native libc's BSD socket wrappers (duet/socket.h) reach the
 *      same kernel socket pool the Win32 ws2_32.dll uses — one TCP/IP
 *      stack, two ABI front-ends.
 *   2. The service manager's Always-respawn path keeps a real resident
 *      process alive: netd never exits on the happy path, so `svc list`
 *      shows it `running`; if it ever dies, svcmon respawns it (rate-
 *      limited against crash loops).
 *
 * Blocking model: accept() and recv() block in the kernel net layer
 * (kernel/net/socket.cpp) until a connection / data arrives or the
 * peer FINs, so the daemon parks cheaply between clients rather than
 * spinning. Single connection at a time (v0) — the listener backlog
 * queues the next client while one is being served.
 *
 * Exit discipline: any setup failure (socket/bind/listen) returns a
 * non-zero status, which the Always policy turns into a respawn. A
 * persistently broken net stack therefore trips the supervisor's
 * crash-loop guard and lands netd in `failed` rather than looping
 * forever — visible in `svc list`.
 */

#include "duet/socket.h"
#include "duet/syscall.h"
#include "stdio.h"

#define NETD_PORT 7777
#define NETD_BACKLOG 4
#define NETD_BUFSZ 1024

int main(void)
{
    const int s = duet_socket(DUET_AF_INET, DUET_SOCK_STREAM);
    if (s < 0)
    {
        puts_str("[netd] FAIL socket\n");
        return 2;
    }

    struct duet_sockaddr_in addr;
    duet_sockaddr_in_any(&addr, NETD_PORT);
    if (duet_bind(s, &addr, (int)sizeof(addr)) != 0)
    {
        puts_str("[netd] FAIL bind\n");
        return 3;
    }
    if (duet_listen(s, NETD_BACKLOG) != 0)
    {
        puts_str("[netd] FAIL listen\n");
        return 4;
    }

    puts_str("[netd] listening on 0.0.0.0:7777 (TCP echo)\n");

    /* Resident accept loop — never returns on the happy path. */
    for (;;)
    {
        const int c = duet_accept(s, 0, 0);
        if (c < 0)
        {
            /* Listener torn down or a fatal accept error: bail so the
             * Always policy can respawn us from a clean state. */
            puts_str("[netd] accept error — exiting for respawn\n");
            duet_sock_close(s);
            return 5;
        }

        puts_str("[netd] client connected\n");
        (void)duet_send(c, "DuetOS netd ready\n", 18);

        /* Echo until the peer closes (recv returns 0) or errors. */
        char buf[NETD_BUFSZ];
        for (;;)
        {
            const long n = duet_recv(c, buf, (long)sizeof(buf));
            if (n <= 0)
                break;
            long off = 0;
            while (off < n)
            {
                const long w = duet_send(c, buf + off, n - off);
                if (w <= 0)
                    break;
                off += w;
            }
        }
        duet_sock_close(c);
        puts_str("[netd] client closed\n");
    }
}
