/*
 * DuetOS — netd_probe, v0.
 *
 * A oneshot client that proves the resident `netd` daemon actually
 * SERVES traffic — not just that it reached listen(). It runs as a
 * Never service right after netd in the manifest: connect to
 * 127.0.0.1:7777 (the loopback short-circuit pairs this with netd's
 * wildcard 0.0.0.0 listener — the kernel matches loopback listeners by
 * port, not address), read netd's banner, send a token, and assert the
 * echo comes back byte-for-byte. Emits a single grep-able PASS/FAIL.
 *
 * This is the cross-process half of the netd story: net_loopback_smoke
 * proves the socket *mechanics* in one process; this proves a separate
 * process can connect to the resident daemon and round-trip data
 * through it — exercising connect() + the loopback accept pairing +
 * netd's accept/echo loop end to end.
 *
 * Race handling: netd binds/listens asynchronously after the service
 * manager spawns it, so the first connect() may land before the
 * listener exists. We retry with a short sleep (duet_sleep_ms) up to a
 * bounded budget rather than racing the daemon's bring-up.
 */

#include "duet/socket.h"
#include "duet/syscall.h"
#include "stdio.h"

#define PROBE_PORT 7777
#define PROBE_TOKEN "PROBE-PING"
#define PROBE_TOKEN_LEN 10
#define CONNECT_TRIES 50
#define CONNECT_RETRY_MS 100

/* Minimal fixed-length compare (no libc memcmp dependency). */
static int bytes_equal(const char* a, const char* b, long n)
{
    for (long i = 0; i < n; ++i)
        if (a[i] != b[i])
            return 0;
    return 1;
}

int main(void)
{
    struct duet_sockaddr_in dst;
    duet_sockaddr_in_loopback(&dst, PROBE_PORT);

    /* Fresh socket per attempt: a connect that fails because netd isn't
     * listening yet can leave the socket in a half-state, so don't reuse
     * it for the retry. */
    int s = -1;
    int connected = 0;
    for (int i = 0; i < CONNECT_TRIES; ++i)
    {
        s = duet_socket(DUET_AF_INET, DUET_SOCK_STREAM);
        if (s < 0)
        {
            puts_str("[netd-probe] FAIL socket\n");
            return 2;
        }
        if (duet_connect(s, &dst, (int)sizeof(dst)) == 0)
        {
            connected = 1;
            break;
        }
        duet_sock_close(s);
        s = -1;
        duet_sleep_ms(CONNECT_RETRY_MS); /* netd not listening yet — back off */
    }
    if (!connected)
    {
        puts_str("[netd-probe] FAIL connect (netd never came up)\n");
        return 3;
    }

    /* netd sends a banner on accept; drain it first. */
    char buf[256];
    const long banner = duet_recv(s, buf, (long)sizeof(buf));
    if (banner <= 0)
    {
        puts_str("[netd-probe] FAIL no banner\n");
        duet_sock_close(s);
        return 4;
    }

    /* Send the token and read it back. */
    if (duet_send(s, PROBE_TOKEN, PROBE_TOKEN_LEN) != PROBE_TOKEN_LEN)
    {
        puts_str("[netd-probe] FAIL send\n");
        duet_sock_close(s);
        return 5;
    }

    long got = 0;
    while (got < PROBE_TOKEN_LEN)
    {
        const long n = duet_recv(s, buf + got, (long)sizeof(buf) - got);
        if (n <= 0)
            break;
        got += n;
    }
    if (got != PROBE_TOKEN_LEN || !bytes_equal(buf, PROBE_TOKEN, PROBE_TOKEN_LEN))
    {
        puts_str("[netd-probe] FAIL echo mismatch\n");
        duet_sock_close(s);
        return 6;
    }

    puts_str("[netd-probe] PASS (banner + echo round-trip)\n");
    duet_sock_close(s);
    return 0;
}
