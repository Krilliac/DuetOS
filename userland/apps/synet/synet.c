// Linux-ABI socket exerciser. Sister of synxtest / synfs. Spawned
// with kCapNet so each call in the socket family actually reaches
// its handler instead of bouncing off the sandbox cap gate.
//
// One sc3(write) per line: see synfs.c for why ("[net] X rc=N\n"
// in a single buffer beats kernel-log interleaving).

typedef unsigned long u64;
typedef unsigned short u16;
typedef long i64;

__attribute__((used)) void* memset(void* d, int c, unsigned long n)
{
    unsigned char* p = (unsigned char*)d;
    for (unsigned long i = 0; i < n; ++i)
        p[i] = (unsigned char)c;
    return d;
}
__attribute__((used)) void* memcpy(void* d, const void* s, unsigned long n)
{
    unsigned char* dp = (unsigned char*)d;
    const unsigned char* sp = (const unsigned char*)s;
    for (unsigned long i = 0; i < n; ++i)
        dp[i] = sp[i];
    return d;
}

static inline i64 sc1(long nr, u64 a1)
{
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1) : "rcx", "r11", "memory");
    return r;
}
static inline i64 sc2(long nr, u64 a1, u64 a2)
{
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return r;
}
static inline i64 sc3(long nr, u64 a1, u64 a2, u64 a3)
{
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return r;
}
static inline i64 sc5(long nr, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5)
{
    i64 r;
    register u64 r10 __asm__("r10") = a4;
    register u64 r8 __asm__("r8") = a5;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return r;
}
static inline i64 sc6(long nr, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6)
{
    i64 r;
    register u64 r10 __asm__("r10") = a4;
    register u64 r8 __asm__("r8") = a5;
    register u64 r9 __asm__("r9") = a6;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}

static char nbuf[160];
static void report_rc(const char* label, i64 v)
{
    int i = 0;
    nbuf[i++] = '[';
    nbuf[i++] = 'n';
    nbuf[i++] = 'e';
    nbuf[i++] = 't';
    nbuf[i++] = ']';
    nbuf[i++] = ' ';
    while (*label && i < (int)sizeof(nbuf) - 16)
        nbuf[i++] = *label++;
    nbuf[i++] = ' ';
    nbuf[i++] = 'r';
    nbuf[i++] = 'c';
    nbuf[i++] = '=';
    int neg = 0;
    if (v < 0)
    {
        neg = 1;
        v = -v;
    }
    if (v == 0)
        nbuf[i++] = '0';
    else
    {
        char tmp[20];
        int j = 0;
        while (v > 0)
        {
            tmp[j++] = '0' + (int)(v % 10);
            v /= 10;
        }
        if (neg)
            nbuf[i++] = '-';
        while (j > 0)
            nbuf[i++] = tmp[--j];
    }
    nbuf[i++] = '\n';
    sc3(1, 1, (u64)nbuf, i);
}
static void puts_raw(const char* s)
{
    unsigned n = 0;
    while (s[n])
        ++n;
    sc3(1, 1, (u64)s, n);
}

// Build a struct sockaddr_in (16 bytes): family=AF_INET(2), port (BE),
// addr (BE), 8 bytes zero pad. We're freestanding so do byte-shuffles
// ourselves.
static void mk_sockaddr_in(unsigned char* dst, u16 port_he, unsigned long ip_he)
{
    for (int i = 0; i < 16; ++i)
        dst[i] = 0;
    dst[0] = 2; // AF_INET little-endian-low byte
    dst[1] = 0;
    dst[2] = (unsigned char)((port_he >> 8) & 0xFF);
    dst[3] = (unsigned char)(port_he & 0xFF);
    dst[4] = (unsigned char)((ip_he >> 24) & 0xFF);
    dst[5] = (unsigned char)((ip_he >> 16) & 0xFF);
    dst[6] = (unsigned char)((ip_he >> 8) & 0xFF);
    dst[7] = (unsigned char)(ip_he & 0xFF);
}

// 127.0.0.1 in host order.
static const unsigned long kLoopback = (127UL << 24) | 1UL;

#define AF_INET 2
#define AF_UNIX 1
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3

void _start(void)
{
    puts_raw("[net] start\n");

    // === socket() — domain matrix ===
    i64 udp_fd = sc3(41 /*socket*/, AF_INET, SOCK_DGRAM, 0);
    report_rc("socket(AF_INET,SOCK_DGRAM)", udp_fd);
    i64 tcp_fd = sc3(41, AF_INET, SOCK_STREAM, 0);
    report_rc("socket(AF_INET,SOCK_STREAM)", tcp_fd);
    report_rc("socket(AF_INET,SOCK_RAW)", sc3(41, AF_INET, SOCK_RAW, 0));
    report_rc("socket(AF_UNIX,SOCK_STREAM)", sc3(41, AF_UNIX, SOCK_STREAM, 0));
    report_rc("socket(AF_INET6,SOCK_DGRAM)", sc3(41, AF_INET6, SOCK_DGRAM, 0));

    if (udp_fd < 0)
    {
        puts_raw("[net] no UDP fd, skipping bind/sendto/recvfrom\n");
    }
    else
    {
        // === bind to 127.0.0.1:0 ===
        unsigned char sa[16];
        mk_sockaddr_in(sa, 0, kLoopback);
        report_rc("bind(udp,127.0.0.1:0)", sc3(49 /*bind*/, udp_fd, (u64)sa, 16));

        // === getsockname ===
        unsigned char gsa[16];
        unsigned int alen = 16;
        for (int i = 0; i < 16; ++i)
            gsa[i] = 0;
        report_rc("getsockname(udp)", sc3(51 /*getsockname*/, udp_fd, (u64)gsa, (u64)&alen));
        // === getpeername (not connected) — expect -ENOTCONN ===
        for (int i = 0; i < 16; ++i)
            gsa[i] = 0;
        alen = 16;
        report_rc("getpeername(udp,unconn)", sc3(52 /*getpeername*/, udp_fd, (u64)gsa, (u64)&alen));

        // === sendto loopback (no listener) — fire-and-forget ===
        unsigned char dst[16];
        mk_sockaddr_in(dst, 9, kLoopback); // discard port
        char payload[8] = {'s', 'y', 'n', 'e', 't', '!', '\n', 0};
        report_rc("sendto(udp,7)", sc6(44 /*sendto*/, udp_fd, (u64)payload, 7, 0, (u64)dst, 16));

        // === recvfrom MSG_DONTWAIT (no data) — expect -EAGAIN ===
        char rbuf[64];
        for (int i = 0; i < 64; ++i)
            rbuf[i] = 0;
        unsigned int slen = 16;
        for (int i = 0; i < 16; ++i)
            gsa[i] = 0;
        report_rc("recvfrom(udp,MSG_DONTWAIT)",
                  sc6(45 /*recvfrom*/, udp_fd, (u64)rbuf, 64, 0x40 /*MSG_DONTWAIT*/, (u64)gsa, (u64)&slen));

        // === setsockopt SO_REUSEADDR / getsockopt round-trip ===
        int one = 1;
        report_rc("setsockopt(SO_REUSEADDR=1)",
                  sc5(54 /*setsockopt*/, udp_fd, 1 /*SOL_SOCKET*/, 2 /*SO_REUSEADDR*/, (u64)&one, sizeof(one)));
        int got = 0;
        unsigned int got_len = sizeof(got);
        report_rc("getsockopt(SO_REUSEADDR)", sc5(55 /*getsockopt*/, udp_fd, 1, 2, (u64)&got, (u64)&got_len));

        // === shutdown(SHUT_RDWR) ===
        report_rc("shutdown(udp,RDWR)", sc2(48 /*shutdown*/, udp_fd, 2 /*SHUT_RDWR*/));

        // === close ===
        report_rc("close(udp)", sc1(3 /*close*/, udp_fd));
    }

    if (tcp_fd >= 0)
    {
        // === bind + listen on a fresh tcp_fd ===
        // Skip connect() — the v0 active-connect slot has no fast-
        // fail path for "peer never answered SYN-ACK", so a connect
        // to a closed port spins the slot-wait + handshake-wait
        // loops in kernel/net/socket.cpp::SocketConnect for ~1.5s
        // EACH (3s total). The kernel's own net-smoke already
        // proves the connect path works against a real listener;
        // synet's role is to prove the syscall surface is wired.
        unsigned char sa[16];
        mk_sockaddr_in(sa, 0, kLoopback);
        report_rc("bind(tcp,127.0.0.1:0)", sc3(49, tcp_fd, (u64)sa, 16));
        report_rc("listen(tcp,5)", sc2(50 /*listen*/, tcp_fd, 5));
        // getsockname after listen gives us the auto-assigned port.
        unsigned char gsa[16];
        unsigned int alen = 16;
        for (int i = 0; i < 16; ++i)
            gsa[i] = 0;
        report_rc("getsockname(tcp,listen)", sc3(51, tcp_fd, (u64)gsa, (u64)&alen));
        report_rc("close(tcp)", sc1(3, tcp_fd));
    }

    // === socketpair(AF_UNIX, SOCK_STREAM) — expect -ENOSYS or 0 + 2 fds ===
    int pair_fds[2] = {-1, -1};
    report_rc("socketpair(AF_UNIX,SOCK_STREAM)", sc5(53 /*socketpair*/, AF_UNIX, SOCK_STREAM, 0, (u64)pair_fds, 0));

    // === sendmsg/recvmsg facade probes (use a dummy iovec) ===
    {
        i64 fd2 = sc3(41, AF_INET, SOCK_DGRAM, 0);
        if (fd2 >= 0)
        {
            char body[6] = {'M', 'S', 'G', '!', '\n', 0};
            struct
            {
                u64 base;
                u64 len;
            } iov = {(u64)body, 5};
            unsigned char dst[16];
            mk_sockaddr_in(dst, 9, kLoopback);
            // struct msghdr layout: name, namelen(4), pad, iov,
            // iovlen, control, controllen, flags
            unsigned char mh[56] = {0};
            *(u64*)(mh + 0) = (u64)dst;
            *(unsigned int*)(mh + 8) = 16;
            *(u64*)(mh + 16) = (u64)&iov;
            *(u64*)(mh + 24) = 1;
            report_rc("sendmsg(udp)", sc3(46 /*sendmsg*/, fd2, (u64)mh, 0));
            sc1(3, fd2);
        }
    }

    puts_raw("[net] all done, exit 0x70\n");
    sc1(231 /*exit_group*/, 0x70);
    __builtin_unreachable();
}
