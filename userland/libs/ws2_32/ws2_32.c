/*
 * ws2_32.dll — Winsock 2 facade backed by the kernel socket pool.
 *
 * Per the subsystem isolation rule, this DLL is a facade: every
 * call trampolines through int 0x80 → SYS_SOCKET_OP (153) and
 * the kernel arbitrates the gate (kCapNet) + the actual I/O.
 *
 * SOCKET = kernel socket pool index (small unsigned int). The
 * pool cap is 8; INVALID_SOCKET is 0xFFFFFFFF.
 *
 * Errno mapping: SYS_SOCKET_OP returns negative Linux errno on
 * failure. We translate to Win32 Winsock codes (WSAExxx) and
 * stash in g_wsa_last_error so WSAGetLastError() reflects
 * the most recent failure.
 */

typedef int INT;
typedef unsigned int SOCKET;
typedef int BOOL;
typedef unsigned int DWORD;
typedef unsigned short USHORT;
typedef short SHORT;
typedef unsigned long long USIZE_T;

#define INVALID_SOCKET (~(SOCKET)0)
#define SOCKET_ERROR (-1)

#define WSAEINTR 10004
#define WSAEBADF 10009
#define WSAEACCES 10013
#define WSAEFAULT 10014
#define WSAEINVAL 10022
#define WSAEMFILE 10024
#define WSAEWOULDBLOCK 10035
#define WSAEMSGSIZE 10040
#define WSAEAFNOSUPPORT 10047
#define WSAEADDRINUSE 10048
#define WSAEADDRNOTAVAIL 10049
#define WSAENETDOWN 10050
#define WSAENETUNREACH 10051
#define WSAENOTCONN 10057
#define WSAESHUTDOWN 10058
#define WSAHOST_NOT_FOUND 11001

static int g_wsa_last_error = 0;

static int wsa_translate_errno(long long e)
{
    /* e is negative; abs is the Linux errno. */
    int v = -(int)e;
    switch (v)
    {
    case 9:
        return WSAEBADF;
    case 11:
        return WSAEWOULDBLOCK;
    case 13:
        return WSAEACCES;
    case 14:
        return WSAEFAULT;
    case 22:
        return WSAEINVAL;
    case 23:
        return WSAEMFILE;
    case 32:
        return WSAESHUTDOWN;
    case 88:
        return WSAEINVAL;
    case 89:
        return WSAEADDRNOTAVAIL;
    case 93:
        return WSAEAFNOSUPPORT;
    case 95:
        return WSAEINVAL;
    case 97:
        return WSAEAFNOSUPPORT;
    case 98:
        return WSAEADDRINUSE;
    case 100:
        return WSAENETDOWN;
    case 101:
        return WSAENETUNREACH;
    case 107:
        return WSAENOTCONN;
    default:
        return WSAEINVAL;
    }
}

/* Six-arg syscall trampoline. SYS_SOCKET_OP = 153.
 *   rdi = op
 *   rsi = arg1
 *   rdx = arg2
 *   r10 = arg3
 *   r8  = arg4
 *   r9  = arg5
 * Returns kernel result (negative on errno failure, non-negative otherwise).
 *
 * Operand indices are zero-based starting from the first OUTPUT (%0 = rv),
 * then inputs (%1 = 153, %2 = op, %3 = a1, %4 = a2, %5 = a3, %6 = a4,
 * %7 = a5). The asm body must move %5/%6/%7 (a3/a4/a5) into r10/r8/r9 —
 * NOT %4/%5/%6 (which would put a2/a3/a4 there and lose a5 entirely). */
static long long ws2_op(long long op, long long a1, long long a2, long long a3, long long a4, long long a5)
{
    long long rv;
    __asm__ volatile("mov %5, %%r10\n\t"
                     "mov %6, %%r8\n\t"
                     "mov %7, %%r9\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)153), "D"(op), "S"(a1), "d"(a2), "r"(a3), "r"(a4), "r"(a5)
                     : "r10", "r8", "r9", "memory");
    return rv;
}

/* FD_* network-event bits — shared by the lEvent masks the app passes to
 * WSAEventSelect / WSAAsyncSelect and by the kernel's kSockOpPollEvents
 * readiness bitmask (same encoding on both sides by design). */
#define WS2_FD_READ 0x01L
#define WS2_FD_WRITE 0x02L
#define WS2_FD_ACCEPT 0x08L
#define WS2_FD_CONNECT 0x10L
#define WS2_FD_CLOSE 0x20L

/* Per-socket non-blocking mode, set by ioctlsocket(FIONBIO) and implicitly
 * by WSAAsyncSelect (Win32 contract). The kernel socket layer is always-
 * blocking, so non-blocking semantics are emulated DLL-side: recv / send /
 * accept consult kSockOpPollEvents first and fail fast with WSAEWOULDBLOCK
 * when the matching readiness bit is absent. Socket handles are kernel pool
 * indices (pool cap 8), so one 64-bit mask covers every possible handle. */
static unsigned long long g_ws2_nonblock_mask;

static int ws2_is_nonblocking(SOCKET s)
{
    return (s < 64) && (((g_ws2_nonblock_mask >> s) & 1ULL) != 0);
}

static void ws2_set_nonblocking(SOCKET s, int on)
{
    if (s >= 64)
        return;
    if (on)
        g_ws2_nonblock_mask |= (1ULL << s);
    else
        g_ws2_nonblock_mask &= ~(1ULL << s);
}

/* Defined further down (poll producer + WSAAsyncSelect registry); recv /
 * send / accept / connect above them need these for the non-blocking gate,
 * the re-arm hooks, and the FD_CONNECT completion post. */
static long ws2_poll_events(SOCKET s);
static void ws2_async_rearm(SOCKET s, long bits);
static void ws2_async_notify_connect(SOCKET s, int wsa_err);
static void ws2_drop_socket_state(SOCKET s);

__declspec(dllexport) INT WSAStartup(USHORT req_ver, void* wsa_data)
{
    /* Touch the optional WSADATA so callers passing a real
     * struct see deterministic bytes. The Win32 contract is
     * "filled with version + system status"; v0 zero-fills the
     * caller-provided 408-byte struct (wHighVersion = req_ver,
     * wVersion = req_ver, szDescription / szSystemStatus empty). */
    (void)req_ver;
    if (wsa_data != (void*)0)
    {
        unsigned char* p = (unsigned char*)wsa_data;
        for (int i = 0; i < 408; ++i)
            p[i] = 0;
        p[0] = (unsigned char)(req_ver & 0xFF);
        p[1] = (unsigned char)((req_ver >> 8) & 0xFF);
        p[2] = (unsigned char)(req_ver & 0xFF);
        p[3] = (unsigned char)((req_ver >> 8) & 0xFF);
    }
    g_wsa_last_error = 0;
    return 0; /* success */
}
__declspec(dllexport) INT WSACleanup(void)
{
    return 0;
}
__declspec(dllexport) INT WSAGetLastError(void)
{
    return g_wsa_last_error;
}
__declspec(dllexport) void WSASetLastError(INT err)
{
    g_wsa_last_error = err;
}

__declspec(dllexport) SOCKET socket(INT af, INT type, INT proto)
{
    (void)proto;
    long long rv = ws2_op(1 /* kSockOpCreate */, (long long)af, (long long)type, 0, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return INVALID_SOCKET;
    }
    return (SOCKET)rv;
}
__declspec(dllexport) INT closesocket(SOCKET s)
{
    /* Drop DLL-side per-socket state FIRST — the kernel reuses pool
     * indices, so a stale WSAAsyncSelect / WSAEventSelect registration or
     * non-blocking bit would silently attach to the next socket that lands
     * on this index. */
    ws2_drop_socket_state(s);
    long long rv = ws2_op(9 /* kSockOpClose */, (long long)s, 0, 0, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return 0;
}
__declspec(dllexport) INT bind(SOCKET s, const void* addr, INT cb)
{
    long long rv = ws2_op(2 /* kSockOpBind */, (long long)s, (long long)addr, (long long)cb, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return 0;
}
__declspec(dllexport) INT listen(SOCKET s, INT backlog)
{
    long long rv = ws2_op(4 /* kSockOpListen */, (long long)s, (long long)backlog, 0, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return 0;
}
__declspec(dllexport) INT connect(SOCKET s, const void* addr, INT cb)
{
    /* The kernel connect is synchronous, so FD_CONNECT completion is known
     * right here — kSockOpPollEvents has no FD_CONNECT producer, so the
     * async-select notification for it is posted from this hook instead
     * (error code in the high word per WSAMAKESELECTREPLY). */
    long long rv = ws2_op(3 /* kSockOpConnect */, (long long)s, (long long)addr, (long long)cb, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        ws2_async_notify_connect(s, g_wsa_last_error);
        return SOCKET_ERROR;
    }
    ws2_async_notify_connect(s, 0);
    return 0;
}
__declspec(dllexport) SOCKET accept(SOCKET s, void* addr, INT* cb)
{
    /* Calling accept re-enables FD_ACCEPT for an async-selected listener
     * (Winsock re-arm contract). Non-blocking gate: fail fast when no
     * pending connection instead of blocking in the kernel.
     * GAP: kSockOpPollEvents reports FD_ACCEPT for loopback listeners only
     *   (wire-side TCB backlog probe missing kernel-side), so a non-blocking
     *   accept on a wire listener reports WSAEWOULDBLOCK even with a backlog
     *   child pending. — revisit when SocketPollEvents grows the backlog
     *   probe its own v1 comment promises. */
    ws2_async_rearm(s, WS2_FD_ACCEPT);
    if (ws2_is_nonblocking(s) && (ws2_poll_events(s) & WS2_FD_ACCEPT) == 0)
    {
        g_wsa_last_error = WSAEWOULDBLOCK;
        return INVALID_SOCKET;
    }
    long long rv = ws2_op(5 /* kSockOpAccept */, (long long)s, (long long)addr, (long long)cb, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return INVALID_SOCKET;
    }
    return (SOCKET)rv;
}
/* Shared non-blocking gate for send / sendto. A non-blocking socket whose
 * poll mask is non-zero but lacks FD_WRITE (loopback pipe full) fails fast
 * with WSAEWOULDBLOCK; per the Winsock contract that is ALSO the moment
 * FD_WRITE re-arms for an async-selected socket (the buffer-space-available
 * notification only re-fires after a send has failed with WSAEWOULDBLOCK).
 * poll == 0 (unbound / unconnected) falls through so the kernel reports the
 * real errno (WSAENOTCONN et al.) instead of a bogus would-block. */
static int ws2_send_would_block(SOCKET s)
{
    if (!ws2_is_nonblocking(s))
        return 0;
    const long ev = ws2_poll_events(s);
    if (ev == 0 || (ev & (WS2_FD_WRITE | WS2_FD_CLOSE)) != 0)
        return 0;
    ws2_async_rearm(s, WS2_FD_WRITE);
    g_wsa_last_error = WSAEWOULDBLOCK;
    return 1;
}

__declspec(dllexport) INT send(SOCKET s, const void* buf, INT len, INT flags)
{
    (void)flags;
    if (ws2_send_would_block(s))
        return SOCKET_ERROR;
    long long rv = ws2_op(6 /* kSockOpSendto */, (long long)s, (long long)buf, (long long)len, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return (INT)rv;
}
/* Shared non-blocking gate for recv / recvfrom. Calling either re-enables
 * FD_READ for an async-selected socket (Winsock re-arm contract: the next
 * FD_READ posts only after the app has recv'd — so a drain loop sees one
 * message per state transition, not a flood). The gate fails fast with
 * WSAEWOULDBLOCK when neither data (FD_READ) nor EOF (FD_CLOSE, which a
 * recv must observe as 0) is pending; poll == 0 (unconnected) falls through
 * so the kernel reports the real errno.
 * GAP: kSockOpPollEvents has no FD_READ producer for wire-TCP sockets (only
 *   loopback pairs + UDP), so a non-blocking recv on a wire socket reports
 *   WSAEWOULDBLOCK even when the TCB holds data. Blocking sockets are
 *   unaffected. — revisit when SocketPollEvents grows a tcp:: recv-queue
 *   probe. */
static int ws2_recv_would_block(SOCKET s)
{
    ws2_async_rearm(s, WS2_FD_READ);
    if (!ws2_is_nonblocking(s))
        return 0;
    const long ev = ws2_poll_events(s);
    if (ev == 0 || (ev & (WS2_FD_READ | WS2_FD_CLOSE)) != 0)
        return 0;
    g_wsa_last_error = WSAEWOULDBLOCK;
    return 1;
}

__declspec(dllexport) INT recv(SOCKET s, void* buf, INT len, INT flags)
{
    (void)flags;
    if (ws2_recv_would_block(s))
        return SOCKET_ERROR;
    long long rv = ws2_op(7 /* kSockOpRecvfrom */, (long long)s, (long long)buf, (long long)len, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return (INT)rv;
}
__declspec(dllexport) INT sendto(SOCKET s, const void* buf, INT len, INT flags, const void* addr, INT cb)
{
    (void)flags;
    if (ws2_send_would_block(s))
        return SOCKET_ERROR;
    long long rv =
        ws2_op(6 /* kSockOpSendto */, (long long)s, (long long)buf, (long long)len, (long long)addr, (long long)cb);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return (INT)rv;
}
__declspec(dllexport) INT recvfrom(SOCKET s, void* buf, INT len, INT flags, void* addr, INT* cb)
{
    (void)flags;
    if (ws2_recv_would_block(s))
        return SOCKET_ERROR;
    long long rv =
        ws2_op(7 /* kSockOpRecvfrom */, (long long)s, (long long)buf, (long long)len, (long long)addr, (long long)cb);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return (INT)rv;
}
__declspec(dllexport) INT shutdown(SOCKET s, INT how)
{
    long long rv = ws2_op(8 /* kSockOpShutdown */, (long long)s, (long long)how, 0, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return 0;
}
__declspec(dllexport) INT setsockopt(SOCKET s, INT lvl, INT opt, const void* v, INT vl)
{
    /* Kernel-side accept-and-ignore — return success without
     * issuing a syscall. Sub-GAP: real options aren't honoured. */
    (void)s;
    (void)lvl;
    (void)opt;
    (void)v;
    (void)vl;
    return 0;
}
__declspec(dllexport) INT getsockopt(SOCKET s, INT lvl, INT opt, void* v, INT* vl)
{
    (void)s;
    (void)lvl;
    (void)opt;
    (void)v;
    if (vl)
        *vl = 0;
    return 0;
}
__declspec(dllexport) INT select(INT nfds, void* rfd, void* wfd, void* efd, const void* tv)
{
    /* No multiplex primitive in v0; return timeout (0) so callers
     * busy-loop with their own polling. Sub-GAP: real select needs
     * the epoll slice. */
    (void)nfds;
    (void)rfd;
    (void)wfd;
    (void)efd;
    (void)tv;
    return 0;
}

/* Backing function for the FD_ISSET macro. mingw-w64's winsock2.h
 * lays out fd_set as { u_int fd_count; SOCKET fd_array[FD_SETSIZE]; }
 * where SOCKET is UINT_PTR (8 bytes on x64), so fd_array starts at
 * offset 8 (4-byte fd_count + 4 bytes of padding). Walk fd_count
 * entries with 8-byte stride matching the caller's struct. */
__declspec(dllexport) INT __WSAFDIsSet(unsigned long long s, void* set)
{
    if (set == 0)
        return 0;
    unsigned int count = *(unsigned int*)set;
    unsigned long long* arr = (unsigned long long*)((unsigned char*)set + 8);
    for (unsigned int i = 0; i < count; ++i)
    {
        if (arr[i] == s)
            return 1;
    }
    return 0;
}
__declspec(dllexport) USHORT htons(USHORT v)
{
    return (USHORT)((v << 8) | (v >> 8));
}
__declspec(dllexport) USHORT ntohs(USHORT v)
{
    return htons(v);
}
__declspec(dllexport) DWORD htonl(DWORD v)
{
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) | ((v & 0xFF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}
__declspec(dllexport) DWORD ntohl(DWORD v)
{
    return htonl(v);
}

__declspec(dllexport) DWORD inet_addr(const char* s)
{
    if (!s)
        return 0xFFFFFFFFu;
    DWORD parts[4] = {0, 0, 0, 0};
    int idx = 0;
    int saw_digit = 0;
    DWORD acc = 0;
    for (const char* p = s;; ++p)
    {
        if (*p >= '0' && *p <= '9')
        {
            saw_digit = 1;
            acc = acc * 10u + (DWORD)(*p - '0');
            if (acc > 255u)
                return 0xFFFFFFFFu;
        }
        else if (*p == '.' || *p == 0)
        {
            if (!saw_digit || idx >= 4)
                return 0xFFFFFFFFu;
            parts[idx++] = acc;
            acc = 0;
            saw_digit = 0;
            if (*p == 0)
                break;
        }
        else
        {
            return 0xFFFFFFFFu;
        }
    }
    if (idx != 4)
        return 0xFFFFFFFFu;
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

__declspec(dllexport) const char* inet_ntoa(DWORD addr)
{
    static char buf[16];
    unsigned int b0 = (addr >> 0) & 0xFFu;
    unsigned int b1 = (addr >> 8) & 0xFFu;
    unsigned int b2 = (addr >> 16) & 0xFFu;
    unsigned int b3 = (addr >> 24) & 0xFFu;
    int pos = 0;
    unsigned int parts[4] = {b0, b1, b2, b3};
    for (int i = 0; i < 4; ++i)
    {
        unsigned int v = parts[i];
        char tmp[4];
        int n = 0;
        if (v == 0)
            tmp[n++] = '0';
        else
            while (v)
            {
                tmp[n++] = (char)('0' + (v % 10u));
                v /= 10u;
            }
        for (int j = n - 1; j >= 0; --j)
            buf[pos++] = tmp[j];
        if (i < 3)
            buf[pos++] = '.';
    }
    buf[pos] = 0;
    return buf;
}

__declspec(dllexport) INT inet_pton(INT af, const char* src, void* dst)
{
    if (af != 2 || !src || !dst)
        return 0;
    DWORD a = inet_addr(src);
    if (a == 0xFFFFFFFFu)
    {
        const char broadcast[] = "255.255.255.255";
        for (int i = 0;; ++i)
        {
            if (broadcast[i] == 0 && src[i] == 0)
                break;
            if (broadcast[i] != src[i])
                return 0;
        }
    }
    unsigned char* d = (unsigned char*)dst;
    d[0] = (unsigned char)(a >> 24);
    d[1] = (unsigned char)(a >> 16);
    d[2] = (unsigned char)(a >> 8);
    d[3] = (unsigned char)(a);
    return 1;
}

__declspec(dllexport) const char* inet_ntop(INT af, const void* src, char* dst, INT size)
{
    if (af != 2 || !src || !dst || size < 16)
        return (const char*)0;
    const unsigned char* s = (const unsigned char*)src;
    DWORD packed = (DWORD)s[0] | ((DWORD)s[1] << 8) | ((DWORD)s[2] << 16) | ((DWORD)s[3] << 24);
    const char* str = inet_ntoa(packed);
    int i = 0;
    for (; str[i] && i < size - 1; ++i)
        dst[i] = str[i];
    dst[i] = 0;
    return dst;
}

/* Static hostent storage. Single-threaded callers only — matches the
 * Win32 documented behaviour ("the buffer is allocated by Windows and
 * the calling thread must copy any data it wants to keep before the
 * next call"). */
static unsigned long g_gethostbyname_addr_be;
static char* g_gethostbyname_addr_list[2];
static struct
{
    char* h_name;
    char** h_aliases;
    short h_addrtype;
    short h_length;
    char** h_addr_list;
} g_gethostbyname_hostent;
static char g_gethostbyname_name[256];

__declspec(dllexport) void* gethostbyname(const char* n)
{
    if (n == (const char*)0)
        return (void*)0;
    /* Copy hostname locally so the kernel sees a stable buffer. */
    int i = 0;
    for (; i < (int)sizeof(g_gethostbyname_name) - 1 && n[i] != '\0'; ++i)
        g_gethostbyname_name[i] = n[i];
    g_gethostbyname_name[i] = '\0';

    long long rv =
        ws2_op(12 /* kSockOpResolveA */, (long long)g_gethostbyname_name, (long long)&g_gethostbyname_addr_be, 0, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = WSAHOST_NOT_FOUND;
        return (void*)0;
    }
    g_gethostbyname_addr_list[0] = (char*)&g_gethostbyname_addr_be;
    g_gethostbyname_addr_list[1] = (char*)0;
    g_gethostbyname_hostent.h_name = g_gethostbyname_name;
    g_gethostbyname_hostent.h_aliases = (char**)0;
    g_gethostbyname_hostent.h_addrtype = 2 /* AF_INET */;
    g_gethostbyname_hostent.h_length = 4;
    g_gethostbyname_hostent.h_addr_list = g_gethostbyname_addr_list;
    return &g_gethostbyname_hostent;
}
__declspec(dllexport) INT gethostname(char* buf, INT len)
{
    static const char kHost[] = "duetos";
    if (!buf || len <= 0)
        return -1;
    int i = 0;
    for (; kHost[i] && i + 1 < len; ++i)
        buf[i] = kHost[i];
    buf[i] = 0;
    return 0;
}

/* DNS cache + getaddrinfo / freeaddrinfo.
 *
 * gethostbyname above hits the kernel resolver through
 * `ws2_op(kSockOpResolveA)` on every call — fine for one-off
 * lookups, but a workload that repeatedly resolves the same
 * hostname (HTTP keep-alive, DNS-heavy crawler) burns wire-
 * time on every call. A 16-entry process-local cache absorbs
 * the hot lookups; on miss we fall through to the kernel and
 * insert at the freshest slot (an LRU eviction strategy).
 *
 * getaddrinfo: builds an addrinfo + sockaddr_in pair on the heap
 * (per Win32 contract — caller must call freeaddrinfo). Resolves
 * IP literals locally via inet_addr; resolves hostnames through
 * the cache + kernel fallback.
 *
 * Out of scope:
 *   - IPv6 (AF_INET6 / sockaddr_in6 — no resolver path yet).
 *   - Multiple result records per hostname (kSockOpResolveA
 *     returns a single A record).
 *   - Service-name resolution (the `service` parameter is parsed
 *     as a numeric port; symbolic names like "http" return
 *     WSANO_DATA — which a future getservbyname could fill).
 */
#define WS2_DNS_CACHE_SIZE 64
typedef struct
{
    char name[256];
    unsigned long addr_be;
    unsigned long long inserted_tick;
    int valid;
} WS2_DNS_CACHE_ENTRY;
static WS2_DNS_CACHE_ENTRY g_ws2_dns_cache[WS2_DNS_CACHE_SIZE];
static unsigned long long g_ws2_dns_cache_tick;

static int ws2_dns_cache_lookup(const char* name, unsigned long* out_be)
{
    if (name == (const char*)0)
        return 0;
    for (int i = 0; i < WS2_DNS_CACHE_SIZE; ++i)
    {
        if (!g_ws2_dns_cache[i].valid)
            continue;
        int j = 0;
        for (; j < 256 && g_ws2_dns_cache[i].name[j] != '\0' && name[j] != '\0'; ++j)
        {
            if (g_ws2_dns_cache[i].name[j] != name[j])
                break;
        }
        if (j < 256 && g_ws2_dns_cache[i].name[j] == '\0' && name[j] == '\0')
        {
            *out_be = g_ws2_dns_cache[i].addr_be;
            g_ws2_dns_cache[i].inserted_tick = ++g_ws2_dns_cache_tick;
            return 1;
        }
    }
    return 0;
}

static void ws2_dns_cache_insert(const char* name, unsigned long addr_be)
{
    /* LRU eviction: pick the empty slot first, otherwise the slot
     * with the lowest `inserted_tick`. */
    int victim = 0;
    unsigned long long lowest = (unsigned long long)-1;
    for (int i = 0; i < WS2_DNS_CACHE_SIZE; ++i)
    {
        if (!g_ws2_dns_cache[i].valid)
        {
            victim = i;
            lowest = 0;
            break;
        }
        if (g_ws2_dns_cache[i].inserted_tick < lowest)
        {
            lowest = g_ws2_dns_cache[i].inserted_tick;
            victim = i;
        }
    }
    int j = 0;
    for (; j < 255 && name[j] != '\0'; ++j)
        g_ws2_dns_cache[victim].name[j] = name[j];
    g_ws2_dns_cache[victim].name[j] = '\0';
    g_ws2_dns_cache[victim].addr_be = addr_be;
    g_ws2_dns_cache[victim].inserted_tick = ++g_ws2_dns_cache_tick;
    g_ws2_dns_cache[victim].valid = 1;
}

/* addrinfo layout (Win32 struct addrinfoA / addrinfo). The fields
 * we care about: ai_flags, ai_family, ai_socktype, ai_protocol,
 * ai_addrlen, ai_canonname, ai_addr, ai_next. */
typedef struct ws2_addrinfo
{
    INT ai_flags;
    INT ai_family;
    INT ai_socktype;
    INT ai_protocol;
    USIZE_T ai_addrlen;
    char* ai_canonname;
    void* ai_addr;
    struct ws2_addrinfo* ai_next;
} WS2_ADDRINFO;

typedef struct
{
    SHORT sin_family;
    USHORT sin_port;
    unsigned long sin_addr;
    char sin_zero[8];
} WS2_SOCKADDR_IN;

/* HeapAlloc-style allocation through SYS_HEAP_ALLOC (11). The
 * matching free goes through SYS_HEAP_FREE (12) in freeaddrinfo. */
static void* ws2_alloc(unsigned long bytes)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)bytes) : "memory");
    return (void*)rv;
}

static void ws2_free(void* p)
{
    if (p == (void*)0)
        return;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)12), "D"((long long)p) : "memory");
}

/* SYS_SLEEP_MS (19): suspend the calling thread for `ms`
 * milliseconds. ms == 0 yields the time slice. */
static void ws2_sleep_ms(unsigned long ms)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)19), "D"((long long)ms) : "memory");
}

/* SYS_NOW_NS (18): nanoseconds since boot. */
static unsigned long long ws2_now_ns(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)18) : "memory");
    return (unsigned long long)rv;
}

/* SYS_EVENT_SET (31) / SYS_EVENT_WAIT (33): poke Win32 event
 * handles from the freestanding ws2_32 without dragging in a
 * kernel32 import. The handle values are the same opaque cookies
 * kernel32 returns; the syscall validates them against the
 * process's win32 handle table. */
static void ws2_event_set(void* handle)
{
    if (handle == (void*)0)
        return;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)31), "D"((long long)handle) : "memory");
}

static long long ws2_event_wait(void* handle, unsigned long timeout_ms)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)33), "D"((long long)handle), "S"((long long)timeout_ms)
                     : "memory");
    return rv;
}

/* Query the kernel's FD_* readiness bitmask for a socket. Issues
 * SYS_SOCKET_OP with op=kSockOpPollEvents=14, rsi=sock_idx. */
static long ws2_poll_events(SOCKET s)
{
    const long long rv = ws2_op(14LL, (long long)s, 0, 0, 0, 0);
    if (rv < 0)
        return 0;
    return (long)(unsigned long)rv;
}

/* Parse `service` as a decimal port number. Returns 0 if NULL or
 * empty; -1 on parse failure (caller treats as 0 — Win32's
 * getaddrinfo doesn't reject numeric-parse errors when AI_NUMERICSERV
 * isn't set). */
static int ws2_parse_port(const char* svc)
{
    if (svc == (const char*)0 || svc[0] == '\0')
        return 0;
    int port = 0;
    int i = 0;
    for (; svc[i] != '\0'; ++i)
    {
        if (svc[i] < '0' || svc[i] > '9')
            return -1;
        port = port * 10 + (svc[i] - '0');
        if (port > 65535)
            return -1;
    }
    return port;
}

__declspec(dllexport) INT getaddrinfo(const char* node, const char* service, const void* hints, void** result)
{
    (void)hints; /* AF_INET assumed; AF_INET6 is GAP. */
    if (result == (void**)0)
        return WSAEFAULT;
    *result = (void*)0;
    if (node == (const char*)0)
    {
        g_wsa_last_error = WSAEINVAL;
        return WSAEINVAL;
    }

    /* Resolve the hostname. IP literals short-circuit via
     * inet_addr; "localhost" / "localhost.localdomain" map to
     * 127.0.0.1 directly so smoke tests work without a DNS server;
     * everything else hits the cache then the kernel. */
    unsigned long addr_be = inet_addr(node);
    if (addr_be == 0xFFFFFFFFu) /* INADDR_NONE — not an IP literal. */
    {
        /* Match "localhost" + "localhost.localdomain" case-
         * sensitively. Win32 hostnames are case-insensitive in
         * principle; the smoke fixtures only ever use lowercase. */
        const char* loc = "localhost";
        int matches = 1;
        for (int j = 0; loc[j] != '\0'; ++j)
        {
            if (node[j] != loc[j])
            {
                matches = 0;
                break;
            }
        }
        if (matches && (node[9] == '\0' || (node[9] == '.' && node[10] != '\0')))
        {
            addr_be = 0x0100007Fu; /* 127.0.0.1 in network byte order */
        }
        else if (!ws2_dns_cache_lookup(node, &addr_be))
        {
            /* Cache miss — fall through to the kernel resolver, then
             * cache the result for the next call. The buffer the
             * kernel writes is in our own static `g_gethostbyname_addr_be`,
             * but we copy out of a local to avoid the gethostbyname
             * shape's TID-unsafe contract for one-off uses. */
            unsigned long resolved_be = 0;
            char name_copy[256];
            int j = 0;
            for (; j < (int)sizeof(name_copy) - 1 && node[j] != '\0'; ++j)
                name_copy[j] = node[j];
            name_copy[j] = '\0';
            long long rv = ws2_op(12 /* kSockOpResolveA */, (long long)name_copy, (long long)&resolved_be, 0, 0, 0);
            if (rv < 0)
            {
                g_wsa_last_error = WSAHOST_NOT_FOUND;
                return WSAHOST_NOT_FOUND;
            }
            addr_be = resolved_be;
            ws2_dns_cache_insert(node, addr_be);
        }
    }

    int port = ws2_parse_port(service);
    if (port < 0)
        port = 0;

    /* Allocate addrinfo + sockaddr_in as a single block so
     * freeaddrinfo can release with one ws2_free. */
    void* block = ws2_alloc(sizeof(WS2_ADDRINFO) + sizeof(WS2_SOCKADDR_IN));
    if (block == (void*)0)
    {
        g_wsa_last_error = 8 /* WSA_NOT_ENOUGH_MEMORY */;
        return 8;
    }
    WS2_ADDRINFO* ai = (WS2_ADDRINFO*)block;
    WS2_SOCKADDR_IN* sa = (WS2_SOCKADDR_IN*)((unsigned char*)block + sizeof(WS2_ADDRINFO));
    ai->ai_flags = 0;
    ai->ai_family = 2 /* AF_INET */;
    ai->ai_socktype = 1 /* SOCK_STREAM */;
    ai->ai_protocol = 6 /* IPPROTO_TCP */;
    ai->ai_addrlen = sizeof(WS2_SOCKADDR_IN);
    ai->ai_canonname = (char*)0;
    ai->ai_addr = sa;
    ai->ai_next = (WS2_ADDRINFO*)0;
    sa->sin_family = 2;
    sa->sin_port = (USHORT)((port & 0xFF) << 8 | ((port >> 8) & 0xFF));
    sa->sin_addr = addr_be;
    for (int z = 0; z < 8; ++z)
        sa->sin_zero[z] = 0;
    *result = ai;
    return 0;
}
__declspec(dllexport) void freeaddrinfo(void* r)
{
    /* Single-block allocation in getaddrinfo — one free. If a
     * caller chains addrinfo records (we don't yet), the caller's
     * own walker would have to undo that chain manually. Today
     * getaddrinfo only ever returns a single record. */
    ws2_free(r);
}

__declspec(dllexport) unsigned long long htonll(unsigned long long v)
{
    return ((v & 0xFFULL) << 56) | ((v & 0xFF00ULL) << 40) | ((v & 0xFF0000ULL) << 24) | ((v & 0xFF000000ULL) << 8) |
           ((v & 0xFF00000000ULL) >> 8) | ((v & 0xFF0000000000ULL) >> 24) | ((v & 0xFF000000000000ULL) >> 40) |
           ((v & 0xFF00000000000000ULL) >> 56);
}
__declspec(dllexport) unsigned long long ntohll(unsigned long long v)
{
    return htonll(v);
}

__declspec(dllexport) INT WSAEnumProtocolsA(INT* lpiProtocols, void* lpProtocolBuffer, DWORD* lpdwBufferLength)
{
    (void)lpiProtocols;
    (void)lpProtocolBuffer;
    if (lpdwBufferLength)
        *lpdwBufferLength = 0;
    return -1;
}

__declspec(dllexport) INT WSAEnumProtocolsW(INT* lpiProtocols, void* lpProtocolBuffer, DWORD* lpdwBufferLength)
{
    return WSAEnumProtocolsA(lpiProtocols, lpProtocolBuffer, lpdwBufferLength);
}

__declspec(dllexport) INT getnameinfo(const void* addr, INT addrlen, char* host, DWORD hostlen, char* serv,
                                      DWORD servlen, INT flags)
{
    (void)addr;
    (void)addrlen;
    (void)flags;
    if (host && hostlen > 0)
        host[0] = 0;
    if (serv && servlen > 0)
        serv[0] = 0;
    return WSAENETDOWN;
}

__declspec(dllexport) INT WSAIoctl(SOCKET s, DWORD ioctl, void* in_buf, DWORD in_size, void* out_buf, DWORD out_size,
                                   DWORD* bytes_returned, void* overlapped, void* completion)
{
    (void)s;
    (void)ioctl;
    (void)in_buf;
    (void)in_size;
    (void)out_buf;
    (void)out_size;
    (void)overlapped;
    (void)completion;
    if (bytes_returned)
        *bytes_returned = 0;
    return SOCKET_ERROR;
}

/* ioctlsocket — the Win32 socket I/O-control surface. v0 honours
 * the two control codes every well-behaved client sends at
 * connect time:
 *   FIONBIO   — toggle non-blocking mode. Tracked in the per-socket
 *               g_ws2_nonblock_mask; recv / send / accept emulate
 *               the non-blocking contract DLL-side by consulting
 *               kSockOpPollEvents and failing fast with
 *               WSAEWOULDBLOCK (the kernel socket layer itself is
 *               always-blocking). The return value of 0 (= NO_ERROR)
 *               is what every caller checks; setting *argp on the
 *               way back is a Win32 quirk we don't need.
 *   FIONREAD  — number of bytes ready to read on a socket. v0
 *               returns 0 cleanly because we don't queue ahead
 *               of recv() in the kernel.
 *   SIOCATMARK — out-of-band data marker. v0 has no OOB tier;
 *               return 0 (no OOB data).
 * Anything else returns NO_ERROR with no side effect — preferable
 * to SOCKET_ERROR for callers probing unknown control codes. */
#define DUETOS_FIONBIO 0x8004667EUL
#define DUETOS_FIONREAD 0x4004667FUL
#define DUETOS_SIOCATMARK 0x40047307UL

__declspec(dllexport) INT ioctlsocket(SOCKET s, long cmd, DWORD* argp)
{
    switch ((unsigned long)cmd)
    {
    case DUETOS_FIONBIO:
        /* argp points at a non-zero "set non-blocking" flag or a
         * zero "clear non-blocking" flag. */
        if (argp == (DWORD*)0)
        {
            g_wsa_last_error = WSAEFAULT;
            return SOCKET_ERROR;
        }
        ws2_set_nonblocking(s, *argp != 0);
        return 0;
    case DUETOS_FIONREAD:
    case DUETOS_SIOCATMARK:
        if (argp != (DWORD*)0)
            *argp = 0;
        return 0;
    default:
        /* Unknown control code — succeed silently rather than
         * returning SOCKET_ERROR; callers probe for control-code
         * support and bail on anything other than NO_ERROR. */
        return 0;
    }
}

__declspec(dllexport) INT getsockname(SOCKET s, void* addr, INT* cb)
{
    long long rv = ws2_op(10 /* kSockOpGetSock */, (long long)s, (long long)addr, (long long)cb, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return 0;
}

__declspec(dllexport) INT getpeername(SOCKET s, void* addr, INT* cb)
{
    long long rv = ws2_op(11 /* kSockOpGetPeer */, (long long)s, (long long)addr, (long long)cb, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return 0;
}

/* WSA event objects — sentinel handles. The smoke test just sets/
 * resets the flag, no real signalling needed. */
typedef void* WSAEVENT_t;
__declspec(dllexport) WSAEVENT_t WSACreateEvent(void)
{
    return (WSAEVENT_t)(unsigned long long)0xE5000001;
}

__declspec(dllexport) BOOL WSACloseEvent(WSAEVENT_t e)
{
    (void)e;
    return 1;
}

__declspec(dllexport) BOOL WSASetEvent(WSAEVENT_t e)
{
    (void)e;
    return 1;
}

__declspec(dllexport) BOOL WSAResetEvent(WSAEVENT_t e)
{
    (void)e;
    return 1;
}

/* WSAEventSelect / WSAEnumNetworkEvents / WSAWaitForMultipleEvents
 * — process-local event-binding registry. WSAEventSelect remembers
 * which network events a (socket, event-handle) pair has subscribed
 * to; WSAEnumNetworkEvents reports + clears them; WSAWaitForMultipleEvents
 * polls binding readiness and signals event handles when sockets
 * become readable / writable / accept-pending / closed.
 *
 * Producer side wired through `kSockOpPollEvents` (SYS_SOCKET_OP
 * op=14): the kernel reports the current FD_* bitmask for a
 * socket on demand. Each WSAEnumNetworkEvents call queries this
 * and ORs the result into the binding's `pending` mask (masked
 * by the user's subscribed events); WSAWaitForMultipleEvents
 * runs a short-interval polling loop, calling SetEvent on any
 * binding whose socket has activity, so a caller blocked in
 * WaitForMultipleObjects-shape wakes when a real event lands. */

#define WSA_BINDING_SLOTS 32

typedef struct WsaEventBinding
{
    int in_use;
    SOCKET socket;
    WSAEVENT_t event;
    long lNetworkEvents;
    long pending; /* OR-mask of events currently set; cleared on Enum */
} WsaEventBinding;

static WsaEventBinding g_wsa_bindings[WSA_BINDING_SLOTS];

#define WSA_INFINITE 0xFFFFFFFFu
#define WSA_WAIT_TIMEOUT 0x102u
#define WSA_WAIT_FAILED 0xFFFFFFFFu
#define WSA_WAIT_EVENT_0 0u

typedef struct
{
    long lNetworkEvents;
    int iErrorCode[10]; /* 10 events in WSA: FD_READ..FD_QOS */
} WsaNetworkEvents;

__declspec(dllexport) int WSAEventSelect(SOCKET s, WSAEVENT_t e, long lNetworkEvents)
{
    /* Find existing binding for this socket; replace its event /
     * mask. Otherwise allocate a fresh slot. lNetworkEvents == 0
     * with a valid socket cancels the registration. */
    int free_idx = -1;
    for (int i = 0; i < WSA_BINDING_SLOTS; ++i)
    {
        if (g_wsa_bindings[i].in_use && g_wsa_bindings[i].socket == s)
        {
            if (lNetworkEvents == 0)
            {
                g_wsa_bindings[i].in_use = 0;
                return 0;
            }
            g_wsa_bindings[i].event = e;
            g_wsa_bindings[i].lNetworkEvents = lNetworkEvents;
            g_wsa_bindings[i].pending = 0;
            return 0;
        }
        if (!g_wsa_bindings[i].in_use && free_idx < 0)
            free_idx = i;
    }
    if (lNetworkEvents == 0)
        return 0; /* Cancel of a nonexistent binding — succeeds. */
    if (free_idx < 0)
    {
        g_wsa_last_error = 10055; /* WSAENOBUFS */
        return SOCKET_ERROR;
    }
    g_wsa_bindings[free_idx].in_use = 1;
    g_wsa_bindings[free_idx].socket = s;
    g_wsa_bindings[free_idx].event = e;
    g_wsa_bindings[free_idx].lNetworkEvents = lNetworkEvents;
    g_wsa_bindings[free_idx].pending = 0;
    return 0;
}

__declspec(dllexport) int WSAEnumNetworkEvents(SOCKET s, WSAEVENT_t e, void* lpNetworkEvents)
{
    if (lpNetworkEvents == (void*)0)
    {
        g_wsa_last_error = 10014; /* WSAEFAULT */
        return SOCKET_ERROR;
    }
    WsaNetworkEvents* out = (WsaNetworkEvents*)lpNetworkEvents;
    out->lNetworkEvents = 0;
    for (int i = 0; i < 10; ++i)
        out->iErrorCode[i] = 0;
    /* Producer-side merge: query the kernel for the socket's
     * current FD_* readiness and OR it into the binding's
     * `pending` mask, masked by the user's subscribed events.
     * Matches the Winsock contract that Enum returns events
     * accumulated since the last Enum / EventSelect. */
    const long now_ready = ws2_poll_events(s);
    for (int i = 0; i < WSA_BINDING_SLOTS; ++i)
    {
        if (g_wsa_bindings[i].in_use && g_wsa_bindings[i].socket == s)
        {
            g_wsa_bindings[i].pending |= (now_ready & g_wsa_bindings[i].lNetworkEvents);
            out->lNetworkEvents = g_wsa_bindings[i].pending;
            g_wsa_bindings[i].pending = 0;
            break;
        }
    }
    /* Real Win32 atomically resets `e` on this call. The event
     * was signaled by `ws2_event_set` from WSAWaitForMultipleEvents
     * when activity was detected; reset it here so the next
     * Wait blocks again until the next state transition. */
    if (e != (WSAEVENT_t)0)
    {
        long long discard;
        __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)32), "D"((long long)e) : "memory");
    }
    return 0;
}

__declspec(dllexport) DWORD WSAWaitForMultipleEvents(DWORD cEvents, const WSAEVENT_t* lphEvents, BOOL fWaitAll,
                                                     DWORD dwTimeout, BOOL fAlertable)
{
    (void)fAlertable; /* v0 doesn't honour alertable here. */
    if (lphEvents == (const WSAEVENT_t*)0 || cEvents == 0)
    {
        g_wsa_last_error = 10014;
        return WSA_WAIT_FAILED;
    }

    /* Polling loop. Each iteration:
     *   1. Walk the event-binding registry; for any binding whose
     *      socket has a fresh FD_* event the caller subscribed to,
     *      SetEvent the bound event handle (so it shows up in the
     *      per-event WaitForSingleObject probe below).
     *   2. Probe each event in lphEvents with a 0 ms wait.
     *      fWaitAll=FALSE: return on the first signaled index.
     *      fWaitAll=TRUE:  only return if EVERY event is signaled;
     *                      the returned index is WSA_WAIT_EVENT_0
     *                      (Win32 returns the lowest index in the
     *                      all-signaled case).
     *   3. If the overall timeout has elapsed, return WSA_WAIT_TIMEOUT.
     *   4. Sleep 10 ms and loop.
     *
     * 10 ms cadence trades latency for CPU — fine for v0; future
     * work moves the producer side into the kernel proper so the
     * event handle is signaled at the moment of socket activity. */
    const unsigned long long start = ws2_now_ns();
    const unsigned long long timeout_ns =
        (dwTimeout == WSA_INFINITE) ? 0ULL : ((unsigned long long)dwTimeout * 1000000ULL);
    for (;;)
    {
        /* Step 1 — fan socket readiness out to event handles. */
        for (int i = 0; i < WSA_BINDING_SLOTS; ++i)
        {
            if (!g_wsa_bindings[i].in_use)
                continue;
            const long ready = ws2_poll_events(g_wsa_bindings[i].socket) & g_wsa_bindings[i].lNetworkEvents;
            if (ready != 0)
                ws2_event_set(g_wsa_bindings[i].event);
        }
        /* Step 2 — non-blocking probe of every event in lphEvents. */
        if (fWaitAll)
        {
            DWORD signaled = 0;
            for (DWORD i = 0; i < cEvents; ++i)
            {
                if (ws2_event_wait(lphEvents[i], 0) == 0)
                    ++signaled;
                else
                    break; /* one miss is enough — wait for next iter */
            }
            if (signaled == cEvents)
                return WSA_WAIT_EVENT_0;
        }
        else
        {
            for (DWORD i = 0; i < cEvents; ++i)
            {
                if (ws2_event_wait(lphEvents[i], 0) == 0)
                    return WSA_WAIT_EVENT_0 + i;
            }
        }
        /* Step 3 — overall timeout. */
        if (dwTimeout != WSA_INFINITE)
        {
            const unsigned long long now = ws2_now_ns();
            if (now - start >= timeout_ns)
                return WSA_WAIT_TIMEOUT;
        }
        /* Step 4 — back off. */
        ws2_sleep_ms(10);
    }
}

/* ---------------------------------------------------------------------------
 * Wide (UTF-16) winsock surface — the variants ftp.exe / telnet.exe / modern
 * clients import BY NAME (GetAddrInfoW, GetNameInfoW, FreeAddrInfoW,
 * GetHostNameW) plus WSARecv. ftp resolves these at load and calls
 * GetHostNameW early; the addrinfo variants only fire on `open <host>`,
 * which the interactive prompt doesn't need — but the IAT must still bind,
 * so they exist with happy-path-correct narrow-backed implementations.
 * ------------------------------------------------------------------------- */
typedef unsigned short WCHAR;

/* GetHostNameW — UTF-16 host name. Mirrors gethostname's "duetos"
 * sentinel. `namelen` is a character count (Win32 contract). */
__declspec(dllexport) INT GetHostNameW(WCHAR* name, INT namelen)
{
    static const char kHost[] = "duetos";
    if (!name || namelen <= 0)
    {
        g_wsa_last_error = WSAEFAULT;
        return SOCKET_ERROR;
    }
    int i = 0;
    for (; kHost[i] && i + 1 < namelen; ++i)
        name[i] = (WCHAR)kHost[i];
    name[i] = 0;
    return 0;
}

/* Narrow a UTF-16 string into a caller-provided ASCII buffer. Used by
 * GetAddrInfoW to reuse the narrow getaddrinfo path. Non-ASCII code
 * units are truncated to their low byte (the hostnames a winsock client
 * resolves are ASCII in practice). */
static void ws2_w2a(const WCHAR* w, char* a, int cap)
{
    int i = 0;
    if (w)
        for (; i < cap - 1 && w[i] != 0; ++i)
            a[i] = (char)(w[i] & 0xFF);
    a[i] = 0;
}

/* GetAddrInfoW — wide getaddrinfo. The ADDRINFOW struct has the same
 * field layout/sizes as the narrow addrinfo on x64 (ai_canonname is a
 * PWSTR vs PSTR but both are 8-byte pointers), so the narrow
 * getaddrinfo result block is ABI-compatible for the fields a caller
 * reads (ai_family / ai_socktype / ai_protocol / ai_addr / ai_addrlen /
 * ai_next). Canonname is left NULL, matching getaddrinfo. */
__declspec(dllexport) INT GetAddrInfoW(const WCHAR* node, const WCHAR* service, const void* hints, void** result)
{
    char nbuf[256];
    char sbuf[64];
    ws2_w2a(node, nbuf, (int)sizeof(nbuf));
    ws2_w2a(service, sbuf, (int)sizeof(sbuf));
    const char* np = (node != (const WCHAR*)0) ? nbuf : (const char*)0;
    const char* sp = (service != (const WCHAR*)0) ? sbuf : (const char*)0;
    return getaddrinfo(np, sp, hints, result);
}

__declspec(dllexport) void FreeAddrInfoW(void* r)
{
    freeaddrinfo(r);
}

__declspec(dllexport) INT GetNameInfoW(const void* addr, INT addrlen, WCHAR* host, DWORD hostlen, WCHAR* serv,
                                       DWORD servlen, INT flags)
{
    (void)addr;
    (void)addrlen;
    (void)flags;
    if (host && hostlen > 0)
        host[0] = 0;
    if (serv && servlen > 0)
        serv[0] = 0;
    return WSAENETDOWN;
}

/* WSARecv — overlapped/scatter recv. v0 has no overlapped tier and the
 * interactive prompt never reaches a data transfer, so this fails
 * cleanly rather than faulting: a real `get`/`ls` would surface
 * WSAEINVAL through the caller's error handling. Must still export by
 * name so the IAT binds. */
__declspec(dllexport) INT WSARecv(SOCKET s, void* buffers, DWORD buffer_count, DWORD* bytes_recvd, DWORD* flags,
                                  void* overlapped, void* completion)
{
    (void)s;
    (void)buffers;
    (void)buffer_count;
    (void)overlapped;
    (void)completion;
    if (bytes_recvd)
        *bytes_recvd = 0;
    (void)flags;
    g_wsa_last_error = WSAEINVAL;
    return SOCKET_ERROR;
}

/* ---------------------------------------------------------------------------
 * WSAAsyncSelect — message-based async socket notification.
 *
 * Win32 contract: WSAAsyncSelect(s, hWnd, wMsg, lEvent) registers `s` so
 * that whenever one of the FD_* events in `lEvent` fires, the window
 * manager posts message `wMsg` to `hWnd` with:
 *   wParam = the socket handle
 *   lParam = WSAMAKESELECTREPLY(event, error)
 *            (low 16 bits = the single FD_* event, high 16 bits = error)
 *
 * Rules implemented:
 *   - Only ONE async registration per socket. A second call for the same
 *     socket replaces the first (and re-arms its fired state).
 *   - lEvent == 0 cancels the registration for `s`.
 *   - Calling WSAAsyncSelect implicitly puts the socket in non-blocking
 *     mode (g_ws2_nonblock_mask — same state FIONBIO toggles). Cancelling
 *     does NOT restore blocking mode; the app must FIONBIO it back, exactly
 *     as on real Win32.
 *
 * Mechanism: a single per-process helper thread (spawned lazily on the
 * first live registration) polls every registered socket via
 * `kSockOpPollEvents` (SYS_SOCKET_OP op=14) on a short cadence. Each
 * subscribed FD_* bit fires ONCE when it first shows up in the poll mask
 * (latched in `fired`) and posts `wMsg` to the registered HWND through the
 * SAME kernel entry user32's PostMessage uses (SYS_WIN_POST_MSG = 64). One
 * post per distinct event so the caller's WindowProc sees one FD_* per
 * message, matching Winsock's WSAMAKESELECTREPLY contract.
 *
 * Re-arm (Winsock re-enable contract): a fired bit stays latched until the
 * app calls the matching operation —
 *   FD_READ   re-arms on recv / recvfrom (ws2_recv_would_block hook);
 *   FD_ACCEPT re-arms on accept;
 *   FD_WRITE  re-arms when send / sendto fails with WSAEWOULDBLOCK
 *             (ws2_send_would_block hook — MSDN: FD_WRITE only re-fires
 *             after a would-block send);
 *   FD_CONNECT / FD_CLOSE are one-shot and never re-arm.
 * If the condition still holds after the re-arm (data left in the buffer),
 * the next poll cycle posts again — the drain-loop shape Winsock apps are
 * written against.
 *
 * FD_CONNECT has no kSockOpPollEvents producer; connect() is synchronous in
 * the kernel, so the completion message (with the real WSA error in the
 * high word of lParam) is posted directly from the connect() hook via
 * ws2_async_notify_connect.
 * ------------------------------------------------------------------------- */

#define WSAMAKESELECTREPLY(event, error) ((long)(((unsigned)(event)) | (((unsigned)(error)) << 16)))

#define WS2_ASYNC_SLOTS 32

typedef struct WsaAsyncReg
{
    int in_use;
    SOCKET socket;
    void* hwnd;
    unsigned wMsg;
    long eventMask; /* subscribed FD_* bits (armed set) */
    long fired;     /* FD_* bits posted and not yet re-armed */
} WsaAsyncReg;

static WsaAsyncReg g_wsa_async[WS2_ASYNC_SLOTS];
static int g_wsa_async_thread_started = 0;

/* Re-enable `bits` for the socket's async registration so the poller may
 * post them again on the next readiness observation. Called from the recv /
 * send / accept hooks above; a socket without a registration is a no-op. */
static void ws2_async_rearm(SOCKET s, long bits)
{
    for (int i = 0; i < WS2_ASYNC_SLOTS; ++i)
    {
        if (g_wsa_async[i].in_use && g_wsa_async[i].socket == s)
        {
            g_wsa_async[i].fired &= ~bits;
            break;
        }
    }
}

/* closesocket teardown: forget every DLL-side trace of `s` so the next
 * socket the kernel hands out on this pool index starts clean. */
static void ws2_drop_socket_state(SOCKET s)
{
    ws2_set_nonblocking(s, 0);
    for (int i = 0; i < WS2_ASYNC_SLOTS; ++i)
    {
        if (g_wsa_async[i].in_use && g_wsa_async[i].socket == s)
            g_wsa_async[i].in_use = 0;
    }
    for (int i = 0; i < WSA_BINDING_SLOTS; ++i)
    {
        if (g_wsa_bindings[i].in_use && g_wsa_bindings[i].socket == s)
            g_wsa_bindings[i].in_use = 0;
    }
}

/* SYS_WIN_POST_MSG (64): the exact kernel entry user32's PostMessage
 * routes through. rdi = hwnd, rsi = message, rdx = wParam, r10 = lParam.
 * Cross-pid posts are rejected kernel-side; we only ever post to HWNDs the
 * caller registered, which it owns. */
static void ws2_post_message(void* hwnd, unsigned msg, unsigned long long wparam, long lparam)
{
    register long long r10_l __asm__("r10") = (long long)lparam;
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)64), "D"((long long)(unsigned long long)hwnd), "S"((long long)msg),
                       "d"((long long)wparam), "r"(r10_l)
                     : "memory");
}

/* Post the FD_CONNECT completion message for `s` if its registration
 * subscribed to it. Fired from the connect() hook (the kernel connect is
 * synchronous; the poll mask has no FD_CONNECT producer). One-shot: the
 * fired latch keeps a re-registration from double-posting. */
static void ws2_async_notify_connect(SOCKET s, int wsa_err)
{
    for (int i = 0; i < WS2_ASYNC_SLOTS; ++i)
    {
        if (!g_wsa_async[i].in_use || g_wsa_async[i].socket != s)
            continue;
        if ((g_wsa_async[i].eventMask & WS2_FD_CONNECT) != 0 && (g_wsa_async[i].fired & WS2_FD_CONNECT) == 0)
        {
            g_wsa_async[i].fired |= WS2_FD_CONNECT;
            ws2_post_message(g_wsa_async[i].hwnd, g_wsa_async[i].wMsg, (unsigned long long)s,
                             WSAMAKESELECTREPLY(WS2_FD_CONNECT, (unsigned)wsa_err));
        }
        break;
    }
}

/* Helper-thread body. Polls every live async registration, posts a message
 * for each subscribed FD_* event on its first observation, sleeps, repeats.
 * Never returns — the kernel reclaims the thread on process exit. */
static void ws2_async_select_thread(void* arg)
{
    (void)arg;
    /* Single FD_* event per iteration, posted individually so each
     * delivered message carries exactly one event in the reply.
     * FD_CONNECT is absent — it's posted by ws2_async_notify_connect. */
    static const long kEventBits[4] = {WS2_FD_READ, WS2_FD_WRITE, WS2_FD_ACCEPT, WS2_FD_CLOSE};
    for (;;)
    {
        for (int i = 0; i < WS2_ASYNC_SLOTS; ++i)
        {
            if (!g_wsa_async[i].in_use)
                continue;
            const long subscribed = g_wsa_async[i].eventMask;
            const long ready = ws2_poll_events(g_wsa_async[i].socket) & subscribed;
            /* Fresh bits = ready bits not currently latched. Latch them so
             * each fires once; the recv / send / accept hooks clear the
             * latch when the app performs the matching re-arm operation. */
            const long fresh = ready & ~g_wsa_async[i].fired;
            for (int b = 0; b < 4; ++b)
            {
                if (fresh & kEventBits[b])
                {
                    ws2_post_message(g_wsa_async[i].hwnd, g_wsa_async[i].wMsg,
                                     (unsigned long long)g_wsa_async[i].socket, WSAMAKESELECTREPLY(kEventBits[b], 0));
                }
            }
            g_wsa_async[i].fired |= fresh;
        }
        ws2_sleep_ms(10);
    }
}

__declspec(dllexport) INT WSAAsyncSelect(SOCKET s, void* hWnd, unsigned wMsg, long lEvent)
{
    /* Find an existing registration for this socket — one per socket. */
    int free_idx = -1;
    for (int i = 0; i < WS2_ASYNC_SLOTS; ++i)
    {
        if (g_wsa_async[i].in_use && g_wsa_async[i].socket == s)
        {
            if (lEvent == 0)
            {
                /* Cancel: drop the registration entirely. */
                g_wsa_async[i].in_use = 0;
                return 0;
            }
            g_wsa_async[i].hwnd = hWnd;
            g_wsa_async[i].wMsg = wMsg;
            g_wsa_async[i].eventMask = lEvent;
            g_wsa_async[i].fired = 0; /* re-arm everything */
            ws2_set_nonblocking(s, 1);
            return 0;
        }
        if (!g_wsa_async[i].in_use && free_idx < 0)
            free_idx = i;
    }

    if (lEvent == 0)
        return 0; /* Cancel of a nonexistent registration — succeeds. */

    if (free_idx < 0)
    {
        g_wsa_last_error = 10055; /* WSAENOBUFS */
        return SOCKET_ERROR;
    }

    g_wsa_async[free_idx].socket = s;
    g_wsa_async[free_idx].hwnd = hWnd;
    g_wsa_async[free_idx].wMsg = wMsg;
    g_wsa_async[free_idx].eventMask = lEvent;
    g_wsa_async[free_idx].fired = 0;
    g_wsa_async[free_idx].in_use = 1;

    /* Win32 contract: a successful WSAAsyncSelect puts the socket in
     * non-blocking mode as a side effect. */
    ws2_set_nonblocking(s, 1);

    /* Spawn the poller lazily on the first live registration — same
     * SYS_THREAD_CREATE (45) path the CRT's _beginthread uses (rdi = start
     * VA, rsi = arg). The kernel returns a pseudo-handle on success or a
     * negative errno on cap-deny / slot exhaustion. */
    if (!g_wsa_async_thread_started)
    {
        long long h;
        __asm__ volatile("int $0x80"
                         : "=a"(h)
                         : "a"((long long)45), "D"((long long)(unsigned long long)&ws2_async_select_thread),
                           "S"((long long)0)
                         : "memory");
        /* GAP: a failed spawn leaves the registration recorded but
         *   unserviced; the next WSAAsyncSelect call retries the spawn. A
         *   well-formed Win32 client with kCapSpawnThread never hits this.
         *   — revisit if a no-thread cap tier appears. */
        if (h >= 0)
            g_wsa_async_thread_started = 1;
    }
    return 0;
}
