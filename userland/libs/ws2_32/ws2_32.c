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
    long long rv = ws2_op(3 /* kSockOpConnect */, (long long)s, (long long)addr, (long long)cb, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return 0;
}
__declspec(dllexport) SOCKET accept(SOCKET s, void* addr, INT* cb)
{
    long long rv = ws2_op(5 /* kSockOpAccept */, (long long)s, (long long)addr, (long long)cb, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return INVALID_SOCKET;
    }
    return (SOCKET)rv;
}
__declspec(dllexport) INT send(SOCKET s, const void* buf, INT len, INT flags)
{
    (void)flags;
    long long rv = ws2_op(6 /* kSockOpSendto */, (long long)s, (long long)buf, (long long)len, 0, 0);
    if (rv < 0)
    {
        g_wsa_last_error = wsa_translate_errno(rv);
        return SOCKET_ERROR;
    }
    return (INT)rv;
}
__declspec(dllexport) INT recv(SOCKET s, void* buf, INT len, INT flags)
{
    (void)flags;
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

__declspec(dllexport) INT getaddrinfo(const char* node, const char* service, const void* hints, void** result)
{
    (void)node;
    (void)service;
    (void)hints;
    if (result)
        *result = (void*)0;
    return WSAENETDOWN;
}
__declspec(dllexport) void freeaddrinfo(void* r)
{
    (void)r;
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
 *   FIONBIO   — toggle non-blocking mode. Stored in a per-process
 *               flag that send / recv loops below treat as
 *               advisory; the kernel-side socket layer is
 *               currently always blocking, so non-blocking
 *               semantics are best-effort (recv may still block
 *               briefly while the kernel fills its buffer). The
 *               return value of 0 (= NO_ERROR) is what every
 *               caller checks; setting *argp on the way back is
 *               a Win32 quirk we don't need.
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
    (void)s;
    switch ((unsigned long)cmd)
    {
    case DUETOS_FIONBIO:
        /* argp points at a non-zero "set non-blocking" flag or a
         * zero "clear non-blocking" flag. We accept either and
         * return success — the kernel-side socket layer is
         * always-blocking in v0, so the flag is advisory only. */
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
