/* ws2_32.dll — Winsock. No networking in v0; all ops fail. */
typedef int INT;
typedef unsigned int SOCKET;
typedef int BOOL;
typedef unsigned int DWORD;
typedef unsigned short USHORT;

#define INVALID_SOCKET (~(SOCKET)0)
#define SOCKET_ERROR (-1)
#define WSAENETDOWN 10050

__declspec(dllexport) INT WSAStartup(USHORT req_ver, void* wsa_data)
{
    (void)req_ver;
    (void)wsa_data;
    return WSAENETDOWN;
}
__declspec(dllexport) INT WSACleanup(void)
{
    return 0;
}
__declspec(dllexport) INT WSAGetLastError(void)
{
    return WSAENETDOWN;
}
__declspec(dllexport) void WSASetLastError(INT err)
{
    (void)err;
}

__declspec(dllexport) SOCKET socket(INT af, INT type, INT proto)
{
    (void)af;
    (void)type;
    (void)proto;
    return INVALID_SOCKET;
}
__declspec(dllexport) INT closesocket(SOCKET s)
{
    (void)s;
    return 0;
}
__declspec(dllexport) INT bind(SOCKET s, const void* addr, INT cb)
{
    (void)s;
    (void)addr;
    (void)cb;
    return SOCKET_ERROR;
}
__declspec(dllexport) INT listen(SOCKET s, INT backlog)
{
    (void)s;
    (void)backlog;
    return SOCKET_ERROR;
}
__declspec(dllexport) INT connect(SOCKET s, const void* addr, INT cb)
{
    (void)s;
    (void)addr;
    (void)cb;
    return SOCKET_ERROR;
}
__declspec(dllexport) SOCKET accept(SOCKET s, void* addr, INT* cb)
{
    (void)s;
    (void)addr;
    (void)cb;
    return INVALID_SOCKET;
}
__declspec(dllexport) INT send(SOCKET s, const void* buf, INT len, INT flags)
{
    (void)s;
    (void)buf;
    (void)len;
    (void)flags;
    return SOCKET_ERROR;
}
__declspec(dllexport) INT recv(SOCKET s, void* buf, INT len, INT flags)
{
    (void)s;
    (void)buf;
    (void)len;
    (void)flags;
    return SOCKET_ERROR;
}
__declspec(dllexport) INT sendto(SOCKET s, const void* buf, INT len, INT flags, const void* addr, INT cb)
{
    (void)s;
    (void)buf;
    (void)len;
    (void)flags;
    (void)addr;
    (void)cb;
    return SOCKET_ERROR;
}
__declspec(dllexport) INT recvfrom(SOCKET s, void* buf, INT len, INT flags, void* addr, INT* cb)
{
    (void)s;
    (void)buf;
    (void)len;
    (void)flags;
    (void)addr;
    (void)cb;
    return SOCKET_ERROR;
}
__declspec(dllexport) INT shutdown(SOCKET s, INT how)
{
    (void)s;
    (void)how;
    return 0;
}
__declspec(dllexport) INT setsockopt(SOCKET s, INT lvl, INT opt, const void* v, INT vl)
{
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
    (void)vl;
    return 0;
}
__declspec(dllexport) INT select(INT nfds, void* rfd, void* wfd, void* efd, const void* tv)
{
    (void)nfds;
    (void)rfd;
    (void)wfd;
    (void)efd;
    (void)tv;
    return 0; /* timeout */
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
    /* Parse "a.b.c.d" — dotted-decimal IPv4 — into a network-
     * order DWORD. INADDR_NONE (0xFFFFFFFF) on any parse failure
     * (matches Win32). Pure-logic helper; no network needed. */
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
    /* Network byte order: big-endian. */
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

/* inet_ntoa — convert network-order DWORD-shaped struct in_addr
 * to dotted-decimal in a static buffer. The Win32 contract is
 * "buffer reused across calls; not thread-safe" — we honour that. */
__declspec(dllexport) const char* inet_ntoa(DWORD addr)
{
    static char buf[16];
    /* Win32 passes struct in_addr by value, which lays out the
     * 4 bytes in host order (a in low byte, d in high byte) on
     * little-endian. Format as a.b.c.d. */
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
    if (af != 2 /* AF_INET */ || !src || !dst)
        return 0;
    DWORD a = inet_addr(src);
    if (a == 0xFFFFFFFFu)
    {
        /* "255.255.255.255" is a legitimate value — re-check
         * literally to disambiguate from the error sentinel. */
        const char broadcast[] = "255.255.255.255";
        for (int i = 0;; ++i)
        {
            if (broadcast[i] == 0 && src[i] == 0)
                break;
            if (broadcast[i] != src[i])
                return 0;
        }
    }
    /* in_addr stores the 4 bytes in network order from MSB to
     * LSB, so re-pack from inet_addr's network-order DWORD. */
    unsigned char* d = (unsigned char*)dst;
    d[0] = (unsigned char)(a >> 24);
    d[1] = (unsigned char)(a >> 16);
    d[2] = (unsigned char)(a >> 8);
    d[3] = (unsigned char)(a);
    return 1;
}

__declspec(dllexport) const char* inet_ntop(INT af, const void* src, char* dst, INT size)
{
    if (af != 2 /* AF_INET */ || !src || !dst || size < 16)
        return (const char*)0;
    const unsigned char* s = (const unsigned char*)src;
    /* Reuse inet_ntoa's formatter via an intermediate DWORD. */
    DWORD packed = (DWORD)s[0] | ((DWORD)s[1] << 8) | ((DWORD)s[2] << 16) | ((DWORD)s[3] << 24);
    const char* str = inet_ntoa(packed);
    int i = 0;
    for (; str[i] && i < size - 1; ++i)
        dst[i] = str[i];
    dst[i] = 0;
    return dst;
}

__declspec(dllexport) void* gethostbyname(const char* n)
{
    (void)n;
    return (void*)0;
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

/* htonll / ntohll — 64-bit byte-swap helpers (Vista+). Pure logic. */
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

/* WSAEnumProtocols / GetProtocolByNumber: empty list. */
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

__declspec(dllexport) INT ioctlsocket(SOCKET s, long cmd, DWORD* argp)
{
    (void)s;
    (void)cmd;
    if (argp)
        *argp = 0;
    return SOCKET_ERROR;
}

__declspec(dllexport) INT getsockname(SOCKET s, void* addr, INT* cb)
{
    (void)s;
    (void)addr;
    if (cb)
        *cb = 0;
    return SOCKET_ERROR;
}

__declspec(dllexport) INT getpeername(SOCKET s, void* addr, INT* cb)
{
    (void)s;
    (void)addr;
    if (cb)
        *cb = 0;
    return SOCKET_ERROR;
}
