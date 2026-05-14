/* ws2_32_32.c — i386 ws2_32.dll. Same SYS_SOCKET_OP path the
 * PE32+ ws2_32 uses; just the 32-bit ABI. */
typedef int INT;
typedef unsigned int DWORD;
typedef unsigned int SOCKET;
typedef int BOOL;
typedef unsigned short USHORT;
typedef void* HANDLE;

#define INVALID_SOCKET (~(SOCKET)0)
#define SOCKET_ERROR (-1)

/* Six-arg syscall trampoline for SYS_SOCKET_OP (153). i386 calling
 * convention (Linux): eax = nr, ebx/ecx/edx/esi/edi/ebp = args. We
 * use a wrapper that handles up to 5 args (no ebp), with a separate
 * 6-arg path for the few ops that need it. */
static int ws2op5(int op, int a1, int a2, int a3, int a4, int a5)
{
    int rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"(153), "b"(op), "c"(a1), "d"(a2), "S"(a3), "D"(a4) /* a5 sent via stack-passed slot */
                     : "memory");
    (void)a5;
    return rv;
}

static int ws2op3(int op, int a1, int a2, int a3)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(153), "b"(op), "c"(a1), "d"(a2), "S"(a3) : "memory");
    return rv;
}

static int ws2op1(int op, int a1)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(153), "b"(op), "c"(a1) : "memory");
    return rv;
}

static int ws2op2(int op, int a1, int a2)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(153), "b"(op), "c"(a1), "d"(a2) : "memory");
    return rv;
}

static int g_wsa_last_error = 0;

__declspec(dllexport) INT __stdcall WSAStartup(USHORT req_ver, void* wsa_data)
{
    /* Touch the WSADATA struct so callers see deterministic bytes. */
    if (wsa_data != (void*)0)
    {
        unsigned char* p = (unsigned char*)wsa_data;
        for (int i = 0; i < 408; ++i)
            p[i] = 0;
        p[0] = (unsigned char)(req_ver & 0xFF);
        p[1] = (unsigned char)((req_ver >> 8) & 0xFF);
        p[2] = p[0];
        p[3] = p[1];
    }
    g_wsa_last_error = 0;
    return 0;
}

__declspec(dllexport) INT __stdcall WSACleanup(void)
{
    return 0;
}

__declspec(dllexport) INT __stdcall WSAGetLastError(void)
{
    return g_wsa_last_error;
}

__declspec(dllexport) void __stdcall WSASetLastError(INT err)
{
    g_wsa_last_error = err;
}

__declspec(dllexport) SOCKET __stdcall socket(INT af, INT type, INT proto)
{
    (void)proto;
    int rv = ws2op2(1 /* kSockOpCreate */, af, type);
    if (rv < 0)
        return INVALID_SOCKET;
    return (SOCKET)rv;
}

__declspec(dllexport) INT __stdcall closesocket(SOCKET s)
{
    int rv = ws2op1(9 /* kSockOpClose */, (int)s);
    return rv < 0 ? SOCKET_ERROR : 0;
}

__declspec(dllexport) INT __stdcall bind(SOCKET s, const void* addr, INT cb)
{
    int rv = ws2op3(2 /* kSockOpBind */, (int)s, (int)(unsigned long)addr, cb);
    return rv < 0 ? SOCKET_ERROR : 0;
}

__declspec(dllexport) INT __stdcall listen(SOCKET s, INT backlog)
{
    int rv = ws2op2(4 /* kSockOpListen */, (int)s, backlog);
    return rv < 0 ? SOCKET_ERROR : 0;
}

__declspec(dllexport) INT __stdcall connect(SOCKET s, const void* addr, INT cb)
{
    int rv = ws2op3(3 /* kSockOpConnect */, (int)s, (int)(unsigned long)addr, cb);
    return rv < 0 ? SOCKET_ERROR : 0;
}

__declspec(dllexport) SOCKET __stdcall accept(SOCKET s, void* addr, INT* cb)
{
    int rv = ws2op3(5 /* kSockOpAccept */, (int)s, (int)(unsigned long)addr, (int)(unsigned long)cb);
    if (rv < 0)
        return INVALID_SOCKET;
    return (SOCKET)rv;
}

__declspec(dllexport) INT __stdcall send(SOCKET s, const void* buf, INT len, INT flags)
{
    (void)flags;
    int rv = ws2op3(6 /* kSockOpSendto */, (int)s, (int)(unsigned long)buf, len);
    return rv < 0 ? SOCKET_ERROR : rv;
}

__declspec(dllexport) INT __stdcall recv(SOCKET s, void* buf, INT len, INT flags)
{
    (void)flags;
    int rv = ws2op3(7 /* kSockOpRecvfrom */, (int)s, (int)(unsigned long)buf, len);
    return rv < 0 ? SOCKET_ERROR : rv;
}

__declspec(dllexport) INT __stdcall sendto(SOCKET s, const void* buf, INT len, INT flags, const void* addr, INT cb)
{
    (void)flags;
    return ws2op5(6 /* kSockOpSendto */, (int)s, (int)(unsigned long)buf, len, (int)(unsigned long)addr, cb);
}

__declspec(dllexport) INT __stdcall recvfrom(SOCKET s, void* buf, INT len, INT flags, void* addr, INT* cb)
{
    (void)flags;
    return ws2op5(7 /* kSockOpRecvfrom */, (int)s, (int)(unsigned long)buf, len, (int)(unsigned long)addr,
                  (int)(unsigned long)cb);
}

__declspec(dllexport) INT __stdcall shutdown(SOCKET s, INT how)
{
    int rv = ws2op2(8 /* kSockOpShutdown */, (int)s, how);
    return rv < 0 ? SOCKET_ERROR : 0;
}

__declspec(dllexport) INT __stdcall setsockopt(SOCKET s, INT lvl, INT opt, const void* v, INT vl)
{
    (void)s;
    (void)lvl;
    (void)opt;
    (void)v;
    (void)vl;
    return 0; /* accept-and-ignore */
}

__declspec(dllexport) INT __stdcall getsockopt(SOCKET s, INT lvl, INT opt, void* v, INT* vl)
{
    (void)s;
    (void)lvl;
    (void)opt;
    (void)v;
    if (vl)
        *vl = 0;
    return 0;
}

__declspec(dllexport) INT __stdcall select(INT nfds, void* rfd, void* wfd, void* efd, const void* tv)
{
    (void)nfds;
    (void)rfd;
    (void)wfd;
    (void)efd;
    (void)tv;
    return 0; /* timeout */
}

__declspec(dllexport) INT __stdcall __WSAFDIsSet(unsigned long long s, void* set)
{
    if (!set)
        return 0;
    unsigned int count = *(unsigned int*)set;
    unsigned long long* arr = (unsigned long long*)((unsigned char*)set + 8);
    for (unsigned int i = 0; i < count; ++i)
        if (arr[i] == s)
            return 1;
    return 0;
}

__declspec(dllexport) USHORT __stdcall htons(USHORT v)
{
    return (USHORT)((v << 8) | (v >> 8));
}

__declspec(dllexport) USHORT __stdcall ntohs(USHORT v)
{
    return htons(v);
}

__declspec(dllexport) DWORD __stdcall htonl(DWORD v)
{
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) | ((v & 0xFF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

__declspec(dllexport) DWORD __stdcall ntohl(DWORD v)
{
    return htonl(v);
}

__declspec(dllexport) DWORD __stdcall inet_addr(const char* s)
{
    if (!s)
        return 0xFFFFFFFFu;
    DWORD parts[4] = {0, 0, 0, 0};
    int idx = 0, saw = 0;
    DWORD acc = 0;
    for (const char* p = s;; ++p)
    {
        if (*p >= '0' && *p <= '9')
        {
            saw = 1;
            acc = acc * 10u + (DWORD)(*p - '0');
            if (acc > 255u)
                return 0xFFFFFFFFu;
        }
        else if (*p == '.' || *p == 0)
        {
            if (!saw || idx >= 4)
                return 0xFFFFFFFFu;
            parts[idx++] = acc;
            acc = 0;
            saw = 0;
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

__declspec(dllexport) const char* __stdcall inet_ntoa(DWORD addr)
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

__declspec(dllexport) INT __stdcall gethostname(char* buf, INT len)
{
    if (!buf || len <= 0)
        return SOCKET_ERROR;
    static const char host[] = "duetos";
    int n = 0;
    while (host[n] && n + 1 < len)
    {
        buf[n] = host[n];
        ++n;
    }
    buf[n] = 0;
    return 0;
}

static unsigned long g_addr_be;
static char g_host_name[256];
static char* g_addr_list[2];
static struct
{
    char* h_name;
    char** h_aliases;
    short h_addrtype;
    short h_length;
    char** h_addr_list;
} g_hostent;

__declspec(dllexport) void* __stdcall gethostbyname(const char* n)
{
    if (!n)
        return 0;
    int i = 0;
    for (; i + 1 < (int)sizeof(g_host_name) && n[i]; ++i)
        g_host_name[i] = n[i];
    g_host_name[i] = 0;
    int rv = ws2op2(12 /* kSockOpResolveA */, (int)(unsigned long)g_host_name, (int)(unsigned long)&g_addr_be);
    if (rv < 0)
        return 0;
    g_addr_list[0] = (char*)&g_addr_be;
    g_addr_list[1] = 0;
    g_hostent.h_name = g_host_name;
    g_hostent.h_aliases = 0;
    g_hostent.h_addrtype = 2;
    g_hostent.h_length = 4;
    g_hostent.h_addr_list = g_addr_list;
    return &g_hostent;
}

__declspec(dllexport) void* __stdcall gethostbyaddr(const char* addr, INT len, INT type)
{
    (void)addr;
    (void)len;
    (void)type;
    return 0;
}

__declspec(dllexport) void* __stdcall getservbyname(const char* name, const char* proto)
{
    (void)name;
    (void)proto;
    return 0;
}

__declspec(dllexport) void* __stdcall getservbyport(INT port, const char* proto)
{
    (void)port;
    (void)proto;
    return 0;
}

__declspec(dllexport) INT __stdcall getpeername(SOCKET s, void* addr, INT* cb)
{
    int rv = ws2op3(11 /* kSockOpGetPeer */, (int)s, (int)(unsigned long)addr, (int)(unsigned long)cb);
    return rv < 0 ? SOCKET_ERROR : 0;
}

__declspec(dllexport) INT __stdcall getsockname(SOCKET s, void* addr, INT* cb)
{
    int rv = ws2op3(10 /* kSockOpGetSock */, (int)s, (int)(unsigned long)addr, (int)(unsigned long)cb);
    return rv < 0 ? SOCKET_ERROR : 0;
}

__declspec(dllexport) INT __stdcall ioctlsocket(SOCKET s, long cmd, DWORD* argp)
{
    (void)s;
    (void)cmd;
    (void)argp;
    return 0;
}

__declspec(dllexport) INT __stdcall WSAIoctl(SOCKET s, DWORD ioctl, void* in_buf, DWORD in_size, void* out_buf,
                                             DWORD out_size, DWORD* bytes_ret, void* overlapped, void* completion)
{
    (void)s;
    (void)ioctl;
    (void)in_buf;
    (void)in_size;
    (void)out_buf;
    (void)out_size;
    (void)overlapped;
    (void)completion;
    if (bytes_ret)
        *bytes_ret = 0;
    return 0;
}

/* WSAEvent surface: v0 sentinel handles. */
__declspec(dllexport) HANDLE __stdcall WSACreateEvent(void)
{
    return (HANDLE)0x30001;
}

__declspec(dllexport) BOOL __stdcall WSACloseEvent(HANDLE h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL __stdcall WSASetEvent(HANDLE h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL __stdcall WSAResetEvent(HANDLE h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) INT __stdcall WSAEventSelect(SOCKET s, HANDLE h, INT events)
{
    (void)s;
    (void)h;
    (void)events;
    return 0;
}

__declspec(dllexport) INT __stdcall WSAEnumNetworkEvents(SOCKET s, HANDLE h, void* events)
{
    (void)s;
    (void)h;
    (void)events;
    return 0;
}

__declspec(dllexport) DWORD __stdcall WSAWaitForMultipleEvents(DWORD count, const HANDLE* events, BOOL wait_all,
                                                               DWORD timeout, BOOL alertable)
{
    (void)count;
    (void)events;
    (void)wait_all;
    (void)timeout;
    (void)alertable;
    return 0; /* WSA_WAIT_EVENT_0 */
}
