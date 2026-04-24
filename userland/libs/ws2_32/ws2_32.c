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
    (void)s;
    return 0xFFFFFFFFu; /* INADDR_NONE */
}
__declspec(dllexport) void* gethostbyname(const char* n)
{
    (void)n;
    return (void*)0;
}
__declspec(dllexport) INT gethostname(char* buf, INT len)
{
    if (buf && len > 0)
        buf[0] = 0;
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
