/* iphlpapi.dll — IP helper API. No network; all fail. */
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef int BOOL;
typedef void* HANDLE;

#define ERROR_NOT_SUPPORTED 50UL
#define ERROR_NO_DATA 232UL

__declspec(dllexport) DWORD GetAdaptersInfo(void* adapter_info, ULONG* out_buf_len)
{
    (void)adapter_info;
    if (out_buf_len)
        *out_buf_len = 0;
    return ERROR_NO_DATA;
}
__declspec(dllexport) DWORD GetAdaptersAddresses(ULONG family, ULONG flags, void* rsv, void* adapter_addrs,
                                                 ULONG* out_buf_len)
{
    (void)family;
    (void)flags;
    (void)rsv;
    (void)adapter_addrs;
    if (out_buf_len)
        *out_buf_len = 0;
    return ERROR_NO_DATA;
}
__declspec(dllexport) DWORD GetIfTable(void* if_table, ULONG* size, BOOL order)
{
    (void)if_table;
    if (size)
        *size = 0;
    (void)order;
    return ERROR_NO_DATA;
}
__declspec(dllexport) DWORD GetNumberOfInterfaces(DWORD* num_if)
{
    if (num_if)
        *num_if = 0;
    return 0;
}
__declspec(dllexport) DWORD IcmpSendEcho(HANDLE icmp, ULONG dst, void* req, unsigned short req_size, void* opts,
                                         void* reply, DWORD reply_size, DWORD timeout)
{
    (void)icmp;
    (void)dst;
    (void)req;
    (void)req_size;
    (void)opts;
    (void)reply;
    (void)reply_size;
    (void)timeout;
    return 0;
}
__declspec(dllexport) HANDLE IcmpCreateFile(void)
{
    return (HANDLE)(long long)-1; /* INVALID */
}
__declspec(dllexport) BOOL IcmpCloseHandle(HANDLE h)
{
    (void)h;
    return 1;
}

/* GetIpForwardTable / GetIpAddrTable / GetTcpTable / GetUdpTable.
 * v0 has no routing table or socket inventory, so each reports
 * ERROR_NO_DATA. The caller's `*size` output is updated to 0
 * so a probe loop ends instead of looping. */
__declspec(dllexport) DWORD GetIpForwardTable(void* tbl, ULONG* size, BOOL order)
{
    (void)tbl;
    (void)order;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}
__declspec(dllexport) DWORD GetIpAddrTable(void* tbl, ULONG* size, BOOL order)
{
    (void)tbl;
    (void)order;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}
__declspec(dllexport) DWORD GetTcpTable(void* tbl, ULONG* size, BOOL order)
{
    (void)tbl;
    (void)order;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}
__declspec(dllexport) DWORD GetUdpTable(void* tbl, ULONG* size, BOOL order)
{
    (void)tbl;
    (void)order;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}

__declspec(dllexport) DWORD GetExtendedTcpTable(void* tbl, DWORD* size, BOOL order, ULONG fam, int klass, ULONG rsv)
{
    (void)tbl;
    (void)order;
    (void)fam;
    (void)klass;
    (void)rsv;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}

__declspec(dllexport) DWORD GetExtendedUdpTable(void* tbl, DWORD* size, BOOL order, ULONG fam, int klass, ULONG rsv)
{
    (void)tbl;
    (void)order;
    (void)fam;
    (void)klass;
    (void)rsv;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}

__declspec(dllexport) DWORD GetNetworkParams(void* fixed, ULONG* size)
{
    (void)fixed;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}

__declspec(dllexport) DWORD GetBestRoute(ULONG dest_addr, ULONG src_addr, void* best_route)
{
    (void)dest_addr;
    (void)src_addr;
    (void)best_route;
    return ERROR_NOT_SUPPORTED;
}

/* IcmpSendEcho2 — newer ICMP API, same v0 stub. */
__declspec(dllexport) DWORD IcmpSendEcho2(HANDLE icmp, HANDLE event, void* apc_routine, void* apc_ctx, ULONG dst,
                                          void* req, unsigned short req_size, void* opts, void* reply, DWORD reply_size,
                                          DWORD timeout)
{
    (void)icmp;
    (void)event;
    (void)apc_routine;
    (void)apc_ctx;
    (void)dst;
    (void)req;
    (void)req_size;
    (void)opts;
    (void)reply;
    (void)reply_size;
    (void)timeout;
    return 0;
}

__declspec(dllexport) HANDLE Icmp6CreateFile(void)
{
    return (HANDLE)(long long)-1;
}
