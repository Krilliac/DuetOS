/* iphlpapi.dll — IP helper API. No network; all fail. */
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef int BOOL;
typedef void* HANDLE;

#define ERROR_NOT_SUPPORTED 50UL
#define ERROR_NO_DATA 232UL

/* IP_ADAPTER_INFO is large (~640 bytes). For v0 we report
 * "no adapters" via ERROR_NO_DATA which the smoke test accepts
 * as PASS. (The docs allow it.) */
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
/* MIB_IPADDRTABLE: dwNumEntries (DWORD) + array of MIB_IPADDRROW.
 * MIB_IPADDRROW: dwAddr, dwIndex, dwMask, dwBCastAddr, dwReasmSize,
 *                wType, wFlags. 24 bytes per row. */
__declspec(dllexport) DWORD GetIpAddrTable(void* tbl, ULONG* size, BOOL order)
{
    (void)order;
    if (size == (ULONG*)0)
        return 87; /* ERROR_INVALID_PARAMETER */
    /* One sentinel row: 127.0.0.1 / 255.0.0.0 (loopback). */
    ULONG needed = 4 + 24;
    if (*size < needed || tbl == (void*)0)
    {
        *size = needed;
        return 122; /* ERROR_INSUFFICIENT_BUFFER */
    }
    unsigned char* b = (unsigned char*)tbl;
    /* dwNumEntries = 1 */
    b[0] = 1;
    b[1] = 0;
    b[2] = 0;
    b[3] = 0;
    /* Row 0: 127.0.0.1 (LE: 01 00 00 7F) */
    b[4] = 0x01;
    b[5] = 0x00;
    b[6] = 0x00;
    b[7] = 0x7F;
    /* dwIndex = 1 */
    b[8] = 1;
    b[9] = 0;
    b[10] = 0;
    b[11] = 0;
    /* dwMask = 255.0.0.0 */
    b[12] = 0xFF;
    b[13] = 0;
    b[14] = 0;
    b[15] = 0;
    /* zero rest */
    for (int i = 16; i < 28; ++i)
        b[i] = 0;
    *size = needed;
    return 0;
}

__declspec(dllexport) DWORD GetTcpTable(void* tbl, ULONG* size, BOOL order)
{
    (void)order;
    if (size == (ULONG*)0)
        return 87;
    /* No active TCP rows. dwNumEntries = 0 only. */
    ULONG needed = 4;
    if (*size < needed || tbl == (void*)0)
    {
        *size = needed;
        return 0;
    }
    unsigned char* b = (unsigned char*)tbl;
    b[0] = 0;
    b[1] = 0;
    b[2] = 0;
    b[3] = 0;
    *size = needed;
    return 0;
}

__declspec(dllexport) DWORD GetUdpTable(void* tbl, ULONG* size, BOOL order)
{
    (void)order;
    if (size == (ULONG*)0)
        return 87;
    ULONG needed = 4;
    if (*size < needed || tbl == (void*)0)
    {
        *size = needed;
        return 0;
    }
    unsigned char* b = (unsigned char*)tbl;
    b[0] = 0;
    b[1] = 0;
    b[2] = 0;
    b[3] = 0;
    *size = needed;
    return 0;
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

/* FIXED_INFO is large (~640 bytes), but our minimum is 4 (HostName)
 * + DomainName + Pad + DnsServerList (IP_ADDR_STRING = 4 + 16 + 16 + 4
 * = ~40 each, prev pointer null) ... For v0 we just write a sane
 * minimum and report success. */
__declspec(dllexport) DWORD GetNetworkParams(void* fixed, ULONG* size)
{
    if (size == (ULONG*)0)
        return 87;
    /* Minimum size to populate: 132 (HostName) + 132 (DomainName)
     * + 8 (CurrentDnsServer ptr) + sizeof(IP_ADDR_STRING) ~= 312. */
    ULONG needed = 312;
    if (*size < needed || fixed == (void*)0)
    {
        *size = needed;
        return 111; /* ERROR_BUFFER_OVERFLOW per FIXED_INFO docs. */
    }
    unsigned char* b = (unsigned char*)fixed;
    for (ULONG i = 0; i < needed; ++i)
        b[i] = 0;
    /* HostName at offset 0: "duetos\0" */
    static const char hn[] = "duetos";
    for (int i = 0; i < 6; ++i)
        b[i] = (unsigned char)hn[i];
    *size = needed;
    return 0;
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
