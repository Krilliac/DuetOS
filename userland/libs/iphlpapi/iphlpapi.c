/* iphlpapi.dll — IP helper API.
 *
 * GetAdaptersInfo emits a chain of two IP_ADAPTER_INFO records:
 *   1. Ethernet adapter (queried from the kernel's DHCP lease via
 *      kSockOpGetLease op = 13 over SYS_SOCKET_OP = 153). When no
 *      lease is bound the IP / mask / gateway fields show 0.0.0.0
 *      but the record still appears so callers see a NIC entry.
 *   2. Loopback adapter (127.0.0.1 / 255.0.0.0).
 *
 * GetAdaptersAddresses still reports ERROR_NO_DATA — the larger
 * IP_ADAPTER_ADDRESSES layout has IPv6 prefix lists, dual-stack
 * gateway chains, and per-adapter DNS that we don't track yet.
 */
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef int BOOL;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define ERROR_NOT_SUPPORTED 50UL
#define ERROR_NO_DATA 232UL

typedef struct
{
    unsigned int valid;
    unsigned int ip_be;
    unsigned int netmask_be;
    unsigned int gateway_be;
    unsigned int dns_be;
    unsigned int lease_seconds;
    unsigned char mac[6];
    unsigned char iface_index;
    unsigned char reserved0;
    unsigned char reserved1[8];
} IPHLP_LEASE;

static long long iphlp_sock_op(long long op, long long a1, long long a2, long long a3)
{
    long long rv;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "xor %%r8, %%r8\n\t"
                     "xor %%r9, %%r9\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)153), "D"(op), "S"(a1), "d"(a2), "r"(a3)
                     : "r10", "r8", "r9", "memory");
    return rv;
}

static int iphlp_get_lease(IPHLP_LEASE* out)
{
    long long rv = iphlp_sock_op(13 /* kSockOpGetLease */, 0, (long long)out, (long long)sizeof(*out));
    return rv == 0 ? 1 : 0;
}

/* Format an IPv4 address (network byte order) into the caller's
 * buffer as a NUL-terminated dotted-decimal string. */
static void iphlp_format_ip(unsigned int be, char* out)
{
    int pos = 0;
    for (int i = 0; i < 4; ++i)
    {
        unsigned int oct = (be >> (i * 8)) & 0xFFu;
        if (oct >= 100)
        {
            out[pos++] = '0' + (char)(oct / 100);
            oct %= 100;
            out[pos++] = '0' + (char)(oct / 10);
            out[pos++] = '0' + (char)(oct % 10);
        }
        else if (oct >= 10)
        {
            out[pos++] = '0' + (char)(oct / 10);
            out[pos++] = '0' + (char)(oct % 10);
        }
        else
        {
            out[pos++] = '0' + (char)oct;
        }
        if (i != 3)
            out[pos++] = '.';
    }
    out[pos] = '\0';
}

/* IP_ADAPTER_INFO layout (relevant fields, sized for v0):
 *   +0    Next pointer (8 bytes)
 *   +8    ComboIndex (DWORD)
 *   +12   AdapterName[260]
 *   +272  Description[132]
 *   +404  AddressLength (UINT)
 *   +408  Address[8]
 *   +416  Index (DWORD)
 *   +420  Type (UINT)
 *   +424  DhcpEnabled (UINT)
 *   +428  CurrentIpAddress (ptr)
 *   +436  IpAddressList (IP_ADDR_STRING: 4+16+16+4 = 40 bytes)
 *   +476  GatewayList   (IP_ADDR_STRING)
 *   ... rest zero-filled
 */
#define IPHLP_ADAPTER_INFO_SIZE 640

static void iphlp_zero(unsigned char* b, ULONG n)
{
    for (ULONG i = 0; i < n; ++i)
        b[i] = 0;
}

static void iphlp_fill_loopback(unsigned char* b)
{
    static const char kName[] = "Loopback";
    static const char kDesc[] = "DuetOS Loopback";
    for (int i = 0; kName[i]; ++i)
        b[12 + i] = (unsigned char)kName[i];
    for (int i = 0; kDesc[i]; ++i)
        b[272 + i] = (unsigned char)kDesc[i];
    b[404] = 6;
    b[408 + 0] = 0x02;
    b[408 + 5] = 0x01;
    b[416] = 1;
    b[420] = 24; /* MIB_IF_TYPE_LOOPBACK */
    static const char kIp[] = "127.0.0.1";
    for (int i = 0; kIp[i]; ++i)
        b[436 + 8 + i] = (unsigned char)kIp[i];
    static const char kMask[] = "255.0.0.0";
    for (int i = 0; kMask[i]; ++i)
        b[436 + 8 + 16 + i] = (unsigned char)kMask[i];
}

static void iphlp_fill_ethernet(unsigned char* b, const IPHLP_LEASE* lease)
{
    static const char kName[] = "eth0";
    static const char kDesc[] = "DuetOS Ethernet (e1000)";
    for (int i = 0; kName[i]; ++i)
        b[12 + i] = (unsigned char)kName[i];
    for (int i = 0; kDesc[i]; ++i)
        b[272 + i] = (unsigned char)kDesc[i];
    b[404] = 6;
    for (int i = 0; i < 6; ++i)
        b[408 + i] = lease->mac[i];
    b[416] = 0;
    b[420] = 6;                             /* MIB_IF_TYPE_ETHERNET_CSMACD */
    b[424] = (unsigned char)(lease->valid); /* DhcpEnabled */
    iphlp_format_ip(lease->ip_be, (char*)(b + 436 + 8));
    iphlp_format_ip(lease->netmask_be, (char*)(b + 436 + 8 + 16));
    iphlp_format_ip(lease->gateway_be, (char*)(b + 476 + 8));
}

__declspec(dllexport) DWORD GetAdaptersInfo(void* adapter_info, ULONG* out_buf_len)
{
    if (!out_buf_len)
        return 87; /* ERROR_INVALID_PARAMETER */
    /* Two-record chain — ethernet + loopback. */
    ULONG needed = IPHLP_ADAPTER_INFO_SIZE * 2;
    if (!adapter_info || *out_buf_len < needed)
    {
        *out_buf_len = needed;
        return 111; /* ERROR_BUFFER_OVERFLOW */
    }
    unsigned char* base = (unsigned char*)adapter_info;
    iphlp_zero(base, needed);
    IPHLP_LEASE lease = {0};
    iphlp_get_lease(&lease);
    iphlp_fill_ethernet(base, &lease);
    unsigned char* second = base + IPHLP_ADAPTER_INFO_SIZE;
    unsigned long long second_va = (unsigned long long)second;
    for (int i = 0; i < 8; ++i)
        base[i] = (unsigned char)((second_va >> (i * 8)) & 0xFFu);
    iphlp_fill_loopback(second);
    *out_buf_len = needed;
    return 0;
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
        *num_if = 1; /* loopback */
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

/* GetIfEntry / GetIfEntry2 / GetIfStackTable / GetIfTable2 — empty / no-op. */
__declspec(dllexport) DWORD GetIfEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD GetIfEntry2(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD GetIfTable2(void** table)
{
    if (table)
        *table = (void*)0;
    return ERROR_NO_DATA;
}

__declspec(dllexport) DWORD GetIfStackTable(void** table)
{
    if (table)
        *table = (void*)0;
    return ERROR_NO_DATA;
}

__declspec(dllexport) void FreeMibTable(void* tbl)
{
    (void)tbl;
}

/* GetInterfaceInfo — list of bindable interfaces. v0 reports
 * insufficient buffer / 0-needed = ERROR_NO_DATA. */
__declspec(dllexport) DWORD GetInterfaceInfo(void* iftable, ULONG* size)
{
    (void)iftable;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}

/* GetBestInterface / GetBestInterfaceEx — best route to dest.
 * v0 reports 0 (loopback / single sentinel) so callers don't
 * abort on no-route. */
__declspec(dllexport) DWORD GetBestInterface(ULONG dest_addr, DWORD* best_if_index)
{
    (void)dest_addr;
    if (best_if_index)
        *best_if_index = 1; /* if-index 1 = our sentinel loopback */
    return 0;
}

__declspec(dllexport) DWORD GetBestInterfaceEx(void* dest_addr, DWORD* best_if_index)
{
    (void)dest_addr;
    if (best_if_index)
        *best_if_index = 1;
    return 0;
}

/* NotifyAddrChange / NotifyRouteChange — wait on net-config
 * change. v0 never reports a change so callers see "still
 * online" by default. We accept either blocking or overlapped
 * variants; the overlapped one returns ERROR_IO_PENDING. */
__declspec(dllexport) DWORD NotifyAddrChange(HANDLE* handle, void* overlapped)
{
    if (handle)
        *handle = (HANDLE)0;
    if (overlapped)
        return 997UL; /* ERROR_IO_PENDING */
    return 0;
}

__declspec(dllexport) DWORD NotifyRouteChange(HANDLE* handle, void* overlapped)
{
    if (handle)
        *handle = (HANDLE)0;
    if (overlapped)
        return 997UL;
    return 0;
}

__declspec(dllexport) BOOL CancelIPChangeNotify(void* overlapped)
{
    (void)overlapped;
    return 1;
}

/* GetUnicastIpAddressTable / GetUnicastIpAddressEntry — modern
 * IPv4 / IPv6 address API. v0 reports zero rows. */
__declspec(dllexport) DWORD GetUnicastIpAddressTable(unsigned short family, void** table)
{
    (void)family;
    if (table)
        *table = (void*)0;
    return ERROR_NO_DATA;
}

__declspec(dllexport) DWORD GetUnicastIpAddressEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

/* GetIpInterfaceTable / GetIpInterfaceEntry — Vista+ link
 * table. */
__declspec(dllexport) DWORD GetIpInterfaceTable(unsigned short family, void** table)
{
    (void)family;
    if (table)
        *table = (void*)0;
    return ERROR_NO_DATA;
}

__declspec(dllexport) DWORD GetIpInterfaceEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

/* SetIpInterfaceEntry / SetUnicastIpAddressEntry — modify
 * link config. v0 reports unsupported (no live writes). */
__declspec(dllexport) DWORD SetIpInterfaceEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD SetUnicastIpAddressEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD CreateUnicastIpAddressEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD DeleteUnicastIpAddressEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

/* GetTcpTable2 / GetTcp6Table / GetTcp6Table2 / GetUdpTable2 /
 * GetUdp6Table — newer table variants. Empty rows. */
__declspec(dllexport) DWORD GetTcpTable2(void* tbl, ULONG* size, BOOL order)
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

__declspec(dllexport) DWORD GetTcp6Table(void* tbl, ULONG* size, BOOL order)
{
    (void)order;
    if (size)
        *size = 0;
    if (tbl)
    {
    }
    return ERROR_NO_DATA;
}

__declspec(dllexport) DWORD GetTcp6Table2(void* tbl, ULONG* size, BOOL order)
{
    (void)tbl;
    (void)order;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}

__declspec(dllexport) DWORD GetUdp6Table(void* tbl, ULONG* size, BOOL order)
{
    (void)tbl;
    (void)order;
    if (size)
        *size = 0;
    return ERROR_NO_DATA;
}

/* GetExtendedTcpTable / GetExtendedUdpTable variants for IPv6 —
 * already covered by the base variants. Add more table calls. */

/* SetTcpEntry — close a TCP connection. v0 ignores. */
__declspec(dllexport) DWORD SetTcpEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD SetIpForwardEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD CreateIpForwardEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD DeleteIpForwardEntry(void* row)
{
    (void)row;
    return ERROR_NOT_SUPPORTED;
}

/* AddIPAddress / DeleteIPAddress — legacy. */
__declspec(dllexport) DWORD AddIPAddress(ULONG addr, ULONG mask, DWORD if_idx, DWORD* ntex_ctx, DWORD* ntex_inst)
{
    (void)addr;
    (void)mask;
    (void)if_idx;
    if (ntex_ctx)
        *ntex_ctx = 0;
    if (ntex_inst)
        *ntex_inst = 0;
    return ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD DeleteIPAddress(ULONG ntex_ctx)
{
    (void)ntex_ctx;
    return ERROR_NOT_SUPPORTED;
}

/* SendARP — issue ARP for a host. v0 reports failure. */
__declspec(dllexport) DWORD SendARP(ULONG dst, ULONG src, void* mac, ULONG* mac_len)
{
    (void)dst;
    (void)src;
    if (mac && mac_len && *mac_len >= 6)
    {
        unsigned char* m = (unsigned char*)mac;
        for (int i = 0; i < 6; ++i)
            m[i] = 0;
    }
    if (mac_len)
        *mac_len = 0;
    return ERROR_NOT_SUPPORTED;
}

/* GetIpStatistics / GetIpStatisticsEx / GetTcpStatistics /
 * GetUdpStatistics / GetIcmpStatistics — counters. Zero. */
__declspec(dllexport) DWORD GetIpStatistics(void* stats)
{
    if (stats)
    {
        unsigned char* p = (unsigned char*)stats;
        for (int i = 0; i < 92; ++i) /* MIB_IPSTATS approx */
            p[i] = 0;
    }
    return 0;
}

__declspec(dllexport) DWORD GetIpStatisticsEx(void* stats, ULONG family)
{
    (void)family;
    return GetIpStatistics(stats);
}

__declspec(dllexport) DWORD GetTcpStatistics(void* stats)
{
    if (stats)
    {
        unsigned char* p = (unsigned char*)stats;
        for (int i = 0; i < 56; ++i)
            p[i] = 0;
    }
    return 0;
}

__declspec(dllexport) DWORD GetUdpStatistics(void* stats)
{
    if (stats)
    {
        unsigned char* p = (unsigned char*)stats;
        for (int i = 0; i < 20; ++i)
            p[i] = 0;
    }
    return 0;
}

__declspec(dllexport) DWORD GetIcmpStatistics(void* stats)
{
    if (stats)
    {
        unsigned char* p = (unsigned char*)stats;
        for (int i = 0; i < 96; ++i)
            p[i] = 0;
    }
    return 0;
}

__declspec(dllexport) DWORD ConvertInterfaceIndexToLuid(DWORD if_idx, void* luid)
{
    (void)if_idx;
    if (luid)
        *(unsigned long long*)luid = 0;
    return 0;
}

__declspec(dllexport) DWORD ConvertInterfaceLuidToIndex(const void* luid, DWORD* if_idx)
{
    (void)luid;
    if (if_idx)
        *if_idx = 1;
    return 0;
}

__declspec(dllexport) DWORD ConvertInterfaceLuidToNameW(const void* luid, wchar_t16* name, unsigned long long len)
{
    (void)luid;
    (void)len;
    if (name)
    {
        static const char kIf[] = "if1";
        for (int i = 0; i < 4; ++i)
            name[i] = (wchar_t16)kIf[i];
    }
    return 0;
}

__declspec(dllexport) DWORD ConvertInterfaceNameToLuidW(const wchar_t16* name, void* luid)
{
    (void)name;
    if (luid)
        *(unsigned long long*)luid = 0;
    return 0;
}
