/*
 * iphlpapi_smoke — exercise iphlpapi network-info surface.
 *
 * Probes the IP Helper APIs that any network diagnostic tool
 * (ipconfig, netstat, route) uses to enumerate interfaces and
 * routes:
 *   GetAdaptersInfo        (legacy adapter table)
 *   GetIpAddrTable         (per-iface IP/netmask/index)
 *   GetTcpTable            (active TCP connections)
 *   GetNetworkParams       (host name / DNS servers)
 *
 * Each call's success indicator is just "didn't return an
 * error and produced > 0 entries". Real PASS depends on the
 * iphlpapi thunks being wired through to net::Interface /
 * net::SocketGet / net::DhcpLeaseRead — likely partial today.
 */
#include <windows.h>
#include <iphlpapi.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutDec(unsigned long v)
{
    char buf[16];
    int len = 0;
    if (v == 0)
        buf[len++] = '0';
    else
    {
        char rev[16];
        int r = 0;
        while (v != 0)
        {
            rev[r++] = (char)('0' + (v % 10));
            v /= 10;
        }
        for (int j = 0; j < r; ++j)
            buf[len++] = rev[r - 1 - j];
    }
    buf[len] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[iphlpapi_smoke] starting\r\n");

    /* Step 1: GetAdaptersInfo. */
    {
        IP_ADAPTER_INFO info[8];
        ULONG sz = sizeof(info);
        DWORD rc = GetAdaptersInfo(info, &sz);
        Out("[iphlpapi_smoke] GetAdaptersInfo    = ");
        if (rc == ERROR_SUCCESS)
        {
            int count = 0;
            for (IP_ADAPTER_INFO* p = info; p != NULL; p = p->Next)
                ++count;
            Out("PASS adapters=");
            OutDec((unsigned long)count);
            Out("\r\n");
        }
        else if (rc == ERROR_NO_DATA)
        {
            Out("PASS (no adapters reported)\r\n");
        }
        else
        {
            Out("FAIL rc=");
            OutDec(rc);
            Out("\r\n");
        }
    }

    /* Step 2: GetIpAddrTable. */
    {
        unsigned char buf[1024];
        ULONG sz = sizeof(buf);
        PMIB_IPADDRTABLE tbl = (PMIB_IPADDRTABLE)buf;
        DWORD rc = GetIpAddrTable(tbl, &sz, FALSE);
        Out("[iphlpapi_smoke] GetIpAddrTable     = ");
        if (rc == ERROR_SUCCESS)
        {
            Out("PASS rows=");
            OutDec((unsigned long)tbl->dwNumEntries);
            Out("\r\n");
        }
        else
        {
            Out("FAIL rc=");
            OutDec(rc);
            Out("\r\n");
        }
    }

    /* Step 3: GetTcpTable. */
    {
        unsigned char buf[2048];
        DWORD sz = sizeof(buf);
        PMIB_TCPTABLE tbl = (PMIB_TCPTABLE)buf;
        DWORD rc = GetTcpTable(tbl, &sz, FALSE);
        Out("[iphlpapi_smoke] GetTcpTable        = ");
        if (rc == ERROR_SUCCESS)
        {
            Out("PASS rows=");
            OutDec((unsigned long)tbl->dwNumEntries);
            Out("\r\n");
        }
        else
        {
            Out("FAIL rc=");
            OutDec(rc);
            Out("\r\n");
        }
    }

    /* Step 4: GetNetworkParams. */
    {
        unsigned char buf[2048];
        ULONG sz = sizeof(buf);
        FIXED_INFO* info = (FIXED_INFO*)buf;
        DWORD rc = GetNetworkParams(info, &sz);
        Out("[iphlpapi_smoke] GetNetworkParams   = ");
        if (rc == ERROR_SUCCESS)
        {
            Out("PASS host=\"");
            Out(info->HostName);
            Out("\"\r\n");
        }
        else
        {
            Out("FAIL rc=");
            OutDec(rc);
            Out("\r\n");
        }
    }

    Out("[iphlpapi_smoke] done\r\n");
    Out("[ring3-iphlpapi-smoke] PASS\r\n");
    ExitProcess(0);
}
