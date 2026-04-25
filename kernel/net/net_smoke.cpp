#include "net_smoke.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../drivers/usb/cdc_ecm.h"
#include "../drivers/usb/rndis.h"
#include "../sched/sched.h"
#include "stack.h"

namespace duetos::net
{

namespace
{

constinit bool g_started = false;

void WriteIp(Ipv4Address ip)
{
    for (u32 i = 0; i < 4; ++i)
    {
        if (i != 0)
            arch::SerialWrite(".");
        // SerialWriteHex prints unsigned hex; for IP dotted-quads
        // we want decimal, so emit each octet by hand.
        char buf[4];
        u32 n = ip.octets[i];
        u32 len = 0;
        if (n == 0)
            buf[len++] = '0';
        else
        {
            char rev[4];
            u32 r = 0;
            while (n != 0)
            {
                rev[r++] = char('0' + (n % 10));
                n /= 10;
            }
            for (u32 j = 0; j < r; ++j)
                buf[len++] = rev[r - 1 - j];
        }
        buf[len] = '\0';
        arch::SerialWrite(buf);
    }
}

bool WaitForDhcp(DhcpLease& out_lease)
{
    // 50 × 100 ms = 5 s.
    for (u32 i = 0; i < 50; ++i)
    {
        out_lease = DhcpLeaseRead();
        if (out_lease.valid)
            return true;
        duetos::sched::SchedSleepTicks(10);
    }
    return false;
}

bool DoIcmpEcho(Ipv4Address dst, u16 id, u32 timeout_ticks)
{
    NetPingArm(id, /*seq=*/1);
    if (!NetIcmpSendEcho(/*iface_index=*/0, dst, id, /*seq=*/1))
        return false;
    for (u32 i = 0; i < timeout_ticks; ++i)
    {
        duetos::sched::SchedSleepTicks(1);
        const auto r = NetPingRead();
        if (r.replied)
            return true;
    }
    return false;
}

bool DoDnsLookup(Ipv4Address resolver, const char* name, Ipv4Address& out_ip, u32 timeout_ticks)
{
    if (!NetDnsQueryA(/*iface_index=*/0, resolver, name))
        return false;
    for (u32 i = 0; i < timeout_ticks; ++i)
    {
        duetos::sched::SchedSleepTicks(1);
        const auto r = NetDnsResultRead();
        if (r.resolved)
        {
            out_ip = r.ip;
            return true;
        }
    }
    return false;
}

// HTTP GET return values, used by the smoke test to give a clearer
// failure message than a single bool can carry.
enum class HttpGetResult : u8
{
    Ok,
    SendRejected, // NetTcpConnect returned false (slot busy / ARP miss / ifce missing)
    Timeout,      // sent but no reply within deadline
    NotHttp,      // got bytes but not an HTTP status line
};

HttpGetResult DoHttpGet(Ipv4Address dst, const char* host_header, u32& out_status_code, u32 timeout_ticks)
{
    // Hand-built minimal HTTP/1.0 GET. Avoid HTTP/1.1 — it requires
    // chunked / connection-management we don't have, and the v0
    // single-shot "send + read until FIN" loop fits 1.0 perfectly.
    char request[256];
    u32 off = 0;
    const char* parts[] = {"GET / HTTP/1.0\r\nHost: ", host_header,
                           "\r\nUser-Agent: DuetOS-NetSmoke/0.1\r\nConnection: close\r\n\r\n"};
    for (const char* p : parts)
    {
        for (u32 i = 0; p[i] != '\0' && off + 1 < sizeof(request); ++i)
            request[off++] = p[i];
    }
    if (!NetTcpConnect(/*iface_index=*/0, dst, /*dst_port=*/80, reinterpret_cast<const u8*>(request), off))
        return HttpGetResult::SendRejected;
    out_status_code = 0;
    for (u32 i = 0; i < timeout_ticks; ++i)
    {
        duetos::sched::SchedSleepTicks(1);
        const auto snap = NetTcpActiveSnapshot();
        if (snap.response_complete || snap.response_len >= 64)
        {
            // Decode "HTTP/1.x SSS " status code from the first
            // up-to-13 bytes of the response.
            u8 head[16] = {};
            const u32 got = NetTcpActiveRead(head, sizeof(head) - 1);
            if (got >= 12 && head[0] == 'H' && head[1] == 'T' && head[2] == 'T' && head[3] == 'P')
            {
                u32 code = 0;
                for (u32 j = 9; j < 12; ++j)
                {
                    if (head[j] >= '0' && head[j] <= '9')
                        code = code * 10 + u32(head[j] - '0');
                }
                out_status_code = code;
                return HttpGetResult::Ok;
            }
            return HttpGetResult::NotHttp;
        }
    }
    return HttpGetResult::Timeout;
}

void NetSmokeEntry(void*)
{
    KLOG_TRACE_SCOPE("net/smoke", "Entry");
    arch::SerialWrite("[net-smoke] starting — waiting up to 5s for DHCP...\n");

    DhcpLease lease = {};
    if (!WaitForDhcp(lease))
    {
        arch::SerialWrite("[net-smoke] FAIL: DHCP did not bind within 5s — aborting test\n");
        return;
    }
    arch::SerialWrite("[net-smoke] DHCP OK ip=");
    WriteIp(lease.ip);
    arch::SerialWrite(" router=");
    WriteIp(lease.router);
    arch::SerialWrite(" dns=");
    WriteIp(lease.dns);
    arch::SerialWrite("\n");

    // Step 1: ping the gateway. SLIRP returns its own ICMP echo
    // reply for the gateway, so this should always succeed when
    // the link is up.
    arch::SerialWrite("[net-smoke] step 1: ping gateway ");
    WriteIp(lease.router);
    arch::SerialWrite("\n");
    if (DoIcmpEcho(lease.router, /*id=*/0xCAFE, /*timeout=*/200))
        arch::SerialWrite("[net-smoke] step 1: PASS — gateway replied to ICMP echo\n");
    else
        arch::SerialWrite("[net-smoke] step 1: FAIL — no reply within 2s\n");

    // Step 2: DNS resolve www.google.com via the DHCP-supplied
    // resolver. SLIRP forwards UDP/53 to the host's resolver,
    // which proxies to a real upstream. Hot path — typically
    // resolves in <100ms.
    Ipv4Address google_ip{};
    bool dns_ok = false;
    arch::SerialWrite("[net-smoke] step 2: DNS A www.google.com via ");
    WriteIp(lease.dns);
    arch::SerialWrite("\n");
    if (DoDnsLookup(lease.dns, "www.google.com", google_ip, /*timeout=*/300))
    {
        dns_ok = true;
        arch::SerialWrite("[net-smoke] step 2: PASS — www.google.com -> ");
        WriteIp(google_ip);
        arch::SerialWrite("\n");
    }
    else
    {
        arch::SerialWrite("[net-smoke] step 2: FAIL — DNS did not resolve within 3s\n");
    }

    // Step 3: ping a public host (8.8.8.8). SLIRP's user-mode
    // stack only forwards ICMP to the outside if the host has the
    // ping-group sysctl set or QEMU runs as root with raw-socket
    // capability — otherwise this will time out cleanly. Reported
    // as "skipped" rather than FAIL so a non-root QEMU run isn't
    // flagged as broken.
    arch::SerialWrite("[net-smoke] step 3: ping 8.8.8.8 (public)\n");
    if (DoIcmpEcho({{8, 8, 8, 8}}, /*id=*/0xBEEF, /*timeout=*/200))
        arch::SerialWrite("[net-smoke] step 3: PASS — 8.8.8.8 replied (real ICMP path)\n");
    else
        arch::SerialWrite("[net-smoke] step 3: skipped — no reply (SLIRP without raw-ICMP, or no public route)\n");

    // Step 4: TCP connect to the resolved Google IP and pull the
    // first response line. Proves end-to-end connectivity over
    // the kernel TCP state machine.
    if (dns_ok)
    {
        arch::SerialWrite("[net-smoke] step 4: TCP GET / HTTP/1.0 -> ");
        WriteIp(google_ip);
        arch::SerialWrite(":80\n");
        u32 status = 0;
        const auto rc = DoHttpGet(google_ip, "www.google.com", status, /*timeout=*/500);
        switch (rc)
        {
        case HttpGetResult::Ok:
        {
            arch::SerialWrite("[net-smoke] step 4: PASS — server replied (HTTP status=");
            char num[8];
            u32 n = status;
            u32 len = 0;
            if (n == 0)
                num[len++] = '?';
            else
            {
                char rev[8];
                u32 r = 0;
                while (n != 0)
                {
                    rev[r++] = char('0' + (n % 10));
                    n /= 10;
                }
                for (u32 j = 0; j < r; ++j)
                    num[len++] = rev[r - 1 - j];
            }
            num[len] = '\0';
            arch::SerialWrite(num);
            arch::SerialWrite(")\n");
            break;
        }
        case HttpGetResult::SendRejected:
            arch::SerialWrite("[net-smoke] step 4: skipped — NetTcpConnect rejected (likely TCP slot busy with the "
                              "boot listener; v0 single-slot limitation)\n");
            break;
        case HttpGetResult::NotHttp:
            arch::SerialWrite("[net-smoke] step 4: PARTIAL — TCP handshake established, but reply was not HTTP\n");
            break;
        case HttpGetResult::Timeout:
            arch::SerialWrite("[net-smoke] step 4: FAIL — TCP did not complete handshake or no HTTP reply within 5s\n");
            break;
        }
    }
    else
    {
        arch::SerialWrite("[net-smoke] step 4: skipped — DNS did not resolve\n");
    }

    arch::SerialWrite("[net-smoke] done\n");

    // Hand the TCP slot back to the boot HTTP listener. main.cpp
    // used to install this directly after NetStackInit, but the
    // single-slot v0 TCP impl made that incompatible with the
    // active-connect step above. Installing here keeps the same
    // post-boot behaviour (port 7777 serves a canned hello).
    static const char kHello[] = "HTTP/1.0 200 OK\r\n"
                                 "Content-Type: text/plain\r\n"
                                 "Content-Length: 24\r\n"
                                 "\r\n"
                                 "Hello from DuetOS!\r\n\r\n";
    TcpListen(7777, reinterpret_cast<const u8*>(kHello), sizeof(kHello) - 1);
    arch::SerialWrite("[net-smoke] boot listener installed on tcp/7777\n");

    // USB-net auto-probe is intentionally NOT called here. With a
    // real RNDIS device attached, the bring-up succeeds but the
    // bulk RX poll task and the synchronous DHCP TX collide on
    // the v0 event-ring consumer (non-atomic evt_idx / evt_cycle).
    // Manual invocation via the `usbnet probe` shell command
    // works for one-shot testing in a controlled context. Real
    // concurrent USB-net needs the event-router slice.
}

} // namespace

void NetSmokeTestStart()
{
    if (g_started)
        return;
    g_started = true;
    duetos::sched::SchedCreate(NetSmokeEntry, nullptr, "net-smoke");
}

} // namespace duetos::net
