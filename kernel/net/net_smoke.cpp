#include "net/net_smoke.h"

#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "drivers/usb/cdc_ecm.h"
#include "drivers/usb/rndis.h"
#include "log/klog.h"
#include "net/socket.h"
#include "net/stack.h"
#include "net/tcp.h"
#include "sched/sched.h"

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
    SendRejected, // socket alloc/connect failed
    Timeout,      // sent but no reply within deadline
    NotHttp,      // got bytes but not an HTTP status line
};

HttpGetResult DoHttpGet(Ipv4Address dst, const char* host_header, u32& out_status_code, u32 timeout_ticks)
{
    char request[256];
    u32 off = 0;
    const char* parts[] = {"GET / HTTP/1.0\r\nHost: ", host_header,
                           "\r\nUser-Agent: DuetOS-NetSmoke/0.1\r\nConnection: close\r\n\r\n"};
    for (const char* p : parts)
    {
        for (u32 i = 0; p[i] != '\0' && off + 1 < sizeof(request); ++i)
            request[off++] = p[i];
    }
    const i32 sock = SocketAlloc(kSocketDomainInet, kSocketTypeStream);
    if (sock < 0)
        return HttpGetResult::SendRejected;
    if (!SocketConnect(static_cast<u32>(sock), dst, /*dst_port=*/80))
    {
        SocketRelease(static_cast<u32>(sock));
        return HttpGetResult::SendRejected;
    }
    {
        u32 sent = 0;
        while (sent < off)
        {
            const i64 n =
                SocketSendStream(static_cast<u32>(sock), reinterpret_cast<const u8*>(request) + sent, off - sent);
            if (n <= 0)
                break;
            sent += static_cast<u32>(n);
        }
    }
    SocketShutdown(static_cast<u32>(sock), /*how=*/1);
    out_status_code = 0;
    u8 head[16] = {};
    u32 got = 0;
    for (u32 i = 0; i < timeout_ticks && got < sizeof(head) - 1; ++i)
    {
        const i64 n = SocketRecvStream(static_cast<u32>(sock), head + got, sizeof(head) - 1 - got);
        if (n == 0)
            break;
        if (n < 0)
        {
            duetos::sched::SchedSleepTicks(1);
            continue;
        }
        got += static_cast<u32>(n);
    }
    SocketRelease(static_cast<u32>(sock));
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
    if (got == 0)
        return HttpGetResult::Timeout;
    return HttpGetResult::NotHttp;
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
            arch::SerialWrite("[net-smoke] step 4: skipped — socket alloc/connect rejected\n");
            break;
        case HttpGetResult::NotHttp:
            arch::SerialWrite("[net-smoke] step 4: PARTIAL — TCP handshake established, but reply was not HTTP\n");
            break;
        case HttpGetResult::Timeout:
            arch::SerialWrite("[net-smoke] step 4: FAIL — TCP did not complete handshake or no HTTP reply within 5s\n");
            break;
        default:
            arch::SerialWrite("[net-smoke] step 4: FAIL — unknown HttpGetResult enumerator\n");
            break;
        }
    }
    else
    {
        arch::SerialWrite("[net-smoke] step 4: skipped — DNS did not resolve\n");
    }

    arch::SerialWrite("[net-smoke] done\n");
    // The v0 boot-time "canned hello" listener on tcp/7777 is gone.
    // The v1 TCP stack supports many concurrent listeners; a real
    // listener is now opt-in via `tcp listen 7777` from the kernel
    // shell or a userland test harness. See wiki/networking/Network-
    // Stack.md for the migration note.

    // USB-net auto-probe is intentionally NOT called here. With a
    // real RNDIS device attached, the bring-up succeeds but the
    // bulk RX poll task and the synchronous DHCP TX collide on
    // the v0 event-ring consumer (non-atomic evt_idx / evt_cycle).
    // Manual invocation via the `usbnet probe` shell command
    // works for one-shot testing in a controlled context. Real
    // concurrent USB-net needs the event-router slice.
}

} // namespace

void NetSmokeTestStart(bool force_on_emulator)
{
    if (g_started)
        return;
    g_started = true;
    // Under a hypervisor the QEMU user-net stack rarely speaks
    // DHCP back to the kernel (it offers a SLIRP lease only when
    // explicitly enabled via -netdev user,dhcpstart=...) and even
    // when it does, the smoke task burns up to 15 s of kernel time
    // on its sequence of timeouts: 5 s DHCP wait, 2 s ICMP echo,
    // 3 s DNS lookup, 5 s HTTP GET. None of that output is on the
    // boot-smoke critical path, so skip the spawn entirely under
    // emulation. Bare metal boots get the full coverage as before.
    // The `netsmoke=force` cmdline flag opts in deliberately.
    if (arch::IsEmulator() && !force_on_emulator)
    {
        arch::SerialWrite("[net-smoke] emulator detected — skipping (would burn ~15s on DHCP/DNS/TCP timeouts; pass "
                          "netsmoke=force to override)\n");
        return;
    }
    if (arch::IsEmulator() && force_on_emulator)
    {
        arch::SerialWrite("[net-smoke] emulator detected but netsmoke=force set — running live probe\n");
    }
    duetos::sched::SchedCreate(NetSmokeEntry, nullptr, "net-smoke");
}

} // namespace duetos::net
