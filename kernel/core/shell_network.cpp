/*
 * DuetOS — kernel shell: network commands (slice 1).
 *
 * Sibling TU of shell.cpp. Houses the simpler networking
 * commands plus the small set of TU-private helpers they share:
 *
 *   ParseIpv4    dotted-quad → Ipv4Address
 *   WriteIpv4    Ipv4Address → "a.b.c.d" on the console
 *   WriteMac     MAC bytes → "aa:bb:..."
 *   Ipv4IsZero   shorthand for "all-zeros address"
 *
 * Commands moved here:
 *
 *   ping     ICMP echo with poll-for-reply
 *   http     HTTP/1.0 GET via TCP
 *   ntp      UDP/123 query → unix_secs
 *   nslookup DNS A-record lookup
 *   nic      driver-only inventory (PCI NIC list)
 *   ifconfig stack-aware iface dump (IP + lease)
 *   arp      ARP cache stats
 *   ipv4     IPv4 RX counters
 *
 * Heavier commands (dhcp / route / netscan / wifi / fwpolicy /
 * fwtrace / crtrace / net / usbnet) stay in shell.cpp pending
 * a follow-up slice. They share the same helpers via this file's
 * `using namespace shell::internal;` glue.
 */

#include "shell_internal.h"

#include "../drivers/net/net.h"
#include "../drivers/video/console.h"
#include "../net/stack.h"
#include "../sched/sched.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

} // namespace

// Parse dotted-quad `a.b.c.d`. Returns true on exact 4-octet match.
bool ParseIpv4(const char* s, duetos::net::Ipv4Address* out)
{
    u32 parts[4] = {};
    u32 idx = 0;
    u32 cur = 0;
    bool had_digit = false;
    for (u32 i = 0;; ++i)
    {
        const char c = s[i];
        if (c == '\0' || c == '.')
        {
            if (!had_digit)
                return false;
            if (idx >= 4)
                return false;
            parts[idx++] = cur;
            cur = 0;
            had_digit = false;
            if (c == '\0')
                break;
            continue;
        }
        if (c < '0' || c > '9')
            return false;
        cur = cur * 10 + u32(c - '0');
        if (cur > 255)
            return false;
        had_digit = true;
    }
    if (idx != 4)
        return false;
    for (u32 i = 0; i < 4; ++i)
        out->octets[i] = u8(parts[i]);
    return true;
}

// Print "a.b.c.d" — used by every networking command that wants to
// surface IPs without each one re-implementing the dotted-quad
// formatter. Zero-tolerance for tabs (kernel console is fixed-width).
void WriteIpv4(duetos::net::Ipv4Address ip)
{
    for (u64 i = 0; i < 4; ++i)
    {
        if (i != 0)
            ConsoleWriteChar('.');
        WriteU64Dec(ip.octets[i]);
    }
}

void WriteMac(const duetos::u8 mac[6])
{
    for (u64 i = 0; i < 6; ++i)
    {
        if (i != 0)
            ConsoleWriteChar(':');
        WriteU64Hex(mac[i], 2);
    }
}

bool Ipv4IsZero(duetos::net::Ipv4Address ip)
{
    for (u64 i = 0; i < 4; ++i)
        if (ip.octets[i] != 0)
            return false;
    return true;
}

void CmdPing(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("PING: usage: ping <ipv4>");
        return;
    }
    duetos::net::Ipv4Address dst = {};
    if (!ParseIpv4(argv[1], &dst))
    {
        ConsoleWriteln("PING: malformed IPv4 (expected dotted-quad)");
        return;
    }
    // Pick a deterministic id/seq so repeats are diagnosable from
    // a pcap — id changes per ping cycle, seq stays 1.
    static u16 next_id = 0x0100;
    const u16 id = next_id++;
    const u16 seq = 1;
    duetos::net::NetPingArm(id, seq);
    if (!duetos::net::NetIcmpSendEcho(/*iface_index=*/0, dst, id, seq))
    {
        ConsoleWriteln("PING: send failed (ARP cache miss? try reaching a peer first)");
        return;
    }
    // Wait up to ~1 second (100 ticks at 100 Hz) for a reply.
    // The ICMP RX path runs from the e1000 RX polling task, so
    // we just yield + poll.
    for (u32 i = 0; i < 100; ++i)
    {
        duetos::sched::SchedSleepTicks(1);
        const auto r = duetos::net::NetPingRead();
        if (r.replied)
        {
            ConsoleWrite("PING: reply from ");
            for (u64 j = 0; j < 4; ++j)
            {
                if (j != 0)
                    ConsoleWriteChar('.');
                WriteU64Dec(r.from.octets[j]);
            }
            ConsoleWrite("  rtt~=");
            WriteU64Dec(r.rtt_ticks * 10); // 100 Hz tick = 10 ms
            ConsoleWriteln("ms");
            return;
        }
    }
    ConsoleWriteln("PING: no reply within 1s");
}

void CmdHttp(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("HTTP: usage: http <ipv4> [port [path]]");
        return;
    }
    duetos::net::Ipv4Address dst = {};
    if (!ParseIpv4(argv[1], &dst))
    {
        ConsoleWriteln("HTTP: malformed IPv4");
        return;
    }
    u16 port = 80;
    if (argc >= 3)
    {
        u16 p = 0;
        if (!ParseU16Decimal(argv[2], &p))
        {
            ConsoleWriteln("HTTP: malformed port");
            return;
        }
        port = p;
    }
    const char* path = "/";
    if (argc >= 4)
        path = argv[3];

    // Build GET request. Host header uses the dotted-quad string
    // the caller passed in since we don't (yet) track reverse
    // DNS. Minimal HTTP/1.0 so we don't need keep-alive handling.
    char req[512];
    u32 ri = 0;
    auto put = [&](const char* s)
    {
        while (*s && ri + 1 < sizeof(req))
            req[ri++] = *s++;
    };
    put("GET ");
    put(path);
    put(" HTTP/1.0\r\nHost: ");
    put(argv[1]);
    put("\r\nConnection: close\r\n\r\n");

    if (!duetos::net::NetTcpConnect(/*iface_index=*/0, dst, port, reinterpret_cast<const u8*>(req), ri))
    {
        ConsoleWriteln("HTTP: connect failed (slot busy / ARP miss / oversized req)");
        return;
    }
    ConsoleWrite("HTTP: connecting to ");
    ConsoleWrite(argv[1]);
    ConsoleWriteln(" ...");

    // Poll up to 4 s for the response to arrive + FIN.
    for (u32 i = 0; i < 400; ++i)
    {
        duetos::sched::SchedSleepTicks(1);
        const auto s = duetos::net::NetTcpActiveSnapshot();
        if (s.response_complete)
        {
            // Print the captured bytes.
            u8 buf[2048];
            const u32 n = duetos::net::NetTcpActiveRead(buf, sizeof(buf));
            ConsoleWrite("HTTP: ");
            WriteU64Dec(n);
            ConsoleWriteln(" bytes received");
            // Print the first ~16 lines of the response so the
            // user can see headers + a bit of body.
            u32 lines = 0;
            for (u32 j = 0; j < n && lines < 16; ++j)
            {
                const char c = static_cast<char>(buf[j]);
                if (c == '\n')
                    ++lines;
                if (c == '\r')
                    continue;
                if (c == '\n' || (c >= 0x20 && c <= 0x7E))
                    ConsoleWriteChar(c);
            }
            ConsoleWriteln("");
            return;
        }
    }
    ConsoleWriteln("HTTP: no complete response within 4s");
}

void CmdNtp(u32 argc, char** argv)
{
    // QEMU SLIRP doesn't run its own NTP server; callers pointing
    // here need an IP SLIRP will forward to. Public stratum-1/2
    // servers on UDP/123 work when SLIRP's outbound-UDP path is
    // open (the default).
    duetos::net::Ipv4Address server{{216, 239, 35, 0}}; // Google time1.google.com
    if (argc >= 2 && !ParseIpv4(argv[1], &server))
    {
        ConsoleWriteln("NTP: malformed server IP");
        return;
    }
    if (!duetos::net::NetNtpQuery(/*iface_index=*/0, server))
    {
        ConsoleWriteln("NTP: send failed (ARP miss for server + gateway)");
        return;
    }
    for (u32 i = 0; i < 200; ++i) // up to ~2 s
    {
        duetos::sched::SchedSleepTicks(1);
        const auto r = duetos::net::NetNtpResultRead();
        if (r.synced)
        {
            ConsoleWrite("NTP: unix_secs=");
            WriteU64Dec(r.unix_secs);
            ConsoleWrite("  stratum=");
            WriteU64Dec(r.stratum);
            ConsoleWriteln("");
            // Rough UTC decode — pure second division; no month /
            // leap-year handling. Proves the epoch is sane enough
            // to surface a recognisable time.
            const u64 rem = r.unix_secs % 86400;
            const u64 h = rem / 3600;
            const u64 m = (rem / 60) % 60;
            const u64 s = rem % 60;
            ConsoleWrite("NTP: ~ ");
            if (h < 10)
                ConsoleWriteChar('0');
            WriteU64Dec(h);
            ConsoleWriteChar(':');
            if (m < 10)
                ConsoleWriteChar('0');
            WriteU64Dec(m);
            ConsoleWriteChar(':');
            if (s < 10)
                ConsoleWriteChar('0');
            WriteU64Dec(s);
            ConsoleWriteln(" UTC (time-of-day)");
            return;
        }
    }
    ConsoleWriteln("NTP: no response within 2s (SLIRP UDP/123 blocked? server down?)");
}

void CmdNslookup(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("NSLOOKUP: usage: nslookup <name> [resolver_ip]");
        return;
    }
    duetos::net::Ipv4Address resolver{{10, 0, 2, 3}}; // QEMU SLIRP default
    if (argc >= 3 && !ParseIpv4(argv[2], &resolver))
    {
        ConsoleWriteln("NSLOOKUP: malformed resolver IP");
        return;
    }
    if (!duetos::net::NetDnsQueryA(/*iface_index=*/0, resolver, argv[1]))
    {
        ConsoleWriteln("NSLOOKUP: send failed (ARP miss, name too long, or no iface)");
        return;
    }
    for (u32 i = 0; i < 200; ++i) // wait up to ~2 seconds
    {
        duetos::sched::SchedSleepTicks(1);
        const auto r = duetos::net::NetDnsResultRead();
        if (r.resolved)
        {
            ConsoleWrite("NSLOOKUP: ");
            ConsoleWrite(argv[1]);
            ConsoleWrite(" -> ");
            for (u64 j = 0; j < 4; ++j)
            {
                if (j != 0)
                    ConsoleWriteChar('.');
                WriteU64Dec(r.ip.octets[j]);
            }
            ConsoleWriteln("");
            return;
        }
    }
    ConsoleWriteln("NSLOOKUP: no response within 2s (NXDOMAIN, no route, or server down)");
}

void CmdNic()
{
    const u64 n = duetos::drivers::net::NicCount();
    if (n == 0)
    {
        ConsoleWriteln("NIC: (none discovered)");
        return;
    }
    for (u64 i = 0; i < n; ++i)
    {
        const auto& nic = duetos::drivers::net::Nic(i);
        ConsoleWrite("NIC ");
        WriteU64Dec(i);
        ConsoleWrite(": vid=");
        WriteU64Hex(nic.vendor_id, 4);
        ConsoleWrite(" did=");
        WriteU64Hex(nic.device_id, 4);
        ConsoleWrite("  vendor=");
        ConsoleWrite(nic.vendor);
        if (nic.family != nullptr)
        {
            ConsoleWrite(" family=");
            ConsoleWrite(nic.family);
        }
        if (nic.mac_valid)
        {
            ConsoleWrite(" mac=");
            for (u64 b = 0; b < 6; ++b)
            {
                if (b != 0)
                    ConsoleWrite(":");
                WriteU64Hex(nic.mac[b], 2);
            }
            ConsoleWrite(nic.link_up ? " link=UP" : " link=DOWN");
        }
        ConsoleWriteChar('\n');
    }
}

void CmdIfconfig()
{
    const duetos::u64 nics = duetos::drivers::net::NicCount();
    if (nics == 0)
    {
        ConsoleWriteln("IFCONFIG: no network interfaces (no PCI NICs discovered)");
        ConsoleWriteln("         (Wi-Fi adapters need a vendor driver — none online yet)");
        return;
    }
    for (duetos::u64 i = 0; i < nics; ++i)
    {
        const auto& nic = duetos::drivers::net::Nic(i);
        const bool bound = duetos::net::InterfaceIsBound(static_cast<duetos::u32>(i));
        ConsoleWrite("net");
        WriteU64Dec(i);
        ConsoleWrite("  ");
        ConsoleWrite(nic.vendor);
        if (nic.family != nullptr)
        {
            ConsoleWriteChar(' ');
            ConsoleWrite(nic.family);
        }
        ConsoleWriteln("");
        ConsoleWrite("       link    ");
        ConsoleWriteln(nic.mac_valid && nic.link_up ? "UP" : "DOWN");
        if (nic.mac_valid)
        {
            ConsoleWrite("       ether   ");
            WriteMac(nic.mac);
            ConsoleWriteln("");
        }
        if (bound)
        {
            const auto ip = duetos::net::InterfaceIp(static_cast<duetos::u32>(i));
            ConsoleWrite("       inet    ");
            WriteIpv4(ip);
            if (Ipv4IsZero(ip))
                ConsoleWriteln(" (waiting for DHCP)");
            else
                ConsoleWriteln("");
        }
        else
        {
            ConsoleWriteln("       inet    (not bound to stack — driver hasn't called bind yet)");
        }
        // Lease detail (DHCP is single-iface in v0; only print on the
        // interface that owns the lease).
        const auto lease = duetos::net::DhcpLeaseRead();
        if (bound && lease.valid)
        {
            ConsoleWrite("       gateway ");
            WriteIpv4(lease.router);
            ConsoleWriteln("");
            ConsoleWrite("       dns     ");
            WriteIpv4(lease.dns);
            ConsoleWriteln("");
            ConsoleWrite("       dhcp    server=");
            WriteIpv4(lease.server);
            ConsoleWrite("  lease=");
            WriteU64Dec(lease.lease_secs);
            ConsoleWriteln("s");
        }
    }
    ConsoleWrite("ARP cache: ");
    WriteU64Dec(duetos::net::ArpEntryCount());
    ConsoleWriteln(" live entries");
}

void CmdArp()
{
    const auto s = duetos::net::ArpStatsRead();
    ConsoleWrite("ARP HITS:       ");
    WriteU64Dec(s.lookups_hit);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP MISSES:     ");
    WriteU64Dec(s.lookups_miss);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP INSERTS:    ");
    WriteU64Dec(s.inserts);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP EVICTIONS:  ");
    WriteU64Dec(s.evictions);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP RX:         ");
    WriteU64Dec(s.rx_packets);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP REJECTS:    ");
    WriteU64Dec(s.rx_rejects);
    ConsoleWriteChar('\n');
}

void CmdIpv4()
{
    const auto s = duetos::net::Ipv4StatsRead();
    ConsoleWrite("IPV4 RX:        ");
    WriteU64Dec(s.rx_packets);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 BAD VER:   ");
    WriteU64Dec(s.rx_bad_version);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 BAD IHL:   ");
    WriteU64Dec(s.rx_bad_ihl);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 BAD LEN:   ");
    WriteU64Dec(s.rx_bad_length);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 BAD CSUM:  ");
    WriteU64Dec(s.rx_bad_checksum);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 RX UDP:    ");
    WriteU64Dec(s.rx_udp);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 RX TCP:    ");
    WriteU64Dec(s.rx_tcp);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 RX ICMP:   ");
    WriteU64Dec(s.rx_icmp);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 RX OTHER:  ");
    WriteU64Dec(s.rx_other_proto);
    ConsoleWriteChar('\n');
}

} // namespace duetos::core::shell::internal
