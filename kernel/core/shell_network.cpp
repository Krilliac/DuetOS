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

#include "../arch/x86_64/serial.h"
#include "../drivers/net/net.h"
#include "../drivers/usb/cdc_ecm.h"
#include "../drivers/usb/rndis.h"
#include "../drivers/video/console.h"
#include "../net/stack.h"
#include "../net/wifi.h"
#include "../sched/sched.h"
#include "cleanroom_trace.h"
#include "firmware_loader.h"

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

void CmdDhcp(u32 argc, char** argv)
{
    if (argc >= 2 && (StrEq(argv[1], "renew") || StrEq(argv[1], "request") || StrEq(argv[1], "start")))
    {
        if (!duetos::net::InterfaceIsBound(0))
        {
            ConsoleWriteln("DHCP: iface 0 not bound (no NIC driver online?)");
            return;
        }
        if (!duetos::net::DhcpStart(0))
        {
            ConsoleWriteln("DHCP: start failed (transaction already in flight?)");
            return;
        }
        ConsoleWriteln("DHCP: DISCOVER sent — wait ~1s then re-run `dhcp` for the bound IP");
        for (u32 i = 0; i < 200; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            const auto poll = duetos::net::DhcpLeaseRead();
            if (poll.valid)
                break;
        }
    }
    const auto lease = duetos::net::DhcpLeaseRead();
    if (!lease.valid)
    {
        ConsoleWriteln("DHCP: no lease (server didn't respond, or transaction in flight)");
        ConsoleWriteln("      try: `dhcp renew`");
        return;
    }
    ConsoleWrite("DHCP: bound  ip=");
    WriteIpv4(lease.ip);
    ConsoleWriteln("");
    ConsoleWrite("      gateway=");
    WriteIpv4(lease.router);
    ConsoleWriteln("");
    ConsoleWrite("      dns    =");
    WriteIpv4(lease.dns);
    ConsoleWriteln("");
    ConsoleWrite("      server =");
    WriteIpv4(lease.server);
    ConsoleWriteln("");
    ConsoleWrite("      lease  =");
    WriteU64Dec(lease.lease_secs);
    ConsoleWriteln(" sec");
}

void CmdRoute(u32 argc, char** argv)
{
    (void)argv;
    const auto lease = duetos::net::DhcpLeaseRead();
    if (!lease.valid)
    {
        ConsoleWriteln("ROUTE: no default route (DHCP not bound — try `dhcp renew`)");
        return;
    }
    ConsoleWrite("default via ");
    WriteIpv4(lease.router);
    ConsoleWrite(" dev net0  src ");
    WriteIpv4(lease.ip);
    ConsoleWriteln("");
    ConsoleWrite("DNS via ");
    WriteIpv4(lease.dns);
    ConsoleWriteln("");
    if (argc < 2)
        return;
    const auto* arp = duetos::net::ArpLookup(0, lease.router);
    ConsoleWrite("gateway L2: ");
    if (arp == nullptr)
    {
        ConsoleWriteln("not in ARP cache (peer hasn't replied to ARP yet)");
        return;
    }
    WriteMac(arp->mac.octets);
    ConsoleWriteln("  (ARP cached)");
}

void CmdNetscan()
{
    const u64 nics = duetos::drivers::net::NicCount();
    bool any_wifi = false;
    bool any_eth = false;
    for (u64 i = 0; i < nics; ++i)
    {
        const auto& nic = duetos::drivers::net::Nic(i);
        const bool wifiish = nic.subclass == 0x80 || (nic.family != nullptr && (StrStartsWith(nic.family, "iwlwifi") ||
                                                                                StrStartsWith(nic.family, "rtl8821") ||
                                                                                StrStartsWith(nic.family, "bcm4")));
        if (wifiish)
            any_wifi = true;
        else
            any_eth = true;
    }
    ConsoleWriteln("WIRELESS NETWORKS:");
    if (any_wifi)
    {
        const auto wifi = duetos::drivers::net::WirelessStatusRead();
        if (wifi.drivers_online > 0)
        {
            ConsoleWrite("  wireless driver shell online for ");
            WriteU64Dec(wifi.drivers_online);
            ConsoleWrite(" of ");
            WriteU64Dec(wifi.adapters_detected);
            ConsoleWriteln(" adapter(s)");
            ConsoleWrite("  firmware: ready=");
            WriteU64Dec(wifi.firmware_ready);
            ConsoleWrite(" missing=");
            WriteU64Dec(wifi.firmware_missing);
            ConsoleWrite(" incompatible=");
            WriteU64Dec(wifi.firmware_incompatible);
            ConsoleWrite(" load-error=");
            WriteU64Dec(wifi.firmware_load_error);
            ConsoleWriteln("");
            if (wifi.firmware_ready == 0)
            {
                ConsoleWriteln("  cannot scan SSIDs yet: no wireless adapter has a usable firmware blob loaded");
            }
            else
            {
                ConsoleWriteln(
                    "  firmware ready on at least one adapter; 802.11 scan/assoc datapath is still not implemented");
            }
        }
        else
        {
            ConsoleWriteln("  wireless adapter detected, but driver shell did not bind");
            ConsoleWriteln("  (device ID outside iwlwifi / rtl88xx / bcm43xx match tables)");
        }
    }
    else
    {
        ConsoleWriteln("  (no wireless adapter detected)");
    }
    ConsoleWriteln("WIRED NETWORKS:");
    if (!any_eth)
    {
        ConsoleWriteln("  (no wired adapter detected)");
        return;
    }
    for (u64 i = 0; i < nics; ++i)
    {
        const auto& nic = duetos::drivers::net::Nic(i);
        if (nic.subclass == 0x80)
            continue;
        ConsoleWrite("  net");
        WriteU64Dec(i);
        ConsoleWrite("  ");
        ConsoleWrite(nic.vendor);
        if (nic.family != nullptr)
        {
            ConsoleWriteChar(' ');
            ConsoleWrite(nic.family);
        }
        ConsoleWrite("  link=");
        ConsoleWrite(nic.mac_valid && nic.link_up ? "UP " : "DOWN ");
        if (duetos::net::InterfaceIsBound(static_cast<u32>(i)))
        {
            const auto ip = duetos::net::InterfaceIp(static_cast<u32>(i));
            if (!Ipv4IsZero(ip))
            {
                ConsoleWrite(" ip=");
                WriteIpv4(ip);
            }
        }
        ConsoleWriteln("");
    }
}

void CmdWifi(u32 argc, char** argv)
{
    if (argc < 2 || StrEq(argv[1], "status"))
    {
        const auto st = duetos::net::WifiStatusRead(0);
        ConsoleWrite("WIFI: iface0 backend=");
        ConsoleWrite(st.backend_present ? "yes" : "no");
        ConsoleWrite(" connected=");
        ConsoleWrite(st.connected ? "yes" : "no");
        if (st.connected)
        {
            ConsoleWrite(" ssid=\"");
            ConsoleWrite(st.ssid);
            ConsoleWrite("\" security=");
            ConsoleWrite(st.security == duetos::net::WifiSecurity::Wpa2Psk ? "wpa2-psk" : "open");
        }
        ConsoleWriteln("");
        if (!st.backend_present)
            ConsoleWriteln("WIFI: no registered Wi-Fi backend yet");
        return;
    }
    if (StrEq(argv[1], "scan"))
    {
        duetos::net::WifiScanResult results[duetos::net::kWifiMaxScanResults] = {};
        u32 count = 0;
        if (!duetos::net::WifiScan(0, results, duetos::net::kWifiMaxScanResults, &count))
        {
            ConsoleWriteln("WIFI: scan failed (backend unavailable or driver refused)");
            return;
        }
        ConsoleWrite("WIFI: ");
        WriteU64Dec(count);
        ConsoleWriteln(" network(s)");
        for (u32 i = 0; i < count; ++i)
        {
            ConsoleWrite("  ");
            ConsoleWrite(results[i].ssid);
            ConsoleWrite("  ");
            ConsoleWrite(results[i].security == duetos::net::WifiSecurity::Wpa2Psk ? "WPA2" : "OPEN");
            ConsoleWrite("  rssi=");
            WriteI64Dec(results[i].rssi_dbm);
            ConsoleWriteln(" dBm");
        }
        return;
    }
    if (StrEq(argv[1], "connect"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("WIFI: usage: wifi connect <ssid> [psk]");
            return;
        }
        const char* ssid = argv[2];
        const bool has_psk = argc >= 4;
        const auto sec = has_psk ? duetos::net::WifiSecurity::Wpa2Psk : duetos::net::WifiSecurity::Open;
        const char* psk = has_psk ? argv[3] : nullptr;
        if (!duetos::net::WifiConnect(0, ssid, sec, psk))
        {
            ConsoleWriteln("WIFI: connect failed (backend missing, invalid auth, or driver rejected)");
            return;
        }
        ConsoleWriteln("WIFI: associated; requesting DHCP lease ...");
        if (!duetos::net::DhcpStart(0))
        {
            ConsoleWriteln("WIFI: DHCP start failed");
            return;
        }
        duetos::net::DhcpLease lease = {};
        for (u32 i = 0; i < 300; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            lease = duetos::net::DhcpLeaseRead();
            if (lease.valid)
                break;
        }
        if (!lease.valid)
        {
            ConsoleWriteln("WIFI: no DHCP ACK");
            return;
        }
        ConsoleWrite("WIFI: connected ip=");
        WriteIpv4(lease.ip);
        ConsoleWrite(" gw=");
        WriteIpv4(lease.router);
        ConsoleWriteln("");
        return;
    }
    if (StrEq(argv[1], "disconnect"))
    {
        if (!duetos::net::WifiDisconnect(0))
        {
            ConsoleWriteln("WIFI: disconnect failed (backend unavailable or driver refused)");
            return;
        }
        ConsoleWriteln("WIFI: disconnected");
        return;
    }
    ConsoleWriteln("WIFI: usage: wifi <status|scan|connect|disconnect>");
}

void CmdFwPolicy(u32 argc, char** argv)
{
    auto policy_name = [](duetos::core::FwSourcePolicy p) -> const char*
    {
        switch (p)
        {
        case duetos::core::FwSourcePolicy::OpenThenVendor:
            return "open-then-vendor";
        case duetos::core::FwSourcePolicy::OpenOnly:
            return "open-only";
        case duetos::core::FwSourcePolicy::VendorOnly:
            return "vendor-only";
        default:
            return "unknown";
        }
    };

    if (argc < 2 || StrEq(argv[1], "status"))
    {
        const auto s = duetos::core::FwBackendStatsRead();
        ConsoleWrite("FWPOLICY: ");
        ConsoleWrite(policy_name(s.policy));
        ConsoleWrite("  backend=");
        ConsoleWrite(s.kind == duetos::core::FwBackendKind::Vfs ? "vfs" : "none");
        ConsoleWrite("  lookups=");
        WriteU64Dec(s.lookups);
        ConsoleWrite("  hits=");
        WriteU64Dec(s.hits);
        ConsoleWrite("  misses=");
        WriteU64Dec(s.misses);
        ConsoleWriteln("");
        return;
    }

    if (StrEq(argv[1], "open-only"))
    {
        duetos::core::FwSetSourcePolicy(duetos::core::FwSourcePolicy::OpenOnly);
        ConsoleWriteln("FWPOLICY: set to open-only");
        return;
    }
    if (StrEq(argv[1], "vendor-only"))
    {
        duetos::core::FwSetSourcePolicy(duetos::core::FwSourcePolicy::VendorOnly);
        ConsoleWriteln("FWPOLICY: set to vendor-only");
        return;
    }
    if (StrEq(argv[1], "open-then-vendor"))
    {
        duetos::core::FwSetSourcePolicy(duetos::core::FwSourcePolicy::OpenThenVendor);
        ConsoleWriteln("FWPOLICY: set to open-then-vendor");
        return;
    }
    ConsoleWriteln("FWPOLICY: usage: fwpolicy <status|open-only|open-then-vendor|vendor-only>");
}

void CmdFwTrace(u32 argc, char** argv)
{
    if (argc >= 2 && StrEq(argv[1], "clear"))
    {
        duetos::core::FwTraceClear();
        ConsoleWriteln("FWTRACE: cleared");
        return;
    }

    u32 limit = duetos::core::FwTraceCount();
    if (argc >= 3 && StrEq(argv[1], "show"))
    {
        const i64 parsed = ParseInt(argv[2]);
        if (parsed > 0)
            limit = static_cast<u32>(parsed);
    }

    const u32 count = duetos::core::FwTraceCount();
    if (count == 0)
    {
        ConsoleWriteln("FWTRACE: empty");
        return;
    }

    if (limit > count)
        limit = count;
    const u32 start = count - limit;
    ConsoleWrite("FWTRACE: showing ");
    WriteU64Dec(limit);
    ConsoleWrite(" of ");
    WriteU64Dec(count);
    ConsoleWriteln(" entries");
    for (u32 i = start; i < count; ++i)
    {
        duetos::core::FwTraceEntry e{};
        if (!duetos::core::FwTraceRead(i, &e))
            continue;
        ConsoleWrite("  [");
        WriteU64Dec(i);
        ConsoleWrite("] policy=");
        switch (e.policy)
        {
        case duetos::core::FwSourcePolicy::OpenOnly:
            ConsoleWrite("open-only");
            break;
        case duetos::core::FwSourcePolicy::VendorOnly:
            ConsoleWrite("vendor-only");
            break;
        default:
            ConsoleWrite("open-then-vendor");
            break;
        }
        ConsoleWrite(" result=");
        ConsoleWrite(duetos::core::ErrorCodeName(e.result));
        ConsoleWrite(" vendor=\"");
        ConsoleWrite(e.vendor);
        ConsoleWrite("\" base=\"");
        ConsoleWrite(e.basename);
        ConsoleWrite("\" path=\"");
        ConsoleWrite(e.attempted_path);
        ConsoleWriteln("\"");
    }
}

void CmdCrTrace(u32 argc, char** argv)
{
    if (argc >= 2 && StrEq(argv[1], "clear"))
    {
        duetos::core::CleanroomTraceClear();
        ConsoleWriteln("CRTRACE: cleared");
        return;
    }

    u32 limit = duetos::core::CleanroomTraceCount();
    if (argc >= 3 && StrEq(argv[1], "show"))
    {
        const i64 parsed = ParseInt(argv[2]);
        if (parsed > 0)
            limit = static_cast<u32>(parsed);
    }

    const u32 count = duetos::core::CleanroomTraceCount();
    if (count == 0)
    {
        ConsoleWriteln("CRTRACE: empty");
        return;
    }
    if (limit > count)
        limit = count;

    const u32 start = count - limit;
    ConsoleWrite("CRTRACE: showing ");
    WriteU64Dec(limit);
    ConsoleWrite(" of ");
    WriteU64Dec(count);
    ConsoleWriteln(" entries");
    duetos::arch::SerialWrite("\n=== CRTRACE DUMP BEGIN ===\n");
    for (u32 i = start; i < count; ++i)
    {
        duetos::core::CleanroomTraceEntry e{};
        if (!duetos::core::CleanroomTraceRead(i, &e))
            continue;
        ConsoleWrite("  [");
        WriteU64Dec(i);
        ConsoleWrite("] ");
        ConsoleWrite(e.subsystem);
        ConsoleWrite("::");
        ConsoleWrite(e.event);
        ConsoleWrite(" a=");
        WriteU64Hex(e.a);
        ConsoleWrite(" b=");
        WriteU64Hex(e.b);
        ConsoleWrite(" c=");
        WriteU64Hex(e.c);
        ConsoleWriteln("");
        duetos::arch::SerialWrite("CRTRACE [");
        duetos::arch::SerialWriteHex(i);
        duetos::arch::SerialWrite("] ");
        duetos::arch::SerialWrite(e.subsystem);
        duetos::arch::SerialWrite("::");
        duetos::arch::SerialWrite(e.event);
        duetos::core::CleanroomTraceWriteDecoded(e);
        duetos::arch::SerialWrite("\n");
    }
    duetos::arch::SerialWrite("=== CRTRACE DUMP END ===\n");
}

void CmdNet(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("NET: usage: net <up|status|test>");
        return;
    }
    if (StrEq(argv[1], "up"))
    {
        if (!duetos::net::InterfaceIsBound(0))
        {
            ConsoleWriteln("NET UP: iface 0 not bound (no NIC driver?)");
            return;
        }
        auto lease = duetos::net::DhcpLeaseRead();
        if (lease.valid)
        {
            ConsoleWrite("NET UP: already bound  ip=");
            WriteIpv4(lease.ip);
            ConsoleWriteln("");
            return;
        }
        if (!duetos::net::DhcpStart(0))
        {
            ConsoleWriteln("NET UP: DHCP start failed");
            return;
        }
        ConsoleWriteln("NET UP: DHCP DISCOVER sent ...");
        for (u32 i = 0; i < 300; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            lease = duetos::net::DhcpLeaseRead();
            if (lease.valid)
                break;
        }
        if (!lease.valid)
        {
            ConsoleWriteln("NET UP: timeout — no DHCP ACK in 3s");
            return;
        }
        ConsoleWrite("NET UP: bound  ip=");
        WriteIpv4(lease.ip);
        ConsoleWrite("  gw=");
        WriteIpv4(lease.router);
        ConsoleWrite("  dns=");
        WriteIpv4(lease.dns);
        ConsoleWriteln("");
        return;
    }
    if (StrEq(argv[1], "status"))
    {
        const auto lease = duetos::net::DhcpLeaseRead();
        const bool bound = duetos::net::InterfaceIsBound(0);
        ConsoleWrite("NET: iface0=");
        ConsoleWrite(bound ? "UP" : "DOWN");
        ConsoleWrite("  dhcp=");
        ConsoleWrite(lease.valid ? "BOUND" : "PENDING");
        if (lease.valid)
        {
            ConsoleWrite("  ip=");
            WriteIpv4(lease.ip);
            ConsoleWrite("  gw=");
            WriteIpv4(lease.router);
        }
        ConsoleWrite("  arp=");
        WriteU64Dec(duetos::net::ArpEntryCount());
        ConsoleWriteln("");
        return;
    }
    if (StrEq(argv[1], "test"))
    {
        ConsoleWrite("NET TEST: dhcp ... ");
        auto lease = duetos::net::DhcpLeaseRead();
        if (!lease.valid)
        {
            duetos::net::DhcpStart(0);
            for (u32 i = 0; i < 300; ++i)
            {
                duetos::sched::SchedSleepTicks(1);
                lease = duetos::net::DhcpLeaseRead();
                if (lease.valid)
                    break;
            }
        }
        if (!lease.valid)
        {
            ConsoleWriteln("FAIL (no lease)");
            return;
        }
        ConsoleWrite("OK ip=");
        WriteIpv4(lease.ip);
        ConsoleWriteln("");

        ConsoleWrite("NET TEST: gateway ARP ... ");
        const auto* arp = duetos::net::ArpLookup(0, lease.router);
        if (arp == nullptr)
        {
            duetos::net::NetIcmpSendEcho(0, lease.router, 0xBEEF, 1);
            for (u32 i = 0; i < 100; ++i)
            {
                duetos::sched::SchedSleepTicks(1);
                arp = duetos::net::ArpLookup(0, lease.router);
                if (arp != nullptr)
                    break;
            }
        }
        if (arp == nullptr)
        {
            ConsoleWriteln("FAIL (gateway didn't reply to ARP)");
            return;
        }
        ConsoleWrite("OK mac=");
        WriteMac(arp->mac.octets);
        ConsoleWriteln("");

        ConsoleWrite("NET TEST: dns ... ");
        if (!duetos::net::NetDnsQueryA(0, lease.dns, "example.com"))
        {
            ConsoleWriteln("FAIL (send rejected)");
            return;
        }
        duetos::net::DnsResult dr{};
        for (u32 i = 0; i < 300; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            dr = duetos::net::NetDnsResultRead();
            if (dr.resolved)
                break;
        }
        if (!dr.resolved)
        {
            ConsoleWriteln("FAIL (no reply)");
            return;
        }
        ConsoleWrite("OK example.com -> ");
        WriteIpv4(dr.ip);
        ConsoleWriteln("");

        ConsoleWrite("NET TEST: ping gateway ... ");
        duetos::net::NetPingArm(0xCAFE, 1);
        if (!duetos::net::NetIcmpSendEcho(0, lease.router, 0xCAFE, 1))
        {
            ConsoleWriteln("FAIL (send rejected)");
            return;
        }
        duetos::net::PingResult pr{};
        for (u32 i = 0; i < 200; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            pr = duetos::net::NetPingRead();
            if (pr.replied)
                break;
        }
        if (!pr.replied)
        {
            ConsoleWriteln("FAIL (no echo reply)");
            return;
        }
        ConsoleWrite("OK rtt~=");
        WriteU64Dec(pr.rtt_ticks * 10);
        ConsoleWriteln("ms");
        ConsoleWriteln("NET TEST: PASS — DuetOS is online");
        return;
    }
    ConsoleWriteln("NET: usage: net <up|status|test>");
}

void CmdUsbNet(u32 argc, char** argv)
{
    if (argc < 2 || StrEq(argv[1], "status"))
    {
        const auto cdc = duetos::drivers::usb::CdcEcmStatsRead();
        const auto rn = duetos::drivers::usb::RndisStatsRead();
        ConsoleWrite("USBNET: cdc-ecm=");
        ConsoleWrite(cdc.online ? "UP" : "down");
        ConsoleWrite("  rndis=");
        ConsoleWrite(rn.online ? "UP" : "down");
        if (cdc.online)
        {
            ConsoleWrite("  cdc-ecm-mac=");
            WriteMac(cdc.mac);
        }
        if (rn.online)
        {
            ConsoleWrite("  rndis-mac=");
            WriteMac(rn.mac);
        }
        ConsoleWriteln("");
        return;
    }
    if (StrEq(argv[1], "probe"))
    {
        ConsoleWriteln("USBNET: probing CDC-ECM ...");
        const bool cdc_ok = duetos::drivers::usb::CdcEcmProbe();
        if (cdc_ok)
        {
            ConsoleWriteln("USBNET: CDC-ECM bound on iface 1 — DHCP started");
            return;
        }
        ConsoleWriteln("USBNET: no CDC-ECM device. probing RNDIS ...");
        const bool rn_ok = duetos::drivers::usb::RndisProbe();
        if (rn_ok)
        {
            ConsoleWriteln("USBNET: RNDIS bound on iface 1 — DHCP started");
            return;
        }
        ConsoleWriteln("USBNET: no compatible USB-Ethernet device found "
                       "(supported: CDC-ECM, RNDIS — Android tether default)");
        return;
    }
    ConsoleWriteln("USBNET: usage: usbnet <probe|status>");
}

} // namespace duetos::core::shell::internal
