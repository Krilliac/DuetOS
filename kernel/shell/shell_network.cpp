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

#include "shell/shell_internal.h"

#include "arch/x86_64/serial.h"
#include "diag/fix_journal.h"
#include "drivers/net/net.h"
#include "drivers/usb/btusb.h"
#include "drivers/usb/cdc_ecm.h"
#include "drivers/usb/rndis.h"
#include "drivers/video/console.h"
#include "net/bluetooth/diag.h"
#include "net/bluetooth/hid.h"
#include "net/firewall.h"
#include "net/socket.h"
#include "net/stack.h"
#include "net/wifi.h"
#include "net/wireless/inventory.h"
#include "net/wireless/wifi_diag.h"
#include "sched/sched.h"
#include "diag/cleanroom_trace.h"
#include "loader/firmware_loader.h"

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

    const i32 sock = duetos::net::SocketAlloc(duetos::net::kSocketDomainInet, duetos::net::kSocketTypeStream);
    if (sock < 0)
    {
        ConsoleWriteln("HTTP: socket pool exhausted");
        return;
    }
    if (!duetos::net::SocketConnect(static_cast<u32>(sock), dst, port))
    {
        duetos::net::SocketRelease(static_cast<u32>(sock));
        ConsoleWriteln("HTTP: connect failed");
        return;
    }
    ConsoleWrite("HTTP: connecting to ");
    ConsoleWrite(argv[1]);
    ConsoleWriteln(" ...");
    // Send the request.
    {
        u32 sent = 0;
        while (sent < ri)
        {
            const i64 n = duetos::net::SocketSendStream(static_cast<u32>(sock), reinterpret_cast<const u8*>(req) + sent,
                                                        ri - sent);
            if (n <= 0)
                break;
            sent += static_cast<u32>(n);
        }
    }
    duetos::net::SocketShutdown(static_cast<u32>(sock), /*how=*/1); // SHUT_WR -> FIN

    u8 buf[2048];
    u32 total = 0;
    for (u32 round = 0; round < 400 && total < sizeof(buf); ++round)
    {
        const i64 n = duetos::net::SocketRecvStream(static_cast<u32>(sock), buf + total, sizeof(buf) - total);
        if (n == 0)
            break; // peer FIN
        if (n < 0)
            break;
        total += static_cast<u32>(n);
    }
    duetos::net::SocketRelease(static_cast<u32>(sock));
    ConsoleWrite("HTTP: ");
    WriteU64Dec(total);
    ConsoleWriteln(" bytes received");
    u32 lines = 0;
    for (u32 j = 0; j < total && lines < 16; ++j)
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
            ConsoleWrite(" upload-failed=");
            WriteU64Dec(wifi.firmware_upload_failed);
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
    if (argc >= 2 && (StrEq(argv[1], "info") || StrEq(argv[1], "inventory") || StrEq(argv[1], "hw")))
    {
        // Hardware inventory: walk every detected wireless adapter
        // (PCI + USB) and print what firmware basename it needs,
        // where to stage it, and current driver/firmware state.
        // Mirrors the boot-log block emitted by
        // `WirelessInventoryDump` but routed through the console
        // so an operator with a shell session can re-print it on
        // demand without rebooting.
        duetos::net::wireless::WirelessInventoryDump();
        return;
    }
    if (argc >= 2 && StrEq(argv[1], "help"))
    {
        ConsoleWriteln("wifi — Wi-Fi adapter / association / hardware test commands");
        ConsoleWriteln("  wifi                       short for `wifi status`");
        ConsoleWriteln("  wifi status                association state for iface 0");
        ConsoleWriteln("  wifi info                  hardware inventory (every detected adapter +");
        ConsoleWriteln("                             expected firmware basename + stage location)");
        ConsoleWriteln("  wifi scan                  active probe; lists nearby BSSIDs (driver-backed)");
        ConsoleWriteln("  wifi connect <ssid> [psk]  associate + DHCP; psk omitted = open auth");
        ConsoleWriteln("  wifi disconnect            tear down the active association");
        ConsoleWriteln("  wifi capture               dump captured frames from the diagnostic ring");
        ConsoleWriteln("");
        ConsoleWriteln("Hardware-test playbook (real-laptop bring-up):");
        ConsoleWriteln("  1. Boot DuetOS from the ISO; run `wifi info`.");
        ConsoleWriteln("  2. Note each adapter's expected basename + stage directory.");
        ConsoleWriteln("  3. Drop the matching `linux-firmware` blob(s) at the listed paths");
        ConsoleWriteln("     (or wrap with `tools/firmware/mkduetfw.py` and use `.duetfw`).");
        ConsoleWriteln("  4. Reboot; `wifi info` should now show fw=ready for each adapter.");
        ConsoleWriteln("  5. `wifi scan` to enumerate; `wifi connect <ssid> <psk>` to join.");
        return;
    }
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
    if (StrEq(argv[1], "activate") || StrEq(argv[1], "capture"))
    {
        const bool capture = StrEq(argv[1], "capture");
        duetos::core::CleanroomTraceRecord("wifi", capture ? "capture" : "activate", duetos::drivers::net::NicCount(),
                                           duetos::net::wireless::diag::TotalRecorded(), 0);
        if (capture)
            duetos::net::wireless::diag::Clear();

        duetos::drivers::net::NetInit();

        const auto wifi = duetos::drivers::net::WirelessStatusRead();
        ConsoleWrite("WIFI: hardware path activated adapters=");
        WriteU64Dec(wifi.adapters_detected);
        ConsoleWrite(" drivers=");
        WriteU64Dec(wifi.drivers_online);
        ConsoleWrite(" fw-ready=");
        WriteU64Dec(wifi.firmware_ready);
        ConsoleWrite(" missing=");
        WriteU64Dec(wifi.firmware_missing);
        ConsoleWrite(" incompatible=");
        WriteU64Dec(wifi.firmware_incompatible);
        ConsoleWrite(" load-error=");
        WriteU64Dec(wifi.firmware_load_error);
        ConsoleWrite(" upload-failed=");
        WriteU64Dec(wifi.firmware_upload_failed);
        ConsoleWriteln("");

        for (u64 i = 0; i < duetos::drivers::net::NicCount(); ++i)
        {
            if (!duetos::drivers::net::NicIsWireless(i))
                continue;
            const auto& nic = duetos::drivers::net::Nic(i);
            ConsoleWrite("  wifi");
            WriteU64Dec(i);
            ConsoleWrite(" vendor=");
            ConsoleWrite(nic.vendor != nullptr ? nic.vendor : "?");
            ConsoleWrite(" family=");
            ConsoleWrite(nic.family != nullptr ? nic.family : "?");
            ConsoleWrite(" did=");
            WriteU64Hex(nic.device_id);
            ConsoleWrite(" chip=");
            WriteU64Hex(nic.chip_id);
            ConsoleWrite(" online=");
            ConsoleWrite(nic.driver_online ? "yes" : "no");
            ConsoleWriteln("");
        }

        const auto fix = duetos::diag::FixJournalGetStats();
        ConsoleWrite("WIFI: capture rings wifi-diag retained=");
        WriteU64Dec(duetos::net::wireless::diag::EventCount());
        ConsoleWrite(" total=");
        WriteU64Dec(duetos::net::wireless::diag::TotalRecorded());
        ConsoleWrite(" crtrace=");
        WriteU64Dec(duetos::core::CleanroomTraceCount());
        ConsoleWrite(" fix-unique=");
        WriteU64Dec(fix.records_unique);
        ConsoleWrite(" fix-dedup=");
        WriteU64Dec(fix.dedup_hits);
        ConsoleWriteln("");

        if (capture)
        {
            duetos::net::wireless::diag::Dump(64);
            duetos::diag::FixJournalEmitBootSummary();
            ConsoleWriteln("WIFI: captured wifi diag, cleanroom trace counters, and fix-journal summary to serial");
        }
        return;
    }
    if (StrEq(argv[1], "diag"))
    {
        if (argc >= 3 && StrEq(argv[2], "clear"))
        {
            duetos::net::wireless::diag::Clear();
            ConsoleWriteln("WIFI: diag ring cleared");
            return;
        }
        u32 max = 0;
        if (argc >= 3)
        {
            // Optional event count cap. Parse as decimal.
            u32 n = 0;
            for (const char* p = argv[2]; *p != '\0'; ++p)
            {
                if (*p < '0' || *p > '9')
                {
                    n = 0;
                    break;
                }
                n = n * 10u + static_cast<u32>(*p - '0');
            }
            max = n;
        }
        ConsoleWrite("WIFI: dumping diag ring (");
        WriteU64Dec(duetos::net::wireless::diag::EventCount());
        ConsoleWrite(" retained, ");
        WriteU64Dec(duetos::net::wireless::diag::TotalRecorded());
        ConsoleWrite(" total, ");
        WriteU64Dec(duetos::net::wireless::diag::TotalDropped());
        ConsoleWriteln(" dropped) — see serial log");
        duetos::net::wireless::diag::Dump(max);
        return;
    }
    ConsoleWriteln("WIFI: usage: wifi <status|activate|capture|scan|connect|disconnect|diag [N|clear]>");
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
    if (argc >= 2 && StrEq(argv[1], "stats"))
    {
        ConsoleWrite("CRTRACE: boot=");
        WriteU64Dec(duetos::core::CleanroomTraceBootCount());
        ConsoleWrite("/");
        WriteU64Dec(duetos::core::kCleanroomTraceBootCapacity);
        ConsoleWrite("  rolling=");
        WriteU64Dec(duetos::core::CleanroomTraceRollingCount());
        ConsoleWrite("/");
        WriteU64Dec(duetos::core::kCleanroomTraceRollingCapacity);
        ConsoleWrite("  total=");
        WriteU64Dec(duetos::core::CleanroomTraceCount());
        ConsoleWriteln("");
        return;
    }
    if (argc >= 2 && StrEq(argv[1], "mark"))
    {
        if (argc < 4)
        {
            ConsoleWriteln("CRTRACE: USAGE: CRTRACE MARK <SUBSYS> <EVENT> [A [B [C]]]");
            return;
        }
        u64 a = 0;
        u64 b = 0;
        u64 c = 0;
        if (argc >= 5)
            ParseU64Str(argv[4], &a);
        if (argc >= 6)
            ParseU64Str(argv[5], &b);
        if (argc >= 7)
            ParseU64Str(argv[6], &c);
        duetos::core::CleanroomTraceRecord(argv[2], argv[3], a, b, c);
        ConsoleWrite("CRTRACE: marked ");
        ConsoleWrite(argv[2]);
        ConsoleWrite("::");
        ConsoleWriteln(argv[3]);
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

namespace
{

bool ParseFwDirection(const char* s, duetos::net::firewall::Direction* out)
{
    if (StrEq(s, "in") || StrEq(s, "ingress"))
    {
        *out = duetos::net::firewall::Direction::Ingress;
        return true;
    }
    if (StrEq(s, "out") || StrEq(s, "egress"))
    {
        *out = duetos::net::firewall::Direction::Egress;
        return true;
    }
    return false;
}

bool ParseFwProto(const char* s, duetos::net::firewall::Proto* out)
{
    if (StrEq(s, "any"))
    {
        *out = duetos::net::firewall::Proto::Any;
        return true;
    }
    if (StrEq(s, "icmp"))
    {
        *out = duetos::net::firewall::Proto::Icmp;
        return true;
    }
    if (StrEq(s, "tcp"))
    {
        *out = duetos::net::firewall::Proto::Tcp;
        return true;
    }
    if (StrEq(s, "udp"))
    {
        *out = duetos::net::firewall::Proto::Udp;
        return true;
    }
    return false;
}

bool ParseFwAction(const char* s, duetos::net::firewall::Action* out)
{
    if (StrEq(s, "allow"))
    {
        *out = duetos::net::firewall::Action::Allow;
        return true;
    }
    if (StrEq(s, "deny"))
    {
        *out = duetos::net::firewall::Action::Deny;
        return true;
    }
    return false;
}

// Parse "1.2.3.4" or "1.2.3.4/24" — bare addr defaults to /32.
bool ParseFwPrefix(const char* s, duetos::net::firewall::Ipv4Prefix* out)
{
    char addr_buf[32];
    u32 i = 0;
    while (s[i] != '\0' && s[i] != '/' && i < sizeof(addr_buf) - 1)
    {
        addr_buf[i] = s[i];
        ++i;
    }
    addr_buf[i] = '\0';
    if (!ParseIpv4(addr_buf, &out->addr))
    {
        return false;
    }
    if (s[i] == '\0')
    {
        out->mask_bits = 32;
        return true;
    }
    if (s[i] != '/')
    {
        return false;
    }
    const i64 mask = ParseInt(s + i + 1);
    if (mask < 0 || mask > 32)
    {
        return false;
    }
    out->mask_bits = static_cast<u8>(mask);
    return true;
}

// Parse "lo-hi" or bare "n" (== n-n) or "any".
bool ParseFwPortRange(const char* s, duetos::net::firewall::PortRange* out)
{
    if (StrEq(s, "any"))
    {
        out->lo = 0;
        out->hi = 0xFFFF;
        return true;
    }
    char buf[16];
    u32 i = 0;
    while (s[i] != '\0' && s[i] != '-' && i < sizeof(buf) - 1)
    {
        buf[i] = s[i];
        ++i;
    }
    buf[i] = '\0';
    const i64 lo = ParseInt(buf);
    if (lo < 0 || lo > 0xFFFF)
    {
        return false;
    }
    if (s[i] == '\0')
    {
        out->lo = static_cast<u16>(lo);
        out->hi = static_cast<u16>(lo);
        return true;
    }
    const i64 hi = ParseInt(s + i + 1);
    if (hi < lo || hi > 0xFFFF)
    {
        return false;
    }
    out->lo = static_cast<u16>(lo);
    out->hi = static_cast<u16>(hi);
    return true;
}

const char* DirectionLabel(duetos::net::firewall::Direction d)
{
    return d == duetos::net::firewall::Direction::Ingress ? "in " : "out";
}

const char* ProtoLabel(duetos::net::firewall::Proto p)
{
    using duetos::net::firewall::Proto;
    switch (p)
    {
    case Proto::Icmp:
        return "icmp";
    case Proto::Tcp:
        return "tcp ";
    case Proto::Udp:
        return "udp ";
    case Proto::Any:
    default:
        return "any ";
    }
}

void WriteFwPrefix(const duetos::net::firewall::Ipv4Prefix& p)
{
    WriteIpv4(p.addr);
    ConsoleWriteChar('/');
    WriteU64Dec(p.mask_bits);
}

void WriteFwPortRange(const duetos::net::firewall::PortRange& r)
{
    if (r.lo == 0 && r.hi == 0xFFFF)
    {
        ConsoleWrite("any");
        return;
    }
    WriteU64Dec(r.lo);
    if (r.lo != r.hi)
    {
        ConsoleWriteChar('-');
        WriteU64Dec(r.hi);
    }
}

void FirewallList()
{
    duetos::net::firewall::Rule snap[duetos::net::firewall::kFwMaxRules];
    const u32 n = duetos::net::firewall::FwSnapshot(snap, duetos::net::firewall::kFwMaxRules);
    ConsoleWrite("DEFAULT in=");
    ConsoleWrite(duetos::net::firewall::FwDefaultPolicy(duetos::net::firewall::Direction::Ingress) ==
                         duetos::net::firewall::Action::Allow
                     ? "allow"
                     : "deny");
    ConsoleWrite("  out=");
    ConsoleWriteln(duetos::net::firewall::FwDefaultPolicy(duetos::net::firewall::Direction::Egress) ==
                           duetos::net::firewall::Action::Allow
                       ? "allow"
                       : "deny");
    ConsoleWriteln("IDX DIR PROTO SRC                DST                SPORT     DPORT     ACTION HITS");
    bool any = false;
    for (u32 i = 0; i < n; ++i)
    {
        if (!snap[i].active)
        {
            continue;
        }
        any = true;
        WriteU64Dec(i);
        ConsoleWrite("   ");
        ConsoleWrite(DirectionLabel(snap[i].dir));
        ConsoleWriteChar(' ');
        ConsoleWrite(ProtoLabel(snap[i].proto));
        ConsoleWriteChar(' ');
        WriteFwPrefix(snap[i].src);
        ConsoleWrite("        ");
        WriteFwPrefix(snap[i].dst);
        ConsoleWriteChar(' ');
        WriteFwPortRange(snap[i].src_port);
        ConsoleWrite("    ");
        WriteFwPortRange(snap[i].dst_port);
        ConsoleWrite("    ");
        ConsoleWrite(snap[i].action == duetos::net::firewall::Action::Allow ? "allow" : "deny ");
        ConsoleWriteChar(' ');
        WriteU64Dec(snap[i].hits);
        ConsoleWriteln("");
    }
    if (!any)
    {
        ConsoleWriteln("(no active rules — only defaults apply)");
    }
}

void FirewallStats()
{
    const auto s = duetos::net::firewall::FwStatsRead();
    ConsoleWrite("FIREWALL: in checked=");
    WriteU64Dec(s.ingress_checked);
    ConsoleWrite(" denied=");
    WriteU64Dec(s.ingress_denied);
    ConsoleWrite("  out checked=");
    WriteU64Dec(s.egress_checked);
    ConsoleWrite(" denied=");
    WriteU64Dec(s.egress_denied);
    ConsoleWriteln("");
    ConsoleWrite("CONNTRACK: inserts=");
    WriteU64Dec(s.conntrack_inserts);
    ConsoleWrite(" hits=");
    WriteU64Dec(s.conntrack_hits);
    ConsoleWrite(" evictions=");
    WriteU64Dec(s.conntrack_evictions);
    ConsoleWriteln("");
}

void FirewallLog()
{
    duetos::net::firewall::DenialRecord rec[duetos::net::firewall::kFwLogCap];
    const u32 n = duetos::net::firewall::FwLogSnapshot(rec, duetos::net::firewall::kFwLogCap);
    if (n == 0)
    {
        ConsoleWrite("FIREWALL: no denials recorded (total=");
        WriteU64Dec(duetos::net::firewall::FwLogTotalCount());
        ConsoleWriteln(")");
        return;
    }
    ConsoleWrite("FIREWALL: ");
    WriteU64Dec(n);
    ConsoleWrite(" of ");
    WriteU64Dec(duetos::net::firewall::FwLogTotalCount());
    ConsoleWriteln(" recent denials (oldest first):");
    ConsoleWriteln("SEQ      TICK       DIR PROTO SRC                    DST                    RULE");
    for (u32 i = 0; i < n; ++i)
    {
        const auto& r = rec[i];
        WriteU64Dec(r.sequence);
        ConsoleWrite("  ");
        WriteU64Dec(r.ticks);
        ConsoleWrite("  ");
        ConsoleWrite(DirectionLabel(r.dir));
        ConsoleWriteChar(' ');
        ConsoleWrite(ProtoLabel(r.proto));
        ConsoleWriteChar(' ');
        WriteIpv4(r.src_ip);
        ConsoleWriteChar(':');
        WriteU64Dec(r.src_port);
        ConsoleWrite("    ");
        WriteIpv4(r.dst_ip);
        ConsoleWriteChar(':');
        WriteU64Dec(r.dst_port);
        ConsoleWrite("    ");
        if (r.matched_rule == duetos::net::firewall::kFwMaxRules)
        {
            ConsoleWrite("default");
        }
        else
        {
            WriteU64Dec(r.matched_rule);
        }
        ConsoleWriteln("");
    }
}

void FirewallConntrack()
{
    duetos::net::firewall::ConntrackEntry entries[duetos::net::firewall::kConntrackCap];
    const u32 n = duetos::net::firewall::ConntrackSnapshot(entries, duetos::net::firewall::kConntrackCap);
    if (n == 0)
    {
        ConsoleWriteln("FIREWALL: no active conntrack entries");
        return;
    }
    ConsoleWrite("FIREWALL: ");
    WriteU64Dec(n);
    ConsoleWriteln(" active conntrack entries:");
    ConsoleWriteln("PROTO LOCAL                  PEER                   EXPIRY-TICK");
    for (u32 i = 0; i < n; ++i)
    {
        const auto& e = entries[i];
        ConsoleWrite(ProtoLabel(e.proto));
        ConsoleWriteChar(' ');
        WriteIpv4(e.local_ip);
        ConsoleWriteChar(':');
        WriteU64Dec(e.local_port);
        ConsoleWrite("    ");
        WriteIpv4(e.peer_ip);
        ConsoleWriteChar(':');
        WriteU64Dec(e.peer_port);
        ConsoleWrite("    ");
        WriteU64Dec(e.expiry_ticks);
        ConsoleWriteln("");
    }
}

void FirewallUsage()
{
    ConsoleWriteln("FIREWALL: usage:");
    ConsoleWriteln("  firewall list");
    ConsoleWriteln("  firewall stats");
    ConsoleWriteln("  firewall log");
    ConsoleWriteln("  firewall conntrack");
    ConsoleWriteln("  firewall add <in|out> <any|tcp|udp|icmp> <src/mask> <dst/mask> "
                   "<sport|sport-range|any> <dport|dport-range|any> <allow|deny>");
    ConsoleWriteln("  firewall del <idx>");
    ConsoleWriteln("  firewall toggle <idx>");
    ConsoleWriteln("  firewall default <in|out> <allow|deny>");
    ConsoleWriteln("  firewall reset");
}

} // namespace

void CmdFirewall(u32 argc, char** argv)
{
    if (argc < 2 || StrEq(argv[1], "list") || StrEq(argv[1], "ls"))
    {
        FirewallList();
        return;
    }
    if (StrEq(argv[1], "stats"))
    {
        FirewallStats();
        return;
    }
    if (StrEq(argv[1], "log"))
    {
        FirewallLog();
        return;
    }
    if (StrEq(argv[1], "conntrack") || StrEq(argv[1], "ct"))
    {
        FirewallConntrack();
        return;
    }
    if (StrEq(argv[1], "reset"))
    {
        duetos::net::firewall::FwInit();
        ConsoleWriteln("FIREWALL: rule table reset; defaults=allow/allow");
        return;
    }
    if (StrEq(argv[1], "default"))
    {
        if (argc < 4)
        {
            FirewallUsage();
            return;
        }
        duetos::net::firewall::Direction dir;
        duetos::net::firewall::Action act;
        if (!ParseFwDirection(argv[2], &dir) || !ParseFwAction(argv[3], &act))
        {
            FirewallUsage();
            return;
        }
        duetos::net::firewall::FwSetDefaultPolicy(dir, act);
        ConsoleWrite("FIREWALL: default ");
        ConsoleWrite(DirectionLabel(dir));
        ConsoleWrite(" set to ");
        ConsoleWriteln(act == duetos::net::firewall::Action::Allow ? "allow" : "deny");
        return;
    }
    if (StrEq(argv[1], "del") || StrEq(argv[1], "remove"))
    {
        if (argc < 3)
        {
            FirewallUsage();
            return;
        }
        const i64 idx = ParseInt(argv[2]);
        if (idx < 0 || idx >= static_cast<i64>(duetos::net::firewall::kFwMaxRules))
        {
            ConsoleWriteln("FIREWALL: index out of range");
            return;
        }
        duetos::net::firewall::FwRemove(static_cast<u32>(idx));
        ConsoleWriteln("FIREWALL: rule removed");
        return;
    }
    if (StrEq(argv[1], "toggle"))
    {
        if (argc < 3)
        {
            FirewallUsage();
            return;
        }
        const i64 idx = ParseInt(argv[2]);
        if (idx < 0 || idx >= static_cast<i64>(duetos::net::firewall::kFwMaxRules))
        {
            ConsoleWriteln("FIREWALL: index out of range");
            return;
        }
        duetos::net::firewall::FwToggle(static_cast<u32>(idx));
        ConsoleWriteln("FIREWALL: rule toggled");
        return;
    }
    if (StrEq(argv[1], "add"))
    {
        if (argc < 9)
        {
            FirewallUsage();
            return;
        }
        duetos::net::firewall::Rule r{};
        if (!ParseFwDirection(argv[2], &r.dir))
        {
            ConsoleWriteln("FIREWALL: bad direction (expected in / out)");
            return;
        }
        if (!ParseFwProto(argv[3], &r.proto))
        {
            ConsoleWriteln("FIREWALL: bad protocol (expected any / tcp / udp / icmp)");
            return;
        }
        if (!ParseFwPrefix(argv[4], &r.src))
        {
            ConsoleWriteln("FIREWALL: bad src prefix");
            return;
        }
        if (!ParseFwPrefix(argv[5], &r.dst))
        {
            ConsoleWriteln("FIREWALL: bad dst prefix");
            return;
        }
        if (!ParseFwPortRange(argv[6], &r.src_port))
        {
            ConsoleWriteln("FIREWALL: bad src port range");
            return;
        }
        if (!ParseFwPortRange(argv[7], &r.dst_port))
        {
            ConsoleWriteln("FIREWALL: bad dst port range");
            return;
        }
        if (!ParseFwAction(argv[8], &r.action))
        {
            ConsoleWriteln("FIREWALL: bad action (expected allow / deny)");
            return;
        }
        const u32 idx = duetos::net::firewall::FwAdd(r);
        if (idx >= duetos::net::firewall::kFwMaxRules)
        {
            ConsoleWriteln("FIREWALL: rule table full");
            return;
        }
        ConsoleWrite("FIREWALL: rule added at index ");
        WriteU64Dec(idx);
        ConsoleWriteln("");
        return;
    }
    FirewallUsage();
}

namespace
{

void WriteHexU8(u8 v)
{
    auto nibble = [](u8 n) -> char { return static_cast<char>(n < 10 ? '0' + n : 'a' + (n - 10)); };
    char buf[3] = {nibble(u8((v >> 4) & 0xF)), nibble(u8(v & 0xF)), '\0'};
    ConsoleWrite(buf);
}

void WriteBdAddr(const u8 bd[6])
{
    // BD_ADDR is little-endian on the wire; render the canonical
    // human form (high-byte-first colon-separated).
    for (i32 i = 5; i >= 0; --i)
    {
        WriteHexU8(bd[i]);
        if (i > 0)
            ConsoleWriteChar(':');
    }
}

void WriteHexU16(u16 v)
{
    WriteHexU8(u8((v >> 8) & 0xFF));
    WriteHexU8(u8(v & 0xFF));
}

const char* BtHidKindName(duetos::net::bluetooth::BtHidKind k)
{
    switch (k)
    {
    case duetos::net::bluetooth::BtHidKind::LeHogp:
        return "le-hogp";
    case duetos::net::bluetooth::BtHidKind::Classic:
        return "classic-hidp";
    case duetos::net::bluetooth::BtHidKind::None:
        break;
    }
    return "?";
}

void BtPrintBtusb()
{
    const auto s = duetos::drivers::usb::BtusbStatsRead();
    ConsoleWrite("  btusb transport: ");
    if (!s.online)
    {
        ConsoleWriteln("offline (run `bt probe`)");
        return;
    }
    ConsoleWrite("online slot=");
    WriteHexU16(s.slot_id);
    ConsoleWrite(" acl_in=");
    WriteHexU16(s.acl_in_ep);
    ConsoleWrite(" acl_out=");
    WriteHexU16(s.acl_out_ep);
    ConsoleWrite(" evt_in=");
    WriteHexU16(s.event_in_ep);
    ConsoleWriteln("");
    ConsoleWrite("    acl rx pkts=");
    WriteU64Dec(s.acl_packets_rx);
    ConsoleWrite(" bytes=");
    WriteU64Dec(s.acl_bytes_rx);
    ConsoleWrite(" short_drops=");
    WriteU64Dec(s.acl_short_drops);
    ConsoleWrite(" hci_cmds=");
    WriteU64Dec(s.hci_cmds_sent);
    ConsoleWrite(" acl tx pkts=");
    WriteU64Dec(s.acl_packets_tx);
    ConsoleWriteln("");
}

void BtPrintHidKeyboards()
{
    const u32 hid = duetos::net::bluetooth::BtHidConnectionCount();
    ConsoleWrite("  HID keyboards: ");
    WriteU64Dec(hid);
    if (hid == 0)
    {
        ConsoleWriteln(" (none connected)");
        return;
    }
    ConsoleWriteln("");
    for (u32 i = 0; i < duetos::net::bluetooth::kBtHidMaxConnections; ++i)
    {
        const auto c = duetos::net::bluetooth::BtHidConnectionAt(i);
        if (!c.live)
            continue;
        ConsoleWrite("    acl=");
        WriteHexU16(c.acl_handle);
        ConsoleWrite(" kind=");
        ConsoleWrite(BtHidKindName(c.kind));
        ConsoleWrite((c.kind == duetos::net::bluetooth::BtHidKind::Classic) ? " int_cid=" : " rpt_handle=");
        WriteHexU16(c.match_id);
        ConsoleWrite(" reports=");
        WriteU64Dec(c.reports_seen);
        ConsoleWriteln("");
    }
}

} // namespace

void CmdBt(u32 argc, char** argv)
{
    if (argc >= 2 && StrEq(argv[1], "probe"))
    {
        ConsoleWriteln("BT: probing for a USB Bluetooth controller...");
        const bool ok = duetos::drivers::usb::BtusbProbe();
        ConsoleWrite("BT: btusb probe ");
        ConsoleWriteln(ok ? "online (ACL RX pump started)" : "no controller found / bring-up failed");
        return;
    }

    const u32 count = duetos::net::bluetooth::BluetoothDiagAdapterCount();
    const bool show_events = (argc >= 2 && StrEq(argv[1], "events"));

    if (count == 0)
    {
        ConsoleWriteln("BT: no Bluetooth adapter registered");
        ConsoleWriteln("    (USB Bluetooth: declare class=0xE0/sub=0x01/prog=0x01)");
        ConsoleWriteln("    (run `bt probe` to bring up an attached USB Bluetooth controller)");
        BtPrintBtusb();
        BtPrintHidKeyboards();
        return;
    }

    ConsoleWrite("BT: ");
    WriteU64Dec(count);
    ConsoleWriteln(" adapter(s)");

    for (u32 i = 0; i < duetos::net::bluetooth::kBluetoothMaxAdapters; ++i)
    {
        const auto& a = duetos::net::bluetooth::BluetoothDiagAdapter(i);
        if (!a.live)
            continue;
        ConsoleWrite("  [");
        WriteU64Dec(i);
        ConsoleWrite("] transport=");
        ConsoleWrite(duetos::net::bluetooth::BluetoothTransportName(a.transport));
        ConsoleWrite(" name=\"");
        ConsoleWrite(a.name);
        ConsoleWrite("\" mfr=");
        WriteHexU16(a.manufacturer_id);
        ConsoleWrite(" hci=");
        WriteHexU8(a.hci_version);
        ConsoleWrite(" lmp=");
        WriteHexU8(a.lmp_version);
        ConsoleWrite(" bdaddr=");
        if (a.bd_addr_valid)
            WriteBdAddr(a.bd_addr);
        else
            ConsoleWrite("?");
        ConsoleWriteln("");
        ConsoleWrite("       events=");
        WriteU64Dec(a.events_seen);
        ConsoleWrite(" cc=");
        WriteU64Dec(a.cmd_complete_seen);
        ConsoleWrite(" cs=");
        WriteU64Dec(a.cmd_status_seen);
        ConsoleWrite(" disc=");
        WriteU64Dec(a.disconnection_seen);
        ConsoleWrite(" le=");
        WriteU64Dec(a.le_meta_seen);
        ConsoleWrite(" unknown=");
        WriteU64Dec(a.unknown_seen);
        ConsoleWrite(" overflow=");
        WriteU64Dec(a.ring_overflows);
        ConsoleWriteln("");

        if (show_events)
        {
            const u32 fill = duetos::net::bluetooth::BluetoothDiagEventRingFill(i);
            ConsoleWrite("       events ring (");
            WriteU64Dec(fill);
            ConsoleWriteln("):");
            for (u32 e = 0; e < fill; ++e)
            {
                const auto& r = duetos::net::bluetooth::BluetoothDiagEventRingAt(i, e);
                ConsoleWrite("         seq=");
                WriteU64Dec(r.sequence);
                ConsoleWrite(" code=");
                WriteHexU8(r.event_code);
                ConsoleWrite(" plen=");
                WriteU64Dec(r.parameter_total_length);
                if (r.command_opcode != 0)
                {
                    ConsoleWrite(" opcode=");
                    WriteHexU16(r.command_opcode);
                }
                if (r.le_subevent != 0)
                {
                    ConsoleWrite(" le_sub=");
                    WriteHexU8(r.le_subevent);
                }
                if (r.event_code == duetos::net::bluetooth::kEvtCommandStatus)
                {
                    ConsoleWrite(" status=");
                    WriteHexU8(r.status);
                }
                ConsoleWriteln("");
            }
        }
    }

    BtPrintBtusb();
    BtPrintHidKeyboards();

    if (!show_events)
        ConsoleWriteln("  (try `bt events` to dump per-adapter event ring, `bt probe` to bring up btusb)");
}

} // namespace duetos::core::shell::internal
