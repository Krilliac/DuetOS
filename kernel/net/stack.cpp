/*
 * DuetOS — TCP/IP stack: implementation.
 *
 * Companion to stack.h — see there for the public socket-style
 * API (open / connect / send / recv / close) and the per-
 * connection state record.
 *
 * WHAT
 *   In-kernel implementation of Ethernet -> ARP -> IPv4 -> ICMP,
 *   UDP, and TCP. Receives packets from the driver layer
 *   (drivers/net/net.cpp), parses headers, demultiplexes by
 *   protocol + (saddr, sport, daddr, dport) tuple, and feeds
 *   the per-connection state machine.
 *
 * HOW
 *   Single big RX path: `NetStackInputPacket` walks Ethernet,
 *   IPv4, then per-protocol. TCP gets its own state machine
 *   (closed / syn-sent / established / fin-wait / ...) with
 *   one block per state in the dispatch switch. ARP cache,
 *   route table, and the connection table are flat arrays at
 *   v0 — the count is small enough that linear scan is faster
 *   than building hashes.
 *
 *   DHCP client + DNS resolver live here too; both are short
 *   state machines driven by the same RX path.
 *
 * WHY THIS FILE IS LARGE
 *   Each protocol's full RX + TX path lives here. TCP alone is
 *   ~600 lines (the state machine + retransmission timer +
 *   sequence-space bookkeeping). Splitting per-protocol is on
 *   the table once a per-protocol unit-test scaffold exists;
 *   for now they share helper functions and stay together.
 */

#include "net/stack.h"
#include "net/firewall.h"
#include "net/socket.h"
#include "net/tcp.h"
#include "net/wifi.h"
#include "parsers_rust.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "time/tick.h"
#include "log/klog.h"
#include "core/panic.h"
#include "drivers/net/net.h"
#include "sched/sched.h"
#include "util/string.h"

namespace duetos::net
{

namespace
{

u64 g_interface_count = 0;

// ARP cache storage. Hash-bucketed lookup — entries are threaded
// through `g_arp_hash_heads` chains keyed on (iface_index, ip).
// 32 entries with 64 buckets keeps the average chain length under 1.
ArpEntry g_arp_cache[kArpCacheCap] = {};
// Bucket head indices into `g_arp_cache`; `kArpEntryNone` (0xFF)
// terminates a chain. Initialised to all-empty in NetStackInit
// — zero-init would alias to "head is entry 0", which is a bug.
u8 g_arp_hash_heads[kArpHashSize] = {};
ArpStats g_arp_stats = {};
Ipv4Stats g_ipv4_stats = {};
IcmpStats g_icmp_stats = {};

// Ping state — single-outstanding in v0. NetPingArm captures the
// id/seq + send tick; the ICMP path in Ipv4HandleIncoming stamps
// the reply tick + flips g_ping_replied when a matching reply
// lands.
constinit bool g_ping_pending = false;
constinit bool g_ping_replied = false;
constinit u16 g_ping_id = 0;
constinit u16 g_ping_seq = 0;
constinit u64 g_ping_send_ticks = 0;
constinit u64 g_ping_reply_ticks = 0;
constinit Ipv4Address g_ping_reply_ip = {};

// Per-interface binding populated by NetStackBindInterface.
// Keyed by iface_index; cap matches kMaxNics so every discovered
// NIC has a slot. Zero-valued `tx` marks an unbound slot —
// InjectRx will log but not respond.
constexpr u32 kMaxInterfaces = 4;
struct Interface
{
    bool bound;
    MacAddress mac;
    Ipv4Address ip;
    NetTxFn tx;
    IfaceCounters counters;
};
Interface g_interfaces[kMaxInterfaces] = {};

// Map an IP protocol number to the firewall's enum. Anything we
// don't recognise is treated as Any so a rule that targets only
// TCP / UDP / ICMP doesn't accidentally match an unknown proto.
firewall::Proto ToFwProto(u8 ip_proto)
{
    switch (ip_proto)
    {
    case 1:
        return firewall::Proto::Icmp;
    case 6:
        return firewall::Proto::Tcp;
    case 17:
        return firewall::Proto::Udp;
    default:
        return firewall::Proto::Any;
    }
}

// Egress helper: parse the ethernet+IPv4 header out of a frame
// already laid down by the per-protocol senders, run the firewall
// check, bump per-iface counters on accept, and forward to the
// driver's bound TX trampoline. Mirrors the rx side for symmetry —
// every TX site that previously called `ifc.tx` directly now goes
// through here so the firewall and counters can't be bypassed.
bool IfaceTx(u32 iface_index, const void* frame, u64 frame_len)
{
    if (iface_index >= kMaxInterfaces)
    {
        return false;
    }
    Interface& ifc = g_interfaces[iface_index];
    if (!ifc.bound || ifc.tx == nullptr)
    {
        ++ifc.counters.tx_dropped_unbound;
        return false;
    }
    if (frame == nullptr || frame_len < 14)
    {
        return false;
    }

    const auto* eth = static_cast<const u8*>(frame);
    const u16 ether_type = (u16(eth[12]) << 8) | u16(eth[13]);
    // Only IPv4 traffic flows through the firewall in v0. ARP /
    // other ethertypes pass straight through; ARP is the L2
    // discovery mechanism the firewall depends on, denying it
    // would break every IPv4 path.
    if (ether_type == kEtherTypeIpv4 && frame_len >= 14 + 20)
    {
        const u8* ip = eth + 14;
        Ipv4Address src_ip = {};
        Ipv4Address dst_ip = {};
        for (u64 i = 0; i < 4; ++i)
        {
            src_ip.octets[i] = ip[12 + i];
            dst_ip.octets[i] = ip[16 + i];
        }
        const firewall::Proto proto = ToFwProto(ip[9]);
        const u8 ihl = ip[0] & 0x0F;
        u16 src_port = 0;
        u16 dst_port = 0;
        u8 tcp_flags = 0;
        if ((proto == firewall::Proto::Tcp || proto == firewall::Proto::Udp) && frame_len >= 14 + u64(ihl) * 4 + 4)
        {
            const u8* l4 = ip + u64(ihl) * 4;
            src_port = (u16(l4[0]) << 8) | u16(l4[1]);
            dst_port = (u16(l4[2]) << 8) | u16(l4[3]);
            // TCP flags byte sits at offset 13 of the TCP
            // header. UDP has no flags so leave tcp_flags=0.
            if (proto == firewall::Proto::Tcp && frame_len >= 14 + u64(ihl) * 4 + 14)
            {
                tcp_flags = l4[13];
            }
        }
        const firewall::Action verdict = firewall::FwEvaluate(firewall::Direction::Egress, proto, src_ip, dst_ip,
                                                              src_port, dst_port, tcp_flags, nullptr);
        if (verdict == firewall::Action::Deny)
        {
            ++ifc.counters.tx_dropped_firewall;
            return false;
        }
    }

    if (!ifc.tx(iface_index, frame, frame_len))
    {
        return false;
    }
    ++ifc.counters.tx_packets;
    ifc.counters.tx_bytes += frame_len;
    return true;
}

// UDP bindings. Fixed-cap table; v0 has a small number of ports
// (DHCP=68, DNS resolver later, custom apps); linear scan is
// fast enough.
struct UdpBinding
{
    bool in_use;
    u16 port;
    UdpRxFn handler;
};
UdpBinding g_udp_bindings[kUdpBindingsMax] = {};
UdpStats g_udp_stats = {};

// DHCP client state. Single-interface in v0 — one transaction at
// a time across the whole stack. Tracks which interface owns the
// in-flight exchange so a stray OFFER/ACK for a different iface
// (not expected today, but cheap to guard) gets dropped.
struct DhcpState
{
    enum class Stage : u8
    {
        Idle = 0,
        Discovered,
        Acked,
    };
    Stage stage;
    u32 iface_index;
    u32 xid;
    Ipv4Address offered_ip;
    Ipv4Address server_ip;
    MacAddress server_mac;
    DhcpLease lease;
};
DhcpState g_dhcp = {};

bool IpEq(Ipv4Address a, Ipv4Address b)
{
    for (u64 i = 0; i < 4; ++i)
        if (a.octets[i] != b.octets[i])
            return false;
    return true;
}

u64 NowTicks()
{
    return ::duetos::time::TickCount();
}

bool IsZeroIp(Ipv4Address ip)
{
    return ip.octets[0] == 0 && ip.octets[1] == 0 && ip.octets[2] == 0 && ip.octets[3] == 0;
}

bool SendArpRequest(u32 iface_index, Ipv4Address target_ip)
{
    if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound)
        return false;
    const Interface& ifc = g_interfaces[iface_index];
    if (ifc.tx == nullptr || IsZeroIp(ifc.ip))
    {
        ++g_arp_stats.tx_failures;
        return false;
    }

    u8 req[42] = {};
    memset(req, 0xFF, 6); // Ethernet broadcast dst
    memcpy(req + 6, ifc.mac.octets, 6);
    req[12] = 0x08;
    req[13] = 0x06; // ARP
    req[14] = 0x00;
    req[15] = 0x01; // Ethernet
    req[16] = 0x08;
    req[17] = 0x00; // IPv4
    req[18] = 0x06;
    req[19] = 0x04;
    req[20] = 0x00;
    req[21] = 0x01; // request
    memcpy(req + 22, ifc.mac.octets, 6);
    memcpy(req + 28, ifc.ip.octets, 4);
    memcpy(req + 38, target_ip.octets, 4);

    ++g_arp_stats.tx_requests;
    const bool ok = IfaceTx(iface_index, req, sizeof(req));
    if (!ok)
        ++g_arp_stats.tx_failures;
    return ok;
}

const ArpEntry* ArpResolveWithWait(u32 iface_index, Ipv4Address ip, u64 per_try_timeout_ticks, u32 max_tries)
{
    const ArpEntry* hit = ArpLookup(iface_index, ip);
    if (hit != nullptr)
        return hit;

    if (max_tries == 0)
        return nullptr;

    for (u32 attempt = 0; attempt < max_tries; ++attempt)
    {
        if (!SendArpRequest(iface_index, ip))
            return nullptr;

        const u64 start = NowTicks();
        while ((NowTicks() - start) < per_try_timeout_ticks)
        {
            duetos::sched::SchedSleepTicks(1);
            hit = ArpLookup(iface_index, ip);
            if (hit != nullptr)
                return hit;
        }
    }
    return nullptr;
}

const ArpEntry* ResolveL2Destination(u32 iface_index, Ipv4Address target_ip)
{
    const DhcpLease lease = DhcpLeaseRead();
    const Ipv4Address fallback_gw =
        lease.valid ? lease.router : Ipv4Address{{target_ip.octets[0], target_ip.octets[1], target_ip.octets[2], 2}};

    // First try direct destination resolution.
    const ArpEntry* dst = ArpResolveWithWait(iface_index, target_ip, /*per_try_timeout_ticks=*/10, /*max_tries=*/3);
    if (dst != nullptr)
        return dst;
    // Then try resolving the DHCP/default gateway.
    return ArpResolveWithWait(iface_index, fallback_gw, /*per_try_timeout_ticks=*/10, /*max_tries=*/3);
}

} // namespace

// Forward decls for UDP + DHCP + TCP helpers defined further down
// in the duetos::net namespace. Must sit OUTSIDE the anonymous
// namespace above or they'd name different functions than the
// ones at duetos::net scope.
void NetUdpDispatch(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len);
void DhcpOnUdp(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len);
// TCP RX dispatch lives in net/tcp.cpp now; the v0 single-slot
// state machine that used to be here is gone. Keep the forward
// reference to the public hook for the Ipv4HandleIncoming caller.

void NetStackInit()
{
    KLOG_TRACE_SCOPE("net/stack", "NetStackInit");
    static constinit bool s_done = false;
    KASSERT(!s_done, "net/stack", "NetStackInit called twice");
    s_done = true;

    // Mark every ARP hash bucket empty. Zero-init would make every
    // bucket "point at entry 0" which is the wrong invariant — a
    // freshly-empty bucket must signal end-of-chain to ArpLookup.
    for (u32 i = 0; i < kArpHashSize; ++i)
    {
        g_arp_hash_heads[i] = kArpEntryNone;
    }
    for (u32 i = 0; i < kArpCacheCap; ++i)
    {
        g_arp_cache[i].next_idx = kArpEntryNone;
    }

    WifiInit();
    firewall::FwInit();
    tcp::Init();

    // Walk the driver-layer NIC table. Today we just log a
    // one-line-per-interface "would bind" record — there's no
    // real TX/RX yet. The binding will be symmetric: each
    // `drivers::net::NicInfo` gets one entry in an internal
    // interface table keyed by (bus, device, function).
    const u64 n = drivers::net::NicCount();
    for (u64 i = 0; i < n; ++i)
    {
        const drivers::net::NicInfo& nic = drivers::net::Nic(i);
        arch::SerialWrite("[net-stack] would bind iface ");
        arch::SerialWriteHex(i);
        arch::SerialWrite(" to nic ");
        arch::SerialWriteHex(nic.bus);
        arch::SerialWrite(":");
        arch::SerialWriteHex(nic.device);
        arch::SerialWrite(".");
        arch::SerialWriteHex(nic.function);
        arch::SerialWrite(" (");
        arch::SerialWrite(nic.vendor);
        if (nic.family != nullptr)
        {
            arch::SerialWrite(" ");
            arch::SerialWrite(nic.family);
        }
        arch::SerialWrite(")\n");
        ++g_interface_count;
    }

    core::LogWithValue(core::LogLevel::Info, "net/stack", "interfaces registered", g_interface_count);
    if (g_interface_count == 0)
    {
        core::Log(core::LogLevel::Warn, "net/stack", "no NICs to bind — stack is up but silent");
    }
    else
    {
        core::Log(core::LogLevel::Warn, "net/stack", "stack bound but no packet I/O yet (skeleton slice)");
    }

    // Self-test the ARP cache by hand-building an ARP reply
    // and feeding it through ArpHandleIncoming. Proves the
    // skeleton path is wired end-to-end even before a real
    // NIC driver feeds us RX'd bytes.
    // Layout: 14-byte Ethernet header + 28-byte ARP payload.
    // ARP reply: HTYPE=1, PTYPE=0x0800, HLEN=6, PLEN=4, OPER=2,
    // SHA = 52:54:00:12:34:56, SPA = 10.0.2.2, THA=zeros, TPA=0.0.0.0.
    {
        u8 frame[42] = {};
        // Ethernet header (dst / src / ether_type=ARP 0x0806).
        frame[0] = 0xFF;
        frame[1] = 0xFF;
        frame[2] = 0xFF;
        frame[3] = 0xFF;
        frame[4] = 0xFF;
        frame[5] = 0xFF;
        frame[6] = 0x52;
        frame[7] = 0x54;
        frame[8] = 0x00;
        frame[9] = 0x12;
        frame[10] = 0x34;
        frame[11] = 0x56;
        frame[12] = 0x08;
        frame[13] = 0x06;
        // ARP payload.
        frame[14] = 0x00;
        frame[15] = 0x01; // HTYPE = Ethernet
        frame[16] = 0x08;
        frame[17] = 0x00; // PTYPE = IPv4
        frame[18] = 6;    // HLEN
        frame[19] = 4;    // PLEN
        frame[20] = 0x00;
        frame[21] = 0x02; // OPER = reply
        // SHA
        frame[22] = 0x52;
        frame[23] = 0x54;
        frame[24] = 0x00;
        frame[25] = 0x12;
        frame[26] = 0x34;
        frame[27] = 0x56;
        // SPA = 10.0.2.2 (QEMU default gateway)
        frame[28] = 10;
        frame[29] = 0;
        frame[30] = 2;
        frame[31] = 2;
        // THA + TPA left zero.
        const u32 iface = 0;
        const bool inserted = ArpHandleIncoming(iface, frame, sizeof(frame));
        if (inserted)
        {
            Ipv4Address gw = {{10, 0, 2, 2}};
            const ArpEntry* e = ArpLookup(iface, gw);
            if (e != nullptr)
            {
                arch::SerialWrite("[arp] self-test OK — cached 10.0.2.2 -> ");
                for (u64 i = 0; i < 6; ++i)
                {
                    if (i != 0)
                        arch::SerialWrite(":");
                    arch::SerialWriteHex(e->mac.octets[i]);
                }
                arch::SerialWrite("\n");
            }
            else
            {
                core::Log(core::LogLevel::Warn, "net/arp", "self-test: insert OK but lookup missed");
            }
        }
        else
        {
            core::Log(core::LogLevel::Warn, "net/arp", "self-test: synthetic ARP reply rejected");
        }
    }

    // IPv4 self-test. Build a minimal Ethernet + IPv4 frame
    // carrying a 0-byte UDP payload and run it through
    // Ipv4HandleIncoming. The checksum is computed
    // programmatically so the test doesn't bake in magic
    // numbers.
    {
        const u64 baseline_rx_udp = Ipv4StatsRead().rx_udp;
        u8 frame[14 + 20 + 8] = {}; // eth + ip + udp
        // Ethernet.
        memset(frame, 0xFF, 6); // dst = bcast
        frame[6] = 0x52;
        frame[7] = 0x54;
        frame[8] = 0x00;
        frame[9] = 0x12;
        frame[10] = 0x34;
        frame[11] = 0x56;
        frame[12] = 0x08;
        frame[13] = 0x00; // ether_type = IPv4
        // IPv4 header (20 bytes, no options).
        u8* ip = frame + 14;
        ip[0] = 0x45; // version=4, IHL=5
        ip[1] = 0x00; // TOS
        ip[2] = 0x00;
        ip[3] = 28; // total length = 20 + 8
        ip[4] = 0x00;
        ip[5] = 0x01; // ident
        ip[6] = 0x00;
        ip[7] = 0x00; // flags + frag off
        ip[8] = 64;   // TTL
        ip[9] = kIpProtoUdp;
        // checksum left 0 initially
        ip[12] = 10;
        ip[13] = 0;
        ip[14] = 2;
        ip[15] = 2; // src 10.0.2.2
        ip[16] = 10;
        ip[17] = 0;
        ip[18] = 2;
        ip[19] = 15; // dst 10.0.2.15
        const u16 csum = Ipv4HeaderChecksum(ip, 20);
        ip[10] = u8(csum >> 8);
        ip[11] = u8(csum & 0xFF);
        // UDP header (8 bytes, payload 0 — won't be parsed in v0).
        // Leave at zeros.
        const bool ok = Ipv4HandleIncoming(0, frame, sizeof(frame));
        const Ipv4Stats s = Ipv4StatsRead();
        // Compare against the captured baseline rather than `== 1`
        // — the NIC RX path may already have classified one or more
        // UDP frames before the self-test runs (e.g. early ARP /
        // DHCP-style chatter on the QEMU user-net), so an absolute
        // count would produce a spurious "did not classify" warning.
        if (ok && s.rx_udp == baseline_rx_udp + 1)
        {
            arch::SerialWrite("[ipv4] self-test OK — UDP proto counted (rx_udp += 1)\n");
        }
        else
        {
            core::Log(core::LogLevel::Warn, "net/ipv4", "self-test: synthetic IPv4/UDP frame did not classify");
        }
    }

    // Protocol-reply self-tests. Bind iface index 1 to a capturing
    // TX hook, inject a synthetic ARP request, verify the captured
    // frame is a valid ARP reply with our MAC + IP. Then do the
    // same for an ICMP echo request. Real drivers bind iface 0,
    // so the index-1 slot stays out of the way. Left bound after
    // the test — no driver drains it, no side effect.
    static u8 s_last_tx[1600];
    static u64 s_last_tx_len;
    struct SelfTestTx
    {
        static bool Fn(u32 /*iface*/, const void* frame, u64 len)
        {
            if (len > sizeof(s_last_tx))
                return false;
            memcpy(s_last_tx, frame, len);
            s_last_tx_len = len;
            return true;
        }
    };

    const MacAddress test_mac{{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}};
    const Ipv4Address test_ip{{192, 168, 1, 1}};
    const MacAddress peer_mac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    const Ipv4Address peer_ip{{192, 168, 1, 100}};
    NetStackBindInterface(/*iface_index=*/1, test_mac, test_ip, &SelfTestTx::Fn);

    // ARP request probe.
    {
        u8 req[42] = {};
        // Ethernet: broadcast dst, peer src, ARP ethertype.
        memset(req, 0xFF, 6);
        memcpy(req + 6, peer_mac.octets, 6);
        req[12] = 0x08;
        req[13] = 0x06;
        // ARP header: htype=1, ptype=0x0800, hlen=6, plen=4, oper=1.
        req[14] = 0x00;
        req[15] = 0x01;
        req[16] = 0x08;
        req[17] = 0x00;
        req[18] = 0x06;
        req[19] = 0x04;
        req[20] = 0x00;
        req[21] = 0x01;
        memcpy(req + 22, peer_mac.octets, 6);
        memcpy(req + 28, peer_ip.octets, 4);
        // THA zeros, TPA = our test IP.
        memcpy(req + 38, test_ip.octets, 4);

        s_last_tx_len = 0;
        NetStackInjectRx(/*iface_index=*/1, req, sizeof(req));

        const bool length_ok = (s_last_tx_len == 42);
        const bool oper_ok = length_ok && s_last_tx[21] == 0x02; // reply
        bool sender_ok = length_ok;
        for (u64 i = 0; i < 6 && sender_ok; ++i)
            sender_ok = (s_last_tx[22 + i] == test_mac.octets[i]);
        for (u64 i = 0; i < 4 && sender_ok; ++i)
            sender_ok = (s_last_tx[28 + i] == test_ip.octets[i]);
        if (length_ok && oper_ok && sender_ok)
            arch::SerialWrite("[arp] reply self-test OK — sender fields match our iface\n");
        else
            core::Log(core::LogLevel::Warn, "net/arp", "reply self-test: malformed reply captured");
    }

    // ICMP echo-request probe.
    {
        // 14 Ethernet + 20 IPv4 + 12 ICMP (8-byte hdr + 4-byte payload) = 46 bytes.
        u8 req[46] = {};
        for (u64 i = 0; i < 6; ++i)
            req[i] = test_mac.octets[i];
        for (u64 i = 0; i < 6; ++i)
            req[6 + i] = peer_mac.octets[i];
        req[12] = 0x08;
        req[13] = 0x00;
        // IPv4 header.
        req[14] = 0x45;             // v=4, IHL=5
        req[14 + 2] = 0x00;         // total_len hi
        req[14 + 3] = 0x20;         // total_len = 32 (20 IPv4 + 12 ICMP)
        req[14 + 8] = 0x40;         // TTL = 64
        req[14 + 9] = kIpProtoIcmp; // proto = 1
        for (u64 i = 0; i < 4; ++i)
            req[14 + 12 + i] = peer_ip.octets[i];
        for (u64 i = 0; i < 4; ++i)
            req[14 + 16 + i] = test_ip.octets[i];
        const u16 ip_ck = Ipv4HeaderChecksum(req + 14, 20);
        req[14 + 10] = u8(ip_ck >> 8);
        req[14 + 11] = u8(ip_ck & 0xFF);
        // ICMP at offset 34.
        req[34] = 0x08; // type = echo request
        req[34 + 4] = 0x00;
        req[34 + 5] = 0x01; // id = 1
        req[34 + 6] = 0x00;
        req[34 + 7] = 0x01; // seq = 1
        req[34 + 8] = 0xDE;
        req[34 + 9] = 0xAD; // payload
        req[34 + 10] = 0xBE;
        req[34 + 11] = 0xEF;
        const u16 icmp_ck = Ipv4HeaderChecksum(req + 34, 12);
        req[34 + 2] = u8(icmp_ck >> 8);
        req[34 + 3] = u8(icmp_ck & 0xFF);

        s_last_tx_len = 0;
        NetStackInjectRx(/*iface_index=*/1, req, sizeof(req));

        const bool length_ok = (s_last_tx_len == 46);
        const bool type_ok = length_ok && s_last_tx[34] == 0x00; // echo reply
        bool ips_swapped = length_ok;
        for (u64 i = 0; i < 4 && ips_swapped; ++i)
            ips_swapped = (s_last_tx[14 + 12 + i] == test_ip.octets[i]);
        for (u64 i = 0; i < 4 && ips_swapped; ++i)
            ips_swapped = (s_last_tx[14 + 16 + i] == peer_ip.octets[i]);
        if (length_ok && type_ok && ips_swapped)
            arch::SerialWrite("[icmp] echo-reply self-test OK — type=0, IPs swapped\n");
        else
            core::Log(core::LogLevel::Warn, "net/icmp", "echo-reply self-test: malformed reply captured");
    }
}

u64 InterfaceCount()
{
    return g_interface_count;
}

bool InterfaceIsBound(u32 iface_index)
{
    if (iface_index >= kMaxInterfaces)
        return false;
    return g_interfaces[iface_index].bound;
}

Ipv4Address InterfaceIp(u32 iface_index)
{
    if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound)
        return Ipv4Address{};
    return g_interfaces[iface_index].ip;
}

MacAddress InterfaceMac(u32 iface_index)
{
    if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound)
        return MacAddress{};
    return g_interfaces[iface_index].mac;
}

u32 ArpEntryCount()
{
    const u64 now = NowTicks();
    u32 live = 0;
    for (const ArpEntry& e : g_arp_cache)
    {
        if (e.expiry_ticks == 0)
            continue;
        if (now >= e.expiry_ticks)
            continue;
        ++live;
    }
    return live;
}

namespace
{

// Hash (iface, ip) → bucket index. Murmur-style 32-bit avalanche
// mixed against a Knuth-derived multiplier so adjacent IPs spread
// across buckets instead of clustering. With kArpHashSize a power
// of two we mask off the high bits.
inline u32 ArpHash(u32 iface, Ipv4Address ip)
{
    u32 h = (static_cast<u32>(ip.octets[0]) << 24) | (static_cast<u32>(ip.octets[1]) << 16) |
            (static_cast<u32>(ip.octets[2]) << 8) | static_cast<u32>(ip.octets[3]);
    h ^= iface * 0x9E3779B9u;
    h ^= h >> 16;
    h *= 0x85EBCA6Bu;
    h ^= h >> 13;
    return h & (kArpHashSize - 1);
}

// Splice the entry at `idx` out of the bucket-`h` chain. Caller
// has already verified the entry IS in that chain (because it
// derived `h` from the entry's own (iface, ip)).
void ArpUnlinkFromBucket(u8 idx, u32 h)
{
    u8* link = &g_arp_hash_heads[h];
    while (*link != kArpEntryNone)
    {
        if (*link == idx)
        {
            *link = g_arp_cache[idx].next_idx;
            g_arp_cache[idx].next_idx = kArpEntryNone;
            return;
        }
        link = &g_arp_cache[*link].next_idx;
    }
}

} // namespace

const ArpEntry* ArpLookup(u32 iface_index, Ipv4Address ip)
{
    const u64 now = NowTicks();
    const u32 h = ArpHash(iface_index, ip);

    u8* link = &g_arp_hash_heads[h];
    while (*link != kArpEntryNone)
    {
        const u8 idx = *link;
        ArpEntry& e = g_arp_cache[idx];
        if (e.iface_index == iface_index && IpEq(e.ip, ip))
        {
            if (now >= e.expiry_ticks)
            {
                // Lazy expiry: splice out of the chain so the next
                // lookup doesn't re-traverse a dead entry, and free
                // the slot for a future insert.
                *link = e.next_idx;
                e.next_idx = kArpEntryNone;
                e.expiry_ticks = 0;
                ++g_arp_stats.lookups_miss;
                return nullptr;
            }
            ++g_arp_stats.lookups_hit;
            return &e;
        }
        link = &e.next_idx;
    }
    ++g_arp_stats.lookups_miss;
    return nullptr;
}

void ArpInsert(u32 iface_index, Ipv4Address ip, MacAddress mac)
{
    const u64 now = NowTicks();
    const u32 h = ArpHash(iface_index, ip);

    // Refresh an existing entry if it's already on this bucket's chain.
    //
    // Bounded by `kArpCacheCap` iterations. If a race between the
    // rx-poll task and the bringup path's NetStackInit had left a
    // chain with a cycle (or simply pointing back into itself
    // through a stale next_idx during a concurrent unlink), this
    // for-loop used to spin forever with IRQs disabled — which on
    // a single-CPU TCG boot looked like "the timer just stopped
    // firing", because the watchdog couldn't run. The bound also
    // covers the more mundane corruption case (a u8 next_idx field
    // got clobbered by a wild write) by reaching the limit and
    // walking out. On a healthy chain the limit is never hit since
    // each bucket holds at most kArpCacheCap entries.
    u32 walked = 0;
    for (u8 idx = g_arp_hash_heads[h]; idx != kArpEntryNone && walked < kArpCacheCap;
         idx = g_arp_cache[idx].next_idx, ++walked)
    {
        if (idx >= kArpCacheCap)
        {
            // Bucket head or next_idx out of range — chain is
            // corrupted. Reset this bucket to empty and proceed
            // to the free-slot path. The lost entries leak space
            // until their TTLs expire; that's strictly better than
            // looping forever with IRQs disabled.
            g_arp_hash_heads[h] = kArpEntryNone;
            break;
        }
        ArpEntry& e = g_arp_cache[idx];
        if (e.iface_index == iface_index && IpEq(e.ip, ip))
        {
            e.mac = mac;
            e.expiry_ticks = now + kArpEntryTtlTicks;
            ++g_arp_stats.inserts;
            return;
        }
    }

    // Find a free or expired slot. Linear scan over the cache —
    // 32 entries, runs at cache-miss frequency, not lookup frequency.
    u8 free_idx = kArpEntryNone;
    for (u32 i = 0; i < kArpCacheCap; ++i)
    {
        if (g_arp_cache[i].expiry_ticks == 0 || g_arp_cache[i].expiry_ticks <= now)
        {
            free_idx = static_cast<u8>(i);
            break;
        }
    }

    if (free_idx == kArpEntryNone)
    {
        // No free slot — evict the entry with the soonest expiry.
        u32 victim = 0;
        for (u32 i = 1; i < kArpCacheCap; ++i)
        {
            if (g_arp_cache[i].expiry_ticks < g_arp_cache[victim].expiry_ticks)
            {
                victim = i;
            }
        }
        // Splice victim out of its current bucket so we don't leave
        // a dangling chain link pointing at its repurposed slot.
        const ArpEntry& v = g_arp_cache[victim];
        if (v.expiry_ticks != 0)
        {
            ArpUnlinkFromBucket(static_cast<u8>(victim), ArpHash(v.iface_index, v.ip));
        }
        free_idx = static_cast<u8>(victim);
        ++g_arp_stats.evictions;
    }
    else if (g_arp_cache[free_idx].expiry_ticks != 0)
    {
        // Slot was an expired entry, not a never-used one — splice
        // it out of its old bucket before reusing.
        const ArpEntry& v = g_arp_cache[free_idx];
        ArpUnlinkFromBucket(free_idx, ArpHash(v.iface_index, v.ip));
    }

    // Initialise the slot and link onto the head of the new bucket.
    ArpEntry& e = g_arp_cache[free_idx];
    e.ip = ip;
    e.mac = mac;
    e.iface_index = iface_index;
    e.expiry_ticks = now + kArpEntryTtlTicks;
    e.next_idx = g_arp_hash_heads[h];
    g_arp_hash_heads[h] = free_idx;
    ++g_arp_stats.inserts;
}

bool ArpHandleIncoming(u32 iface_index, const void* frame, u64 len)
{
    ++g_arp_stats.rx_packets;
    // Minimum: Ethernet header (14) + ARP payload (28) = 42 bytes.
    if (frame == nullptr || len < 42)
    {
        ++g_arp_stats.rx_rejects;
        return false;
    }
    const auto* eth = static_cast<const u8*>(frame);
    const u16 ether_type = u16(eth[12]) << 8 | u16(eth[13]);
    if (ether_type != kEtherTypeArp)
    {
        ++g_arp_stats.rx_rejects;
        return false;
    }
    const u8* arp = eth + 14;
    const u16 htype = (u16(arp[0]) << 8) | u16(arp[1]);
    const u16 ptype = (u16(arp[2]) << 8) | u16(arp[3]);
    const u8 hlen = arp[4];
    const u8 plen = arp[5];
    const u16 oper = (u16(arp[6]) << 8) | u16(arp[7]);
    // Only IPv4-over-Ethernet requests + replies are meaningful.
    if (htype != 1 || ptype != kEtherTypeIpv4 || hlen != 6 || plen != 4)
    {
        ++g_arp_stats.rx_rejects;
        return false;
    }
    MacAddress sha = {};
    for (u64 i = 0; i < 6; ++i)
        sha.octets[i] = arp[8 + i];
    Ipv4Address spa = {};
    for (u64 i = 0; i < 4; ++i)
        spa.octets[i] = arp[14 + i];
    Ipv4Address tpa = {};
    for (u64 i = 0; i < 4; ++i)
        tpa.octets[i] = arp[24 + i];

    if (oper == 2 /* reply */)
    {
        ArpInsert(iface_index, spa, sha);
        return true;
    }
    if (oper != 1 /* request */)
    {
        return false;
    }

    // ARP request: reply iff we own the target IP on a bound
    // interface. Also learn the requester's mapping so the next
    // L3 transmit path can cache-hit without doing its own ARP.
    if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound)
    {
        return false;
    }
    const Interface& ifc = g_interfaces[iface_index];
    if (!IpEq(tpa, ifc.ip))
    {
        return false; // not asking about us
    }
    ArpInsert(iface_index, spa, sha);

    // Build the reply directly on the stack. 42-byte ethernet +
    // ARP frame — small enough that we don't bother with a heap
    // allocation. The controller's PSP will pad on the wire.
    u8 reply[42] = {};
    // Ethernet: dst = requester's MAC, src = our MAC,
    // ethertype = ARP (big-endian 0x0806).
    for (u64 i = 0; i < 6; ++i)
        reply[i] = sha.octets[i];
    for (u64 i = 0; i < 6; ++i)
        reply[6 + i] = ifc.mac.octets[i];
    reply[12] = 0x08;
    reply[13] = 0x06;
    // ARP header: htype=1, ptype=0x0800, hlen=6, plen=4, oper=2.
    reply[14] = 0x00;
    reply[15] = 0x01;
    reply[16] = 0x08;
    reply[17] = 0x00;
    reply[18] = 0x06;
    reply[19] = 0x04;
    reply[20] = 0x00;
    reply[21] = 0x02; // reply
    // Sender (us).
    for (u64 i = 0; i < 6; ++i)
        reply[22 + i] = ifc.mac.octets[i];
    for (u64 i = 0; i < 4; ++i)
        reply[28 + i] = ifc.ip.octets[i];
    // Target (requester).
    for (u64 i = 0; i < 6; ++i)
        reply[32 + i] = sha.octets[i];
    for (u64 i = 0; i < 4; ++i)
        reply[38 + i] = spa.octets[i];

    (void)IfaceTx(iface_index, reply, sizeof(reply));
    return true;
}

ArpStats ArpStatsRead()
{
    return g_arp_stats;
}

u16 Ipv4HeaderChecksum(const void* buf, u64 len)
{
    const auto* p = static_cast<const u8*>(buf);
    u32 sum = 0;
    u64 i = 0;
    // 16-bit big-endian words.
    while (i + 2 <= len)
    {
        const u16 word = (u16(p[i]) << 8) | u16(p[i + 1]);
        sum += word;
        i += 2;
    }
    if (i < len)
    {
        // Odd trailing byte — pad with 0 in the low half.
        sum += u32(p[i]) << 8;
    }
    // Fold carry.
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return u16(~sum & 0xFFFF);
}

bool Ipv4HeaderValid(const void* buf, u64 len)
{
    if (buf == nullptr)
        return false;
    const auto* p = static_cast<const u8*>(buf);
    if (len < sizeof(Ipv4Header))
        return false;
    const u8 version = p[0] >> 4;
    const u8 ihl = p[0] & 0x0F;
    if (version != 4)
        return false;
    if (ihl < 5)
        return false;
    const u64 header_bytes = u64(ihl) * 4;
    if (header_bytes > len)
        return false;
    const u16 total_len = (u16(p[2]) << 8) | u16(p[3]);
    if (total_len > len)
        return false;
    // A computed checksum of 0 means the stored checksum matches.
    return Ipv4HeaderChecksum(p, header_bytes) == 0;
}

bool Ipv4HandleIncoming(u32 iface_index, const void* frame, u64 len)
{
    (void)iface_index;
    ++g_ipv4_stats.rx_packets;
    if (frame == nullptr || len < 14 + sizeof(Ipv4Header))
    {
        ++g_ipv4_stats.rx_bad_length;
        return false;
    }
    const auto* eth = static_cast<const u8*>(frame);
    const u16 ether_type = (u16(eth[12]) << 8) | u16(eth[13]);
    if (ether_type != kEtherTypeIpv4)
    {
        ++g_ipv4_stats.rx_bad_length;
        return false;
    }
    const u8* ip = eth + 14;
    const u64 ip_len = len - 14;
    const u8 version = ip[0] >> 4;
    const u8 ihl = ip[0] & 0x0F;
    if (version != 4)
    {
        ++g_ipv4_stats.rx_bad_version;
        return false;
    }
    if (ihl < 5 || u64(ihl) * 4 > ip_len)
    {
        ++g_ipv4_stats.rx_bad_ihl;
        return false;
    }
    const u16 total_len = (u16(ip[2]) << 8) | u16(ip[3]);
    if (total_len > ip_len)
    {
        ++g_ipv4_stats.rx_bad_length;
        return false;
    }
    if (Ipv4HeaderChecksum(ip, u64(ihl) * 4) != 0)
    {
        ++g_ipv4_stats.rx_bad_checksum;
        return false;
    }
    // Firewall ingress check. Parse the 5-tuple needed by the
    // rule table: proto, src/dst IP, and (for TCP/UDP) src/dst
    // ports. Drop on Deny — the rest of the L3 path never sees
    // the packet, and per-rule hit counters / iface counters
    // accurately reflect what was filtered.
    {
        Ipv4Address src_ip = {};
        Ipv4Address dst_ip = {};
        for (u64 i = 0; i < 4; ++i)
        {
            src_ip.octets[i] = ip[12 + i];
            dst_ip.octets[i] = ip[16 + i];
        }
        const firewall::Proto fw_proto = ToFwProto(ip[9]);
        u16 src_port = 0;
        u16 dst_port = 0;
        u8 tcp_flags = 0;
        if ((fw_proto == firewall::Proto::Tcp || fw_proto == firewall::Proto::Udp) && total_len >= u16(ihl) * 4 + 4)
        {
            const u8* l4 = ip + u64(ihl) * 4;
            src_port = (u16(l4[0]) << 8) | u16(l4[1]);
            dst_port = (u16(l4[2]) << 8) | u16(l4[3]);
            if (fw_proto == firewall::Proto::Tcp && total_len >= u16(ihl) * 4 + 14)
            {
                tcp_flags = l4[13];
            }
        }
        const firewall::Action verdict = firewall::FwEvaluate(firewall::Direction::Ingress, fw_proto, src_ip, dst_ip,
                                                              src_port, dst_port, tcp_flags, nullptr);
        if (verdict == firewall::Action::Deny)
        {
            return false;
        }
    }
    // Auto-learn the ARP cache from every valid IPv4 frame: the
    // ethernet src MAC + IPv4 src IP are always consistent with
    // the sender. Saves us from issuing an explicit ARP request
    // before pinging a peer that just talked to us.
    {
        MacAddress src_mac = {};
        for (u64 i = 0; i < 6; ++i)
            src_mac.octets[i] = eth[6 + i];
        Ipv4Address src_ip = {};
        for (u64 i = 0; i < 4; ++i)
            src_ip.octets[i] = ip[12 + i];
        ArpInsert(iface_index, src_ip, src_mac);
    }
    const u8 proto = ip[9];
    switch (proto)
    {
    case kIpProtoUdp:
    {
        ++g_ipv4_stats.rx_udp;
        // Dispatch to UDP layer. UDP header starts at ip +
        // ihl*4 and is always 8 bytes. Payload follows.
        const u64 ip_header_bytes = u64(ihl) * 4;
        if (total_len < ip_header_bytes + 8)
            break;
        const u8* udp = ip + ip_header_bytes;
        const u16 src_port = (u16(udp[0]) << 8) | u16(udp[1]);
        const u16 dst_port = (u16(udp[2]) << 8) | u16(udp[3]);
        const u16 udp_len = (u16(udp[4]) << 8) | u16(udp[5]);
        if (udp_len < 8 || udp_len > total_len - ip_header_bytes)
            break;
        Ipv4Address src_ip = {};
        for (u64 i = 0; i < 4; ++i)
            src_ip.octets[i] = ip[12 + i];
        NetUdpDispatch(iface_index, src_ip, src_port, dst_port, udp + 8, udp_len - 8);
        break;
    }
    case kIpProtoTcp:
    {
        ++g_ipv4_stats.rx_tcp;
        // Parse + dispatch to the passive TCP handler. TCP starts
        // at the end of the IPv4 options (IHL × 4). Peer MAC is
        // whatever the ethernet header had as src.
        const u64 ip_header_bytes = u64(ihl) * 4;
        if (total_len < ip_header_bytes + 20)
            break;
        const u8* tcp = ip + ip_header_bytes;
        MacAddress peer_mac = {};
        for (u64 i = 0; i < 6; ++i)
            peer_mac.octets[i] = eth[6 + i];
        Ipv4Address peer_ip = {};
        for (u64 i = 0; i < 4; ++i)
            peer_ip.octets[i] = ip[12 + i];
        tcp::OnSegment(iface_index, peer_mac, peer_ip, tcp, total_len - ip_header_bytes);
        break;
    }
    case kIpProtoIcmp:
    {
        ++g_ipv4_stats.rx_icmp;
        // ICMP echo-reply path — only fire if this iface is bound
        // and the IPv4 destination matches our address (we don't
        // reply on behalf of other hosts). ICMP starts after the
        // IPv4 header options.
        if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound)
            break;
        const Interface& ifc = g_interfaces[iface_index];
        Ipv4Address dst = {};
        for (u64 i = 0; i < 4; ++i)
            dst.octets[i] = ip[16 + i];
        if (!IpEq(dst, ifc.ip))
            break;

        const u64 ip_header_bytes = u64(ihl) * 4;
        if (total_len < ip_header_bytes + 8)
            break; // ICMP header alone is 8 bytes
        const u8* icmp = ip + ip_header_bytes;

        // Echo Reply (type=0) — match against the pending ping
        // request. If id + seq match, stash the reply arrival
        // tick so the shell's wait loop can print the RTT.
        if (icmp[0] == 0x00 && g_ping_pending)
        {
            const u16 id = (u16(icmp[4]) << 8) | u16(icmp[5]);
            const u16 seq = (u16(icmp[6]) << 8) | u16(icmp[7]);
            if (id == g_ping_id && seq == g_ping_seq)
            {
                Ipv4Address src_ip = {};
                for (u64 i = 0; i < 4; ++i)
                    src_ip.octets[i] = ip[12 + i];
                g_ping_reply_ticks = NowTicks();
                g_ping_reply_ip = src_ip;
                g_ping_replied = true;
                ++g_icmp_stats.echo_replies_rx;
            }
            break;
        }

        if (icmp[0] != 0x08 /* Echo Request */)
            break;

        ++g_icmp_stats.echo_requests_rx;

        // Build the reply into a stack buffer. Size = 14 (ethernet)
        // + total_len (copy of IPv4 + ICMP). Cap at 1514 bytes
        // (standard ethernet MTU + header) so we never overflow.
        constexpr u64 kMaxReply = 1514;
        if (u64(total_len) + 14 > kMaxReply)
            break;
        // Deliberately uninitialized — the ethernet header, IPv4
        // header, and ICMP payload are all written below from the
        // 14 + total_len prefix. `= {}` would lower to a libc
        // memset call the freestanding linker can't resolve.
        u8 reply[kMaxReply];
        const u64 reply_len = u64(total_len) + 14;

        // Ethernet: swap src/dst, ethertype = IPv4.
        memcpy(reply, eth + 6, 6); // dst = incoming src
        memcpy(reply + 6, ifc.mac.octets, 6);
        reply[12] = 0x08;
        reply[13] = 0x00;

        // Copy IPv4 header + ICMP payload.
        memcpy(reply + 14, ip, total_len);
        // Swap src/dst addresses.
        u8* r_ip = reply + 14;
        for (u64 i = 0; i < 4; ++i)
        {
            const u8 tmp = r_ip[12 + i];
            r_ip[12 + i] = r_ip[16 + i];
            r_ip[16 + i] = tmp;
        }
        // Reset TTL to something sane and recompute header checksum.
        r_ip[8] = 64;
        r_ip[10] = 0;
        r_ip[11] = 0;
        const u16 ip_ck = Ipv4HeaderChecksum(r_ip, ip_header_bytes);
        r_ip[10] = u8(ip_ck >> 8);
        r_ip[11] = u8(ip_ck & 0xFF);

        // ICMP: type from 8 (echo request) to 0 (echo reply);
        // recompute ICMP checksum (one's complement sum over the
        // whole ICMP message, checksum field zeroed during the
        // compute).
        u8* r_icmp = r_ip + ip_header_bytes;
        r_icmp[0] = 0x00;
        r_icmp[2] = 0;
        r_icmp[3] = 0;
        const u64 icmp_bytes = u64(total_len) - ip_header_bytes;
        const u16 icmp_ck = Ipv4HeaderChecksum(r_icmp, icmp_bytes);
        r_icmp[2] = u8(icmp_ck >> 8);
        r_icmp[3] = u8(icmp_ck & 0xFF);

        if (IfaceTx(iface_index, reply, reply_len))
        {
            ++g_icmp_stats.echo_replies_tx;
        }
        else
        {
            ++g_icmp_stats.tx_failures;
        }
        break;
    }
    default:
        ++g_ipv4_stats.rx_other_proto;
        break;
    }
    return true;
}

Ipv4Stats Ipv4StatsRead()
{
    return g_ipv4_stats;
}

IcmpStats IcmpStatsRead()
{
    return g_icmp_stats;
}

// ---------------------------------------------------------------
// UDP layer
// ---------------------------------------------------------------

namespace
{

// 16-bit one's-complement sum over a pseudo-header + UDP segment.
// Used for UDP TX checksum generation. RFC 768: pseudo-header is
// {src_ip, dst_ip, 0, protocol, udp_length} all in network order.
u16 UdpChecksum(Ipv4Address src, Ipv4Address dst, const u8* udp, u64 udp_len)
{
    u32 sum = 0;
    // Pseudo-header.
    sum += (u32(src.octets[0]) << 8) | u32(src.octets[1]);
    sum += (u32(src.octets[2]) << 8) | u32(src.octets[3]);
    sum += (u32(dst.octets[0]) << 8) | u32(dst.octets[1]);
    sum += (u32(dst.octets[2]) << 8) | u32(dst.octets[3]);
    sum += kIpProtoUdp;
    sum += u32(udp_len);
    // UDP header + payload.
    for (u64 i = 0; i + 1 < udp_len; i += 2)
        sum += (u32(udp[i]) << 8) | u32(udp[i + 1]);
    if ((udp_len & 1) != 0)
        sum += u32(udp[udp_len - 1]) << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    const u16 ck = u16(~sum & 0xFFFF);
    return ck == 0 ? u16(0xFFFF) : ck; // RFC: 0 is reserved
}

} // namespace

void NetUdpDispatch(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len)
{
    ++g_udp_stats.rx_packets;
    // Drop frames whose iface_index is outside our interface table —
    // every UDP handler indexes g_interfaces[iface_index] without
    // its own bounds check, and the IP RX path does not gate UDP
    // on iface_index the way it does for ICMP. A driver bug or a
    // crafted IP frame with an unmapped iface index would otherwise
    // alias into adjacent kernel state.
    if (iface_index >= kMaxInterfaces)
    {
        ++g_udp_stats.rx_no_port;
        return;
    }
    // A null payload with a non-zero len would be a driver bug —
    // refuse rather than walk a null pointer in the handler.
    if (payload == nullptr && len != 0)
    {
        ++g_udp_stats.rx_no_port;
        return;
    }
    // Sockets first — once a userland process binds a UDP port via
    // socket()/bind(), it owns dispatch on that port. The legacy
    // UdpBinding table stays for kernel-resident callers (DHCP /
    // DNS / NTP) and only fires if no socket consumed the datagram.
    if (SocketUdpDispatch(iface_index, src_ip, src_port, dst_port, payload, len))
        return;
    for (const UdpBinding& b : g_udp_bindings)
    {
        if (b.in_use && b.port == dst_port && b.handler != nullptr)
        {
            b.handler(iface_index, src_ip, src_port, dst_port, payload, len);
            return;
        }
    }
    ++g_udp_stats.rx_no_port;
}

bool NetUdpBindRx(u16 local_port, UdpRxFn handler)
{
    // Unbind request: clear any slot holding this port.
    if (handler == nullptr)
    {
        for (UdpBinding& b : g_udp_bindings)
        {
            if (b.in_use && b.port == local_port)
            {
                b.in_use = false;
                b.port = 0;
                b.handler = nullptr;
            }
        }
        return true;
    }
    // Reject a duplicate binding.
    for (const UdpBinding& b : g_udp_bindings)
    {
        if (b.in_use && b.port == local_port)
            return false;
    }
    for (UdpBinding& b : g_udp_bindings)
    {
        if (!b.in_use)
        {
            b.in_use = true;
            b.port = local_port;
            b.handler = handler;
            return true;
        }
    }
    return false; // table full
}

bool NetUdpSend(u32 iface_index, const MacAddress& dst_mac, Ipv4Address dst_ip, u16 dst_port, Ipv4Address src_ip,
                u16 src_port, const void* payload, u64 payload_len)
{
    if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound)
        return false;
    const Interface& ifc = g_interfaces[iface_index];
    constexpr u64 kMaxFrame = 1514;
    const u64 frame_len = 14 + 20 + 8 + payload_len;
    if (frame_len > kMaxFrame)
    {
        ++g_udp_stats.tx_failures;
        return false;
    }
    // Same stack-buffer trick as the ICMP reply: leave uninitialized
    // because every byte gets written below; `= {}` lowers to libc
    // memset in this freestanding TU.
    u8 frame[kMaxFrame];

    // Ethernet.
    for (u64 i = 0; i < 6; ++i)
        frame[i] = dst_mac.octets[i];
    for (u64 i = 0; i < 6; ++i)
        frame[6 + i] = ifc.mac.octets[i];
    frame[12] = 0x08;
    frame[13] = 0x00;

    // IPv4 header (20 bytes, no options).
    u8* ip = frame + 14;
    ip[0] = 0x45; // v=4, IHL=5
    ip[1] = 0x00;
    const u16 ip_total_len = u16(20 + 8 + payload_len);
    ip[2] = u8(ip_total_len >> 8);
    ip[3] = u8(ip_total_len & 0xFF);
    ip[4] = 0x00;
    ip[5] = 0x00; // ident
    ip[6] = 0x00;
    ip[7] = 0x00; // flags + frag off
    ip[8] = 64;
    ip[9] = kIpProtoUdp;
    ip[10] = 0;
    ip[11] = 0; // checksum placeholder
    for (u64 i = 0; i < 4; ++i)
        ip[12 + i] = src_ip.octets[i];
    for (u64 i = 0; i < 4; ++i)
        ip[16 + i] = dst_ip.octets[i];
    const u16 ip_ck = Ipv4HeaderChecksum(ip, 20);
    ip[10] = u8(ip_ck >> 8);
    ip[11] = u8(ip_ck & 0xFF);

    // UDP header (8 bytes).
    u8* udp = ip + 20;
    udp[0] = u8(src_port >> 8);
    udp[1] = u8(src_port & 0xFF);
    udp[2] = u8(dst_port >> 8);
    udp[3] = u8(dst_port & 0xFF);
    const u16 udp_len = u16(8 + payload_len);
    udp[4] = u8(udp_len >> 8);
    udp[5] = u8(udp_len & 0xFF);
    udp[6] = 0;
    udp[7] = 0; // checksum placeholder

    // Payload.
    const auto* p = static_cast<const u8*>(payload);
    for (u64 i = 0; i < payload_len; ++i)
        udp[8 + i] = p[i];

    // UDP checksum (pseudo-header + header + payload).
    const u16 udp_ck = UdpChecksum(src_ip, dst_ip, udp, udp_len);
    udp[6] = u8(udp_ck >> 8);
    udp[7] = u8(udp_ck & 0xFF);

    if (!IfaceTx(iface_index, frame, frame_len))
    {
        ++g_udp_stats.tx_failures;
        return false;
    }
    ++g_udp_stats.tx_packets;
    return true;
}

UdpStats UdpStatsRead()
{
    return g_udp_stats;
}

// ---------------------------------------------------------------
// DHCP client (RFC 2131 subset — enough for one lease acquisition)
// ---------------------------------------------------------------

namespace
{

[[maybe_unused]] constexpr u32 kDhcpMagicCookie = 0x63825363;
constexpr u8 kDhcpOpRequest = 1;
constexpr u8 kDhcpOpReply = 2;
constexpr u8 kDhcpMsgDiscover = 1;
constexpr u8 kDhcpMsgOffer = 2;
constexpr u8 kDhcpMsgRequest = 3;
constexpr u8 kDhcpMsgAck = 5;
constexpr u8 kDhcpOptSubnetMask = 1;
constexpr u8 kDhcpOptRouter = 3;
constexpr u8 kDhcpOptDns = 6;
constexpr u8 kDhcpOptRequestedIp = 50;
constexpr u8 kDhcpOptLeaseTime = 51;
constexpr u8 kDhcpOptMsgType = 53;
constexpr u8 kDhcpOptServerId = 54;
constexpr u8 kDhcpOptParamList = 55;
constexpr u8 kDhcpOptEnd = 255;

// Fixed-layout BOOTP header (§2 of RFC 951). DHCP adds the magic
// cookie + options after the 236-byte BOOTP frame.
struct BootpHeader
{
    u8 op;
    u8 htype;
    u8 hlen;
    u8 hops;
    u32 xid;
    u16 secs;
    u16 flags;
    Ipv4Address ciaddr;
    Ipv4Address yiaddr;
    Ipv4Address siaddr;
    Ipv4Address giaddr;
    u8 chaddr[16];
    u8 sname[64];
    u8 file[128];
};
static_assert(sizeof(BootpHeader) == 236, "BOOTP header is 236 bytes");

constexpr u64 kDhcpFrameBytes = 236 + 4 + 64; // BOOTP + magic + options region

// Walk the option-byte stream looking for `opt_code`. On hit, sets
// `*out_data` + `*out_len` to the value bytes and returns true.
// Handles the DHCP `pad` (0) + `end` (255) short options.
//
// Implementation lives in the Rust crate `duetos_net_parsers` for
// bounds-checked slice traversal on attacker-controlled bytes; the
// C++ wrapper just adapts to the existing `u64` / `bool` types.
bool DhcpFindOption(const u8* opts, u64 opts_len, u8 opt_code, const u8** out_data, u8* out_len)
{
    using ::duetos::net::parsers::duetos_parsers_dhcp_find_option;
    if (opts == nullptr || out_data == nullptr || out_len == nullptr)
        return false;
    return duetos_parsers_dhcp_find_option(opts, static_cast<usize>(opts_len), opt_code, out_data, out_len);
}

void DhcpBuildPayload(u8* buf, u64 cap, u8 msg_type, u32 xid, const MacAddress& mac, bool include_requested_ip,
                      Ipv4Address requested_ip, Ipv4Address server_id)
{
    KASSERT(cap >= kDhcpFrameBytes, "net/dhcp", "DhcpBuildPayload buffer too small");
    for (u64 i = 0; i < kDhcpFrameBytes; ++i)
        buf[i] = 0;
    auto* h = reinterpret_cast<BootpHeader*>(buf);
    h->op = kDhcpOpRequest;
    h->htype = 1; // Ethernet
    h->hlen = 6;
    h->hops = 0;
    // xid in big-endian — write byte-wise so host-endianness
    // quirks don't bite.
    u8* p = buf + 4;
    p[0] = u8(xid >> 24);
    p[1] = u8(xid >> 16);
    p[2] = u8(xid >> 8);
    p[3] = u8(xid);
    // flags = 0x8000 (broadcast) — tells the server to reply via
    // broadcast, which SLIRP honours and hardware normally does.
    buf[10] = 0x80;
    buf[11] = 0x00;
    for (u64 i = 0; i < 6; ++i)
        buf[28 + i] = mac.octets[i];
    // Magic cookie.
    u8* cookie = buf + 236;
    cookie[0] = 0x63;
    cookie[1] = 0x82;
    cookie[2] = 0x53;
    cookie[3] = 0x63;
    // Options.
    u64 o = 240;
    auto put = [&](u8 code, u8 len, const u8* val)
    {
        buf[o++] = code;
        buf[o++] = len;
        for (u8 i = 0; i < len; ++i)
            buf[o++] = val[i];
    };
    const u8 msg_arr[1] = {msg_type};
    put(kDhcpOptMsgType, 1, msg_arr);
    if (include_requested_ip)
    {
        put(kDhcpOptRequestedIp, 4, requested_ip.octets);
        put(kDhcpOptServerId, 4, server_id.octets);
    }
    const u8 plist[4] = {kDhcpOptSubnetMask, kDhcpOptRouter, kDhcpOptDns, kDhcpOptLeaseTime};
    put(kDhcpOptParamList, 4, plist);
    buf[o++] = kDhcpOptEnd;
}

void DhcpSendDiscover()
{
    const Interface& ifc = g_interfaces[g_dhcp.iface_index];
    u8 payload[kDhcpFrameBytes];
    DhcpBuildPayload(payload, sizeof(payload), kDhcpMsgDiscover, g_dhcp.xid, ifc.mac, false, {}, {});
    const MacAddress bcast_mac{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    const Ipv4Address bcast_ip{{0xFF, 0xFF, 0xFF, 0xFF}};
    const Ipv4Address any_ip{{0, 0, 0, 0}};
    NetUdpSend(g_dhcp.iface_index, bcast_mac, bcast_ip, /*dst_port=*/67, any_ip, /*src_port=*/68, payload,
               sizeof(payload));
    arch::SerialWrite("[dhcp] DISCOVER sent\n");
}

void DhcpSendRequest()
{
    const Interface& ifc = g_interfaces[g_dhcp.iface_index];
    u8 payload[kDhcpFrameBytes];
    DhcpBuildPayload(payload, sizeof(payload), kDhcpMsgRequest, g_dhcp.xid, ifc.mac, true, g_dhcp.offered_ip,
                     g_dhcp.server_ip);
    const MacAddress bcast_mac{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    const Ipv4Address bcast_ip{{0xFF, 0xFF, 0xFF, 0xFF}};
    const Ipv4Address any_ip{{0, 0, 0, 0}};
    NetUdpSend(g_dhcp.iface_index, bcast_mac, bcast_ip, /*dst_port=*/67, any_ip, /*src_port=*/68, payload,
               sizeof(payload));
    {
        arch::SerialLineGuard line;
        arch::SerialWrite("[dhcp] REQUEST sent for ");
        for (u64 i = 0; i < 4; ++i)
        {
            if (i != 0)
                arch::SerialWrite(".");
            arch::SerialWriteHex(g_dhcp.offered_ip.octets[i]);
        }
        arch::SerialWrite("\n");
    }
}

} // namespace

void DhcpOnUdp(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len)
{
    (void)src_port;
    (void)dst_port;
    if (iface_index >= kMaxInterfaces || iface_index != g_dhcp.iface_index)
        return;
    if (payload == nullptr || len < kDhcpFrameBytes)
        return;
    const auto* buf = static_cast<const u8*>(payload);
    if (buf[0] != kDhcpOpReply)
        return;
    // Check xid matches our in-flight transaction.
    const u32 xid = (u32(buf[4]) << 24) | (u32(buf[5]) << 16) | (u32(buf[6]) << 8) | u32(buf[7]);
    if (xid != g_dhcp.xid)
        return;
    // Magic cookie at offset 236.
    if (buf[236] != 0x63 || buf[237] != 0x82 || buf[238] != 0x53 || buf[239] != 0x63)
        return;
    const u8* opts = buf + 240;
    const u64 opts_len = len - 240;
    const u8* v = nullptr;
    u8 vl = 0;
    if (!DhcpFindOption(opts, opts_len, kDhcpOptMsgType, &v, &vl) || vl != 1)
        return;
    const u8 msg = v[0];

    // yiaddr = your (client) IP, bytes 16..19 of BOOTP header.
    Ipv4Address yiaddr = {};
    for (u64 i = 0; i < 4; ++i)
        yiaddr.octets[i] = buf[16 + i];
    Ipv4Address server_id = src_ip;
    if (DhcpFindOption(opts, opts_len, kDhcpOptServerId, &v, &vl) && vl == 4)
    {
        for (u64 i = 0; i < 4; ++i)
            server_id.octets[i] = v[i];
    }

    if (msg == kDhcpMsgOffer && g_dhcp.stage == DhcpState::Stage::Discovered)
    {
        g_dhcp.offered_ip = yiaddr;
        g_dhcp.server_ip = server_id;
        DhcpSendRequest();
        return;
    }
    if (msg == kDhcpMsgAck && (g_dhcp.stage == DhcpState::Stage::Discovered || g_dhcp.stage == DhcpState::Stage::Acked))
    {
        g_dhcp.stage = DhcpState::Stage::Acked;
        g_dhcp.lease.valid = true;
        g_dhcp.lease.ip = yiaddr;
        g_dhcp.lease.server = server_id;
        if (DhcpFindOption(opts, opts_len, kDhcpOptRouter, &v, &vl) && vl >= 4)
            for (u64 i = 0; i < 4; ++i)
                g_dhcp.lease.router.octets[i] = v[i];
        if (DhcpFindOption(opts, opts_len, kDhcpOptDns, &v, &vl) && vl >= 4)
            for (u64 i = 0; i < 4; ++i)
                g_dhcp.lease.dns.octets[i] = v[i];
        if (DhcpFindOption(opts, opts_len, kDhcpOptLeaseTime, &v, &vl) && vl == 4)
            g_dhcp.lease.lease_secs = (u32(v[0]) << 24) | (u32(v[1]) << 16) | (u32(v[2]) << 8) | u32(v[3]);

        // Rebind the interface's IP so subsequent outbound traffic
        // uses the leased address.
        g_interfaces[iface_index].ip = yiaddr;

        {
            arch::SerialLineGuard line;
            arch::SerialWrite("[dhcp] ACK bound ip=");
            for (u64 i = 0; i < 4; ++i)
            {
                if (i != 0)
                    arch::SerialWrite(".");
                arch::SerialWriteHex(yiaddr.octets[i]);
            }
            arch::SerialWrite(" router=");
            for (u64 i = 0; i < 4; ++i)
            {
                if (i != 0)
                    arch::SerialWrite(".");
                arch::SerialWriteHex(g_dhcp.lease.router.octets[i]);
            }
            arch::SerialWrite(" lease_secs=");
            arch::SerialWriteHex(g_dhcp.lease.lease_secs);
            arch::SerialWrite("\n");
        }
    }
}

bool DhcpStart(u32 iface_index)
{
    if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound)
        return false;
    if (g_dhcp.stage == DhcpState::Stage::Discovered)
        return false; // already in flight

    g_dhcp = {};
    g_dhcp.iface_index = iface_index;
    // Deterministic xid derived from MAC + a constant so repeated
    // starts don't reuse xid=0 (DHCP servers filter that).
    const MacAddress& mac = g_interfaces[iface_index].mac;
    g_dhcp.xid = 0xC05A0000u ^ ((u32(mac.octets[2]) << 24) | (u32(mac.octets[3]) << 16) | (u32(mac.octets[4]) << 8) |
                                u32(mac.octets[5]));
    g_dhcp.stage = DhcpState::Stage::Discovered;
    NetUdpBindRx(/*local_port=*/68, DhcpOnUdp);
    DhcpSendDiscover();
    return true;
}

DhcpLease DhcpLeaseRead()
{
    return g_dhcp.lease;
}

// ---------------------------------------------------------------
// ICMP echo-request (ping) sender + wait-state accessors.
// ---------------------------------------------------------------

bool NetIcmpSendEcho(u32 iface_index, Ipv4Address dst_ip, u16 id, u16 seq)
{
    if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound)
        return false;
    const Interface& ifc = g_interfaces[iface_index];
    const ArpEntry* arp = ArpLookup(iface_index, dst_ip);
    if (arp == nullptr)
        return false;

    // Build ethernet + IPv4 + ICMP echo request (14 + 20 + 8 + 32).
    constexpr u32 kPayloadBytes = 32;
    u8 frame[14 + 20 + 8 + kPayloadBytes];
    // Ethernet.
    for (u64 i = 0; i < 6; ++i)
        frame[i] = arp->mac.octets[i];
    for (u64 i = 0; i < 6; ++i)
        frame[6 + i] = ifc.mac.octets[i];
    frame[12] = 0x08;
    frame[13] = 0x00;
    // IPv4.
    u8* ip = frame + 14;
    ip[0] = 0x45;
    ip[1] = 0x00;
    const u16 total_len = u16(20 + 8 + kPayloadBytes);
    ip[2] = u8(total_len >> 8);
    ip[3] = u8(total_len & 0xFF);
    ip[4] = 0x00;
    ip[5] = 0x01;
    ip[6] = 0x00;
    ip[7] = 0x00;
    ip[8] = 64;
    ip[9] = kIpProtoIcmp;
    ip[10] = 0;
    ip[11] = 0;
    for (u64 i = 0; i < 4; ++i)
        ip[12 + i] = ifc.ip.octets[i];
    for (u64 i = 0; i < 4; ++i)
        ip[16 + i] = dst_ip.octets[i];
    const u16 ip_ck = Ipv4HeaderChecksum(ip, 20);
    ip[10] = u8(ip_ck >> 8);
    ip[11] = u8(ip_ck & 0xFF);
    // ICMP.
    u8* icmp = ip + 20;
    icmp[0] = 0x08; // echo request
    icmp[1] = 0x00; // code
    icmp[2] = 0;    // checksum placeholder
    icmp[3] = 0;
    icmp[4] = u8(id >> 8);
    icmp[5] = u8(id & 0xFF);
    icmp[6] = u8(seq >> 8);
    icmp[7] = u8(seq & 0xFF);
    for (u32 i = 0; i < kPayloadBytes; ++i)
        icmp[8 + i] = 0xA5;
    const u16 icmp_ck = Ipv4HeaderChecksum(icmp, 8 + kPayloadBytes);
    icmp[2] = u8(icmp_ck >> 8);
    icmp[3] = u8(icmp_ck & 0xFF);

    if (!IfaceTx(iface_index, frame, sizeof(frame)))
    {
        ++g_icmp_stats.tx_failures;
        return false;
    }
    ++g_icmp_stats.echo_requests_tx;
    return true;
}

void NetPingArm(u16 id, u16 seq)
{
    g_ping_pending = true;
    g_ping_replied = false;
    g_ping_id = id;
    g_ping_seq = seq;
    g_ping_send_ticks = NowTicks();
    g_ping_reply_ticks = 0;
}

PingResult NetPingRead()
{
    PingResult r = {};
    r.replied = g_ping_replied;
    r.rtt_ticks = g_ping_replied ? (g_ping_reply_ticks - g_ping_send_ticks) : 0;
    r.from = g_ping_reply_ip;
    return r;
}

// ---------------------------------------------------------------
// DNS client — single in-flight query, A-record only.
// ---------------------------------------------------------------

namespace
{

constinit bool g_dns_pending = false;
constinit bool g_dns_resolved = false;
constinit u16 g_dns_xid = 0;
constinit Ipv4Address g_dns_result_ip = {};
constexpr u16 kDnsEphemeralPort = 54321;

// Skip over a DNS name in the RR stream. Handles both raw label
// sequences + RFC 1035 §4.1.4 name-compression pointers (top two
// bits of a byte = 11 means "this byte + next one together form
// a 14-bit offset into the packet"). Returns the offset after
// the name, or `len` on truncation / invalid input / guard cap.
//
// Implementation lives in the Rust crate `duetos_net_parsers` —
// bounds-checked slice traversal with an explicit iteration cap.
u64 DnsSkipName(const u8* buf, u64 offset, u64 len)
{
    using ::duetos::net::parsers::duetos_parsers_dns_skip_name;
    if (buf == nullptr)
        return len;
    return static_cast<u64>(duetos_parsers_dns_skip_name(buf, static_cast<usize>(offset), static_cast<usize>(len)));
}

void DnsOnUdp(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len)
{
    (void)iface_index;
    (void)src_ip;
    (void)src_port;
    (void)dst_port;
    if (!g_dns_pending)
        return;
    if (payload == nullptr || len < 12)
        return;
    const auto* b = static_cast<const u8*>(payload);
    const u16 xid = (u16(b[0]) << 8) | u16(b[1]);
    if (xid != g_dns_xid)
        return;
    // Flags bit 15 == 1 (response). Flags bits 3..0 = RCODE.
    const u16 flags = (u16(b[2]) << 8) | u16(b[3]);
    if ((flags & 0x8000) == 0)
        return;
    if ((flags & 0x000F) != 0)
    {
        // RCODE non-zero — server says no. Leave g_dns_resolved
        // false; the shell's polling loop will time out.
        return;
    }
    const u16 qdcount = (u16(b[4]) << 8) | u16(b[5]);
    const u16 ancount = (u16(b[6]) << 8) | u16(b[7]);
    if (ancount == 0)
        return;
    // Skip QDCOUNT questions.
    u64 off = 12;
    for (u32 i = 0; i < qdcount && off < len; ++i)
    {
        off = DnsSkipName(b, off, len);
        off += 4; // QTYPE + QCLASS
    }
    // Walk answers looking for an A record.
    for (u32 i = 0; i < ancount && off + 10 <= len; ++i)
    {
        off = DnsSkipName(b, off, len);
        if (off + 10 > len)
            return;
        const u16 type = (u16(b[off]) << 8) | u16(b[off + 1]);
        const u16 rdlen = (u16(b[off + 8]) << 8) | u16(b[off + 9]);
        off += 10;
        if (off + rdlen > len)
            return;
        if (type == 0x0001 /* A */ && rdlen == 4)
        {
            Ipv4Address ip = {};
            for (u64 k = 0; k < 4; ++k)
                ip.octets[k] = b[off + k];
            g_dns_result_ip = ip;
            g_dns_resolved = true;
            return;
        }
        off += rdlen;
    }
}

// Encode `name` ("www.example.com") into DNS label format: each
// dot-separated component becomes a length byte followed by the
// component bytes; terminates with a 0 byte. Returns bytes
// written (including the terminator), or 0 on invalid input.
u32 EncodeDnsName(const char* name, u8* out, u32 cap)
{
    if (name == nullptr || out == nullptr || cap < 2)
        return 0;
    u32 w = 0;
    u32 label_start = w;
    out[w++] = 0; // placeholder for first length byte
    u32 label_len = 0;
    for (u32 i = 0;; ++i)
    {
        const char c = name[i];
        if (c == 0)
        {
            out[label_start] = u8(label_len);
            if (w >= cap)
                return 0;
            out[w++] = 0;
            return w;
        }
        if (c == '.')
        {
            if (label_len == 0 || label_len > 63)
                return 0;
            out[label_start] = u8(label_len);
            label_start = w;
            if (w >= cap)
                return 0;
            out[w++] = 0; // placeholder
            label_len = 0;
            continue;
        }
        if (w >= cap)
            return 0;
        out[w++] = u8(c);
        ++label_len;
        if (label_len > 63)
            return 0;
    }
}

} // namespace

bool NetDnsQueryA(u32 iface_index, Ipv4Address resolver_ip, const char* name)
{
    if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound || name == nullptr)
        return false;
    const Interface& ifc = g_interfaces[iface_index];

    // Resolve the L2 destination. First try direct resolver IP;
    // on miss, resolve and use the gateway.
    const ArpEntry* arp = ResolveL2Destination(iface_index, resolver_ip);
    MacAddress dst_mac = {};
    if (arp == nullptr)
        return false;
    dst_mac = arp->mac;

    // Build query.
    u8 qbuf[12 + kDnsMaxName + 2 + 4];
    // Transaction ID — xor the name's first few bytes so repeats
    // against the same name don't collide with each other's
    // in-flight answers (prev landing in current's pending slot
    // would resolve wrong).
    u16 xid = 0x1000 ^ u16(name[0]) ^ (u16(name[1]) << 4);
    if (xid == 0)
        xid = 0x1234;
    qbuf[0] = u8(xid >> 8);
    qbuf[1] = u8(xid & 0xFF);
    // Flags: RD=1 (request recursion), everything else 0.
    qbuf[2] = 0x01;
    qbuf[3] = 0x00;
    // QDCOUNT = 1, others 0.
    qbuf[4] = 0;
    qbuf[5] = 1;
    qbuf[6] = 0;
    qbuf[7] = 0;
    qbuf[8] = 0;
    qbuf[9] = 0;
    qbuf[10] = 0;
    qbuf[11] = 0;
    const u32 name_bytes = EncodeDnsName(name, qbuf + 12, kDnsMaxName);
    if (name_bytes == 0)
        return false;
    u32 qpos = 12 + name_bytes;
    // QTYPE = 1 (A), QCLASS = 1 (IN).
    qbuf[qpos++] = 0;
    qbuf[qpos++] = 1;
    qbuf[qpos++] = 0;
    qbuf[qpos++] = 1;

    g_dns_pending = true;
    g_dns_resolved = false;
    g_dns_xid = xid;
    g_dns_result_ip = {};
    NetUdpBindRx(kDnsEphemeralPort, DnsOnUdp);

    return NetUdpSend(iface_index, dst_mac, resolver_ip, /*dst_port=*/53, ifc.ip, kDnsEphemeralPort, qbuf, qpos);
}

DnsResult NetDnsResultRead()
{
    DnsResult r = {};
    r.resolved = g_dns_resolved;
    r.ip = g_dns_result_ip;
    return r;
}

// ---------------------------------------------------------------
// NTP client — one-shot query, capture Transmit Timestamp.
// ---------------------------------------------------------------

namespace
{

constinit bool g_ntp_pending = false;
constinit bool g_ntp_synced = false;
constinit NtpResult g_ntp_result = {};
constexpr u16 kNtpEphemeralPort = 32123;
// NTP epoch (1900-01-01) → Unix epoch (1970-01-01) offset in
// seconds. 70 years × 365.25 × 86400 rounded to the right value.
constexpr u64 kNtpToUnixEpochOffset = 2208988800ULL;

void NtpOnUdp(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len)
{
    (void)iface_index;
    (void)src_ip;
    (void)src_port;
    (void)dst_port;
    if (!g_ntp_pending || len < 48)
        return;
    const auto* b = static_cast<const u8*>(payload);
    // byte 0 low 3 bits = Mode; server replies are Mode 4.
    const u8 mode = b[0] & 0x07;
    if (mode != 4)
        return;
    const u8 stratum = b[1];
    // Transmit Timestamp — bytes 40..47. Top 32 bits = NTP seconds
    // since 1900, bottom 32 bits = fractional seconds.
    u64 ntp_secs = 0;
    for (u32 i = 0; i < 4; ++i)
        ntp_secs = (ntp_secs << 8) | u64(b[40 + i]);
    u32 ntp_frac = 0;
    for (u32 i = 0; i < 4; ++i)
        ntp_frac = (ntp_frac << 8) | u32(b[44 + i]);
    if (ntp_secs == 0)
        return; // unsynchronized server

    g_ntp_result.synced = true;
    g_ntp_result.unix_secs = ntp_secs - kNtpToUnixEpochOffset;
    g_ntp_result.fractional_secs = ntp_frac;
    g_ntp_result.stratum = stratum;
    g_ntp_synced = true;
}

} // namespace

bool NetNtpQuery(u32 iface_index, Ipv4Address server_ip)
{
    if (iface_index >= kMaxInterfaces || !g_interfaces[iface_index].bound)
        return false;
    const Interface& ifc = g_interfaces[iface_index];

    const ArpEntry* arp = ResolveL2Destination(iface_index, server_ip);
    MacAddress dst_mac = {};
    if (arp == nullptr)
        return false;
    dst_mac = arp->mac;

    // 48-byte NTP v3 client packet. Only byte 0 matters for a
    // query: LI=0, VN=3, Mode=3 (client) → 0x1B. Everything else
    // zero — the server ignores them.
    u8 pkt[48] = {};
    pkt[0] = 0x1B;

    g_ntp_pending = true;
    g_ntp_synced = false;
    g_ntp_result = {};
    NetUdpBindRx(kNtpEphemeralPort, NtpOnUdp);

    return NetUdpSend(iface_index, dst_mac, server_ip, /*dst_port=*/123, ifc.ip, kNtpEphemeralPort, pkt, sizeof(pkt));
}

NtpResult NetNtpResultRead()
{
    return g_ntp_result;
}

bool NetStackBindInterface(u32 iface_index, MacAddress mac, Ipv4Address ip, NetTxFn tx)
{
    if (iface_index >= kMaxInterfaces || tx == nullptr)
        return false;
    g_interfaces[iface_index].mac = mac;
    g_interfaces[iface_index].ip = ip;
    g_interfaces[iface_index].tx = tx;
    g_interfaces[iface_index].bound = true;
    g_interfaces[iface_index].counters = IfaceCounters{};
    arch::SerialWrite("[net-stack] iface ");
    arch::SerialWriteHex(iface_index);
    arch::SerialWrite(" bound ip=");
    arch::SerialWriteHex(ip.octets[0]);
    arch::SerialWrite(".");
    arch::SerialWriteHex(ip.octets[1]);
    arch::SerialWrite(".");
    arch::SerialWriteHex(ip.octets[2]);
    arch::SerialWrite(".");
    arch::SerialWriteHex(ip.octets[3]);
    arch::SerialWrite("\n");
    return true;
}

IfaceCounters InterfaceCountersRead(u32 iface_index)
{
    if (iface_index >= kMaxInterfaces)
    {
        return IfaceCounters{};
    }
    return g_interfaces[iface_index].counters;
}

void NetStackInjectRx(u32 iface_index, const void* frame, u64 len)
{
    if (frame == nullptr || len < 14)
        return;
    // Drop frames from interfaces outside our table — every L3
    // handler indexes g_interfaces[iface_index] and the per-handler
    // checks vary (ICMP guards, UDP newly guards, ARP relies on
    // ArpInsert's internal cap). One gate at the bus boundary
    // makes the invariant uniform.
    if (iface_index >= kMaxInterfaces)
        return;
    ++g_interfaces[iface_index].counters.rx_packets;
    g_interfaces[iface_index].counters.rx_bytes += len;
    const auto* eth = static_cast<const u8*>(frame);
    const u16 ether_type = (u16(eth[12]) << 8) | u16(eth[13]);
    switch (ether_type)
    {
    case kEtherTypeArp:
        (void)ArpHandleIncoming(iface_index, frame, len);
        break;
    case kEtherTypeIpv4:
        (void)Ipv4HandleIncoming(iface_index, frame, len);
        break;
    default:
        // Silently drop unknown ethertypes — no upper protocol
        // claims them. Per-ethertype counter goes to the generic
        // "rx_other_proto" bucket in IPv4 stats when it's v4-ish,
        // otherwise not tracked (v0 intentionally narrow).
        break;
    }
}

} // namespace duetos::net

// -------------------------------------------------------------------
// extern "C" shim — exposes the firewall-gated TX path to the TCP
// v1 TUs (tcp_segment.cpp). The IfaceTx helper above lives in an
// anonymous namespace; cross-TU calls go through this trampoline so
// every TCP segment runs through the same firewall + counters logic
// the rest of the stack uses.
// -------------------------------------------------------------------

extern "C" bool DuetosNetIfaceTx(::duetos::u32 iface_index, const void* frame, ::duetos::u64 frame_len)
{
    return ::duetos::net::IfaceTx(iface_index, frame, frame_len);
}
