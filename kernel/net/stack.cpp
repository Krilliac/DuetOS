#include "stack.h"

#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "../core/klog.h"
#include "../core/panic.h"
#include "../drivers/net/net.h"

namespace customos::net
{

namespace
{

u64 g_interface_count = 0;

// ARP cache storage. Linear-scan lookup — 32 entries is enough
// for the handful of machines we'd realistically reach from a v0
// stack, and grows before the lookup cost matters.
ArpEntry g_arp_cache[kArpCacheCap] = {};
ArpStats g_arp_stats = {};
Ipv4Stats g_ipv4_stats = {};
IcmpStats g_icmp_stats = {};

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
};
Interface g_interfaces[kMaxInterfaces] = {};

bool IpEq(Ipv4Address a, Ipv4Address b)
{
    for (u64 i = 0; i < 4; ++i)
        if (a.octets[i] != b.octets[i])
            return false;
    return true;
}

u64 NowTicks()
{
    return arch::TimerTicks();
}

} // namespace

void NetStackInit()
{
    KLOG_TRACE_SCOPE("net/stack", "NetStackInit");
    static constinit bool s_done = false;
    KASSERT(!s_done, "net/stack", "NetStackInit called twice");
    s_done = true;

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
        u8 frame[14 + 20 + 8] = {}; // eth + ip + udp
        // Ethernet.
        for (u64 i = 0; i < 6; ++i)
            frame[i] = 0xFF; // dst = bcast
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
        if (ok && s.rx_udp == 1)
        {
            arch::SerialWrite("[ipv4] self-test OK — UDP proto counted (rx_udp=1)\n");
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
            const auto* b = static_cast<const u8*>(frame);
            for (u64 i = 0; i < len; ++i)
                s_last_tx[i] = b[i];
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
        for (u64 i = 0; i < 6; ++i)
            req[i] = 0xFF;
        for (u64 i = 0; i < 6; ++i)
            req[6 + i] = peer_mac.octets[i];
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
        for (u64 i = 0; i < 6; ++i)
            req[22 + i] = peer_mac.octets[i];
        for (u64 i = 0; i < 4; ++i)
            req[28 + i] = peer_ip.octets[i];
        // THA zeros, TPA = our test IP.
        for (u64 i = 0; i < 4; ++i)
            req[38 + i] = test_ip.octets[i];

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

const ArpEntry* ArpLookup(u32 iface_index, Ipv4Address ip)
{
    const u64 now = NowTicks();
    for (ArpEntry& e : g_arp_cache)
    {
        if (e.expiry_ticks == 0)
            continue;
        if (e.iface_index != iface_index)
            continue;
        if (!IpEq(e.ip, ip))
            continue;
        if (now >= e.expiry_ticks)
        {
            // Lazy expiry — clear the slot.
            e.expiry_ticks = 0;
            ++g_arp_stats.lookups_miss;
            return nullptr;
        }
        ++g_arp_stats.lookups_hit;
        return &e;
    }
    ++g_arp_stats.lookups_miss;
    return nullptr;
}

void ArpInsert(u32 iface_index, Ipv4Address ip, MacAddress mac)
{
    const u64 now = NowTicks();
    // First pass — refresh an existing entry if we find it.
    for (ArpEntry& e : g_arp_cache)
    {
        if (e.expiry_ticks != 0 && e.iface_index == iface_index && IpEq(e.ip, ip))
        {
            e.mac = mac;
            e.expiry_ticks = now + kArpEntryTtlTicks;
            ++g_arp_stats.inserts;
            return;
        }
    }
    // Second pass — slot into a free entry.
    for (ArpEntry& e : g_arp_cache)
    {
        if (e.expiry_ticks == 0)
        {
            e.ip = ip;
            e.mac = mac;
            e.iface_index = iface_index;
            e.expiry_ticks = now + kArpEntryTtlTicks;
            ++g_arp_stats.inserts;
            return;
        }
    }
    // Third pass — evict the entry with the soonest expiry.
    ArpEntry* victim = &g_arp_cache[0];
    for (ArpEntry& e : g_arp_cache)
    {
        if (e.expiry_ticks < victim->expiry_ticks)
            victim = &e;
    }
    victim->ip = ip;
    victim->mac = mac;
    victim->iface_index = iface_index;
    victim->expiry_ticks = now + kArpEntryTtlTicks;
    ++g_arp_stats.inserts;
    ++g_arp_stats.evictions;
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

    (void)ifc.tx(iface_index, reply, sizeof(reply));
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
    const u8 proto = ip[9];
    switch (proto)
    {
    case kIpProtoUdp:
        ++g_ipv4_stats.rx_udp;
        break;
    case kIpProtoTcp:
        ++g_ipv4_stats.rx_tcp;
        break;
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
        for (u64 i = 0; i < 6; ++i)
            reply[i] = eth[6 + i]; // dst = incoming src
        for (u64 i = 0; i < 6; ++i)
            reply[6 + i] = ifc.mac.octets[i];
        reply[12] = 0x08;
        reply[13] = 0x00;

        // Copy IPv4 header + ICMP payload.
        for (u64 i = 0; i < total_len; ++i)
            reply[14 + i] = ip[i];
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

        if (ifc.tx(iface_index, reply, reply_len))
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

bool NetStackBindInterface(u32 iface_index, MacAddress mac, Ipv4Address ip, NetTxFn tx)
{
    if (iface_index >= kMaxInterfaces || tx == nullptr)
        return false;
    g_interfaces[iface_index].mac = mac;
    g_interfaces[iface_index].ip = ip;
    g_interfaces[iface_index].tx = tx;
    g_interfaces[iface_index].bound = true;
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

void NetStackInjectRx(u32 iface_index, const void* frame, u64 len)
{
    if (frame == nullptr || len < 14)
        return;
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

} // namespace customos::net
