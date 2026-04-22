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
    // Only IPv4-over-Ethernet replies populate the cache.
    if (htype != 1 || ptype != kEtherTypeIpv4 || hlen != 6 || plen != 4)
    {
        ++g_arp_stats.rx_rejects;
        return false;
    }
    if (oper != 2 /* reply */)
    {
        // Requests don't populate our cache; a proper L2 handler
        // will enqueue a reply from here in a future slice.
        return false;
    }
    MacAddress sha = {};
    for (u64 i = 0; i < 6; ++i)
        sha.octets[i] = arp[8 + i];
    Ipv4Address spa = {};
    for (u64 i = 0; i < 4; ++i)
        spa.octets[i] = arp[14 + i];
    ArpInsert(iface_index, spa, sha);
    return true;
}

ArpStats ArpStatsRead()
{
    return g_arp_stats;
}

} // namespace customos::net
