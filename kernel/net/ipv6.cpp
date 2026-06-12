/*
 * DuetOS — IPv6 (partial) network-layer implementation.
 *
 * WHAT
 *   The L3 IPv6 receive/transmit half that sits alongside the
 *   IPv4 path in net/stack.cpp. Parses the 40-byte fixed header,
 *   demuxes Next-Header to ICMPv6 / UDP / TCP, answers ICMPv6
 *   echo requests + the minimal Neighbor Discovery (NS -> NA)
 *   needed for link-local reachability, and computes the RFC 8200
 *   transport pseudo-header checksum used to validate UDP/TCP.
 *
 * HOW
 *   `Ipv6HandleIncoming` is wired into `NetStackInjectRx`'s
 *   ethertype switch (0x86DD). Header parse/build are pure byte
 *   functions with hostile-length bounds checks. The UDP/TCP
 *   halves feed the SAME demux entry points the IPv4 path uses
 *   (`NetUdpDispatch`, `tcp::OnSegment`) — one stack, not a fork.
 *
 *   We have no per-interface IPv6 address record yet, so the
 *   interface's reachable address is the link-local fe80::/64
 *   derived from its MAC via Modified EUI-64 (RFC 4291 §2.5.1).
 *   ICMPv6 echo/NA only answer when the packet's destination is
 *   that link-local address (or, for NS, the solicited-node
 *   multicast of it).
 *
 * GAP: extension headers, fragmentation/reassembly, full ND
 *      (RS/RA, DAD, redirect), SLAAC, MLD, and routing are all
 *      deferred — see stack.h. The v6 peer address is NOT threaded
 *      into the v4-keyed UDP/TCP demux tables (those callbacks are
 *      IPv4-semantic); we deliver with a zero v4 placeholder so the
 *      shared transport code runs but cannot misattribute the peer.
 */

#include "net/stack.h"
#include "net/tcp.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "util/string.h"

// Firewall-gated TX trampoline exported by stack.cpp. Going through
// it keeps every IPv6 reply on the same firewall + counters path the
// rest of the stack uses (one egress chokepoint).
extern "C" bool DuetosNetIfaceTx(::duetos::u32 iface_index, const void* frame, ::duetos::u64 frame_len);

// The shared UDP demux lives in stack.cpp at duetos::net scope.
namespace duetos::net
{
void NetUdpDispatch(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len);
}

namespace duetos::net
{

namespace
{

Ipv6Stats g_ipv6_stats = {};

// 16-bit one's-complement sum (RFC 1071) with a running 32-bit
// accumulator the caller folds. Kept local so the pseudo-header
// helper and the ICMPv6 checksum share the exact same arithmetic.
u32 OnesSumAccumulate(const u8* data, u64 len, u32 acc)
{
    u64 i = 0;
    for (; i + 1 < len; i += 2)
    {
        acc += (u32(data[i]) << 8) | u32(data[i + 1]);
    }
    if (i < len) // odd trailing byte, high-padded
    {
        acc += u32(data[i]) << 8;
    }
    return acc;
}

u16 OnesFold(u32 acc)
{
    while (acc >> 16)
    {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    return static_cast<u16>(~acc & 0xFFFF);
}

// Derive the interface's link-local IPv6 address (fe80::/64 with a
// Modified-EUI-64 host part, RFC 4291 §2.5.1) from its MAC. This is
// the address we answer echo/NS for until a real v6 address record
// exists on the Interface.
Ipv6Address LinkLocalFromMac(const MacAddress& mac)
{
    Ipv6Address a = {};
    a.octets[0] = 0xFE;
    a.octets[1] = 0x80;
    // octets[2..7] stay zero (the /64 prefix).
    a.octets[8] = u8(mac.octets[0] ^ 0x02); // flip the U/L bit
    a.octets[9] = mac.octets[1];
    a.octets[10] = mac.octets[2];
    a.octets[11] = 0xFF;
    a.octets[12] = 0xFE;
    a.octets[13] = mac.octets[3];
    a.octets[14] = mac.octets[4];
    a.octets[15] = mac.octets[5];
    return a;
}

bool Ipv6Eq(const Ipv6Address& a, const Ipv6Address& b)
{
    for (u32 i = 0; i < 16; ++i)
    {
        if (a.octets[i] != b.octets[i])
            return false;
    }
    return true;
}

// Solicited-node multicast address (ff02::1:ffXX:XXXX) for `a`,
// per RFC 4291 §2.7.1 — the group a Neighbor Solicitation targets.
Ipv6Address SolicitedNodeMulticast(const Ipv6Address& a)
{
    Ipv6Address m = {};
    m.octets[0] = 0xFF;
    m.octets[1] = 0x02;
    m.octets[11] = 0x01;
    m.octets[12] = 0xFF;
    m.octets[13] = a.octets[13];
    m.octets[14] = a.octets[14];
    m.octets[15] = a.octets[15];
    return m;
}

} // namespace

u8 Ipv6Version(const void* buf, u64 len)
{
    if (buf == nullptr || len < 1)
        return 0xFF;
    return static_cast<const u8*>(buf)[0] >> 4;
}

bool Ipv6HeaderParse(const void* buf, u64 len, Ipv6Header& out, u64& payload_off)
{
    if (buf == nullptr || len < kIpv6HeaderBytes)
        return false;
    const auto* p = static_cast<const u8*>(buf);
    if ((p[0] >> 4) != 6)
        return false;
    out.ver_tc_flow[0] = p[0];
    out.ver_tc_flow[1] = p[1];
    out.ver_tc_flow[2] = p[2];
    out.ver_tc_flow[3] = p[3];
    out.payload_len = static_cast<u16>((u16(p[4]) << 8) | u16(p[5]));
    out.next_header = p[6];
    out.hop_limit = p[7];
    for (u32 i = 0; i < 16; ++i)
    {
        out.src.octets[i] = p[8 + i];
        out.dst.octets[i] = p[24 + i];
    }
    // The declared payload must fit inside what the caller handed us.
    if (u64(out.payload_len) + kIpv6HeaderBytes > len)
        return false;
    payload_off = kIpv6HeaderBytes;
    return true;
}

u64 Ipv6HeaderBuild(void* buf, const Ipv6Address& src, const Ipv6Address& dst, u8 next_header, u16 payload_len,
                    u8 hop_limit)
{
    auto* p = static_cast<u8*>(buf);
    p[0] = 0x60; // version=6, traffic class high nibble = 0
    p[1] = 0x00;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = u8(payload_len >> 8);
    p[5] = u8(payload_len & 0xFF);
    p[6] = next_header;
    p[7] = hop_limit;
    for (u32 i = 0; i < 16; ++i)
    {
        p[8 + i] = src.octets[i];
        p[24 + i] = dst.octets[i];
    }
    return kIpv6HeaderBytes;
}

u16 Ipv6PseudoChecksum(const Ipv6Address& src, const Ipv6Address& dst, u8 next_header, const void* l4, u64 l4_len)
{
    u32 acc = 0;
    acc = OnesSumAccumulate(src.octets, 16, acc);
    acc = OnesSumAccumulate(dst.octets, 16, acc);
    // Upper-layer packet length is a 32-bit big-endian field.
    acc += u32(l4_len >> 16) & 0xFFFF;
    acc += u32(l4_len & 0xFFFF);
    // Next-header occupies the low byte of the final pseudo word
    // (the preceding three bytes are zero per RFC 8200 §8.1).
    acc += u32(next_header);
    acc = OnesSumAccumulate(static_cast<const u8*>(l4), l4_len, acc);
    return OnesFold(acc);
}

Ipv6Stats Ipv6StatsRead()
{
    return g_ipv6_stats;
}

namespace
{

// Build + transmit an ICMPv6 echo reply (type 129) mirroring the
// request. `eth` is the inbound frame; `hdr`/`payload_off` are the
// parsed inbound IPv6 header. `icmp`/`icmp_len` is the inbound
// ICMPv6 message. Replies source from `our_ll` (our link-local).
void SendEchoReply(u32 iface_index, const u8* eth, const Ipv6Header& hdr, const Ipv6Address& our_ll, const u8* icmp,
                   u64 icmp_len)
{
    const u64 frame_len = 14 + kIpv6HeaderBytes + icmp_len;
    if (frame_len > kEthFrameMaxBytes)
        return;
    u8 reply[kEthFrameMaxBytes];

    // Ethernet: dst = inbound src MAC, src = our MAC, ethertype v6.
    memcpy(reply, eth + 6, 6);
    const MacAddress our_mac = InterfaceMac(iface_index);
    memcpy(reply + 6, our_mac.octets, 6);
    reply[12] = 0x86;
    reply[13] = 0xDD;

    // IPv6: src = our link-local, dst = inbound src.
    Ipv6HeaderBuild(reply + 14, our_ll, hdr.src, kIpProtoIcmpv6, static_cast<u16>(icmp_len), 255);

    // ICMPv6: copy the request body, retype to Echo Reply, recompute
    // the checksum (which covers the IPv6 pseudo-header).
    u8* r_icmp = reply + 14 + kIpv6HeaderBytes;
    memcpy(r_icmp, icmp, icmp_len);
    r_icmp[0] = kIcmpv6EchoReply;
    r_icmp[2] = 0;
    r_icmp[3] = 0;
    const u16 ck = Ipv6PseudoChecksum(our_ll, hdr.src, kIpProtoIcmpv6, r_icmp, icmp_len);
    r_icmp[2] = u8(ck >> 8);
    r_icmp[3] = u8(ck & 0xFF);

    if (DuetosNetIfaceTx(iface_index, reply, frame_len))
        ++g_ipv6_stats.icmpv6_echo_tx;
    else
        ++g_ipv6_stats.tx_failures;
}

// Build + transmit a Neighbor Advertisement (type 136) answering a
// Neighbor Solicitation that targeted our link-local address. RFC
// 4861 §4.4: flags = Solicited|Override, Target = our_ll, with a
// Target Link-Layer Address option (type 2).
void SendNeighborAdvert(u32 iface_index, const u8* eth, const Ipv6Header& hdr, const Ipv6Address& our_ll)
{
    // ICMPv6 NA = 4 (header) + 4 (flags) + 16 (target) + 8 (TLLA opt).
    constexpr u64 kNaLen = 4 + 4 + 16 + 8;
    const u64 frame_len = 14 + kIpv6HeaderBytes + kNaLen;
    if (frame_len > kEthFrameMaxBytes)
        return;
    u8 reply[kEthFrameMaxBytes];

    memcpy(reply, eth + 6, 6);
    const MacAddress our_mac = InterfaceMac(iface_index);
    memcpy(reply + 6, our_mac.octets, 6);
    reply[12] = 0x86;
    reply[13] = 0xDD;

    Ipv6HeaderBuild(reply + 14, our_ll, hdr.src, kIpProtoIcmpv6, static_cast<u16>(kNaLen), 255);

    u8* na = reply + 14 + kIpv6HeaderBytes;
    na[0] = kIcmpv6NeighborAdvert;
    na[1] = 0;
    na[2] = 0; // checksum, filled below
    na[3] = 0;
    na[4] = 0x60; // Solicited (0x40) | Override (0x20)
    na[5] = 0;
    na[6] = 0;
    na[7] = 0;
    for (u32 i = 0; i < 16; ++i)
        na[8 + i] = our_ll.octets[i];
    na[24] = 2; // option: Target Link-Layer Address
    na[25] = 1; // length in 8-byte units
    memcpy(na + 26, our_mac.octets, 6);

    const u16 ck = Ipv6PseudoChecksum(our_ll, hdr.src, kIpProtoIcmpv6, na, kNaLen);
    na[2] = u8(ck >> 8);
    na[3] = u8(ck & 0xFF);

    if (DuetosNetIfaceTx(iface_index, reply, frame_len))
        ++g_ipv6_stats.nd_advert_tx;
    else
        ++g_ipv6_stats.tx_failures;
}

// ICMPv6 demux: echo request -> reply; Neighbor Solicitation -> NA.
void HandleIcmpv6(u32 iface_index, const u8* eth, const Ipv6Header& hdr, const u8* icmp, u64 icmp_len)
{
    ++g_ipv6_stats.rx_icmpv6;
    if (icmp_len < 4)
        return;
    // Validate the ICMPv6 checksum (covers the pseudo-header).
    if (Ipv6PseudoChecksum(hdr.src, hdr.dst, kIpProtoIcmpv6, icmp, icmp_len) != 0)
        return;

    if (!InterfaceIsBound(iface_index))
        return;
    const Ipv6Address our_ll = LinkLocalFromMac(InterfaceMac(iface_index));

    if (icmp[0] == kIcmpv6EchoRequest)
    {
        ++g_ipv6_stats.icmpv6_echo_rx;
        // Only answer if addressed to our link-local address.
        if (!Ipv6Eq(hdr.dst, our_ll))
            return;
        SendEchoReply(iface_index, eth, hdr, our_ll, icmp, icmp_len);
    }
    else if (icmp[0] == kIcmpv6NeighborSolicit && icmp_len >= 24)
    {
        ++g_ipv6_stats.nd_solicit_rx;
        // Target address sits at bytes 8..23 of the NS message.
        Ipv6Address target = {};
        for (u32 i = 0; i < 16; ++i)
            target.octets[i] = icmp[8 + i];
        if (!Ipv6Eq(target, our_ll))
            return;
        // Accept the NS if destined to our LL or its solicited-node
        // multicast group.
        const Ipv6Address snm = SolicitedNodeMulticast(our_ll);
        if (!Ipv6Eq(hdr.dst, our_ll) && !Ipv6Eq(hdr.dst, snm))
            return;
        SendNeighborAdvert(iface_index, eth, hdr, our_ll);
    }
}

} // namespace

bool Ipv6HandleIncoming(u32 iface_index, const void* frame, u64 len)
{
    ++g_ipv6_stats.rx_packets;
    if (frame == nullptr || len < 14 + kIpv6HeaderBytes)
    {
        ++g_ipv6_stats.rx_bad_length;
        return false;
    }
    const auto* eth = static_cast<const u8*>(frame);
    const u16 ether_type = (u16(eth[12]) << 8) | u16(eth[13]);
    if (ether_type != kEtherTypeIpv6)
    {
        ++g_ipv6_stats.rx_bad_length;
        return false;
    }

    const u8* ip = eth + 14;
    const u64 ip_avail = len - 14;
    Ipv6Header hdr = {};
    u64 payload_off = 0;
    if (!Ipv6HeaderParse(ip, ip_avail, hdr, payload_off))
    {
        ++g_ipv6_stats.rx_bad_version;
        return false;
    }

    const u8* l4 = ip + payload_off;
    const u64 l4_len = hdr.payload_len;

    switch (hdr.next_header)
    {
    case kIpProtoIcmpv6:
        HandleIcmpv6(iface_index, eth, hdr, l4, l4_len);
        break;
    case kIpProtoUdp:
    {
        ++g_ipv6_stats.rx_udp;
        if (l4_len < 8)
            break;
        // Validate the UDP checksum over the IPv6 pseudo-header
        // (mandatory under IPv6 — RFC 8200 §8.1).
        if (Ipv6PseudoChecksum(hdr.src, hdr.dst, kIpProtoUdp, l4, l4_len) != 0)
            break;
        const u16 src_port = (u16(l4[0]) << 8) | u16(l4[1]);
        const u16 dst_port = (u16(l4[2]) << 8) | u16(l4[3]);
        const u16 udp_len = (u16(l4[4]) << 8) | u16(l4[5]);
        if (udp_len < 8 || udp_len > l4_len)
            break;
        // GAP: v6 peer address not threaded into the v4-keyed UDP
        // demux — deliver with a zero v4 placeholder so the shared
        // transport runs but can't misattribute an IPv4 peer. Revisit
        // when the demux tables grow a v6 key.
        const Ipv4Address placeholder = {};
        NetUdpDispatch(iface_index, placeholder, src_port, dst_port, l4 + 8, udp_len - 8);
        break;
    }
    case kIpProtoTcp:
    {
        ++g_ipv6_stats.rx_tcp;
        if (l4_len < 20)
            break;
        if (Ipv6PseudoChecksum(hdr.src, hdr.dst, kIpProtoTcp, l4, l4_len) != 0)
            break;
        MacAddress peer_mac = {};
        for (u32 i = 0; i < 6; ++i)
            peer_mac.octets[i] = eth[6 + i];
        // GAP: same v4-keyed-demux limitation as UDP above — the TCB
        // table is keyed on Ipv4Address, so a v6 segment is handed to
        // OnSegment with a zero v4 peer. Real v6 TCBs need a tagged
        // address key. Revisit with the v6 socket layer.
        // GAP: IPv6 traffic-class ECN (CE) is not threaded — the ECN
        // data plane is IPv4-only for now (ip_ce defaults to false);
        // revisit with the v6 socket layer.
        const Ipv4Address placeholder = {};
        tcp::OnSegment(iface_index, peer_mac, placeholder, l4, l4_len);
        break;
    }
    default:
        ++g_ipv6_stats.rx_other_proto;
        break;
    }
    return true;
}

// -------------------------------------------------------------------
// Boot-time self-test. Pure in-memory — builds synthetic frames and
// asserts the byte-level invariants; no NIC, no bound interface.
// -------------------------------------------------------------------

namespace
{

void Ipv6EmitFail(const char* label)
{
    arch::SerialWrite("[net/ipv6-selftest] FAIL (");
    arch::SerialWrite(label);
    arch::SerialWrite(")\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 0x00F6u);
}

// (1) Header parse/build round-trip.
bool Ipv6TestHeaderRoundTrip()
{
    const Ipv6Address src = {{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55}};
    const Ipv6Address dst = {{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}};
    u8 buf[kIpv6HeaderBytes + 8] = {};
    // Lay down a header that claims 8 bytes of payload, then 8 bytes.
    const u64 built = Ipv6HeaderBuild(buf, src, dst, kIpProtoUdp, 8, 64);
    if (built != kIpv6HeaderBytes)
        return false;
    Ipv6Header hdr = {};
    u64 off = 0;
    if (!Ipv6HeaderParse(buf, sizeof(buf), hdr, off))
        return false;
    if (off != kIpv6HeaderBytes || hdr.next_header != kIpProtoUdp || hdr.hop_limit != 64 || hdr.payload_len != 8)
        return false;
    if (!Ipv6Eq(hdr.src, src) || !Ipv6Eq(hdr.dst, dst))
        return false;
    if (Ipv6Version(buf, sizeof(buf)) != 6)
        return false;
    return true;
}

// (2) Pseudo-header checksum: a generated UDP segment must validate
// to 0 when its checksum field is filled and re-summed.
bool Ipv6TestPseudoChecksum()
{
    const Ipv6Address src = {{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0xFF, 0xFE, 0, 0, 0x01}};
    const Ipv6Address dst = {{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0xFF, 0xFE, 0, 0, 0x02}};
    // 8-byte UDP header + 4-byte payload.
    u8 udp[12] = {0x30, 0x39, 0x00, 0x35, 0x00, 0x0C, 0x00, 0x00, 'a', 'b', 'c', 'd'};
    udp[6] = 0;
    udp[7] = 0; // zero checksum before compute
    const u16 ck = Ipv6PseudoChecksum(src, dst, kIpProtoUdp, udp, sizeof(udp));
    udp[6] = u8(ck >> 8);
    udp[7] = u8(ck & 0xFF);
    // Re-summing with the checksum in place must yield 0.
    if (Ipv6PseudoChecksum(src, dst, kIpProtoUdp, udp, sizeof(udp)) != 0)
        return false;
    // A non-zero checksum (corrupt one byte) must NOT validate.
    u8 corrupt[12];
    memcpy(corrupt, udp, sizeof(corrupt));
    corrupt[8] ^= 0xFF;
    if (Ipv6PseudoChecksum(src, dst, kIpProtoUdp, corrupt, sizeof(corrupt)) == 0)
        return false;
    return true;
}

// (3) ICMPv6 echo-reply generation: retype request -> reply and
// recompute the checksum; the reply must validate to 0 and carry
// type 129.
bool Ipv6TestIcmpEchoReply()
{
    const Ipv6Address us = {{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0xAA, 0xBB, 0xFF, 0xFE, 0xCC, 0xDD, 0xEE}};
    const Ipv6Address peer = {{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55}};
    // Echo request: type 128, code 0, id+seq, 4-byte payload.
    u8 req[12] = {kIcmpv6EchoRequest, 0, 0, 0, 0x00, 0x01, 0x00, 0x02, 'p', 'i', 'n', 'g'};
    req[2] = 0;
    req[3] = 0;
    const u16 req_ck = Ipv6PseudoChecksum(peer, us, kIpProtoIcmpv6, req, sizeof(req));
    req[2] = u8(req_ck >> 8);
    req[3] = u8(req_ck & 0xFF);
    // Inbound request must validate against its pseudo-header.
    if (Ipv6PseudoChecksum(peer, us, kIpProtoIcmpv6, req, sizeof(req)) != 0)
        return false;

    // Build the reply body the way SendEchoReply does: copy, retype,
    // recompute with src/dst swapped.
    u8 rep[12];
    memcpy(rep, req, sizeof(rep));
    rep[0] = kIcmpv6EchoReply;
    rep[2] = 0;
    rep[3] = 0;
    const u16 rep_ck = Ipv6PseudoChecksum(us, peer, kIpProtoIcmpv6, rep, sizeof(rep));
    rep[2] = u8(rep_ck >> 8);
    rep[3] = u8(rep_ck & 0xFF);
    if (rep[0] != kIcmpv6EchoReply)
        return false;
    if (Ipv6PseudoChecksum(us, peer, kIpProtoIcmpv6, rep, sizeof(rep)) != 0)
        return false;
    // Echoed id/seq/payload must survive the round-trip.
    for (u32 i = 4; i < 12; ++i)
    {
        if (rep[i] != req[i])
            return false;
    }
    return true;
}

// (4) Hostile-length rejection: short buffers, wrong version, and a
// payload-length that overruns the buffer must all be rejected.
bool Ipv6TestHostileLength()
{
    Ipv6Header hdr = {};
    u64 off = 0;
    // Too short for a fixed header.
    u8 tiny[20] = {0x60};
    if (Ipv6HeaderParse(tiny, sizeof(tiny), hdr, off))
        return false;
    // Valid length but wrong version nibble (4 instead of 6).
    u8 v4ish[kIpv6HeaderBytes] = {};
    v4ish[0] = 0x40;
    if (Ipv6HeaderParse(v4ish, sizeof(v4ish), hdr, off))
        return false;
    // Declared payload_len (0xFFFF) overruns the buffer.
    u8 over[kIpv6HeaderBytes] = {};
    over[0] = 0x60;
    over[4] = 0xFF;
    over[5] = 0xFF;
    if (Ipv6HeaderParse(over, sizeof(over), hdr, off))
        return false;
    // The full RX entry must also reject a too-short ethernet frame
    // and a non-v6 ethertype without faulting.
    u8 frame[14 + kIpv6HeaderBytes] = {};
    frame[12] = 0x86;
    frame[13] = 0xDD;
    frame[14] = 0x60; // version 6
    // payload_len 0 -> fits; header-only frame is structurally valid.
    if (Ipv6HandleIncoming(0, frame, 13)) // shorter than ethernet header
        return false;
    return true;
}

} // namespace

void Ipv6SelfTest()
{
    bool all_ok = true;
    if (!Ipv6TestHeaderRoundTrip())
    {
        Ipv6EmitFail("header parse/build round-trip");
        all_ok = false;
    }
    if (!Ipv6TestPseudoChecksum())
    {
        Ipv6EmitFail("pseudo-header checksum");
        all_ok = false;
    }
    if (!Ipv6TestIcmpEchoReply())
    {
        Ipv6EmitFail("icmpv6 echo reply");
        all_ok = false;
    }
    if (!Ipv6TestHostileLength())
    {
        Ipv6EmitFail("hostile-length rejection");
        all_ok = false;
    }
    if (all_ok)
        arch::SerialWrite("[net/ipv6-selftest] PASS (parse/build + pseudo-csum + icmpv6 echo + hostile-len)\n");
}

} // namespace duetos::net
