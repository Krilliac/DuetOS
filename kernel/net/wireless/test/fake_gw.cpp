#include "net/wireless/test/fake_gw.h"

namespace duetos::net::wireless::test
{

namespace
{

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

constexpr u16 kEtherArp = 0x0806;
constexpr u16 kEtherIpv4 = 0x0800;
constexpr u8 kIpProtoIcmp = 1;
constexpr u8 kIpProtoUdp = 17;

void Copy(u8* d, const u8* s, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        d[i] = s[i];
}

bool Equal(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

u16 Rd16be(const u8* p)
{
    return static_cast<u16>((static_cast<u16>(p[0]) << 8) | p[1]);
}

void Wr16be(u8* p, u16 v)
{
    p[0] = static_cast<u8>(v >> 8);
    p[1] = static_cast<u8>(v & 0xFF);
}

// Standard ones-complement Internet checksum (RFC 1071).
u16 Checksum(const u8* data, u32 len)
{
    u32 sum = 0;
    for (u32 i = 0; i + 1 < len; i += 2)
        sum += (static_cast<u32>(data[i]) << 8) | data[i + 1];
    if (len & 1)
        sum += static_cast<u32>(data[len - 1]) << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<u16>(~sum & 0xFFFF);
}

// Build the 14-byte Ethernet II header (gw → client).
void EthHeader(u8* f, const u8 dst[6], const u8 src[6], u16 ethertype)
{
    Copy(f, dst, 6);
    Copy(f + 6, src, 6);
    Wr16be(f + 12, ethertype);
}

u32 BuildArpReply(const FakeGwConfig& cfg, const u8* in, u8* out)
{
    // ARP request layout: [14 eth][2 htype][2 ptype][1 hlen][1 plen]
    // [2 oper][6 SHA][4 SPA][6 THA][4 TPA].
    const u8* arp = in + 14;
    if (Rd16be(arp + 6) != 1) // oper must be request
        return 0;
    if (!Equal(arp + 24, cfg.gw_ip, 4)) // TPA == our gateway IP?
        return 0;

    EthHeader(out, in + 6, cfg.gw_mac, kEtherArp);
    u8* a = out + 14;
    Wr16be(a + 0, 1);          // htype Ethernet
    Wr16be(a + 2, kEtherIpv4); // ptype IPv4
    a[4] = 6;                  // hlen
    a[5] = 4;                  // plen
    Wr16be(a + 6, 2);          // oper = reply
    Copy(a + 8, cfg.gw_mac, 6);
    Copy(a + 14, cfg.gw_ip, 4);
    Copy(a + 18, arp + 8, 6);  // THA = requester SHA
    Copy(a + 24, arp + 14, 4); // TPA = requester SPA
    return 42;
}

u32 BuildIcmpEchoReply(const FakeGwConfig& cfg, const u8* in, u32 in_len, u8* out, u32 out_cap)
{
    const u8* ip = in + 14;
    const u32 ihl = (ip[0] & 0x0F) * 4u;
    const u16 total = Rd16be(ip + 2);
    if (ihl < 20 || 14u + total > in_len)
        return 0;
    if (ip[9] != kIpProtoIcmp || !Equal(ip + 16, cfg.gw_ip, 4))
        return 0;
    const u8* icmp = ip + ihl;
    if (14u + ihl + 8 > in_len || icmp[0] != 0x08) // echo request
        return 0;

    const u32 frame_len = 14 + total;
    if (frame_len > out_cap)
        return 0;

    EthHeader(out, in + 6, cfg.gw_mac, kEtherIpv4);
    u8* oip = out + 14;
    Copy(oip, ip, total);         // copy IP+ICMP verbatim, then fix up
    Copy(oip + 12, cfg.gw_ip, 4); // src = gateway
    Copy(oip + 16, ip + 12, 4);   // dst = original sender
    oip[8] = 64;                  // ttl
    oip[10] = 0;
    oip[11] = 0;
    Wr16be(oip + 10, Checksum(oip, ihl));

    u8* oicmp = oip + ihl;
    oicmp[0] = 0x00; // echo reply
    oicmp[2] = 0;
    oicmp[3] = 0;
    Wr16be(oicmp + 2, Checksum(oicmp, total - ihl));
    return frame_len;
}

constexpr u8 kDhcpMsgDiscover = 1;
constexpr u8 kDhcpMsgOffer = 2;
constexpr u8 kDhcpMsgRequest = 3;
constexpr u8 kDhcpMsgAck = 5;
constexpr u32 kDhcpPayload = 236 + 4 + 64; // BOOTP + magic + 64-byte option region

// Find a DHCP option in the option region [opts, opts+len).
const u8* DhcpOpt(const u8* opts, u32 len, u8 code, u8* out_len)
{
    u32 i = 0;
    while (i < len)
    {
        const u8 c = opts[i];
        if (c == 255)
            break;
        if (c == 0)
        {
            ++i;
            continue;
        }
        if (i + 1 >= len)
            break;
        const u8 l = opts[i + 1];
        if (i + 2 + l > len)
            break;
        if (c == code)
        {
            *out_len = l;
            return opts + i + 2;
        }
        i += 2 + l;
    }
    return nullptr;
}

u32 BuildDhcpReply(const FakeGwConfig& cfg, const u8* in, u32 in_len, u8* out, u32 out_cap)
{
    const u8* ip = in + 14;
    const u32 ihl = (ip[0] & 0x0F) * 4u;
    if (ip[9] != kIpProtoUdp || 14u + ihl + 8 > in_len)
        return 0;
    const u8* udp = ip + ihl;
    if (Rd16be(udp + 2) != 67) // dst port = DHCP server
        return 0;
    const u8* bootp = udp + 8;
    const u32 bootp_len = in_len - 14 - ihl - 8;
    if (bootp_len < kDhcpPayload || bootp[0] != 1 /* BOOTREQUEST */)
        return 0;
    // Magic cookie + msg-type option.
    const u8* cookie = bootp + 236;
    if (cookie[0] != 0x63 || cookie[1] != 0x82 || cookie[2] != 0x53 || cookie[3] != 0x63)
        return 0;
    u8 ol = 0;
    const u8* mt = DhcpOpt(bootp + 240, bootp_len - 240, 53, &ol);
    if (mt == nullptr || ol != 1)
        return 0;
    u8 reply_type = 0;
    if (mt[0] == kDhcpMsgDiscover)
        reply_type = kDhcpMsgOffer;
    else if (mt[0] == kDhcpMsgRequest)
        reply_type = kDhcpMsgAck;
    else
        return 0;

    const u32 frame_len = 14 + 20 + 8 + kDhcpPayload;
    if (frame_len > out_cap)
        return 0;
    for (u32 i = 0; i < frame_len; ++i)
        out[i] = 0;

    // Reply via broadcast — the client has no IP bound yet and
    // sets the BOOTP broadcast flag.
    const u8 bcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    EthHeader(out, bcast_mac, cfg.gw_mac, kEtherIpv4);

    u8* oip = out + 14;
    oip[0] = 0x45;
    Wr16be(oip + 2, static_cast<u16>(20 + 8 + kDhcpPayload));
    oip[8] = 64; // ttl
    oip[9] = kIpProtoUdp;
    Copy(oip + 12, cfg.gw_ip, 4);
    for (u32 i = 0; i < 4; ++i)
        oip[16 + i] = 0xFF; // dst = 255.255.255.255
    Wr16be(oip + 10, Checksum(oip, 20));

    u8* oudp = oip + 20;
    Wr16be(oudp + 0, 67); // src port
    Wr16be(oudp + 2, 68); // dst port
    Wr16be(oudp + 4, static_cast<u16>(8 + kDhcpPayload));
    // UDP checksum 0 (legal over IPv4; matches the stack's own TX).

    u8* bp = oudp + 8;
    bp[0] = 2;                      // BOOTREPLY
    bp[1] = 1;                      // htype Ethernet
    bp[2] = 6;                      // hlen
    Copy(bp + 4, bootp + 4, 4);     // xid echo
    Copy(bp + 16, cfg.lease_ip, 4); // yiaddr
    Copy(bp + 20, cfg.gw_ip, 4);    // siaddr
    Copy(bp + 28, bootp + 28, 6);   // chaddr echo
    u8* mc = bp + 236;
    mc[0] = 0x63;
    mc[1] = 0x82;
    mc[2] = 0x53;
    mc[3] = 0x63;

    u8* o = bp + 240;
    auto put = [&](u8 code, u8 len, const u8* val)
    {
        *o++ = code;
        *o++ = len;
        for (u8 i = 0; i < len; ++i)
            *o++ = val[i];
    };
    const u8 mta[1] = {reply_type};
    put(53, 1, mta);
    put(54, 4, cfg.gw_ip);  // server id
    put(1, 4, cfg.netmask); // subnet mask
    put(3, 4, cfg.gw_ip);   // router
    put(6, 4, cfg.gw_ip);   // DNS
    const u8 lease[4] = {static_cast<u8>(cfg.lease_secs >> 24), static_cast<u8>(cfg.lease_secs >> 16),
                         static_cast<u8>(cfg.lease_secs >> 8), static_cast<u8>(cfg.lease_secs)};
    put(51, 4, lease);
    *o = 255; // end
    return frame_len;
}

} // namespace

Result<void> FakeGwHandle(const FakeGwConfig& cfg, const u8* eth_in, u32 in_len, u8* out, u32 out_cap, u32* out_len)
{
    if (eth_in == nullptr || out == nullptr || out_len == nullptr || out_cap < 64)
        return Err{ErrorCode::InvalidArgument};
    *out_len = 0;
    if (in_len < 14)
        return Result<void>{};

    const u16 ethertype = Rd16be(eth_in + 12);
    u32 n = 0;
    if (ethertype == kEtherArp && in_len >= 42)
    {
        n = BuildArpReply(cfg, eth_in, out);
    }
    else if (ethertype == kEtherIpv4 && in_len >= 14 + 20)
    {
        const u8 proto = eth_in[14 + 9];
        if (proto == kIpProtoUdp)
            n = BuildDhcpReply(cfg, eth_in, in_len, out, out_cap);
        else if (proto == kIpProtoIcmp)
            n = BuildIcmpEchoReply(cfg, eth_in, in_len, out, out_cap);
    }
    *out_len = n;
    return Result<void>{};
}

} // namespace duetos::net::wireless::test
