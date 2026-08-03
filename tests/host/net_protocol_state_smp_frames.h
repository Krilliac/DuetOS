#pragma once

#include "net/stack.h"

#include <array>

namespace duetos::net::host_test
{

inline constexpr u64 kIpv4UdpFrameBytes = 14 + 20 + 8;
inline constexpr u64 kIpv4IcmpFrameBytes = 14 + 20 + 8;
inline constexpr u64 kIpv6EmptyFrameBytes = 14 + kIpv6HeaderBytes;

inline void BuildEthernetHeader(u8* frame, u16 ether_type)
{
    constexpr u8 kDestination[6] = {0x02, 0, 0, 0, 0, 4};
    constexpr u8 kSource[6] = {0x52, 0x54, 0, 0, 0, 0x2A};
    for (u32 i = 0; i < 6; ++i)
    {
        frame[i] = kDestination[i];
        frame[6 + i] = kSource[i];
    }
    frame[12] = static_cast<u8>(ether_type >> 8);
    frame[13] = static_cast<u8>(ether_type);
}

inline void BuildIpv4Header(u8* ip, Ipv4Address src, Ipv4Address dst, u8 proto, u16 payload_bytes)
{
    ip[0] = 0x45;
    ip[1] = 0;
    const u16 total_bytes = static_cast<u16>(20 + payload_bytes);
    ip[2] = static_cast<u8>(total_bytes >> 8);
    ip[3] = static_cast<u8>(total_bytes);
    ip[4] = 0;
    ip[5] = 1;
    ip[6] = 0;
    ip[7] = 0;
    ip[8] = 64;
    ip[9] = proto;
    ip[10] = 0;
    ip[11] = 0;
    for (u32 i = 0; i < 4; ++i)
    {
        ip[12 + i] = src.octets[i];
        ip[16 + i] = dst.octets[i];
    }
    const u16 checksum = Ipv4HeaderChecksum(ip, 20);
    ip[10] = static_cast<u8>(checksum >> 8);
    ip[11] = static_cast<u8>(checksum);
}

inline std::array<u8, kIpv4UdpFrameBytes> BuildIpv4UdpFrame(Ipv4Address src, Ipv4Address dst, u16 src_port,
                                                            u16 dst_port)
{
    std::array<u8, kIpv4UdpFrameBytes> frame{};
    BuildEthernetHeader(frame.data(), kEtherTypeIpv4);
    BuildIpv4Header(frame.data() + 14, src, dst, kIpProtoUdp, 8);
    u8* udp = frame.data() + 14 + 20;
    udp[0] = static_cast<u8>(src_port >> 8);
    udp[1] = static_cast<u8>(src_port);
    udp[2] = static_cast<u8>(dst_port >> 8);
    udp[3] = static_cast<u8>(dst_port);
    udp[4] = 0;
    udp[5] = 8;
    // A zero UDP checksum is valid for IPv4.
    udp[6] = 0;
    udp[7] = 0;
    return frame;
}

inline std::array<u8, kIpv4IcmpFrameBytes> BuildIpv4IcmpEchoFrame(Ipv4Address src, Ipv4Address dst, u8 type, u16 id,
                                                                  u16 sequence)
{
    std::array<u8, kIpv4IcmpFrameBytes> frame{};
    BuildEthernetHeader(frame.data(), kEtherTypeIpv4);
    BuildIpv4Header(frame.data() + 14, src, dst, kIpProtoIcmp, 8);
    u8* icmp = frame.data() + 14 + 20;
    icmp[0] = type;
    icmp[1] = 0;
    icmp[2] = 0;
    icmp[3] = 0;
    icmp[4] = static_cast<u8>(id >> 8);
    icmp[5] = static_cast<u8>(id);
    icmp[6] = static_cast<u8>(sequence >> 8);
    icmp[7] = static_cast<u8>(sequence);
    const u16 checksum = Ipv4HeaderChecksum(icmp, 8);
    icmp[2] = static_cast<u8>(checksum >> 8);
    icmp[3] = static_cast<u8>(checksum);
    return frame;
}

inline std::array<u8, kIpv6EmptyFrameBytes> BuildIpv6EmptyFrame()
{
    std::array<u8, kIpv6EmptyFrameBytes> frame{};
    BuildEthernetHeader(frame.data(), kEtherTypeIpv6);
    const Ipv6Address src = {{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xFF, 0xFE, 0, 0, 0x2A}};
    const Ipv6Address dst = {{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}};
    constexpr u8 kNoNextHeader = 59;
    Ipv6HeaderBuild(frame.data() + 14, src, dst, kNoNextHeader, 0, 64);
    return frame;
}

} // namespace duetos::net::host_test
