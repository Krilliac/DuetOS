#pragma once

#include "../core/types.h"

/*
 * CustomOS — Kernel network stack, v0 skeleton.
 *
 * This is the empty surface the NIC drivers (drivers/net/) plug
 * into. No packet I/O, no state machines — just the types, the
 * layering contract, and the init entry point. A future slice
 * fills each layer in:
 *
 *   Link / L2    : Ethernet II frame parse + MAC address handling
 *   Addressing   : ARP cache + resolution
 *   Network / L3 : IPv4 header + fragmentation
 *   Transport    : UDP (minimal), TCP (full state machine)
 *   Socket       : user-facing bind/connect/send/recv API
 *
 * Each layer owns its own file when it grows past ~300 lines.
 * Today the whole skeleton lives in stack.{h,cpp} so the
 * diff for the v0 shell stays small.
 *
 * Threading model: single-CPU today; every layer is called from
 * either the NIC IRQ path (RX) or a user/kernel thread (TX).
 * When SMP comes online, the plan is:
 *   - Per-CPU RX queues fed by IRQ-directed packet steering.
 *   - Per-connection locks at the TCP layer.
 *   - ARP cache read-mostly RCU-lite.
 *
 * Context: kernel. `NetStackInit` runs once at boot after
 * `NetInit` (the driver-layer discovery). Accessors are
 * read-only after.
 */

namespace customos::net
{

// -------------------------------------------------------------------
// L2: Ethernet
// -------------------------------------------------------------------

struct MacAddress
{
    u8 octets[6];
};

struct EthernetHeader
{
    MacAddress dst;
    MacAddress src;
    u16 ether_type; // 0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6
};
static_assert(sizeof(EthernetHeader) == 14, "Ethernet header is exactly 14 bytes on the wire");

inline constexpr u16 kEtherTypeIpv4 = 0x0800;
inline constexpr u16 kEtherTypeArp = 0x0806;
inline constexpr u16 kEtherTypeIpv6 = 0x86DD;

// -------------------------------------------------------------------
// L3: IPv4
// -------------------------------------------------------------------

struct Ipv4Address
{
    u8 octets[4];
};

struct Ipv4Header
{
    u8 ver_ihl;     // high 4 = version (4), low 4 = IHL in 32-bit words
    u8 tos;         // type of service / DSCP / ECN
    u16 total_len;  // big-endian
    u16 ident;      // big-endian
    u16 flags_frag; // big-endian, 3-bit flags + 13-bit offset
    u8 ttl;
    u8 protocol; // 0x01 ICMP, 0x06 TCP, 0x11 UDP
    u16 checksum;
    Ipv4Address src;
    Ipv4Address dst;
    // Options follow iff IHL > 5.
};
static_assert(sizeof(Ipv4Header) == 20, "IPv4 fixed header is 20 bytes");

inline constexpr u8 kIpProtoIcmp = 0x01;
inline constexpr u8 kIpProtoTcp = 0x06;
inline constexpr u8 kIpProtoUdp = 0x11;

// -------------------------------------------------------------------
// L3: ARP
// -------------------------------------------------------------------

struct ArpHeader
{
    u16 htype;       // 1 = Ethernet
    u16 ptype;       // 0x0800 = IPv4
    u8 hlen;         // 6
    u8 plen;         // 4
    u16 oper;        // 1 = request, 2 = reply
    MacAddress sha;  // sender hardware (MAC)
    Ipv4Address spa; // sender protocol (IPv4)
    MacAddress tha;  // target hardware
    Ipv4Address tpa; // target protocol
};
static_assert(sizeof(ArpHeader) == 28, "ARP-over-Ethernet/IPv4 packet is 28 bytes");

// -------------------------------------------------------------------
// L4: UDP / TCP
// -------------------------------------------------------------------

struct UdpHeader
{
    u16 src_port;
    u16 dst_port;
    u16 length; // header + payload, big-endian
    u16 checksum;
};
static_assert(sizeof(UdpHeader) == 8, "UDP header is 8 bytes");

struct TcpHeader
{
    u16 src_port;
    u16 dst_port;
    u32 seq;
    u32 ack;
    u8 data_off_reserved; // high 4 = data offset in 32-bit words
    u8 flags;             // CWR ECE URG ACK PSH RST SYN FIN
    u16 window;
    u16 checksum;
    u16 urgent_ptr;
};
static_assert(sizeof(TcpHeader) == 20, "TCP fixed header is 20 bytes");

inline constexpr u8 kTcpFlagFin = 0x01;
inline constexpr u8 kTcpFlagSyn = 0x02;
inline constexpr u8 kTcpFlagRst = 0x04;
inline constexpr u8 kTcpFlagPsh = 0x08;
inline constexpr u8 kTcpFlagAck = 0x10;

// -------------------------------------------------------------------
// Stack entry point + status
// -------------------------------------------------------------------

/// Bring up the network stack. Walks the NIC table from
/// drivers/net/ and registers each link with the L2 layer. Today
/// this just logs what it would bind — actual packet I/O is
/// deferred to the first real NIC driver slice.
void NetStackInit();

/// Number of L2 interfaces the stack has bound. Matches
/// `drivers::net::NicCount()` today; will diverge when virtual
/// interfaces (loopback, tun/tap) come online.
u64 InterfaceCount();

} // namespace customos::net
