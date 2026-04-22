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

// -------------------------------------------------------------------
// ARP cache — skeleton API.
//
// A full implementation maps IPv4 addresses to Ethernet MAC
// addresses via ARP request/reply exchange. Today the state machine
// is absent; we expose the cache surface so that a future L3 slice
// can plumb lookups and, when a cache miss happens, punt to the L2
// driver's transmit path (not yet wired either).
//
// Design constraints:
//   - Fixed-capacity cache (no per-entry heap alloc in v0).
//   - Entries carry an expiry tick — defaults to 60 seconds, refreshed
//     on any ARP reply that matches.
//   - Lookups are O(N) linear scan over the small cap. When we need
//     more entries we'll swap in an open-addressing hash.
// -------------------------------------------------------------------

inline constexpr u64 kArpCacheCap = 32;
inline constexpr u64 kArpEntryTtlTicks = 60ULL * 100; // 60 s at 100 Hz

struct ArpEntry
{
    Ipv4Address ip;
    MacAddress mac;
    u64 expiry_ticks; // 0 = slot free
    u32 iface_index;  // L2 interface the entry belongs to
};

/// Look up an ARP entry by IPv4 address on the given interface.
/// Returns nullptr on miss or expired. On hit, returns a pointer
/// into the cache (valid until the next mutating call).
const ArpEntry* ArpLookup(u32 iface_index, Ipv4Address ip);

/// Insert / refresh an ARP entry. Overwrites the matching slot if
/// present; otherwise evicts the oldest entry on the same iface.
void ArpInsert(u32 iface_index, Ipv4Address ip, MacAddress mac);

/// Process an incoming ARP packet (Ethernet + ARP payload, 42
/// bytes minimum). Skeleton: parses the header and, on a valid
/// IPv4-over-Ethernet reply, inserts into the cache. Returns
/// true if the cache was touched. The L2 RX path from the NIC
/// driver will call this once a driver actually hands us packets.
bool ArpHandleIncoming(u32 iface_index, const void* frame, u64 len);

/// Snapshot counters — boot-log + shell reporting.
struct ArpStats
{
    u64 lookups_hit;
    u64 lookups_miss;
    u64 inserts;
    u64 evictions;
    u64 rx_packets;
    u64 rx_rejects;
};
ArpStats ArpStatsRead();

// -------------------------------------------------------------------
// IPv4 header validation.
//
// Separate compute helper so both the L3 receive path and any unit
// test can share the same bit manipulation. The checksum is the
// classic 16-bit one's-complement sum over the header (options
// included); the carry folds back into the low 16 bits.
// -------------------------------------------------------------------

/// Compute the RFC 1071 16-bit one's-complement sum over a byte
/// buffer. `len` should typically be the IHL × 4 for an IPv4
/// header. The checksum field of the header must be zero when the
/// sum is computed over a packet we are generating; when validating
/// a received packet, leaving the field in place and comparing the
/// result to 0 is the correct check.
u16 Ipv4HeaderChecksum(const void* buf, u64 len);

/// Validate an IPv4 header: version=4, IHL>=5, total_length within
/// the buffer, checksum matches. Returns true iff the header passes
/// every gate. No payload parsing.
bool Ipv4HeaderValid(const void* buf, u64 len);

struct Ipv4Stats
{
    u64 rx_packets;
    u64 rx_bad_version;
    u64 rx_bad_ihl;
    u64 rx_bad_length;
    u64 rx_bad_checksum;
    u64 rx_udp;
    u64 rx_tcp;
    u64 rx_icmp;
    u64 rx_other_proto;
};

/// Process an incoming Ethernet+IPv4 frame. Returns true iff the
/// L3 path touched a counter (valid or rejected). Skeleton: we
/// validate the IPv4 header, classify the protocol, and increment
/// per-proto counters. No actual UDP/TCP/ICMP handler exists yet.
bool Ipv4HandleIncoming(u32 iface_index, const void* frame, u64 len);

Ipv4Stats Ipv4StatsRead();

} // namespace customos::net
