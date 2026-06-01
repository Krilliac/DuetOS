#pragma once

#include "util/types.h"

/*
 * DuetOS — Kernel network stack, v0 skeleton.
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

namespace duetos::net
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

// Maximum Ethernet frame this v0 stack accepts: 14-byte header +
// 1500-byte standard MTU payload. Used as the RX bounds clamp and
// as the size of on-stack frame scratch buffers in the L3/TCP
// paths. Single definition so the RX clamp, the ICMP reply cap,
// and every `u8 frame[...]` scratch buffer cannot drift apart.
inline constexpr u64 kEthFrameMaxBytes = 1514;

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
// L3: IPv6 (partial — see net/ipv6.cpp).
//
// v0 scope: 40-byte fixed-header parse + build, ICMPv6 echo
// reply, the minimal Neighbor Discovery (NS -> NA) needed for
// link-local reachability, and the IPv6 pseudo-header checksum
// used to validate/generate UDP and TCP transport. Next-Header
// is demuxed to ICMPv6 / UDP / TCP and the UDP/TCP halves feed
// the EXISTING v4-keyed demux (one stack — see ipv6.cpp for the
// honest GAP on the peer-address threading).
//
// GAP: extension headers (Hop-by-Hop, Routing, Fragment, Dest
//      Options), fragmentation/reassembly, full ND (Router
//      Solicit/Advert, DAD, redirect), SLAAC, MLD, and routing
//      are all deferred — revisit when a real v6 socket layer
//      and on-link prefix model land.
// -------------------------------------------------------------------

struct Ipv6Address
{
    u8 octets[16];
};

// IPv6 fixed header (RFC 8200 §3). The first 32 bits pack
// version (4b) / traffic-class (8b) / flow-label (20b); we keep
// them as a big-endian word and only read the version nibble.
struct Ipv6Header
{
    u8 ver_tc_flow[4]; // big-endian: version | traffic class | flow label
    u16 payload_len;   // big-endian, length after this 40-byte header
    u8 next_header;    // 58 ICMPv6, 6 TCP, 17 UDP
    u8 hop_limit;
    Ipv6Address src;
    Ipv6Address dst;
};
static_assert(sizeof(Ipv6Header) == 40, "IPv6 fixed header is 40 bytes");

inline constexpr u64 kIpv6HeaderBytes = 40;
inline constexpr u8 kIpProtoIcmpv6 = 58;

// ICMPv6 message types we act on (RFC 4443 / RFC 4861).
inline constexpr u8 kIcmpv6EchoRequest = 128;
inline constexpr u8 kIcmpv6EchoReply = 129;
inline constexpr u8 kIcmpv6NeighborSolicit = 135;
inline constexpr u8 kIcmpv6NeighborAdvert = 136;

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

/// True iff `NetStackBindInterface` has run for `iface_index`. The
/// driver-layer NIC table can have entries that aren't bound here
/// (probe-only NICs whose vendor driver isn't done yet).
bool InterfaceIsBound(u32 iface_index);

/// Bound IPv4 address for `iface_index`. Returns 0.0.0.0 if not
/// bound or if DHCP hasn't completed yet (the iface is bound with
/// 0.0.0.0 at NIC bring-up so DHCP DISCOVER goes out with the
/// correct src=0.0.0.0).
Ipv4Address InterfaceIp(u32 iface_index);

/// Bound MAC for `iface_index`. Returns all-zero MAC if unbound.
MacAddress InterfaceMac(u32 iface_index);

/// Per-interface byte/packet counters. Bumped by the L2 RX
/// path (`NetStackInjectRx`) and the L3 TX helper (`IfaceTx`).
/// Read access is unprivileged — the Network Status app polls
/// these to render per-iface throughput and the firewall app
/// uses them to contextualise per-rule hit counters.
struct IfaceCounters
{
    u64 rx_packets;
    u64 rx_bytes;
    u64 tx_packets;
    u64 tx_bytes;
    u64 tx_dropped_firewall;
    u64 tx_dropped_unbound;
};

IfaceCounters InterfaceCountersRead(u32 iface_index);

/// Number of currently-cached, non-expired ARP entries. Useful for
/// shell `ifconfig` / `route` to indicate L2 reachability without
/// dumping the whole table.
u32 ArpEntryCount();

// -------------------------------------------------------------------
// ARP cache — skeleton API.
//
// A full implementation maps IPv4 addresses to Ethernet MAC
// addresses via ARP request/reply exchange. v0 includes cache
// lookups/inserts plus a minimal "send request + wait briefly"
// miss path used by DNS/TCP/NTP destination resolution.
//
// Design constraints:
//   - Fixed-capacity cache (no per-entry heap alloc in v0).
//   - Entries carry an expiry tick — defaults to 60 seconds, refreshed
//     on any ARP reply that matches.
//   - Lookup is O(chain length) — entries are threaded through hash
//     buckets keyed on (iface_index, ip). At cap 32 / 64 buckets the
//     average chain length is ~0.5; worst case under a degenerate
//     hash is still bounded by the cap.
// -------------------------------------------------------------------

inline constexpr u64 kArpCacheCap = 32;
inline constexpr u64 kArpHashSize = 64;               ///< Power of two; 2x the cache cap.
inline constexpr u8 kArpEntryNone = 0xFF;             ///< End-of-chain sentinel.
inline constexpr u64 kArpEntryTtlTicks = 60ULL * 100; // 60 s at 100 Hz

struct ArpEntry
{
    Ipv4Address ip;
    MacAddress mac;
    u64 expiry_ticks; // 0 = slot free
    u32 iface_index;  // L2 interface the entry belongs to
    u8 next_idx;      // chain link: index into g_arp_cache, or kArpEntryNone for tail
    u8 _pad[3];
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
    u64 tx_requests;
    u64 tx_failures;
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
/// L3 path touched a counter (valid or rejected). Validates the
/// IPv4 header, classifies the protocol, updates per-proto
/// counters, and for ICMP echo requests builds + transmits a
/// matching echo reply via the registered TX hook.
bool Ipv4HandleIncoming(u32 iface_index, const void* frame, u64 len);

Ipv4Stats Ipv4StatsRead();

// -------------------------------------------------------------------
// NIC driver interface.
//
// Drivers call `NetStackBindInterface` once per NIC at bring-up
// time, passing their MAC, an IPv4 address to advertise, and a
// transmit trampoline. The stack then owns L2/L3 protocol
// handling: the driver's RX path just forwards raw ethernet
// frames via `NetStackInjectRx`, and protocol handlers reply
// through the bound TX trampoline.
//
// `NetTxFn` must be safe to call from the driver's RX task
// context (not from IRQ). Returns true on successful
// enqueue, false on ring-full / driver-not-ready.
// -------------------------------------------------------------------

using NetTxFn = bool (*)(u32 iface_index, const void* frame, u64 len);

/// Bind a NIC to the stack. `iface_index` must be < InterfaceCount().
/// `tx` is the driver's send trampoline. `mac` is the local MAC
/// (used as Ethernet src on every transmitted frame). `ip` is the
/// IPv4 address the stack will respond to for ARP / ICMP. Returns
/// false if iface_index is out of range or tx is null.
bool NetStackBindInterface(u32 iface_index, MacAddress mac, Ipv4Address ip, NetTxFn tx);

/// Inject a raw ethernet frame received by the NIC. The stack
/// parses the ethertype and dispatches to ARP or IPv4. Safe to
/// call from the driver's RX task. No-op when iface_index isn't
/// bound or no handler matches.
void NetStackInjectRx(u32 iface_index, const void* frame, u64 len);

struct IcmpStats
{
    u64 echo_requests_rx;
    u64 echo_replies_tx;
    u64 tx_failures;
    u64 echo_requests_tx;
    u64 echo_replies_rx;
};
IcmpStats IcmpStatsRead();

/// Send one ICMP echo request to `dst_ip` via `iface_index`. Uses
/// the ARP cache to resolve the peer's MAC — fails if the cache
/// doesn't have an entry (caller should arrange learning first;
/// every IPv4 RX auto-inserts, so pinging something we've already
/// received a packet from always succeeds). `id` + `seq` are
/// echoed back by the peer so the sender can match the reply.
/// Payload is 32 bytes of 0xA5 for easy visual identification.
bool NetIcmpSendEcho(u32 iface_index, Ipv4Address dst_ip, u16 id, u16 seq);

struct PingResult
{
    bool replied;
    u64 rtt_ticks; // scheduler ticks between send + reply
    Ipv4Address from;
};

/// Record the outgoing ID/seq so the RX path can match a reply.
/// Intended as a one-shot — caller sends, sleeps, reads.
void NetPingArm(u16 id, u16 seq);

/// Poll the pending-reply state set by NetPingArm + an incoming
/// echo reply. `replied` is true iff NetPingArm was called and
/// a matching reply landed.
PingResult NetPingRead();

// -------------------------------------------------------------------
// DNS client (RFC 1035 subset — A-record queries only).
//
// Single in-flight query at a time. `NetDnsQueryA` sends a UDP
// packet to the configured resolver and registers an ephemeral
// port callback; the RX path parses the answer section for the
// first A-record + stashes it. `NetDnsResultRead` polls the
// resolution state.
// -------------------------------------------------------------------

inline constexpr u32 kDnsMaxName = 253;

struct DnsResult
{
    bool resolved;
    Ipv4Address ip;
};

/// Send a DNS A-record query for `name` (NUL-terminated, max
/// kDnsMaxName chars) via `iface_index`. `resolver_ip` is the
/// DNS server (typically the DHCP-supplied value or 10.0.2.3 for
/// QEMU SLIRP). Returns false on oversized name, malformed
/// labels, interface missing, or unresolved L2 destination
/// after direct ARP + gateway fallback attempts.
bool NetDnsQueryA(u32 iface_index, Ipv4Address resolver_ip, const char* name);

/// Snapshot of the latest DNS query state. `resolved` is true
/// iff the RX path parsed a matching A-record since the last
/// NetDnsQueryA. Callers should read this after polling for
/// reply arrival.
DnsResult NetDnsResultRead();

// -------------------------------------------------------------------
// NTP client (RFC 5905 subset — one-shot Transmit Timestamp read).
//
// Sends a 48-byte NTP v3 client packet and on reply captures the
// server's Transmit Timestamp. Converted from NTP epoch (1900) to
// Unix epoch (1970) by subtracting 2208988800. Does not attempt
// to write the RTC hardware — the result is exposed for callers
// that want a wall-clock synchronization source.
// -------------------------------------------------------------------

struct NtpResult
{
    bool synced;
    u64 unix_secs;       // seconds since 1970-01-01 UTC
    u32 fractional_secs; // NTP fraction (u32 fixed-point)
    u8 stratum;
};

/// Send one NTP v3 client query to `server_ip:123`. Binds an
/// ephemeral UDP port for the reply. Returns false on iface
/// binding miss or unresolved L2 destination after ARP
/// attempts.
bool NetNtpQuery(u32 iface_index, Ipv4Address server_ip);

/// Snapshot of the latest NTP transaction. `synced` is true iff
/// the server replied with a non-zero Transmit Timestamp.
NtpResult NetNtpResultRead();

// -------------------------------------------------------------------
// UDP send + receive dispatch.
//
// v0 design: a small registration table (capped at kUdpBindingsMax)
// maps local UDP ports to callbacks. `NetUdpBindRx` registers a
// handler; `NetStackInjectRx → Ipv4HandleIncoming → UDP dispatch`
// delivers every matching datagram. `NetUdpSend` builds an
// ethernet+IPv4+UDP frame from the given fields and pushes it out
// via the interface's bound TX trampoline. Checksums are computed
// per RFC 768 (UDP; the UDP checksum field is optional over IPv4
// but we always emit one for peers that require it).
// -------------------------------------------------------------------

inline constexpr u32 kUdpBindingsMax = 8;

using UdpRxFn = void (*)(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len);

/// Bind a local UDP port to a receive handler. The handler fires
/// from the driver's RX task context (never from IRQ). Returns
/// false if the bindings table is full or the port is already
/// claimed. A zero handler unbinds the port.
bool NetUdpBindRx(u16 local_port, UdpRxFn handler);

/// Build + transmit a UDP datagram. Fills in ethernet, IPv4, UDP
/// headers from interface state + caller args, computes
/// checksums, pushes via the interface's TX trampoline. `dst_mac`
/// is used verbatim — caller resolves ARP or passes broadcast
/// (0xFF × 6) for DHCP / link-local. Returns false if the
/// interface isn't bound or the frame exceeds the wire MTU.
bool NetUdpSend(u32 iface_index, const MacAddress& dst_mac, Ipv4Address dst_ip, u16 dst_port, Ipv4Address src_ip,
                u16 src_port, const void* payload, u64 payload_len);

struct UdpStats
{
    u64 rx_packets;
    u64 rx_no_port;
    u64 tx_packets;
    u64 tx_failures;
};
UdpStats UdpStatsRead();

// -------------------------------------------------------------------
// DHCP client (RFC 2131, subset).
//
// Runs one DHCP transaction per interface on request:
//   DISCOVER → (wait for OFFER) → REQUEST → (wait for ACK) → bind
// On ACK, the interface's IP is rebound to the offered yiaddr and
// the ARP cache is seeded with the server's MAC. No lease
// renewal in v0 — the lease timer is recorded but not acted on.
// -------------------------------------------------------------------

struct DhcpLease
{
    bool valid;
    Ipv4Address ip;
    Ipv4Address router;
    Ipv4Address dns;
    Ipv4Address server;
    u32 lease_secs;
};

/// Kick off a DHCP transaction on `iface_index`. Non-blocking —
/// state advances inside the stack's UDP receive callbacks as
/// OFFER / ACK arrive. Safe to call after `NetStackBindInterface`
/// has run with a placeholder IP (typically 0.0.0.0). Returns
/// false on already-in-progress or missing binding.
bool DhcpStart(u32 iface_index);

/// Active lease across all interfaces: the first valid lease scanning
/// from iface 0 upward (so the wired NIC wins when it has one). For
/// UI / shell / syscall consumers that just want "the IP this box is
/// using." Returns an invalid lease if no interface is bound.
DhcpLease DhcpLeaseRead();

/// Lease snapshot for a SPECIFIC `iface_index`. `valid` is true only
/// after a DHCP ACK bound a new IP on that interface. DHCP state is
/// per-interface, so each NIC's lease is independent — callers that
/// transmit on a particular NIC (net-smoke, ARP gateway resolution)
/// must read the iface they send on, not the active-lease scan.
/// Out-of-range indices return an invalid lease.
DhcpLease DhcpLeaseRead(u32 iface_index);

// -------------------------------------------------------------------
// TCP. The full multi-connection TCB state machine + retransmit +
// reassembly + sliding window lives in net/tcp.{h,cpp}. This header
// no longer exposes a v0 single-slot surface — every caller goes
// through the socket layer (net/socket.{h,cpp}) or directly through
// the tcp:: namespace.
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// IPv6 protocol surface (implementation in net/ipv6.cpp).
// -------------------------------------------------------------------

/// Read the version nibble from an IPv6 fixed header laid out at
/// `buf` (>= 40 bytes). Returns 6 for a valid header, 0xFF if the
/// buffer is too short to read the first byte.
u8 Ipv6Version(const void* buf, u64 len);

/// Parse a 40-byte IPv6 fixed header from `buf` into `out`. Bounds-
/// checked: returns false if `len` < 40, the version nibble != 6,
/// or the declared payload length overruns the buffer. On success
/// `payload_off` is set to 40 (start of the next header) and the
/// caller can read `out.payload_len` bytes after it.
bool Ipv6HeaderParse(const void* buf, u64 len, Ipv6Header& out, u64& payload_off);

/// Build a 40-byte IPv6 fixed header into `buf` (must be >= 40
/// bytes). version=6, traffic class / flow label = 0. Returns the
/// header size (40) written.
u64 Ipv6HeaderBuild(void* buf, const Ipv6Address& src, const Ipv6Address& dst, u8 next_header, u16 payload_len,
                    u8 hop_limit);

/// RFC 8200 §8.1 transport pseudo-header checksum over an IPv6
/// {src, dst, upper-layer length, next-header} prefix followed by
/// the L4 segment `l4`/`l4_len`. The L4 checksum field must be
/// zeroed in `l4` before calling when generating; when validating
/// a received segment, leave it in place and compare the result
/// to 0. Folds carries per RFC 1071.
u16 Ipv6PseudoChecksum(const Ipv6Address& src, const Ipv6Address& dst, u8 next_header, const void* l4, u64 l4_len);

struct Ipv6Stats
{
    u64 rx_packets;
    u64 rx_bad_length;
    u64 rx_bad_version;
    u64 rx_icmpv6;
    u64 rx_udp;
    u64 rx_tcp;
    u64 rx_other_proto;
    u64 icmpv6_echo_rx;
    u64 icmpv6_echo_tx;
    u64 nd_solicit_rx;
    u64 nd_advert_tx;
    u64 tx_failures;
};

Ipv6Stats Ipv6StatsRead();

/// Process an incoming Ethernet+IPv6 frame (ethertype 0x86DD).
/// Validates the fixed header, demuxes Next-Header to ICMPv6 / UDP
/// / TCP, replies to ICMPv6 echo requests and Neighbor
/// Solicitations targeting a bound interface, and verifies the
/// transport pseudo-header checksum before handing UDP/TCP to the
/// shared demux. Returns true iff a counter was touched.
bool Ipv6HandleIncoming(u32 iface_index, const void* frame, u64 len);

/// Boot-time IPv6 self-test. Builds synthetic frames in memory and
/// asserts header parse/build round-trip, ICMPv6 echo-reply
/// generation, pseudo-header checksum, and hostile-length
/// rejection. Emits `[net/ipv6-selftest] PASS (...)`. Called from
/// the net self-test entry (net/tcp_selftest.cpp).
void Ipv6SelfTest();

} // namespace duetos::net
