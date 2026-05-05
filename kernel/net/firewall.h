#pragma once

#include "net/stack.h"
#include "util/types.h"

/*
 * DuetOS firewall — v0.
 *
 * A static rule table with first-match-wins evaluation and
 * configurable default policies per direction. Hooks live at
 * IPv4 ingress (`Ipv4HandleIncoming`) and IPv4 egress
 * (`IfaceTx` in the network stack); both pass the parsed
 * 5-tuple through `FwEvaluate` and drop the packet on a Deny
 * verdict.
 *
 * The cap that gates editing is `kCapNetAdmin`. Read access
 * (snapshot for the Network Status / Firewall app) is
 * unprivileged: the rule list is configuration, not secrets.
 *
 * Default policies at boot are Allow / Allow so adding the
 * subsystem does not break existing DHCP / DNS / TCP smoke
 * paths. Operators flip the inbound default to Deny once
 * their explicit allow-list covers the workloads that need
 * unsolicited inbound traffic.
 */

namespace duetos::net::firewall
{

enum class Direction : u8
{
    Ingress = 0,
    Egress = 1,
};

enum class Proto : u8
{
    Any = 0,
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
};

enum class Action : u8
{
    Allow = 0,
    Deny = 1,
};

/// Rule capacity. Static for v0; promote to dynamic once a
/// real workload demands it.
inline constexpr u32 kFwMaxRules = 32;

/// IPv4 prefix: address + bit-count mask. mask_bits=0 matches
/// any address; mask_bits=32 matches exactly `addr`.
struct Ipv4Prefix
{
    Ipv4Address addr;
    u8 mask_bits;
};

/// Inclusive port range. lo=0 hi=0xFFFF matches any port.
/// Ignored when proto != Tcp / Udp.
struct PortRange
{
    u16 lo;
    u16 hi;
};

struct Rule
{
    bool active;
    Direction dir;
    Proto proto;
    Ipv4Prefix src;
    Ipv4Prefix dst;
    PortRange src_port;
    PortRange dst_port;
    Action action;
    u64 hits;
};

/// Reset the rule table and default policies to v0 boot
/// state (Allow / Allow, no rules). Idempotent. Called from
/// `NetStackInit` so the module is live before the first
/// `Ipv4HandleIncoming` runs.
void FwInit();

/// Default policy for `dir` when no rule matches. Configurable
/// at runtime; readable without `kCapNetAdmin`.
Action FwDefaultPolicy(Direction dir);
void FwSetDefaultPolicy(Direction dir, Action action);

/// Add a rule to the table. Returns the rule index on success,
/// `kFwMaxRules` on capacity exhausted.
u32 FwAdd(const Rule& rule);

/// Mark a rule slot inactive. Out-of-range or already-inactive
/// indices are ignored.
void FwRemove(u32 index);

/// Toggle a rule's `active` flag. Useful for the editor surface.
void FwToggle(u32 index);

/// TCP flag bits as observed in the TCP header (offset 13).
/// Used by the conntrack state machine — see Firewall-Roadmap.md.
inline constexpr u8 kTcpFin = 0x01;
inline constexpr u8 kTcpSyn = 0x02;
inline constexpr u8 kTcpRst = 0x04;
inline constexpr u8 kTcpAck = 0x10;

/// Conntrack TCP state. Egress observation drives transitions:
/// NEW on first SYN, Established once a SYN+ACK or pure ACK has
/// flowed, FinWait after a FIN, Closed after RST. Per-state
/// expiry replaces the proto-based fixed TTL. UDP entries stay
/// in `Established` for their lifetime.
enum class TcpState : u8
{
    New = 0,
    Established = 1,
    FinWait = 2,
    Closed = 3,
};

const char* TcpStateName(TcpState s);

/// Evaluate one packet against the rule table. Returns the
/// resulting action and (optionally) the matching rule index.
/// `*matched_index` is `kFwMaxRules` when the default policy
/// fired. Increments the matched rule's hit counter. `tcp_flags`
/// is the TCP header's flag byte (offset 13) when proto==Tcp; it
/// drives the conntrack state transitions and is ignored for
/// other protocols.
Action FwEvaluate(Direction dir, Proto proto, Ipv4Address src_ip, Ipv4Address dst_ip, u16 src_port, u16 dst_port,
                  u8 tcp_flags, u32* matched_index);

struct Stats
{
    u64 ingress_checked;
    u64 ingress_denied;
    u64 egress_checked;
    u64 egress_denied;
    u64 conntrack_inserts;
    u64 conntrack_hits;
    u64 conntrack_evictions;
};

Stats FwStatsRead();

/// Snapshot up to `cap` rules into `out`. Returns the number
/// written. Read-only — safe from any context.
u32 FwSnapshot(Rule* out, u32 cap);

// -------------------------------------------------------------
// Recent-denial ring. Bounded (32 slots); circular write,
// monotone read sequence so a consumer can detect wraparound.
// Surface for the kernel shell's `firewall log` command and
// for any future GUI pane that wants to render "why is this
// connection failing".
// -------------------------------------------------------------

inline constexpr u32 kFwLogCap = 32;

struct DenialRecord
{
    u64 sequence; // monotone; 0 means "slot empty" only when no record ever landed
    u64 ticks;    // scheduler-tick timestamp at the deny moment
    Direction dir;
    Proto proto;
    Ipv4Address src_ip;
    Ipv4Address dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 matched_rule; // kFwMaxRules == default policy fired
};

/// Snapshot up to `cap` recent denials into `out` ordered
/// oldest-first. Returns the number written. Read-only.
u32 FwLogSnapshot(DenialRecord* out, u32 cap);

/// Total number of denials ever recorded (also the next
/// sequence number that would be assigned). Useful for tests
/// that need to detect "did any new denial land?".
u64 FwLogTotalCount();

// -------------------------------------------------------------
// Connection tracking (v0 — TCP / UDP only).
//
// On egress, when a TCP / UDP packet leaves through a bound
// interface, the firewall registers a conntrack entry keyed on
// (proto, local_ip, local_port, peer_ip, peer_port). On ingress,
// if no explicit rule matches, the firewall consults conntrack
// for the reverse-direction tuple before falling through to the
// default policy: a hit allows the packet, modeling "established
// connections are accepted" — the v0 minimum needed to flip the
// default-deny inbound default safely without breaking outbound-
// initiated TCP connect / UDP request-reply.
//
// Capacity is fixed; eviction is LRU on full ring. TTLs:
// kConntrackTtlTcp ≈ 5 minutes, kConntrackTtlUdp ≈ 60 seconds.
// Both refresh on each matching packet.
// -------------------------------------------------------------

inline constexpr u32 kConntrackCap = 64;
inline constexpr u32 kConntrackTtlTcpSecs = 300;
inline constexpr u32 kConntrackTtlUdpSecs = 60;

/// Conntrack TTL per state (seconds). Entries refresh to the
/// new state's TTL on every transition. Closed gets a short
/// drain so the slot recycles quickly after a clean teardown.
inline constexpr u32 kConntrackTtlNewSecs = 30;
inline constexpr u32 kConntrackTtlEstSecs = 300;
inline constexpr u32 kConntrackTtlFinSecs = 60;
inline constexpr u32 kConntrackTtlClosedSecs = 10;

struct ConntrackEntry
{
    bool active;
    Proto proto;
    Ipv4Address local_ip;
    u16 local_port;
    Ipv4Address peer_ip;
    u16 peer_port;
    u64 expiry_ticks;
    u64 last_use_ticks;
    TcpState tcp_state; // ignored when proto != Tcp
};

/// Snapshot up to `cap` active conntrack entries into `out`.
u32 ConntrackSnapshot(ConntrackEntry* out, u32 cap);

/// Reset the conntrack table. Idempotent — used by `FwInit`
/// and the `firewall reset` shell command.
void ConntrackReset();

/// Boot-time self-test. Exercises add / match / miss / default
/// / hit-counter / mask matching. Logs PASS/FAIL through
/// klog so a regression surfaces in the boot log.
void FwSelfTest();

} // namespace duetos::net::firewall
