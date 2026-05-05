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

/// Evaluate one packet against the rule table. Returns the
/// resulting action and (optionally) the matching rule index.
/// `*matched_index` is `kFwMaxRules` when the default policy
/// fired. Increments the matched rule's hit counter.
Action FwEvaluate(Direction dir, Proto proto, Ipv4Address src_ip, Ipv4Address dst_ip, u16 src_port, u16 dst_port,
                  u32* matched_index);

struct Stats
{
    u64 ingress_checked;
    u64 ingress_denied;
    u64 egress_checked;
    u64 egress_denied;
};

Stats FwStatsRead();

/// Snapshot up to `cap` rules into `out`. Returns the number
/// written. Read-only — safe from any context.
u32 FwSnapshot(Rule* out, u32 cap);

/// Boot-time self-test. Exercises add / match / miss / default
/// / hit-counter / mask matching. Logs PASS/FAIL through
/// klog so a regression surfaces in the boot log.
void FwSelfTest();

} // namespace duetos::net::firewall
