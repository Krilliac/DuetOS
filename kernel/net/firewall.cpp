#include "net/firewall.h"

#include "log/klog.h"
#include "time/tick.h"

namespace duetos::net::firewall
{

namespace
{

constinit Rule g_rules[kFwMaxRules] = {};
constinit Action g_default_in = Action::Allow;
constinit Action g_default_out = Action::Allow;
constinit Stats g_stats = {};

// Recent-denial ring. `g_log_total` is the next sequence
// number AND the count of denials ever recorded. Slot index
// for sequence N is N % kFwLogCap. When `g_log_total >
// kFwLogCap`, the oldest live entry sits at sequence
// `g_log_total - kFwLogCap`.
constinit DenialRecord g_log[kFwLogCap] = {};
constinit u64 g_log_total = 0;

// Conntrack table. Linear-scan lookup is fine for v0 — 64
// entries × 5-tuple compare is fast enough that a hash adds
// more code than it saves. Eviction picks the entry with the
// oldest `last_use_ticks`.
constinit ConntrackEntry g_conntrack[kConntrackCap] = {};

constexpr u32 kSchedulerHz = 100;

constexpr u32 Ipv4ToHost(Ipv4Address a)
{
    return (u32(a.octets[0]) << 24) | (u32(a.octets[1]) << 16) | (u32(a.octets[2]) << 8) | u32(a.octets[3]);
}

constexpr u32 PrefixMask(u8 mask_bits)
{
    if (mask_bits == 0)
    {
        return 0;
    }
    if (mask_bits >= 32)
    {
        return 0xFFFFFFFFu;
    }
    return 0xFFFFFFFFu << (32 - mask_bits);
}

bool PrefixMatch(const Ipv4Prefix& p, Ipv4Address addr)
{
    const u32 mask = PrefixMask(p.mask_bits);
    return (Ipv4ToHost(p.addr) & mask) == (Ipv4ToHost(addr) & mask);
}

bool PortInRange(const PortRange& r, u16 port)
{
    return port >= r.lo && port <= r.hi;
}

bool ProtoMatch(Proto rule_proto, Proto pkt_proto)
{
    return rule_proto == Proto::Any || rule_proto == pkt_proto;
}

bool IpEq(Ipv4Address a, Ipv4Address b)
{
    return a.octets[0] == b.octets[0] && a.octets[1] == b.octets[1] && a.octets[2] == b.octets[2] &&
           a.octets[3] == b.octets[3];
}

bool ConntrackTupleMatch(const ConntrackEntry& e, Proto proto, Ipv4Address local_ip, u16 local_port,
                         Ipv4Address peer_ip, u16 peer_port)
{
    return e.active && e.proto == proto && IpEq(e.local_ip, local_ip) && e.local_port == local_port &&
           IpEq(e.peer_ip, peer_ip) && e.peer_port == peer_port;
}

void ConntrackInsertOrRefresh(Proto proto, Ipv4Address local_ip, u16 local_port, Ipv4Address peer_ip, u16 peer_port)
{
    if (proto != Proto::Tcp && proto != Proto::Udp)
    {
        return;
    }
    const u64 now = ::duetos::time::TickCount();
    const u32 ttl_secs = (proto == Proto::Tcp) ? kConntrackTtlTcpSecs : kConntrackTtlUdpSecs;
    const u64 expiry = now + u64(ttl_secs) * kSchedulerHz;

    // Refresh-or-evict pass: walk once, look for a tuple match;
    // along the way track the oldest `last_use_ticks` slot for a
    // possible eviction. Inactive slots win over both — fill
    // them first.
    u32 free_idx = kConntrackCap;
    u32 lru_idx = 0;
    u64 lru_ticks = ~u64(0);
    for (u32 i = 0; i < kConntrackCap; ++i)
    {
        if (g_conntrack[i].active &&
            ConntrackTupleMatch(g_conntrack[i], proto, local_ip, local_port, peer_ip, peer_port))
        {
            g_conntrack[i].expiry_ticks = expiry;
            g_conntrack[i].last_use_ticks = now;
            return;
        }
        if (!g_conntrack[i].active && free_idx == kConntrackCap)
        {
            free_idx = i;
        }
        if (g_conntrack[i].active && g_conntrack[i].last_use_ticks < lru_ticks)
        {
            lru_ticks = g_conntrack[i].last_use_ticks;
            lru_idx = i;
        }
    }

    u32 slot;
    if (free_idx != kConntrackCap)
    {
        slot = free_idx;
    }
    else
    {
        slot = lru_idx;
        ++g_stats.conntrack_evictions;
    }
    g_conntrack[slot].active = true;
    g_conntrack[slot].proto = proto;
    g_conntrack[slot].local_ip = local_ip;
    g_conntrack[slot].local_port = local_port;
    g_conntrack[slot].peer_ip = peer_ip;
    g_conntrack[slot].peer_port = peer_port;
    g_conntrack[slot].expiry_ticks = expiry;
    g_conntrack[slot].last_use_ticks = now;
    ++g_stats.conntrack_inserts;
}

bool ConntrackLookupReverse(Proto proto, Ipv4Address ingress_src_ip, u16 ingress_src_port, Ipv4Address ingress_dst_ip,
                            u16 ingress_dst_port)
{
    if (proto != Proto::Tcp && proto != Proto::Udp)
    {
        return false;
    }
    const u64 now = ::duetos::time::TickCount();
    // Ingress packet (src=peer, dst=local) matches an egress
    // entry whose (local, peer) is the reverse tuple.
    for (u32 i = 0; i < kConntrackCap; ++i)
    {
        ConntrackEntry& e = g_conntrack[i];
        if (!e.active)
        {
            continue;
        }
        if (now >= e.expiry_ticks)
        {
            e.active = false;
            continue;
        }
        if (ConntrackTupleMatch(e, proto, ingress_dst_ip, ingress_dst_port, ingress_src_ip, ingress_src_port))
        {
            e.last_use_ticks = now;
            ++g_stats.conntrack_hits;
            return true;
        }
    }
    return false;
}

void LogDenial(Direction dir, Proto proto, Ipv4Address src_ip, Ipv4Address dst_ip, u16 src_port, u16 dst_port,
               u32 matched_rule)
{
    const u64 seq = g_log_total++;
    DenialRecord& r = g_log[seq % kFwLogCap];
    r.sequence = seq + 1; // 1-based externally so 0 stays the "slot empty" sentinel
    r.ticks = ::duetos::time::TickCount();
    r.dir = dir;
    r.proto = proto;
    r.src_ip = src_ip;
    r.dst_ip = dst_ip;
    r.src_port = src_port;
    r.dst_port = dst_port;
    r.matched_rule = matched_rule;
}

bool RuleMatches(const Rule& r, Direction dir, Proto proto, Ipv4Address src_ip, Ipv4Address dst_ip, u16 src_port,
                 u16 dst_port)
{
    if (!r.active)
    {
        return false;
    }
    if (r.dir != dir)
    {
        return false;
    }
    if (!ProtoMatch(r.proto, proto))
    {
        return false;
    }
    if (!PrefixMatch(r.src, src_ip))
    {
        return false;
    }
    if (!PrefixMatch(r.dst, dst_ip))
    {
        return false;
    }
    // Ports only meaningful for TCP / UDP. ICMP / Any rules
    // ignore the port range — the rule should set lo=0, hi=0xFFFF
    // for clarity, but we treat any rule whose proto isn't TCP/UDP
    // as port-agnostic.
    if (proto == Proto::Tcp || proto == Proto::Udp)
    {
        if (!PortInRange(r.src_port, src_port))
        {
            return false;
        }
        if (!PortInRange(r.dst_port, dst_port))
        {
            return false;
        }
    }
    return true;
}

} // namespace

void FwInit()
{
    for (u32 i = 0; i < kFwMaxRules; ++i)
    {
        g_rules[i] = Rule{};
    }
    g_default_in = Action::Allow;
    g_default_out = Action::Allow;
    g_stats = Stats{};
    for (u32 i = 0; i < kFwLogCap; ++i)
    {
        g_log[i] = DenialRecord{};
    }
    g_log_total = 0;
    ConntrackReset();
    KLOG_INFO("net/firewall", "rule-table reset; defaults=allow/allow");
}

void ConntrackReset()
{
    for (u32 i = 0; i < kConntrackCap; ++i)
    {
        g_conntrack[i] = ConntrackEntry{};
    }
}

u32 ConntrackSnapshot(ConntrackEntry* out, u32 cap)
{
    if (out == nullptr || cap == 0)
    {
        return 0;
    }
    u32 written = 0;
    for (u32 i = 0; i < kConntrackCap && written < cap; ++i)
    {
        if (g_conntrack[i].active)
        {
            out[written++] = g_conntrack[i];
        }
    }
    return written;
}

u32 FwLogSnapshot(DenialRecord* out, u32 cap)
{
    if (out == nullptr || cap == 0)
    {
        return 0;
    }
    const u64 total = g_log_total;
    if (total == 0)
    {
        return 0;
    }
    const u64 want = (total < kFwLogCap) ? total : kFwLogCap;
    const u64 first_seq = total - want;
    u32 written = 0;
    for (u64 s = first_seq; s < total && written < cap; ++s)
    {
        out[written++] = g_log[s % kFwLogCap];
    }
    return written;
}

u64 FwLogTotalCount()
{
    return g_log_total;
}

Action FwDefaultPolicy(Direction dir)
{
    return dir == Direction::Ingress ? g_default_in : g_default_out;
}

void FwSetDefaultPolicy(Direction dir, Action action)
{
    if (dir == Direction::Ingress)
    {
        g_default_in = action;
    }
    else
    {
        g_default_out = action;
    }
}

u32 FwAdd(const Rule& rule)
{
    for (u32 i = 0; i < kFwMaxRules; ++i)
    {
        if (!g_rules[i].active)
        {
            g_rules[i] = rule;
            g_rules[i].active = true;
            g_rules[i].hits = 0;
            return i;
        }
    }
    return kFwMaxRules;
}

void FwRemove(u32 index)
{
    if (index >= kFwMaxRules)
    {
        return;
    }
    g_rules[index].active = false;
    g_rules[index].hits = 0;
}

void FwToggle(u32 index)
{
    if (index >= kFwMaxRules)
    {
        return;
    }
    g_rules[index].active = !g_rules[index].active;
}

Action FwEvaluate(Direction dir, Proto proto, Ipv4Address src_ip, Ipv4Address dst_ip, u16 src_port, u16 dst_port,
                  u32* matched_index)
{
    if (dir == Direction::Ingress)
    {
        ++g_stats.ingress_checked;
    }
    else
    {
        ++g_stats.egress_checked;
    }
    for (u32 i = 0; i < kFwMaxRules; ++i)
    {
        if (RuleMatches(g_rules[i], dir, proto, src_ip, dst_ip, src_port, dst_port))
        {
            ++g_rules[i].hits;
            if (matched_index != nullptr)
            {
                *matched_index = i;
            }
            if (g_rules[i].action == Action::Deny)
            {
                if (dir == Direction::Ingress)
                {
                    ++g_stats.ingress_denied;
                }
                else
                {
                    ++g_stats.egress_denied;
                }
                LogDenial(dir, proto, src_ip, dst_ip, src_port, dst_port, i);
            }
            return g_rules[i].action;
        }
    }
    if (matched_index != nullptr)
    {
        *matched_index = kFwMaxRules;
    }
    // Egress that no explicit rule matched: register a
    // conntrack entry so the corresponding inbound reply
    // is recognised even under a default-deny inbound policy.
    if (dir == Direction::Egress)
    {
        ConntrackInsertOrRefresh(proto, src_ip, src_port, dst_ip, dst_port);
    }
    // Ingress that no explicit rule matched and the default
    // would deny: consult conntrack for a matching outbound
    // before logging.
    Action def = FwDefaultPolicy(dir);
    if (dir == Direction::Ingress && def == Action::Deny)
    {
        if (ConntrackLookupReverse(proto, src_ip, src_port, dst_ip, dst_port))
        {
            return Action::Allow;
        }
    }
    if (def == Action::Deny)
    {
        if (dir == Direction::Ingress)
        {
            ++g_stats.ingress_denied;
        }
        else
        {
            ++g_stats.egress_denied;
        }
        LogDenial(dir, proto, src_ip, dst_ip, src_port, dst_port, kFwMaxRules);
    }
    return def;
}

Stats FwStatsRead()
{
    return g_stats;
}

u32 FwSnapshot(Rule* out, u32 cap)
{
    if (out == nullptr || cap == 0)
    {
        return 0;
    }
    u32 written = 0;
    for (u32 i = 0; i < kFwMaxRules && written < cap; ++i)
    {
        out[written++] = g_rules[i];
    }
    return written;
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (!cond)
    {
        KLOG_WARN("net/firewall", what);
    }
}

} // namespace

void FwSelfTest()
{
    KLOG_TRACE_SCOPE("net/firewall", "FwSelfTest");
    FwInit();

    constexpr Ipv4Address kAny = {{0, 0, 0, 0}};
    constexpr Ipv4Address kHostA = {{10, 0, 0, 1}};
    constexpr Ipv4Address kHostB = {{10, 0, 0, 2}};
    constexpr Ipv4Address kSubnetC = {{192, 168, 1, 0}};
    constexpr Ipv4Address kSubnetCHost = {{192, 168, 1, 42}};
    constexpr Ipv4Address kOtherSubnet = {{192, 168, 2, 5}};

    constexpr Ipv4Prefix kAnyPfx = {kAny, 0};
    constexpr PortRange kAnyPort = {0, 0xFFFF};

    // Default policy fires on empty table.
    {
        u32 matched = 0;
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 80, &matched);
        Expect(a == Action::Allow, "empty-table ingress defaults allow");
        Expect(matched == kFwMaxRules, "empty-table reports default-policy match");
    }

    // Switching the default to deny must take effect.
    FwSetDefaultPolicy(Direction::Ingress, Action::Deny);
    {
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 80, nullptr);
        Expect(a == Action::Deny, "ingress default flipped to deny");
    }
    FwSetDefaultPolicy(Direction::Ingress, Action::Allow);

    // Adding a deny rule fires before the default.
    Rule r{};
    r.dir = Direction::Ingress;
    r.proto = Proto::Tcp;
    r.src = kAnyPfx;
    r.dst = kAnyPfx;
    r.src_port = kAnyPort;
    r.dst_port = {22, 22};
    r.action = Action::Deny;
    const u32 idx = FwAdd(r);
    Expect(idx < kFwMaxRules, "FwAdd allocates a slot");
    {
        u32 matched = 0;
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 22, &matched);
        Expect(a == Action::Deny, "explicit deny overrides allow default");
        Expect(matched == idx, "matched the rule we just added");
    }
    // Rule that doesn't match the dst port falls through.
    {
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 80, nullptr);
        Expect(a == Action::Allow, "dst_port=80 falls through to default allow");
    }
    // Wrong direction does not match.
    {
        const Action a = FwEvaluate(Direction::Egress, Proto::Tcp, kHostA, kHostB, 1234, 22, nullptr);
        Expect(a == Action::Allow, "egress packet ignores ingress rule");
    }
    // Hit counter incremented exactly twice (one match above).
    {
        Rule snap[kFwMaxRules];
        const u32 n = FwSnapshot(snap, kFwMaxRules);
        Expect(n == kFwMaxRules, "snapshot returns full slot count");
        Expect(snap[idx].hits == 1, "rule hits incremented once on match");
    }

    // Subnet matching — /24 prefix.
    Rule subnet{};
    subnet.dir = Direction::Egress;
    subnet.proto = Proto::Any;
    subnet.src = kAnyPfx;
    subnet.dst = {kSubnetC, 24};
    subnet.src_port = kAnyPort;
    subnet.dst_port = kAnyPort;
    subnet.action = Action::Deny;
    const u32 sidx = FwAdd(subnet);
    Expect(sidx < kFwMaxRules, "subnet rule allocates");
    {
        const Action a = FwEvaluate(Direction::Egress, Proto::Tcp, kHostA, kSubnetCHost, 1024, 80, nullptr);
        Expect(a == Action::Deny, "/24 subnet rule denies in-range dst");
    }
    {
        const Action a = FwEvaluate(Direction::Egress, Proto::Tcp, kHostA, kOtherSubnet, 1024, 80, nullptr);
        Expect(a == Action::Allow, "/24 subnet rule does not match other subnet");
    }

    // Toggle de-activates without removing.
    FwToggle(idx);
    {
        Rule snap[kFwMaxRules];
        FwSnapshot(snap, kFwMaxRules);
        Expect(!snap[idx].active, "FwToggle clears active flag");
    }
    {
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 22, nullptr);
        Expect(a == Action::Allow, "toggled-off rule no longer matches");
    }

    // FwRemove releases the slot.
    FwRemove(idx);
    {
        Rule snap[kFwMaxRules];
        FwSnapshot(snap, kFwMaxRules);
        Expect(!snap[idx].active, "FwRemove clears active flag");
    }

    // ---------- Conntrack: outbound establishes ingress-allow ----------
    FwInit();
    FwSetDefaultPolicy(Direction::Ingress, Action::Deny);
    {
        constexpr Ipv4Address local = {{10, 0, 0, 5}};
        constexpr Ipv4Address peer = {{93, 184, 216, 34}};
        constexpr u16 local_port = 50000;
        constexpr u16 peer_port = 80;
        // Egress packet registers conntrack.
        const Action a_out = FwEvaluate(Direction::Egress, Proto::Tcp, local, peer, local_port, peer_port, nullptr);
        Expect(a_out == Action::Allow, "egress allowed by default");
        // Ingress reply matches conntrack -> Allow even under default-deny.
        const Action a_in = FwEvaluate(Direction::Ingress, Proto::Tcp, peer, local, peer_port, local_port, nullptr);
        Expect(a_in == Action::Allow, "ingress reply allowed via conntrack");
        // Ingress from a different peer port -> denied (no conntrack).
        const Action a_in2 = FwEvaluate(Direction::Ingress, Proto::Tcp, peer, local, 81, local_port, nullptr);
        Expect(a_in2 == Action::Deny, "ingress without conntrack hits default-deny");
    }
    FwSetDefaultPolicy(Direction::Ingress, Action::Allow);

    // ---------- Denial log captured the deny above ----------
    {
        DenialRecord rec[kFwLogCap];
        const u32 n = FwLogSnapshot(rec, kFwLogCap);
        Expect(n >= 1, "denial log captured at least one entry");
        Expect(FwLogTotalCount() >= 1, "denial total monotone");
    }

    // Reset back to clean v0 state.
    FwInit();
    KLOG_INFO("net/firewall", "selftest complete");
}

} // namespace duetos::net::firewall
