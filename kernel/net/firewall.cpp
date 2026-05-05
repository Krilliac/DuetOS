#include "net/firewall.h"

#include "log/klog.h"

namespace duetos::net::firewall
{

namespace
{

constinit Rule g_rules[kFwMaxRules] = {};
constinit Action g_default_in = Action::Allow;
constinit Action g_default_out = Action::Allow;
constinit Stats g_stats = {};

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
    KLOG_INFO("net/firewall", "rule-table reset; defaults=allow/allow");
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
            }
            return g_rules[i].action;
        }
    }
    if (matched_index != nullptr)
    {
        *matched_index = kFwMaxRules;
    }
    const Action def = FwDefaultPolicy(dir);
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

    // Reset back to clean v0 state.
    FwInit();
    KLOG_INFO("net/firewall", "selftest complete");
}

} // namespace duetos::net::firewall
