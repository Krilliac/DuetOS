#include "net/firewall.h"

#include "core/boot_cmdline.h"
#include "drivers/video/notify.h"
#include "log/klog.h"
#include "net/fw_exception.h"
#include "security/exception_id.h"
#include "sync/lockdep.h"
#include "sync/spinlock.h"
#include "time/tick.h"
#include "util/compiler.h"

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

// How many active exceptions came from `fw-allow=` boot tokens.
// Surfaced by `firewall status` so a pre-authorised boot is never
// mistaken for a clean one.
constinit u32 g_cmdline_seeded = 0;

// Boot token that installs firewall exceptions without an operator
// present. Repeatable; each occurrence carries a comma-separated
// list of specs (grammar in net/fw_exception.h). Every spec names a
// direction, protocol, peer prefix and port — there is deliberately
// no "allow everything" spelling.
constexpr const char* kCmdlineAllowKey = "fw-allow";

// Rate limit for the denial toast. A blocked port scan produces one
// denial per probe; without this the toast slot would thrash and the
// operator would see only the last packet of a burst. One toast per
// this many scheduler ticks is enough to say "something is being
// blocked, go look at `firewall log`" without becoming the noise it
// is warning about.
constexpr u64 kDenialToastCooldownTicks = 5 * 100; // ~5s at kSchedulerHz
constinit u64 g_last_toast_ticks = 0;
constinit bool g_toast_armed = false;

// One IRQ-save lock publishes the firewall's mutually related rule, stats,
// denial-log, conntrack, and toast-rate state. It is intentionally never held
// across TickCount, logging, notification delivery, or any network callback.
// Public readers copy complete snapshots before releasing it.
constinit sync::SpinLock g_firewall_lock = {
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};

constexpr u32 kSchedulerHz = 100;

constexpr u32 Ipv4ToHost(Ipv4Address a)
{
    return (u32(a.octets[0]) << 24) | (u32(a.octets[1]) << 16) | (u32(a.octets[2]) << 8) | u32(a.octets[3]);
}

DUETOS_NO_SANITIZE_WRAP constexpr u32 PrefixMask(u8 mask_bits)
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

u32 TtlSecsForState(Proto proto, TcpState state)
{
    if (proto != Proto::Tcp)
    {
        // UDP / Any keeps a single fixed TTL — no flag-driven
        // state to ride.
        return kConntrackTtlEstSecs;
    }
    switch (state)
    {
    case TcpState::New:
        return kConntrackTtlNewSecs;
    case TcpState::FinWait:
        return kConntrackTtlFinSecs;
    case TcpState::Closed:
        return kConntrackTtlClosedSecs;
    case TcpState::Established:
    default:
        return kConntrackTtlEstSecs;
    }
}

// State machine driven by an egress-direction TCP packet. Local
// is sending to peer.
TcpState TcpStateAfterEgress(TcpState s, u8 flags)
{
    if ((flags & kTcpRst) != 0)
    {
        return TcpState::Closed;
    }
    if ((flags & kTcpFin) != 0)
    {
        return TcpState::FinWait;
    }
    // Pure ACK from local with no SYN promotes a half-open
    // connection (peer's SYN+ACK already moved us to Established
    // via the ingress side; this catches a connect we initiated
    // where the local ACK is what we're observing).
    if (s == TcpState::New && (flags & kTcpAck) != 0 && (flags & kTcpSyn) == 0)
    {
        return TcpState::Established;
    }
    return s;
}

// State machine driven by an ingress-direction TCP packet. Peer
// is sending to local.
TcpState TcpStateAfterIngress(TcpState s, u8 flags)
{
    if ((flags & kTcpRst) != 0)
    {
        return TcpState::Closed;
    }
    if ((flags & kTcpFin) != 0)
    {
        return TcpState::FinWait;
    }
    // Classic SYN+ACK reply from peer to our outbound SYN
    // graduates the entry to Established.
    if (s == TcpState::New && (flags & kTcpSyn) != 0 && (flags & kTcpAck) != 0)
    {
        return TcpState::Established;
    }
    return s;
}

void ConntrackResetLocked()
{
    for (u32 i = 0; i < kConntrackCap; ++i)
        g_conntrack[i] = ConntrackEntry{};
}

void ConntrackInsertOrRefreshLocked(Proto proto, Ipv4Address local_ip, u16 local_port, Ipv4Address peer_ip,
                                    u16 peer_port, u8 tcp_flags, u64 now)
{
    if (proto != Proto::Tcp && proto != Proto::Udp)
    {
        return;
    }
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
            g_conntrack[i].tcp_state = TcpStateAfterEgress(g_conntrack[i].tcp_state, tcp_flags);
            const u32 ttl_secs = TtlSecsForState(proto, g_conntrack[i].tcp_state);
            g_conntrack[i].expiry_ticks = now + u64(ttl_secs) * kSchedulerHz;
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
    // First-observation state: TCP starts in NEW (refined when
    // SYN/ACK or FIN/RST arrives); UDP / Any treated as
    // Established for TTL purposes.
    TcpState initial_state = (proto == Proto::Tcp) ? TcpState::New : TcpState::Established;
    initial_state = TcpStateAfterEgress(initial_state, tcp_flags);
    const u32 ttl_secs = TtlSecsForState(proto, initial_state);
    g_conntrack[slot].active = true;
    g_conntrack[slot].proto = proto;
    g_conntrack[slot].local_ip = local_ip;
    g_conntrack[slot].local_port = local_port;
    g_conntrack[slot].peer_ip = peer_ip;
    g_conntrack[slot].peer_port = peer_port;
    g_conntrack[slot].expiry_ticks = now + u64(ttl_secs) * kSchedulerHz;
    g_conntrack[slot].last_use_ticks = now;
    g_conntrack[slot].tcp_state = initial_state;
    ++g_stats.conntrack_inserts;
}

bool ConntrackLookupReverseLocked(Proto proto, Ipv4Address ingress_src_ip, u16 ingress_src_port,
                                  Ipv4Address ingress_dst_ip, u16 ingress_dst_port, u8 tcp_flags, u64 now)
{
    if (proto != Proto::Tcp && proto != Proto::Udp)
    {
        return false;
    }
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
            // Drive the state machine on the ingress side and
            // refresh the expiry to the new state's TTL.
            e.tcp_state = TcpStateAfterIngress(e.tcp_state, tcp_flags);
            const u32 ttl_secs = TtlSecsForState(proto, e.tcp_state);
            e.expiry_ticks = now + u64(ttl_secs) * kSchedulerHz;
            e.last_use_ticks = now;
            ++g_stats.conntrack_hits;
            return true;
        }
    }
    return false;
}

// Append `v` as decimal to `buf` at `*w`, bounded by `cap`.
void AppendDecimal(char* buf, u32* w, u32 cap, u32 v)
{
    char digits[6];
    u32 n = 0;
    do
    {
        digits[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    } while (v != 0 && n < sizeof(digits));
    while (n > 0 && *w < cap)
        buf[(*w)++] = digits[--n];
}

void AppendLiteral(char* buf, u32* w, u32 cap, const char* s)
{
    for (u32 i = 0; s[i] != '\0' && *w < cap; ++i)
        buf[(*w)++] = s[i];
}

/// Surface a blocked packet to the desktop.
///
/// This is the firewall's answer to the guard's modal. It cannot be
/// a modal: `FwEvaluate` sits on the packet path, so blocking here
/// for an operator decision would stall the network stack for every
/// probe an attacker cares to send. A toast instead tells the
/// operator that something is being dropped and names it; the
/// exception itself is added afterwards, out of band, via
/// `firewall except <seq>`.
///
/// Rate-limited (see kDenialToastCooldownTicks) so a scan cannot
/// turn the notification surface into a denial-of-service of its
/// own.
bool PrepareDenialToastLocked(const DenialRecord& r, u64 now, char* text, u32 text_capacity)
{
    if (text == nullptr || text_capacity == 0)
        return false;
    if (g_toast_armed && (now - g_last_toast_ticks) < kDenialToastCooldownTicks)
        return false;
    g_toast_armed = true;
    g_last_toast_ticks = now;

    // "firewall blocked in 10.0.2.2:445 (#7 — firewall except 7)"
    u32 w = 0;
    const u32 cap = text_capacity - 1;
    AppendLiteral(text, &w, cap, "firewall blocked ");
    AppendLiteral(text, &w, cap, r.dir == Direction::Ingress ? "in " : "out ");
    const Ipv4Address& peer = (r.dir == Direction::Ingress) ? r.src_ip : r.dst_ip;
    for (u32 i = 0; i < 4; ++i)
    {
        if (i != 0)
            AppendLiteral(text, &w, cap, ".");
        AppendDecimal(text, &w, cap, peer.octets[i]);
    }
    AppendLiteral(text, &w, cap, ":");
    AppendDecimal(text, &w, cap, r.dst_port);
    AppendLiteral(text, &w, cap, " — 'firewall except ");
    AppendDecimal(text, &w, cap, static_cast<u32>(r.sequence));
    AppendLiteral(text, &w, cap, "' to allow");
    text[w] = '\0';
    return true;
}

DenialRecord LogDenialLocked(Direction dir, Proto proto, Ipv4Address src_ip, Ipv4Address dst_ip, u16 src_port,
                             u16 dst_port, u32 matched_rule, u64 now)
{
    const u64 seq = g_log_total++;
    DenialRecord& r = g_log[seq % kFwLogCap];
    r.sequence = seq + 1; // 1-based externally so 0 stays the "slot empty" sentinel
    r.ticks = now;
    r.dir = dir;
    r.proto = proto;
    r.src_ip = src_ip;
    r.dst_ip = dst_ip;
    r.src_port = src_port;
    r.dst_port = dst_port;
    r.matched_rule = matched_rule;
    return r;
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

u32 FwAddLocked(const Rule& rule)
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

} // namespace

void FwInit()
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
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
    g_cmdline_seeded = 0;
    g_toast_armed = false;
    g_last_toast_ticks = 0;
    ConntrackResetLocked();
    sync::SpinLockRelease(g_firewall_lock, flags);
    KLOG_INFO("net/firewall", "rule-table reset; defaults=allow/allow");

    // Seed operator exceptions from the boot cmdline. Runs after the
    // reset so the table is empty and the seeded rules occupy the
    // lowest slots — first-match-wins, so an exception the operator
    // asked for is evaluated before anything a later subsystem adds.
    // FindBootCmdline(0) reads the cache warmed during early boot.
    FwSeedExceptionsFromCmdline(duetos::core::FindBootCmdline(0));
}

void ConntrackReset()
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    ConntrackResetLocked();
    sync::SpinLockRelease(g_firewall_lock, flags);
}

u32 ConntrackSnapshot(ConntrackEntry* out, u32 cap)
{
    if (out == nullptr || cap == 0)
    {
        return 0;
    }
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    u32 written = 0;
    for (u32 i = 0; i < kConntrackCap && written < cap; ++i)
    {
        if (g_conntrack[i].active)
        {
            out[written++] = g_conntrack[i];
        }
    }
    sync::SpinLockRelease(g_firewall_lock, flags);
    return written;
}

u32 FwLogSnapshot(DenialRecord* out, u32 cap)
{
    if (out == nullptr || cap == 0)
    {
        return 0;
    }
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    const u64 total = g_log_total;
    if (total == 0)
    {
        sync::SpinLockRelease(g_firewall_lock, flags);
        return 0;
    }
    const u64 want = (total < kFwLogCap) ? total : kFwLogCap;
    const u64 first_seq = total - want;
    u32 written = 0;
    for (u64 s = first_seq; s < total && written < cap; ++s)
    {
        out[written++] = g_log[s % kFwLogCap];
    }
    sync::SpinLockRelease(g_firewall_lock, flags);
    return written;
}

u64 FwLogTotalCount()
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    const u64 total = g_log_total;
    sync::SpinLockRelease(g_firewall_lock, flags);
    return total;
}

const char* TcpStateName(TcpState s)
{
    switch (s)
    {
    case TcpState::New:
        return "NEW";
    case TcpState::Established:
        return "EST";
    case TcpState::FinWait:
        return "FIN";
    case TcpState::Closed:
        return "CLO";
    default:
        return "?";
    }
}

Action FwDefaultPolicy(Direction dir)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    const Action action = dir == Direction::Ingress ? g_default_in : g_default_out;
    sync::SpinLockRelease(g_firewall_lock, flags);
    return action;
}

void FwSetDefaultPolicy(Direction dir, Action action)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    if (dir == Direction::Ingress)
    {
        g_default_in = action;
    }
    else
    {
        g_default_out = action;
    }
    sync::SpinLockRelease(g_firewall_lock, flags);
}

u32 FwAdd(const Rule& rule)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    const u32 index = FwAddLocked(rule);
    sync::SpinLockRelease(g_firewall_lock, flags);
    return index;
}

void FwRemove(u32 index)
{
    if (index >= kFwMaxRules)
    {
        return;
    }
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    g_rules[index].active = false;
    g_rules[index].hits = 0;
    sync::SpinLockRelease(g_firewall_lock, flags);
}

namespace
{

/// Turn a parsed spec into a rule. The peer prefix binds to the
/// source for ingress and the destination for egress; the local
/// side stays wildcard because a host that has not been assigned
/// its address yet (DHCP still in flight) would otherwise fail to
/// match its own exception.
Rule RuleFromSpec(const ExceptionSpec& spec)
{
    Rule r{};
    r.active = true;
    r.exception = true;
    r.action = Action::Allow;
    r.dir = spec.egress ? Direction::Egress : Direction::Ingress;
    r.proto = static_cast<Proto>(spec.proto);

    Ipv4Prefix peer{};
    for (u32 i = 0; i < 4; ++i)
        peer.addr.octets[i] = spec.addr[i];
    peer.mask_bits = spec.mask_bits;
    const Ipv4Prefix any{{{0, 0, 0, 0}}, 0};

    r.src = spec.egress ? any : peer;
    r.dst = spec.egress ? peer : any;

    // Source port is always wildcard: it is ephemeral, so pinning it
    // would produce an exception that matches exactly one connection
    // and then never again.
    r.src_port = PortRange{0, 0xFFFF};
    r.dst_port = spec.any_port ? PortRange{0, 0xFFFF} : PortRange{spec.port, spec.port};
    return r;
}

/// Install a parsed spec. `origin` names where the operator's
/// instruction came from and is logged verbatim — a reader working
/// out why a hole exists needs to know whether a human typed it at
/// the shell or a boot token installed it unattended.
bool InstallException(const char* spec_text, u32 len, u32* out_index, const char* origin)
{
    ExceptionSpec spec{};
    if (!ParseExceptionSpec(spec_text, len, &spec))
        return false;
    const u32 idx = FwAdd(RuleFromSpec(spec));
    if (idx >= kFwMaxRules)
        return false;
    if (out_index != nullptr)
        *out_index = idx;
    KLOG_WARN_V("net/firewall", "operator firewall exception installed (rule index)", idx);
    KLOG_WARN_S("net/firewall", "firewall exception origin", "origin", origin);
    return true;
}

} // namespace

bool FwExceptionFromDenial(u64 sequence, u32* out_index)
{
    // Sequences are 1-based externally (0 is the empty-slot
    // sentinel). Reject anything the ring has already overwritten
    // rather than promoting whatever now occupies that slot — the
    // operator asked to allow a specific packet they saw, not
    // whatever landed in its place.
    u32 idx = kFwMaxRules;
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    const bool sequence_live =
        sequence != 0 && sequence <= g_log_total && (g_log_total <= kFwLogCap || sequence > g_log_total - kFwLogCap);
    if (sequence_live)
    {
        const DenialRecord& d = g_log[(sequence - 1) % kFwLogCap];
        if (d.sequence == sequence)
        {
            ExceptionSpec spec{};
            spec.egress = (d.dir == Direction::Egress);
            spec.proto = static_cast<u8>(d.proto);
            const Ipv4Address& peer = (d.dir == Direction::Ingress) ? d.src_ip : d.dst_ip;
            for (u32 i = 0; i < 4; ++i)
                spec.addr[i] = peer.octets[i];
            // /32: promoting a denial allows exactly the host that was
            // blocked. Widening to a subnet is a separate, deliberate act
            // through `firewall except add <spec>`.
            spec.mask_bits = 32;
            spec.any_port = (d.proto != Proto::Tcp && d.proto != Proto::Udp);
            spec.port = d.dst_port;
            idx = FwAddLocked(RuleFromSpec(spec));
        }
    }
    sync::SpinLockRelease(g_firewall_lock, flags);
    if (idx >= kFwMaxRules)
        return false;
    if (out_index != nullptr)
        *out_index = idx;
    KLOG_WARN_V("net/firewall", "operator firewall exception installed (rule index)", idx);
    KLOG_WARN_S("net/firewall", "firewall exception origin", "origin", "denial-log");
    return true;
}

bool FwExceptionAdd(const char* spec_text, u32 len, u32* out_index)
{
    return InstallException(spec_text, len, out_index, "shell");
}

void FwSeedExceptionsFromCmdline(const char* cmdline)
{
    using duetos::security::CmdlineFindNthValue;
    using duetos::security::CsvField;
    using duetos::security::CsvFieldCount;

    u32 installed = 0;
    u32 rejected = 0;
    const char* value = nullptr;
    u32 value_len = 0;
    for (u32 tok = 0; CmdlineFindNthValue(cmdline, kCmdlineAllowKey, tok, &value, &value_len); ++tok)
    {
        const u32 fields = CsvFieldCount(value, value_len);
        for (u32 f = 0; f < fields; ++f)
        {
            const char* field = nullptr;
            u32 field_len = 0;
            if (!CsvField(value, value_len, f, &field, &field_len))
                continue;
            u32 idx = 0;
            if (!InstallException(field, field_len, &idx, "boot-cmdline"))
            {
                ++rejected;
                continue;
            }
            ++installed;
        }
    }

    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    g_cmdline_seeded = installed;
    sync::SpinLockRelease(g_firewall_lock, flags);
    if (rejected > 0)
    {
        // A rejected spec means traffic the operator meant to permit
        // will be dropped instead. Never silent.
        KLOG_WARN_V("net/firewall", "fw-allow= entries rejected (malformed or table full)", rejected);
    }
    if (installed > 0)
    {
        KLOG_WARN_V("net/firewall", "cmdline-seeded firewall exceptions in force (fw-allow=)", installed);
    }
}

u32 FwExceptionCount()
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    u32 n = 0;
    for (u32 i = 0; i < kFwMaxRules; ++i)
    {
        if (g_rules[i].active && g_rules[i].exception)
            ++n;
    }
    sync::SpinLockRelease(g_firewall_lock, flags);
    return n;
}

u32 FwCmdlineSeededCount()
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    const u32 count = g_cmdline_seeded;
    sync::SpinLockRelease(g_firewall_lock, flags);
    return count;
}

void FwToggle(u32 index)
{
    if (index >= kFwMaxRules)
    {
        return;
    }
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    g_rules[index].active = !g_rules[index].active;
    sync::SpinLockRelease(g_firewall_lock, flags);
}

Action FwEvaluate(Direction dir, Proto proto, Ipv4Address src_ip, Ipv4Address dst_ip, u16 src_port, u16 dst_port,
                  u8 tcp_flags, u32* matched_index)
{
    const u64 now = ::duetos::time::TickCount();
    char toast_text[duetos::drivers::video::kNotifyMaxText] = {};
    bool show_toast = false;
    bool explicit_match = false;
    u32 matched = kFwMaxRules;
    Action verdict = Action::Allow;

    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    if (dir == Direction::Ingress)
        ++g_stats.ingress_checked;
    else
        ++g_stats.egress_checked;

    for (u32 i = 0; i < kFwMaxRules; ++i)
    {
        if (RuleMatches(g_rules[i], dir, proto, src_ip, dst_ip, src_port, dst_port))
        {
            explicit_match = true;
            matched = i;
            ++g_rules[i].hits;
            verdict = g_rules[i].action;
            if (verdict == Action::Deny)
            {
                if (dir == Direction::Ingress)
                    ++g_stats.ingress_denied;
                else
                    ++g_stats.egress_denied;
                const DenialRecord denial = LogDenialLocked(dir, proto, src_ip, dst_ip, src_port, dst_port, i, now);
                show_toast = PrepareDenialToastLocked(denial, now, toast_text, sizeof(toast_text));
            }
            break;
        }
    }

    if (!explicit_match)
    {
        // Egress that no explicit rule matched registers a conntrack entry so
        // the corresponding inbound reply is recognised under default-deny.
        if (dir == Direction::Egress)
            ConntrackInsertOrRefreshLocked(proto, src_ip, src_port, dst_ip, dst_port, tcp_flags, now);

        verdict = dir == Direction::Ingress ? g_default_in : g_default_out;
        if (dir == Direction::Ingress && verdict == Action::Deny &&
            ConntrackLookupReverseLocked(proto, src_ip, src_port, dst_ip, dst_port, tcp_flags, now))
        {
            verdict = Action::Allow;
        }
        else if (verdict == Action::Deny)
        {
            if (dir == Direction::Ingress)
                ++g_stats.ingress_denied;
            else
                ++g_stats.egress_denied;
            const DenialRecord denial =
                LogDenialLocked(dir, proto, src_ip, dst_ip, src_port, dst_port, kFwMaxRules, now);
            show_toast = PrepareDenialToastLocked(denial, now, toast_text, sizeof(toast_text));
        }
    }
    sync::SpinLockRelease(g_firewall_lock, flags);

    if (matched_index != nullptr)
        *matched_index = matched;
    if (show_toast)
        duetos::drivers::video::NotifyShowKind(toast_text, duetos::drivers::video::NotifyKind::Warning);
    return verdict;
}

Stats FwStatsRead()
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    const Stats stats = g_stats;
    sync::SpinLockRelease(g_firewall_lock, flags);
    return stats;
}

u32 FwSnapshot(Rule* out, u32 cap)
{
    if (out == nullptr || cap == 0)
    {
        return 0;
    }
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_firewall_lock);
    u32 written = 0;
    for (u32 i = 0; i < kFwMaxRules && written < cap; ++i)
    {
        out[written++] = g_rules[i];
    }
    sync::SpinLockRelease(g_firewall_lock, flags);
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
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 80, 0, &matched);
        Expect(a == Action::Allow, "empty-table ingress defaults allow");
        Expect(matched == kFwMaxRules, "empty-table reports default-policy match");
    }

    // Switching the default to deny must take effect.
    FwSetDefaultPolicy(Direction::Ingress, Action::Deny);
    {
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 80, 0, nullptr);
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
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 22, 0, &matched);
        Expect(a == Action::Deny, "explicit deny overrides allow default");
        Expect(matched == idx, "matched the rule we just added");
    }
    // Rule that doesn't match the dst port falls through.
    {
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 80, 0, nullptr);
        Expect(a == Action::Allow, "dst_port=80 falls through to default allow");
    }
    // Wrong direction does not match.
    {
        const Action a = FwEvaluate(Direction::Egress, Proto::Tcp, kHostA, kHostB, 1234, 22, 0, nullptr);
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
        const Action a = FwEvaluate(Direction::Egress, Proto::Tcp, kHostA, kSubnetCHost, 1024, 80, 0, nullptr);
        Expect(a == Action::Deny, "/24 subnet rule denies in-range dst");
    }
    {
        const Action a = FwEvaluate(Direction::Egress, Proto::Tcp, kHostA, kOtherSubnet, 1024, 80, 0, nullptr);
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
        const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kHostA, kHostB, 1234, 22, 0, nullptr);
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
    // Drives the TCP state machine through SYN -> SYN+ACK -> RST
    // and verifies the per-state TTL is applied.
    FwInit();
    FwSetDefaultPolicy(Direction::Ingress, Action::Deny);
    {
        constexpr Ipv4Address local = {{10, 0, 0, 5}};
        constexpr Ipv4Address peer = {{93, 184, 216, 34}};
        constexpr u16 local_port = 50000;
        constexpr u16 peer_port = 80;
        // Egress SYN registers conntrack in NEW.
        const Action a_out =
            FwEvaluate(Direction::Egress, Proto::Tcp, local, peer, local_port, peer_port, kTcpSyn, nullptr);
        Expect(a_out == Action::Allow, "egress SYN allowed by default");
        {
            ConntrackEntry snap[kConntrackCap];
            const u32 n = ConntrackSnapshot(snap, kConntrackCap);
            Expect(n >= 1, "conntrack entry recorded after egress SYN");
            bool found_new = false;
            for (u32 i = 0; i < n; ++i)
            {
                if (snap[i].local_port == local_port && snap[i].peer_port == peer_port)
                {
                    found_new = (snap[i].tcp_state == TcpState::New);
                    break;
                }
            }
            Expect(found_new, "tcp_state is NEW after first SYN");
        }
        // Ingress SYN+ACK matches conntrack -> Allow + graduate to Established.
        const Action a_in =
            FwEvaluate(Direction::Ingress, Proto::Tcp, peer, local, peer_port, local_port, kTcpSyn | kTcpAck, nullptr);
        Expect(a_in == Action::Allow, "ingress SYN+ACK allowed via conntrack");
        {
            ConntrackEntry snap[kConntrackCap];
            const u32 n = ConntrackSnapshot(snap, kConntrackCap);
            bool found_est = false;
            for (u32 i = 0; i < n; ++i)
            {
                if (snap[i].local_port == local_port && snap[i].peer_port == peer_port)
                {
                    found_est = (snap[i].tcp_state == TcpState::Established);
                    break;
                }
            }
            Expect(found_est, "tcp_state graduates to EST after SYN+ACK");
        }
        // Ingress from a different peer port -> denied (no conntrack).
        const Action a_in2 = FwEvaluate(Direction::Ingress, Proto::Tcp, peer, local, 81, local_port, kTcpAck, nullptr);
        Expect(a_in2 == Action::Deny, "ingress without conntrack hits default-deny");
        // RST collapses the entry to Closed.
        FwEvaluate(Direction::Egress, Proto::Tcp, local, peer, local_port, peer_port, kTcpRst, nullptr);
        {
            ConntrackEntry snap[kConntrackCap];
            const u32 n = ConntrackSnapshot(snap, kConntrackCap);
            for (u32 i = 0; i < n; ++i)
            {
                if (snap[i].local_port == local_port && snap[i].peer_port == peer_port)
                {
                    Expect(snap[i].tcp_state == TcpState::Closed, "tcp_state CLO after RST");
                }
            }
        }
    }
    FwSetDefaultPolicy(Direction::Ingress, Action::Allow);

    // ---------- Denial log captured the deny above ----------
    {
        DenialRecord rec[kFwLogCap];
        const u32 n = FwLogSnapshot(rec, kFwLogCap);
        Expect(n >= 1, "denial log captured at least one entry");
        Expect(FwLogTotalCount() >= 1, "denial total monotone");
    }

    // ---------- Exceptions: BOTH directions ----------
    //
    // The point of these checks is that an exception is narrow. A
    // test that only shows the excepted tuple passing cannot tell a
    // working exception apart from a disabled firewall, so every
    // allow below is paired with a neighbouring tuple that must
    // still be denied under the same default policy.
    FwInit();
    FwSetDefaultPolicy(Direction::Ingress, Action::Deny);
    ConntrackReset();
    {
        // `FwInit` re-seeds `fw-allow=` boot tokens, so the table is
        // NOT necessarily empty here. Compare against a captured
        // baseline rather than absolute counts — an absolute
        // `== 1` passes only on boots with no seed, which is exactly
        // the kind of test that quietly stops meaning anything.
        const u32 base_exceptions = FwExceptionCount();

        // Addresses chosen to sit outside any plausible fw-allow=
        // seed a developer would type, so a seeded rule cannot mask
        // the deny half of the comparison below.
        constexpr Ipv4Address kPeer = {{198, 51, 100, 7}};
        constexpr Ipv4Address kOtherPeer = {{198, 51, 100, 8}};
        constexpr Ipv4Address kLocal = {{198, 51, 100, 1}};

        // Baseline: with inbound default-deny and no exception, the
        // target tuple is refused.
        {
            const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kPeer, kLocal, 40000, 8080, kTcpSyn, nullptr);
            Expect(a == Action::Deny, "exception baseline: tuple denied before the exception exists");
        }

        // Install the exception via the textual spec path.
        u32 eidx = kFwMaxRules;
        const char kSpec[] = "in:tcp:198.51.100.7/32:8080";
        Expect(FwExceptionAdd(kSpec, sizeof(kSpec) - 1, &eidx), "FwExceptionAdd accepts a well-formed spec");
        Expect(eidx < kFwMaxRules, "exception occupies a rule slot");
        Expect(FwExceptionCount() == base_exceptions + 1, "exception counted as an exception");

        // ALLOW direction: the excepted tuple now passes.
        {
            const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kPeer, kLocal, 40000, 8080, kTcpSyn, nullptr);
            Expect(a == Action::Allow, "exception allows the tuple it names");
        }

        // STILL-DENIED direction 1: a different peer.
        {
            const Action a =
                FwEvaluate(Direction::Ingress, Proto::Tcp, kOtherPeer, kLocal, 40000, 8080, kTcpSyn, nullptr);
            Expect(a == Action::Deny, "exception does not generalise to another peer");
        }
        // STILL-DENIED direction 2: a different port on the same peer.
        {
            const Action a = FwEvaluate(Direction::Ingress, Proto::Tcp, kPeer, kLocal, 40000, 8081, kTcpSyn, nullptr);
            Expect(a == Action::Deny, "exception does not generalise to another port");
        }
        // STILL-DENIED direction 3: a different protocol.
        {
            const Action a = FwEvaluate(Direction::Ingress, Proto::Udp, kPeer, kLocal, 40000, 8080, 0, nullptr);
            Expect(a == Action::Deny, "exception does not generalise to another protocol");
        }

        // Malformed specs must be rejected outright, never applied
        // partially — a half-understood exception is a hole of
        // unknown shape.
        const char kBadProto[] = "in:sctp:198.51.100.7/32:8080";
        const char kBadMask[] = "in:tcp:198.51.100.7/33:8080";
        const char kBadPort[] = "in:tcp:198.51.100.7/32:70000";
        const char kBadShape[] = "in:tcp:198.51.100.7/32";
        Expect(!FwExceptionAdd(kBadProto, sizeof(kBadProto) - 1, nullptr), "unknown proto rejected");
        Expect(!FwExceptionAdd(kBadMask, sizeof(kBadMask) - 1, nullptr), "mask > 32 rejected");
        Expect(!FwExceptionAdd(kBadPort, sizeof(kBadPort) - 1, nullptr), "port > 65535 rejected");
        Expect(!FwExceptionAdd(kBadShape, sizeof(kBadShape) - 1, nullptr), "missing field rejected");
        Expect(FwExceptionCount() == base_exceptions + 1, "rejected specs installed nothing");

        // Promoting a logged denial produces a working exception for
        // that exact host, and only that host.
        ConntrackReset();
        const u64 before = FwLogTotalCount();
        (void)FwEvaluate(Direction::Ingress, Proto::Tcp, kOtherPeer, kLocal, 40000, 9090, kTcpSyn, nullptr);
        Expect(FwLogTotalCount() == before + 1, "denial recorded for the promote test");
        u32 pidx = kFwMaxRules;
        Expect(FwExceptionFromDenial(FwLogTotalCount(), &pidx), "FwExceptionFromDenial promotes a live denial");
        {
            const Action a =
                FwEvaluate(Direction::Ingress, Proto::Tcp, kOtherPeer, kLocal, 40000, 9090, kTcpSyn, nullptr);
            Expect(a == Action::Allow, "promoted denial now allowed");
        }
        {
            constexpr Ipv4Address kThirdPeer = {{198, 51, 100, 9}};
            const Action a =
                FwEvaluate(Direction::Ingress, Proto::Tcp, kThirdPeer, kLocal, 40000, 9090, kTcpSyn, nullptr);
            Expect(a == Action::Deny, "promoted denial did not widen to other hosts");
        }
        // A sequence that never existed must not promote anything.
        Expect(!FwExceptionFromDenial(0, nullptr), "sequence 0 rejected");
        Expect(!FwExceptionFromDenial(FwLogTotalCount() + 100, nullptr), "future sequence rejected");
    }
    FwSetDefaultPolicy(Direction::Ingress, Action::Allow);

    // Reset back to clean v0 state.
    FwInit();
    KLOG_INFO("net/firewall", "selftest complete");
}

} // namespace duetos::net::firewall
