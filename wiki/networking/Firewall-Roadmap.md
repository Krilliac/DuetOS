# Firewall — Roadmap

DuetOS ships a v0 packet filter wired into the IPv4 ingress
path (`Ipv4HandleIncoming`) and the IPv4 egress helper
(`IfaceTx`). The Start menu's **FIREWALL** entry renders the
live rule table — direction, protocol, src/dst prefixes,
action, and per-rule hit counters.

## Today (v0 — landed)

- **Connection tracking** for TCP / UDP with a real TCP
  state machine. Every egress packet that no rule
  explicitly matches registers a conntrack entry keyed on
  `(proto, local_ip, local_port, peer_ip, peer_port)`. On
  ingress, if no rule matches AND the default policy is
  Deny, the firewall consults conntrack for the reverse-
  direction tuple before denying — a hit yields Allow.
  Each TCP entry rides a four-state machine
  (NEW / Established / FinWait / Closed): SYN egress
  inserts NEW; SYN+ACK ingress graduates to Established;
  FIN moves to FinWait; RST collapses to Closed. UDP
  entries stay in Established. Per-state expiry replaces
  fixed proto TTLs — NEW=30s, Established=300s, FinWait=
  60s, Closed=10s. Capacity 64; LRU eviction.
- **Recent-denial ring** (`kFwLogCap = 32`) captures
  every Deny verdict (timestamp ticks, direction,
  protocol, src/dst IP+port, matched rule index — or
  `kFwMaxRules` for default-policy denies). Surface via
  `FwLogSnapshot` / `FwLogTotalCount` and the
  `firewall log` shell command.
- **Static rule table** at `kernel/net/firewall.{h,cpp}`,
  capacity 32, evaluated first-match-wins.
- **Tuple:** direction (Ingress / Egress), protocol
  (Any / ICMP / TCP / UDP), source prefix, destination
  prefix, source port range, destination port range,
  action (Allow / Deny). Port ranges only match for
  TCP / UDP — ICMP / Any rules ignore them.
- **Default policies** are configurable per direction and
  default to Allow / Allow at boot so the existing DHCP
  / DNS / TCP smoke paths keep working without explicit
  allow-list rules.
- **Hooks:**
  - **Ingress:** `Ipv4HandleIncoming` runs the firewall after
    header validation but before any per-protocol dispatch.
    A Deny verdict drops the frame and returns false; the
    rest of the stack never sees it.
  - **Egress:** `IfaceTx` parses the IPv4 header out of the
    frame the per-protocol senders already laid down, runs
    the firewall, and bumps `tx_dropped_firewall` on a Deny.
    Every TX site (UDP send, TCP segment, ICMP echo
    request, ICMP echo reply, ARP request, ARP reply) routes
    through this helper — the firewall cannot be bypassed
    from inside the stack.
- **Read access** (snapshot rules, observe per-rule hit
  counters, read aggregate `Stats`) is unprivileged — the
  rule list is configuration, not secrets, and the
  Network Status / Firewall apps poll without a cap.
- **Edit access** (`FwAdd`, `FwRemove`, `FwToggle`,
  `FwSetDefaultPolicy`) is gated on the new
  `kCapNetAdmin` capability so a sandboxed PE cannot
  disable a Deny rule that's blocking it. `kCapNetAdmin`
  is distinct from `kCapNet` — a process can be allowed
  to USE the network without being allowed to
  RECONFIGURE it. Both belong to the trusted profile.
- **Boot self-test** (`FwSelfTest`) exercises rule add /
  match / miss / default-policy flip / subnet-mask
  matching / hit-counter increment / toggle / remove.
  Runs at the same point as the other net subsystem
  self-tests.

## Shell command (landed)

The kernel shell exposes the firewall via a `firewall`
command:

```
firewall list                                   — show rules + per-rule hit counts
firewall stats                                  — aggregate ingress/egress + conntrack counters
firewall log                                    — recent denials (oldest first)
firewall conntrack                              — active conntrack entries
firewall add <in|out> <any|tcp|udp|icmp>
             <src/mask> <dst/mask>
             <sport|sport-range|any>
             <dport|dport-range|any>
             <allow|deny>                       — add a rule (returns its index)
firewall del <idx>                              — clear a rule slot
firewall toggle <idx>                           — flip the active flag
firewall default <in|out> <allow|deny>          — set per-direction default
firewall reset                                  — wipe rule table + conntrack + log; defaults=allow/allow
```

Examples:

```
firewall add in tcp 0.0.0.0/0 0.0.0.0/0 any 22-22 deny
firewall default in deny
firewall add in tcp 10.0.2.0/24 0.0.0.0/0 any 80 allow
firewall list
```

The kernel shell runs trusted, so its calls satisfy
`kCapNetAdmin` automatically; a future userland editor
issuing the same calls through a syscall surface will
gate on the cap.

## Planned (not committed yet)

1. **Desktop editor surface in `kernel/apps/firewall.cpp`.**
   The app now renders rules + recent denials + active
   conntrack entries (read-only). Editing from the desktop
   needs an interactive widget bound to `kCapNetAdmin` —
   the kernel shell's `firewall` command is the v0 edit
   path.
2. **Per-process socket policy.** Filter keyed off the
   owning `Process::caps` so a sandboxed Win32 PE can be
   denied network egress entirely regardless of the
   global rule table.

The placeholder text on the Firewall app stays accurate as
each item lands: today the app shows real rules, real
defaults, and real per-rule hit counters; the editor
surface is the next slice.
