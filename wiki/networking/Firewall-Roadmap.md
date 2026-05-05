# Firewall — Roadmap

DuetOS ships a v0 packet filter wired into the IPv4 ingress
path (`Ipv4HandleIncoming`) and the IPv4 egress helper
(`IfaceTx`). The Start menu's **FIREWALL** entry renders the
live rule table — direction, protocol, src/dst prefixes,
action, and per-rule hit counters.

## Today (v0 — landed)

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
firewall stats                                  — aggregate ingress/egress counters
firewall add <in|out> <any|tcp|udp|icmp>
             <src/mask> <dst/mask>
             <sport|sport-range|any>
             <dport|dport-range|any>
             <allow|deny>                       — add a rule (returns its index)
firewall del <idx>                              — clear a rule slot
firewall toggle <idx>                           — flip the active flag
firewall default <in|out> <allow|deny>          — set per-direction default
firewall reset                                  — wipe rule table; defaults=allow/allow
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
   Today the app is read-only. Adding / removing / toggling
   rules from the desktop needs an interactive widget
   bound to `kCapNetAdmin` (the kernel shell + the new
   `firewall` command can already drive the API directly).
2. **Connection tracking** for "established + related"
   semantics so the Windows-style default-deny inbound
   policy can be flipped on without breaking outbound TCP
   replies. v0 keeps default Allow inbound for that
   reason — a TCP connect we initiated would be
   unanswerable otherwise.
3. **Per-process socket policy.** Filter keyed off the
   owning `Process::caps` so a sandboxed Win32 PE can be
   denied network egress entirely regardless of the
   global rule table.
4. **Logging hooks.** A bounded ring of recent denials
   (timestamp, direction, 5-tuple) for the kernel shell
   to surface — useful when an operator is debugging a
   "why is this connection failing?" question.

The placeholder text on the Firewall app stays accurate as
each item lands: today the app shows real rules, real
defaults, and real per-rule hit counters; the editor
surface is the next slice.
