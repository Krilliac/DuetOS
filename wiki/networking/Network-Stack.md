# Network Stack

> **Audience:** Net stack hackers, driver authors
>
> **Execution context:** Kernel — IRQ for RX/TX completions, softirq for stack
>
> **Maturity:** v1 TCP (multi-connection, sliding-window, retransmit)
> + v0 of every other protocol; async winsock surface deferred

## Overview

`kernel/net/` is the single kernel-owned net stack. It is reached from
two ABI front-ends:

- **Native sockets**: `SYS_SOCK_*` syscalls
- **Win32 sockets**: `userland/libs/ws2_32/` translates the Winsock
  API to `SYS_SOCK_*`

Three netifs feed the stack today (e1000, USB CDC-ECM, USB RNDIS).
See [Networking Drivers](../drivers/Networking-Drivers.md).

## Layered Composition

```
[ socket API (native or ws2_32 translator) ]
        |
[ syscall dispatch ]                       SYS_SOCK_*
        |
[ kernel net stack ]                       kernel/net/
        |
[ ARP / IP / UDP / TCP / DNS / DHCP ]
        |
[ netif ]                                  driver-side adapter
        |
[ device adapter ]                         e1000 / USB ECM / USB RNDIS
        |
[ link ]
```

## Protocols Live Today

- **Ethernet** + ARP
- **IPv4** with proper TTL / fragmentation handling
- **ICMP** (ping)
- **UDP**
- **TCP v1** — full RFC-793 state machine, sliding window,
  retransmit with RFC-6298 RTO, out-of-order reassembly, Reno
  congestion control. Up to 256 concurrent TCBs per host. See
  [TCP State Machine](TCP-State-Machine.md) for the design + RFC
  mapping.
- **TCP SACK (receiver side)** — when a peer negotiates
  SACK-Permitted on the SYN, every ACK from us that carries
  out-of-order RX state emits up to 4 SACK blocks (RFC 2018),
  most-recent-first, sourced directly from the reassembly queue.
  Sender-side SACK processing (RFC 6675 scoreboard / NextSeg) is
  the next slice.
- **TCP ECN negotiation (RFC 3168 §6.1.1)** — the initial SYN
  carries ECE+CWR; an ECN-capable peer replies SYN+ACK with
  ECE=1, CWR=0, and the connection records `ecn_ok = true`. A
  listener that receives an ECN-Setup-SYN echoes ECE=1, CWR=0 in
  its SYN+ACK. The IP-layer ECT/CE bit threading (data segments
  carry ECT(0); received CE → ECE feedback → CWR confirmation)
  is the next slice and lives in `stack.cpp`'s IPv4 emit/recv
  path — see GAP below.
- **DHCP client** — gets an IP from the local network
- **DNS resolver** — `getaddrinfo`-equivalent

## Live Verification

DuetOS reaches Google over a real connection:

1. e1000 link comes up.
2. DHCP OFFER + ACK acquire an IP.
3. DNS query for `www.google.com` resolves.
4. TCP connect to port 80 succeeds.
5. HTTP `GET /` returns a real response.

See [Live Internet Verification](Live-Internet.md).

## Shell Commands

The kernel shell exposes:

- `ifconfig` — list netifs + addresses
- `dhcp` — kick the DHCP client
- `route` — route table
- `netscan` — local scan
- `net <addr>` — quick reach test

See [Shell Commands](../reference/Shell-Commands.md) for the full list.

## Capability Surface

- `kCapNet` — `SYS_SOCK_*`, raw socket, listen, connect.
- `kCapNetAdmin` — firewall edit operations (`FwAdd`,
  `FwRemove`, `FwToggle`, `FwSetDefaultPolicy`). Read access
  to the rule table and per-iface counters is unprivileged.

## Operator Surface

The kernel shell exposes the firewall via a `firewall`
command (`firewall list / stats / add / del / toggle /
default / reset`) — see the Firewall page for syntax and
examples.

## Firewall (v0)

A static rule table in `kernel/net/firewall.{h,cpp}` runs at
two hook points:

- **Ingress:** `Ipv4HandleIncoming` consults the firewall
  after IPv4 header validation and drops a Deny verdict
  before any per-protocol dispatch.
- **Egress:** `IfaceTx` (the helper every TX site routes
  through) parses the IPv4 header, runs the firewall, and
  bumps `tx_dropped_firewall` on a Deny.

Rules are evaluated first-match-wins on the 5-tuple
`(direction, proto, src_prefix, dst_prefix, src_port_range,
dst_port_range)`. Default policies are configurable per
direction and default to Allow / Allow at boot so existing
DHCP / DNS / TCP smoke paths keep working without explicit
allow-list rules.

## Per-interface Counters

`InterfaceCountersRead(iface_index)` returns a snapshot of
`{ rx_packets, rx_bytes, tx_packets, tx_bytes,
tx_dropped_firewall, tx_dropped_unbound }`. Counters are
bumped at `NetStackInjectRx` (rx side) and `IfaceTx` (tx
side). The Network Status app polls them for per-iface
throughput display.

## Known Limits / GAPs

- **No IPv6.** v6 is on the deferred list — IPv4 covers the workload
  surface today.
- **`WSAEventSelect` / `WSAEnumNetworkEvents` /
  `WSAWaitForMultipleEvents` shipped** with a real producer
  side — `kSockOpPollEvents` (op 14 on `SYS_SOCKET_OP = 153`)
  reports the current FD_READ / FD_WRITE / FD_ACCEPT / FD_CLOSE
  bitmask per socket, and the userland Wait loop polls every
  10 ms to signal event handles. **`WSAAsyncSelect` (window-
  message delivery) and IOCP overlapped socket reads are still
  out of scope.**
- **TCP NewReno fast retransmit + Reno congestion control;
  receiver-side SACK lands but no CUBIC / BBR** yet. CUBIC is
  ~400 LoC + 56 bytes/TCB and is the next congestion-control
  slice; BBR needs a pacer + delivery-rate estimator and is
  deferred. See [TCP State Machine](TCP-State-Machine.md#known-limits--gaps-v1)
  for the full v1 GAP list.
- **TCP SACK sender-side processing** — receiver-side SACK
  emission lands; sender-side scoreboard + RFC 6675 NextSeg
  (~600 LoC + ~16 B per outstanding hole) is the next slice.
  Until then the sender ignores incoming SACK blocks and falls
  back to NewReno's fast-retransmit on triple-dup-ACK. Reference:
  FreeBSD `sys/netinet/tcp_sack.c` (hole-list scoreboard, ~1100
  LoC).
- **TCP ECN IP-layer ECT/CE threading** — RFC 3168 negotiation
  is live; the data-plane half (set ECT(0) on outbound IP TOS for
  `ecn_ok` connections, detect inbound CE, schedule the ECE
  feedback, halve cwnd + emit CWR on the ECE arrival) wires
  through `stack.cpp`'s IPv4 path next. Pairs naturally with
  AccECN (RFC 9768 — the 2024 successor) for L4S / DOCSIS
  prioritisation.
- **No TCP Fast Open (RFC 7413).** Middlebox interference (~6%
  of paths drop SYN-data) plus disabled-by-default at major
  CDNs (Cloudflare, Fastly, Google Frontends) means the
  cost/benefit doesn't pencil. Deferred indefinitely; QUIC 0-RTT
  is the modern replacement.
- Conntrack and the recent-denial log ring (`kFwLogCap = 32`) have
  landed; see [Firewall Roadmap](Firewall-Roadmap.md) for the live
  state machine and capacity. Default-deny inbound is still off by
  policy choice (Allow by default), not by missing infrastructure.

## Related Pages

- [TCP State Machine](TCP-State-Machine.md) — TCB layout, RFC-793 state
  diagram, retransmit + reassembly + congestion-control internals.
- [Networking Drivers](../drivers/Networking-Drivers.md)
- [Live Internet Verification](Live-Internet.md)
- [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md) — `ws2_32`
  end of the stack
- [Linux Networking Port Opportunities](../advanced/Linux-Networking-Port-Opportunities.md)
