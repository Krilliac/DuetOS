# Network Stack

> **Audience:** Net stack hackers, driver authors
>
> **Execution context:** Kernel — IRQ for RX/TX completions, softirq for stack
>
> **Maturity:** v0 — DHCP + DNS + TCP/UDP live; async winsock surface deferred

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
- **TCP** — synchronous send / recv, listen / accept
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
- **No async winsock surface.** `WSAAsyncSelect`, `WSAEventSelect`,
  IOCP — none implemented. Synchronous BSD-socket subset works.
- **TCP is single-stream-friendly.** Real congestion control is
  basic; bulk-transfer throughput optimisation is deferred.
- **No connection tracking** in the firewall — flipping the
  default-deny inbound policy on without it would break TCP
  connects we initiated, since the peer's reply would arrive
  unsolicited. v0 defaults Allow inbound for that reason.
- **No firewall logging ring** for recent denials; the
  per-rule hit counters are the only signal an operator can
  read today.

## Related Pages

- [Networking Drivers](../drivers/Networking-Drivers.md)
- [Live Internet Verification](Live-Internet.md)
- [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md) — `ws2_32`
  end of the stack
- [Linux Networking Port Opportunities](../advanced/Linux-Networking-Port-Opportunities.md)
