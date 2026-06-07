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
[ ARP / IPv4 / IPv6 / UDP / TCP / DNS / DHCP / HTTP / TLS ]
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

## Native Socket ABI (`SYS_SOCKET_OP`)

`SYS_SOCKET_OP = 153` is the native ABI front-end into the stack — a
multi-op syscall whose `rdi` selects the operation. `userland/libs/ws2_32/`
translates Winsock onto the same op table. Defined in
`kernel/syscall/syscall.h`, dispatched in `kernel/syscall/syscall.cpp`:

| Op | Name | Purpose |
|----|------|---------|
| 1 | `kSockOpCreate` | Create a socket (`AF_INET`) |
| 2 | `kSockOpBind` | Bind to a `sockaddr_in` |
| 3 | `kSockOpConnect` | Connect to a `sockaddr_in` |
| 4 | `kSockOpListen` | Listen with a backlog |
| 5 | `kSockOpAccept` | Accept; fills peer `sockaddr_in` |
| 6 | `kSockOpSendto` | Send to a buffer / address |
| 7 | `kSockOpRecvfrom` | Receive into a buffer |
| 8 | `kSockOpShutdown` | Half/full shutdown (how 0/1/2) |
| 9 | `kSockOpClose` | Close the socket |
| 10 | `kSockOpGetSock` | Read local `sockaddr` |
| 11 | `kSockOpGetPeer` | Read peer `sockaddr` |
| 12 | `kSockOpResolveA` | Blocking A-record lookup |
| 13 | `kSockOpGetLease` | Snapshot the current DHCP lease |
| 14 | `kSockOpPollEvents` | Non-blocking readiness probe (FD_READ / FD_WRITE / FD_ACCEPT / FD_CLOSE), backs the Winsock event surface (`net::SocketPollEvents`) |

## HTTP Client

`kernel/net/http.cpp` is the in-kernel HTTP/1.1 client used by the shell
`wget` path, the browser, and the install fetchers. It drives a TCP (or
TLS, via the TLS client below) socket, sends the request line + headers,
and decodes the response body via both `Content-Length` and
chunked transfer-encoding.

GAP: `http.cpp:718` — chunked trailers are drained off the wire but not
surfaced to the caller.

## Cookie Jar

`kernel/net/cookies.cpp` is the per-host cookie jar consumed by the HTTP
client and browser. It parses `Set-Cookie`, honours expiry / `Max-Age` /
`Path` / domain matching, and persists to a FAT32 volume when one is
mounted (`cookies.cpp:730`).

GAPs:

- `cookies.cpp:26` + `cookies.h:14` — no public-suffix list, so eTLD+1
  enforcement is absent (a site cannot be stopped from setting a cookie
  for a too-broad domain like `.com` by the PSL, only by the basic
  domain-match rule).
- No `__Secure-` / `__Host-` cookie-prefix handling.

## TLS Client

The HTTPS path layers `kernel/net/tls.{h,cpp}` (a TLS 1.2 client) over
the TCP socket. See [TLS Client](TLS-Roadmap.md) for the handshake state
machine, the embedded root store, and the cert-verification GAPs.

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

## Threading & Locking Model

- **RX** runs from the netif driver's IRQ tail via `NetStackInjectRx`,
  which copies the frame and hands it to the protocol demux. ARP / IPv4
  / IPv6 dispatch, TCP reassembly, and UDP delivery all complete in this
  context, so no sleeping primitive may be taken on the RX path.
- **Socket syscalls** (`SYS_SOCKET_OP`) run in the calling process's
  context. Blocking ops (`kSockOpConnect`, `kSockOpAccept`,
  `kSockOpRecvfrom`, `kSockOpResolveA`) park the thread on a wait queue;
  `kSockOpPollEvents` never blocks.
- The TCB table, socket table, ARP cache, and DHCP lease are guarded by
  per-table spinlocks taken IRQ-off, because the IRQ RX path and the
  process-context syscall path both touch them.
- **TLS / HTTP / cookies** run entirely in the caller's process context
  on top of a socket — they may block on socket reads and never run from
  IRQ.

## Capability Surface

- `kCapNet` — `SYS_SOCK_*`, raw socket, listen, connect.
- `kCapNetAdmin` — firewall edit operations (`FwAdd`,
  `FwRemove`, `FwToggle`, `FwSetDefaultPolicy`). Read access
  to the rule table and per-iface counters is unprivileged.

## Spoofing resistance

- **TCP ISN** is generated with an RFC-6528-style keyed hash over the
  connection 4-tuple plus a boot-seeded CSPRNG secret (`core::RandomU64`),
  not the old tick-seeded LCG — an off-path attacker can no longer predict
  the initial sequence number to forge in-window segments, while the
  per-4-tuple keying keeps `TIME-WAIT` old-duplicate monotonicity.
  (Security audit ML-02, CWE-330.)
- **DNS** now uses a random transaction ID and a random ephemeral source
  port per query, and `DnsOnUdp` validates the reply's source IP
  (resolver), source port (53), and destination port before accepting it —
  blind cache poisoning now requires guessing ~30 bits instead of zero.
  (Security audit ML-03, CWE-290.)

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

- **IPv6 is partial.** `kernel/net/ipv6.cpp` parses/builds the 40-byte
  fixed header, answers ICMPv6 echo, does the minimal Neighbor
  Discovery (NS → NA) needed for link-local reachability, and computes
  the IPv6 pseudo-header checksum for UDP/TCP. EtherType `0x86DD` is
  demuxed in `stack.h` (`kEtherTypeIpv6`, the `Ipv6Header` struct).
  Three GAPs cap the v0 surface:
  - `ipv6.cpp:385` (UDP) and `ipv6.cpp:403` (TCP) — the transport demux
    tables are keyed on `Ipv4Address`, so a v6 datagram is delivered
    with a zero v4 placeholder peer. The shared transport runs but the
    peer address is not threaded through; real v6 sockets need a tagged
    address key.
  - `stack.h:106` — extension headers (Hop-by-Hop, Routing, Fragment,
    Dest Options), fragmentation/reassembly, full ND (RS/RA, DAD,
    redirect), SLAAC, MLD, and routing are all deferred.
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

## Troubleshooting

- **No DHCP lease** — check `ifconfig` for a link-up netif, then `dhcp`
  to re-kick the client; `kSockOpGetLease` (op 13) snapshots the current
  lease for a programmatic check.
- **DNS resolves but TCP connect hangs** — confirm a route exists
  (`route`) and that no firewall Deny rule is shadowing the egress;
  `firewall log` lists recent denials with the matched rule index.
- **HTTPS fails where HTTP works** — a non-browser TLS caller that never
  installed a cert verifier skips chain validation (`tls_socket.cpp:174`);
  cert-chain rejects for unsupported algorithms fail closed (see the TLS
  Client Known Limits).
- **A socket reports readable but recv returns 0** — that is a peer FIN /
  `FD_CLOSE`; re-check `kSockOpPollEvents` (op 14) for the `FD_CLOSE` bit.

## Related Pages

- [TCP State Machine](TCP-State-Machine.md) — TCB layout, RFC-793 state
  diagram, retransmit + reassembly + congestion-control internals.
- [Networking Drivers](../drivers/Networking-Drivers.md)
- [Live Internet Verification](Live-Internet.md)
- [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md) — `ws2_32`
  end of the stack
- [Linux Networking Port Opportunities](../advanced/Linux-Networking-Port-Opportunities.md)
