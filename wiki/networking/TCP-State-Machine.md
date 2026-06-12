# TCP v1 State Machine

> **Audience:** Net stack hackers, socket-layer authors
>
> **Execution context:** Kernel — segment dispatch from softirq /
> driver RX task; timer task runs every 50 ms
>
> **Maturity:** v1 — full RFC-793 state machine + per-TCB retransmit
> + sliding window + out-of-order reassembly + full SACK (RFC 2018
> RX + RFC 6675 sender recovery) + CUBIC (Reno-floored) + classic
> ECN (RFC 3168 negotiation **and** data plane).

## What lives here

`kernel/net/tcp.{h,cpp}` and its sibling TUs (`tcp_segment.cpp`,
`tcp_timer.cpp`, `tcp_cubic.cpp`, `tcp_sack.{h,cpp}`,
`tcp_selftest.cpp`, `tcp_internal.h`) host the in-kernel TCP
implementation. There is **one** TCP stack in DuetOS;
every caller — kernel shells, native syscalls, Linux subsystem,
Win32 subsystem, DRSH — reaches it through `net/socket.h` or
directly through the `duetos::net::tcp::` namespace.

The v0 single-slot machine that used to live in `kernel/net/stack.cpp`
is gone. The wiki/reference/Design-Decisions.md log records the
choice to replace it with a TCB-table machine rather than scaling
the slot count.

## TCB layout

A TCB (transmission control block) holds the per-connection state:

| Field | Purpose |
|---|---|
| `state` | RFC-793 lifecycle marker. See state table below. |
| `iface_index`, `local_ip`/`port`, `peer_ip`/`port`, `peer_mac` | Identity. |
| `iss`, `irs` | Initial seq numbers. |
| `snd_una`, `snd_nxt`, `snd_wnd` | Send-side bookkeeping. |
| `rcv_nxt`, `rcv_wnd` | Receive-side bookkeeping. |
| `mss_send`, `snd_wscale`, `rcv_wscale` | Negotiated options. |
| `peer_supports_timestamps`, `ts_recent` | RFC-7323 timestamps. |
| `cwnd`, `ssthresh`, `dup_acks`, `in_fast_recovery` | Congestion control (CUBIC with Reno floor; `cubic.*` holds the RFC 9438 state). |
| `sack_high`, `sack` | RFC 6675 sender scoreboard: highest SACKed edge + hole list / HighRxt / RecoveryPoint (`tcp_sack.{h,cpp}`). |
| `ecn_ok`, `peer_ce_pending`, `sent_cwr`, `ecn_react_seq` | RFC 3168 ECN: negotiation result + CE→ECE echo obligation + one-shot CWR + once-per-window reduction mark. |
| `srtt_ticks`, `rttvar_ticks`, `rto_ticks`, `retries` | RFC-6298 RTT estimator. |
| `rtx_deadline`, `timewait_deadline`, `delack_deadline`, `keepalive_deadline` | Timer fields, all in scheduler ticks. |
| `sndbuf`, `rcvbuf`, `rtx_queue`, `oo_queue` | Heap-allocated buffers. |
| `read_wq`, `write_wq`, `connect_wq`, `accept_wq` | Wait queues for blocking I/O. |
| `backlog_ring` | Listener-only: queue of accepted children. |

Each TCB is ~2 KiB of metadata. The data buffers (`sndbuf`, `rcvbuf`,
`rtx_queue`) are heap-allocated lazily — a fresh TCB without traffic
costs nothing beyond the metadata slot. With both buffers allocated
plus the rtx queue, a full TCB consumes ~88 KiB of heap.

The table holds `kTcbCap = 256` slots, indexed via a 64-bucket hash
on `(iface, local_ip, local_port, peer_ip, peer_port)`. Listeners
are excluded from the hash and live in a separate linear scan.

`TcbId` is a 32-bit handle that packs `(generation << 24) | (idx + 1)`.
The generation bumps on every allocation/free, so stale handles can't
resurrect a freed slot.

## State table

```
CLOSED ─SYN(active)──> SYN_SENT
        SYN(passive)─> SYN_RCVD ───────────┐
                                            │
SYN_SENT ─SYN+ACK──> ESTABLISHED  <──ACK── ┘
                       │
                       │ user Close()    peer FIN
                       ▼                   ▼
                    FIN_WAIT_1         CLOSE_WAIT
                       │                   │ user Close()
                       │ ACK               ▼
                       ▼                LAST_ACK
                    FIN_WAIT_2             │ ACK
                       │                   ▼
                       │ peer FIN       CLOSED
                       ▼
                    TIME_WAIT
                       │ 2 * MSL
                       ▼
                    CLOSED
```

Simultaneous close: `FIN_WAIT_1` + peer FIN → `CLOSING` → `TIME_WAIT`.

## Segment dispatch

```
NIC RX ──> NetStackInjectRx ──> Ipv4HandleIncoming
                                       │
                                       ▼
                              tcp::OnSegment(iface, mac, ip, hdr, len, ce)
                                       │
                                       ▼  exact 5-tuple match?
                            ┌──────────┴──────────┐
                          yes                    no
                            │                     │
                            ▼                     ▼
                       Deliver to TCB        SYN to listener?
                            │            ┌────────┴────────┐
                            ▼          yes                 no
                       state machine     │                  │
                                         ▼                  ▼
                                  HandleListenSyn       send RST
```

## Sliding window

The receive window advertised in our ACKs is `kRcvBufBytes -
rcvbuf_count`, shifted down by `rcv_wscale` (set to 0 in v1 — we
advertise the full window without scaling). The sender's effective
window is `min(snd_wnd, cwnd) - in_flight`; `DrainSendBuffer` slices
data out of `sndbuf` into the rtx queue under this cap.

Window updates: a ACK that opens room (≥ `mss_send` bytes) past the
last-advertised window triggers an immediate window-update ACK so
the peer learns about the open window.

## Retransmit

`rtx_queue` holds at most `kRtxQueueMax = 16` in-flight segments.
Each segment carries its send seq and timestamp. The timer task walks
every TCB every 50 ms; when `now >= rtx_deadline`:

- Flush the SACK scoreboard (`SackOnRto` — RFC 2018 §8: the receiver
  may have reneged, so every `sacked` bit and hole is untrustworthy).
- Collapse `cwnd` to `mss_send`; `ssthresh` comes from the CA hook
  (CUBIC beta when enabled, `(snd_nxt - snd_una) / 2` RFC-5681 §4.2
  otherwise).
- Double `rto_ticks` (bounded by `kMaxRtoMs = 60_000`).
- Resend the lowest-seq unacked segment.
- Increment `retries`; once `retries > kMaxRetries = 7`, the TCB
  sends a final RST and tears down.

RTT samples come from the RFC-7323 timestamp echo: when an ACK
carries `tsecr`, we compute `now - tsecr`. Karn's algorithm is
honoured by ignoring samples on retransmitted segments (the
timestamp echo guarantees this — a peer ACK only echoes a tsval we
sent without a retransmit).

## Congestion control: CUBIC (Reno-floored) + SACK / ECN reactions

Slow-start while `cwnd < ssthresh`: `cwnd += mss_send` per ACK. In
congestion avoidance, CUBIC (RFC 9438, integer-only port of Linux
`tcp_cubic.c` in `tcp_cubic.cpp`) computes the window, floored to
the NewReno candidate via `max(cubic, reno)`; `cubic.enabled` is the
per-TCB kill switch back to pure NewReno.

Fast retransmit fires on the third duplicate ACK. What happens next
depends on the SACK scoreboard (`tcp_sack.{h,cpp}`):

- **SACK recovery (RFC 6675)** — when the scoreboard holds holes
  (the peer negotiated SACK and sent blocks), the episode is
  pipe-driven: `ssthresh` comes from the CA hook (CUBIC beta or Reno
  halving), `cwnd` holds at `ssthresh`, the first presumed-lost
  segment is retransmitted immediately (§5 step 3), then
  `SackRecoveryTransmit` keeps sending — `NextSeg()` holes first,
  new data second — while `cwnd − SetPipe() ≥ SMSS`. Partial ACKs
  (below `RecoveryPoint`, §5.1) keep the episode open, trim covered
  holes and re-run the loop without growing `cwnd`; the episode ends
  when the cumulative ACK reaches `RecoveryPoint`.
- **NewReno fallback** — without SACK information:
  `cwnd = ssthresh + 3 * mss_send`, retransmit the oldest unacked
  segment, inflate `cwnd` by one MSS per further dup-ACK, exit on
  the first advancing ACK (the pre-SACK behaviour, unchanged).

**ECN (RFC 3168)** is a third congestion signal: an inbound ECE on an
`ecn_ok` connection routes through the same CA hooks (CUBIC beta /
Reno halving) but retransmits nothing; `ecn_react_seq` limits the
reaction to once per window of data, and the next outbound data
segment announces CWR. Outbound data segments carry ECT(0) in the IP
TOS ECN field; an inbound CE mark schedules the ECE echo on every
ACK until the peer's CWR arrives. AccECN (RFC 9768) is deliberately
not implemented — classic feedback only.

## Out-of-order reassembly

Each TCB owns an inline `oo_queue[kReassQueueMax = 8]`. When an
in-order segment arrives at `rcv_nxt`, `DeliverPayload` copies it
into the rcv ring then loops through `oo_queue` looking for
segments whose seq has become contiguous, splicing them in. An
OOO segment past the window or with a duplicate seq is dropped
silently.

## Options

| Option | Negotiated on | Honoured by v1? |
|---|---|---|
| MSS (RFC 879) | SYN | Yes — caps `mss_send`. |
| Window scale (RFC 7323) | SYN | Yes — we advertise wscale=0, accept peer's. |
| SACK-permitted (RFC 2018) | SYN | Yes — `peer_supports_sack` captured both sides; SACK blocks emitted from the OoO reassembly queue on every ACK that carries OoO state. |
| SACK (RFC 2018 / RFC 6675) | Any non-SYN ACK | Yes, both directions — RX emits up to 4 blocks per ACK, most-recent-first; TX consumes inbound blocks into the per-segment `sacked` bits + the RFC 6675 hole scoreboard that drives pipe-based fast recovery (see Congestion control below). |
| Timestamps (RFC 7323) | SYN, every seg | Yes — drives RTT estimation + PAWS. |
| ECN (RFC 3168) | SYN flag bits + IP TOS | Yes (negotiation **and** data plane) — connector sends SYN with ECE+CWR, listener echoes ECE; on `ecn_ok` connections data segments leave with ECT(0), an inbound CE mark schedules the ECE echo, and an inbound ECE halves cwnd through the CA hooks + announces CWR. AccECN (RFC 9768) deliberately omitted. |

The selftest covers the option-encoder/decoder round-trip and
explicitly asserts SACK block emission from the OoO queue,
SACK-suppression when the peer didn't negotiate, the ECN flag-bit
encoding round-trip, the RFC 6675 scoreboard (hole rebuild, IsLost,
SetPipe, NextSeg, cumulative-ACK trim, teardown free) and the
RFC 3168 data plane (CE→ECE echo, once-per-window ECE reduction,
one-shot CWR, ECT(0)-on-data-only).

## Capabilities

TCP doesn't introduce new capability gates — `kCapNet` still gates
`SYS_SOCK_*` syscalls. The cross-cutting roadmap item to split
`kCapNet` into `kCapNetConnect` / `kCapNetBind` / `kCapNetBindPriv` /
`kCapNetListen` / `kCapNetRaw` lands in a follow-up slice.

## Self-test

`DUETOS_BOOT_SELFTEST(duetos::net::tcp::SelfTest())` runs at boot:

- `TcbId` encode/decode round-trip (catches generation drift).
- Bucket insert + lookup + remove for the 5-tuple hash.
- `AckInWindow` wrap-around math.
- Out-of-order reassembly: deliver seg2 first, then seg1, assert
  the rcv buffer holds both segments contiguously.
- RTO backoff math stays within `[kMinRtoMs, kMaxRtoMs]`.
- `StateName` covers every enum value.
- RFC 6675 sender scoreboard: hole rebuild from SACK blocks,
  `IsLost` / `SetPipe` / `NextSeg` rules (1)/(3), HighRxt-preserving
  rebuild, cumulative-ACK trim, teardown free. Emits its own
  `[net/tcp-selftest] PASS (rfc6675 sack scoreboard)` sentinel.
- RFC 3168 ECN data plane: CE→ECE echo until CWR, once-per-window
  ECE reduction through the CA hook, one-shot CWR, ECT(0) on data
  segments only. Emits `[net/tcp-selftest] PASS (rfc3168 ecn data
  plane)`.

On pass: one explicit `[net/tcp-selftest] PASS (...)` line (plus the
two sentinels above). On any failure: `[net/tcp-selftest] FAIL
(<which>)` + `kBootSelftestFail` probe fire.

## Known limits / GAPs (v1)

These get explicit roadmap rows; future slices retire them one at
a time.

- **No AccECN (RFC 9768).** Classic RFC 3168 ECN feedback only —
  one ECE-driven reduction per window, no per-packet CE counting.
  Revisit if/when an L4S / DOCSIS target needs it.
- **ECN is IPv4-only.** The IPv6 RX path doesn't thread the
  traffic-class ECN field (`ip_ce` defaults to false); pairs with
  the v6 socket-layer work (the v6 TCB demux is itself a GAP).
- **ECT(0) on retransmits.** RFC 3168 §6.1.5 prefers not-ECT on
  retransmitted segments; `EcnApplyTx` doesn't distinguish them.
  Revisit if ECN blackholing shows up against real middleboxes.
- **No SYN cookies.** SYN flood defense is a backlog-overflow drop
  in v1. A follow-up slice adds RFC-4987 SYN cookies.
- **No persist timer.** Zero-window probes piggyback on the
  retransmit timer.
- **Window-scale advertised as 0.** We accept the peer's shift but
  advertise 0 ourselves. Bump to 7 once `kRcvBufBytes` grows past
  64 KiB.
- **Single global IRQ-off lock** (`arch::Cli` / `arch::Sti`). SMP
  migration lands per-bucket spinlocks; the structure is ready.
- **Half-open recovery is RST-only.** When a connection's peer
  vanishes mid-stream, the retransmit timer eventually times out
  and we send RST. Keepalive is opt-in.

## Reading the source

- [`tcp.h`](../../kernel/net/tcp.h) — public surface (`Listen`, `Connect`, `Accept`, `Send`, `Recv`, `Close`).
- [`tcp_internal.h`](../../kernel/net/tcp_internal.h) — TCB layout, internal helpers.
- [`tcp.cpp`](../../kernel/net/tcp.cpp) — TCB table, public API, allocation/release.
- [`tcp_segment.cpp`](../../kernel/net/tcp_segment.cpp) — segment build/parse, state machine, reassembly.
- [`tcp_timer.cpp`](../../kernel/net/tcp_timer.cpp) — periodic timer task.
- [`tcp_selftest.cpp`](../../kernel/net/tcp_selftest.cpp) — boot-time self-test.

## Related pages

- [Network Stack](Network-Stack.md) — overall stack overview.
- [DRSH Remote Access](DRSH-Remote-Access.md) — the kernel's remote-shell protocol, now able to host multiple concurrent sessions on top of v1.
- [Design Decisions](../reference/Design-Decisions.md) — why TCB table over slot scaling, why Reno over CUBIC, etc.
