#pragma once

#include "net/tcp.h"
#include "sched/sched.h"
#include "util/types.h"

/*
 * DuetOS — TCP v1 internal types. Shared between tcp.cpp,
 * tcp_segment.cpp, tcp_timer.cpp, and tcp_selftest.cpp.
 *
 * Nothing in here is part of the public API — kernel callers should
 * include net/tcp.h. The split exists so the state machine can know
 * about the TCB layout without dragging it into the public header.
 */

namespace duetos::net::tcp
{

namespace internal
{

inline constexpr u8 kFlagFin = 0x01;
inline constexpr u8 kFlagSyn = 0x02;
inline constexpr u8 kFlagRst = 0x04;
inline constexpr u8 kFlagPsh = 0x08;
inline constexpr u8 kFlagAck = 0x10;
inline constexpr u8 kFlagUrg = 0x20;
inline constexpr u8 kFlagEce = 0x40; ///< ECN-Echo (RFC 3168).
inline constexpr u8 kFlagCwr = 0x80; ///< Congestion Window Reduced (RFC 3168).

inline constexpr u8 kOptEnd = 0;
inline constexpr u8 kOptNop = 1;
inline constexpr u8 kOptMss = 2;
inline constexpr u8 kOptWindowScale = 3;
inline constexpr u8 kOptSackPermitted = 4;
inline constexpr u8 kOptSack = 5;
inline constexpr u8 kOptTimestamp = 8;

inline constexpr u8 kBucketNone = 0xFF;

// One in-flight segment. Allocated as an array on the TCB heap;
// `len == 0` marks an unused slot.
struct SegmentBuf
{
    u32 seq;
    u32 len;
    u8 flags;
    u8 _pad[3];
    u64 ticks_sent;
    u8 data[kSegmentBytes];
};

// One out-of-order received segment, awaiting in-order delivery.
struct OoSegment
{
    bool in_use;
    u8 _pad[3];
    u32 seq;
    u32 len;
    u8 data[kSegmentBytes];
};

struct Tcb
{
    bool in_use;
    bool is_listener;
    u8 generation;
    State state;

    u32 iface_index;
    Ipv4Address local_ip;
    Ipv4Address peer_ip;
    u16 local_port;
    u16 peer_port;
    MacAddress peer_mac;
    u8 _pad0[2];

    u32 refs;

    // LISTEN-only: backlog ring of TcbIds for accepted children.
    u32 backlog_max;
    u32 backlog_count;
    u32 backlog_head;
    u32 backlog_tail;
    u32 backlog_ring[kListenBacklogMax];
    sched::WaitQueue accept_wq;

    // Child connections track their parent listener so the state
    // machine can push them onto the backlog when SYN_RCVD →
    // ESTABLISHED, and wake any accept().
    TcbId parent_listener;

    // Sequence space.
    u32 iss;
    u32 irs;
    u32 snd_una;
    u32 snd_nxt;
    u32 snd_wnd;
    u32 rcv_nxt;
    u32 rcv_wnd;

    // Options.
    u8 snd_wscale;
    u8 rcv_wscale;
    bool peer_supports_wscale;
    bool peer_supports_timestamps;
    bool peer_supports_sack;
    u32 ts_recent;
    u64 ts_recent_age_ticks;
    u16 mss_send;

    // ECN (RFC 3168). v0 implements the SYN-time negotiation only;
    // marking IP-layer ECT/CE bits is the next slice and lives in
    // stack.cpp's IPv4 emit/recv path.
    //
    // ecn_ok       — peer's SYN-ACK echoed (ECE=1, CWR=0) so we may
    //                use ECN-marked IP packets on this connection.
    // peer_ce_pending — RX side: we received an IP-layer CE-marked
    //                   segment and owe the peer an ECE on the next
    //                   outgoing ACK. (Not threaded yet — see GAP.)
    // sent_cwr     — TX side: we already lowered cwnd in response
    //                to the most recent ECE; next data segment
    //                emits CWR=1 to inform the peer.
    bool ecn_ok;
    bool peer_ce_pending;
    bool sent_cwr;

    // Congestion control (simplified Reno, RFC-5681).
    u32 cwnd;
    u32 ssthresh;
    u32 dup_acks;
    bool in_fast_recovery;

    // CUBIC congestion control (RFC 9438 / Linux tcp_cubic.c port).
    // Window members are in MSS-PACKETS to match the reference
    // fixed-point scaling; converted to/from cwnd (BYTES) at the CA
    // boundary. epoch_start uses the 100Hz tick clock. Growth is
    // floored to NewReno at the call site (max(cubic,reno)) so it can
    // never underperform; `enabled` is the kill switch back to Reno.
    struct CubicState
    {
        u32 last_max_cwnd;    // W_max in packets
        u32 bic_origin_point; // origin (W_max or cwnd), packets
        u32 bic_K;            // time-to-origin (BICTCP_HZ-scaled)
        u32 tcp_cwnd;         // Reno-friendly estimate, packets
        u32 cnt;              // ACKs needed per +1 packet
        u32 cwnd_cnt;         // ACK accumulator toward next +1
        u32 ack_cnt;          // ACKed packets this epoch
        u32 delay_min_ticks;  // min RTT seen (ticks); 0 = unknown
        u64 epoch_start;      // tick at epoch start; 0 = not in epoch
        bool enabled;         // false → fall back to NewReno
    } cubic;

    // RTT estimator (RFC-6298). All in ticks (100 Hz).
    bool rtt_have_sample;
    u32 srtt_ticks;
    u32 rttvar_ticks;
    u32 rto_ticks;
    u8 retries;

    // Timers. 0 = disarmed. Compared against NowTicks() by the
    // timer task.
    u64 rtx_deadline;
    u64 timewait_deadline;
    u64 delack_deadline;
    u64 keepalive_deadline;
    // Zero-window persist timer (RFC 9293 §3.8.6.1 / RFC 1122
    // §4.2.2.17). Armed by DrainSendBuffer when the peer advertises a
    // zero send window while we still have data queued; fired by the
    // timer task to probe the peer for a window update. Without it, a
    // lost window-reopening ACK strands the sender forever. backoff
    // doubles per probe, capped at kMaxRtoMs.
    u64 persist_deadline;
    u32 persist_backoff_ticks;
    bool delack_pending;
    bool keepalive_on;

    // Options + RX flags.
    bool nodelay;
    bool peer_fin_seen;
    u32 peer_fin_seq;
    bool tx_closed;

    // Blocking primitives — readers/writers/connectors block on
    // these; the state machine wakes them on data, window updates,
    // and state changes.
    sched::WaitQueue read_wq;
    sched::WaitQueue write_wq;
    sched::WaitQueue connect_wq;

    // Bucket linkage. kBucketNone for chain tail.
    u8 bucket_next;
    u8 _pad1[3];

    // Heap-backed buffers (allocated by AllocTcbBuffers, freed by
    // FreeTcbBuffers).
    u8* sndbuf; // ring of bytes pushed by the user, awaiting TX.
    u8* rcvbuf; // ring of in-order bytes ready for Recv().
    SegmentBuf* rtx_queue;

    u32 sndbuf_head;
    u32 sndbuf_tail;
    u32 sndbuf_count;
    u32 rcvbuf_head;
    u32 rcvbuf_tail;
    u32 rcvbuf_count;
    u32 rtx_count;

    OoSegment oo_queue[kReassQueueMax];
};

// These are `extern` declarations; the definitions in tcp.cpp are
// `constinit`, so the kernel never relies on dynamic (.init_array)
// initialization for them — the freestanding-kernel hazard this check
// guards against is already eliminated at the definition site. The check
// still flags the header declaration because it can't see the constinit
// definition from here; suppress with that rationale.
// NOLINTBEGIN(bugprone-dynamic-static-initializers)
extern constinit Tcb g_tcbs[kTcbCap];
extern constinit u8 g_buckets[kTcbBuckets];
extern constinit Stats g_stats;
extern constinit bool g_initialised;
extern constinit u16 g_ephemeral_cursor;
// NOLINTEND(bugprone-dynamic-static-initializers)

// Helpers shared across the TCP TUs. All assume the caller holds
// arch::Cli (single-CPU stand-in for a per-bucket lock).
u64 NowTicks();
u32 MsToTicks(u32 ms);
bool IpEq(Ipv4Address a, Ipv4Address b);
bool IpZero(Ipv4Address a);
u32 BucketHash(u32 iface, Ipv4Address local_ip, u16 local_port, Ipv4Address peer_ip, u16 peer_port);
TcbId MakeId(u32 idx, u8 generation);
bool DecodeId(TcbId id, u32* out_idx);
Tcb* TcbFromId(TcbId id);
void BucketInsert(u32 idx);
void BucketRemove(u32 idx);
u32 LookupExact(u32 iface, Ipv4Address local_ip, u16 local_port, Ipv4Address peer_ip, u16 peer_port);
u32 LookupListener(u16 local_port);
u32 AllocSlot();
u16 AllocEphemeralPort();
void ResetTcbStorage(Tcb& t);
bool AllocTcbBuffers(Tcb& t);
void FreeTcbBuffers(Tcb& t);

// Segment building / sending. Defined in tcp_segment.cpp.
//
// SendSegment owns L2/L3/L4 framing: builds the ethernet + IPv4 +
// TCP header with the correct options for this TCB's state, runs
// it through the firewall via IfaceTx, bumps stats. `payload` /
// `payload_len` may be null/0 for control segments.
bool SendSegment(Tcb& t, u8 flags, u32 seq, u32 ack, const u8* payload, u32 payload_len);

// Drain bytes from sndbuf onto the wire, honouring snd_wnd, cwnd,
// and the rtx_queue depth. Called from Send(), from ACK processing,
// and from the timer (after retransmit completes). `extra_cwnd`
// temporarily widens the effective congestion window for RFC 3042
// Limited Transmit (one new segment per early dup-ACK); 0 = normal.
void DrainSendBuffer(Tcb& t, u32 extra_cwnd = 0);

// Effective send window = min(snd_wnd, cwnd + extra_cwnd), overflow-safe.
// Exposed for the self-test; used by DrainSendBuffer's clamp.
u32 EffectiveSendWindow(const Tcb& t, u32 extra_cwnd);

// PAWS (RFC 7323 §5.3): true if a segment carrying `seg_tsval` should be
// dropped as a stale duplicate — i.e. the connection is synchronized,
// the peer uses timestamps, the segment is not a RST, and seg_tsval is
// older (mod-2^32) than ts_recent. Exposed for the self-test.
bool PawsReject(const Tcb& t, u32 seg_tsval, u8 flags, bool has_timestamp);

// Schedule a retransmit timer. Sets t.rtx_deadline = now + rto_ticks.
// No-op if the rtx_queue is empty.
void ArmRtxTimer(Tcb& t);

// Process an inbound segment. Called from OnSegment after the TCB
// lookup. `peer_mac`/`peer_ip` come from the L2/L3 headers; the rest
// is parsed inline. Drops the TCB on Closed.
void DeliverSegment(u32 idx, const MacAddress& peer_mac, Ipv4Address peer_ip, const u8* tcp, u64 tcp_len);

// Send a one-shot RST in response to a segment that didn't match
// any TCB. Used as the default reject path.
void SendStandaloneRst(u32 iface_index, const MacAddress& peer_mac, Ipv4Address peer_ip, u16 peer_port, u16 local_port,
                       u32 peer_seq, u32 peer_ack, u8 peer_flags);

// Selftest hooks — exposed for the boot-time self-test in
// tcp_selftest.cpp. Production callers go through OnSegment /
// Send / Recv on the public surface.
bool AckInWindow(u32 ack, u32 snd_una, u32 snd_nxt);
bool DeliverPayload(Tcb& t, u32 seq, const u8* data, u32 len);

/// Build the TCP option block for an outgoing segment. Same
/// semantics as the internal call site in tcp_segment.cpp. Exposed
/// so the boot self-test can assert SACK / timestamp / ECN-related
/// option encoding without going through the wire path.
u32 BuildOptions(const Tcb& t, u8 flags, u8* opts);

/// Number of in-use slots in the OoO reassembly queue. O(N) walk
/// over kReassQueueMax — at the v0 cap (8) it's cheaper than a
/// running counter we'd have to keep in sync.
u32 OoSegmentCount(const Tcb& t);

// Move a TCB into TIME_WAIT (arms the 2*MSL timer).
void EnterTimeWait(Tcb& t);

// Tear down a TCB. Wakes all waiters, frees buffers, bumps
// generation so any pending TcbId becomes invalid.
void DropTcb(u32 idx);

// Wake any blocked accept() on the parent listener after a child
// hits ESTABLISHED. Idempotent.
void NotifyParentAccept(Tcb& child);

// ---------------------------------------------------------------
// CUBIC congestion control (RFC 9438 / Linux tcp_cubic.c port).
// Implemented in tcp_cubic.cpp; declared here for the call sites
// (tcp_segment.cpp, tcp_timer.cpp) and the self-test. Integer-only.
// ---------------------------------------------------------------
// Compile-time integer constants (no float). BICTCP_HZ=10,
// beta=717/1024≈0.7, bic_scale=41 — all from Linux defaults.
inline constexpr u32 kBictcpHz = 10;
inline constexpr u32 kBictcpBetaScale = 1024;
inline constexpr u32 kCubicBeta = 717; // ≈0.7
inline constexpr u32 kCubicBicScale = 41;
inline constexpr u32 kCubeRttScale = kCubicBicScale * 10;                                  // 410
inline constexpr u64 kCubeFactor = (1ull << (10 + 3 * kBictcpHz)) / (kCubicBicScale * 10); // 2^40/410
inline constexpr u32 kBetaScale = (8 * (kBictcpBetaScale + kCubicBeta) / 3) / (kBictcpBetaScale - kCubicBeta); // 15

// 1-based index of the highest set bit (0 for 0). Linux fls64.
u32 Fls64(u64 a);
// Exact floor(cbrt(a)) — the self-test oracle.
u64 IcbrtExact(u64 a);
// Linux table+Newton cube root (~0.2% err) — used on the live path.
u32 CubicRoot(u64 a);
// Pure CUBIC window target for a scaled time `tt` relative to origin
// `origin_pkts` and time-to-origin `bic_K`. Exposed so the self-test
// can pin the concave/convex shape without a clock.
u32 CubicTarget(u32 origin_pkts, u32 bic_K, u64 tt);
// Per-ACK CA update: recomputes cubic.cnt for the current cwnd (pkts).
void CubicUpdate(Tcb& t, u32 cwnd_pkts, u32 acked_pkts);
// Loss reaction: returns new ssthresh (pkts), updates last_max_cwnd,
// ends the epoch. beta=717/1024 with fast-convergence.
u32 CubicRecalcSsthresh(Tcb& t, u32 cwnd_pkts);

} // namespace internal

} // namespace duetos::net::tcp
