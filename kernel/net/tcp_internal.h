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
    u32 ts_recent;
    u64 ts_recent_age_ticks;
    u16 mss_send;

    // Congestion control (simplified Reno, RFC-5681).
    u32 cwnd;
    u32 ssthresh;
    u32 dup_acks;
    bool in_fast_recovery;

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

extern Tcb g_tcbs[kTcbCap];
extern u8 g_buckets[kTcbBuckets];
extern Stats g_stats;
extern bool g_initialised;
extern u16 g_ephemeral_cursor;

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
// and from the timer (after retransmit completes).
void DrainSendBuffer(Tcb& t);

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

// Move a TCB into TIME_WAIT (arms the 2*MSL timer).
void EnterTimeWait(Tcb& t);

// Tear down a TCB. Wakes all waiters, frees buffers, bumps
// generation so any pending TcbId becomes invalid.
void DropTcb(u32 idx);

// Wake any blocked accept() on the parent listener after a child
// hits ESTABLISHED. Idempotent.
void NotifyParentAccept(Tcb& child);

} // namespace internal

} // namespace duetos::net::tcp
