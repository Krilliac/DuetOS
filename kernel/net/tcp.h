#pragma once

#include "net/stack.h"
#include "sched/sched.h"
#include "util/types.h"

/*
 * DuetOS — TCP v1 multi-connection state machine.
 *
 * Replaces the v0 single-slot machine that used to live in
 * stack.cpp. The kernel now hosts a real TCB table that maps an
 * incoming 5-tuple (iface, src ip:port, dst ip:port) to a
 * connection control block, runs the full RFC-793 state machine
 * per TCB, and drives retransmit / sliding-window / out-of-order
 * reassembly out of a periodic timer task.
 *
 * The socket layer (kernel/net/socket.cpp) owns the user-facing
 * pool slot and stores a TcbId per connected stream socket. All
 * direct callers of the v0 API (browser, shell_network, net_smoke)
 * now route through sockets — this header is the only public TCP
 * surface in the kernel.
 *
 * Threading: every TCB touches g_tcb_table under a single
 * net-stack-wide spinlock (arch::Cli for v0; the slot for a real
 * per-bucket lock is wired but not enabled). The timer task uses
 * the same lock — IRQ-off windows are short (walk one bucket,
 * fire one segment).
 *
 * Reference: RFC 793 (base), RFC 5681 (congestion), RFC 6298
 * (RTO), RFC 7323 (timestamps + window scale).
 */

namespace duetos::net::tcp
{

// -------------------------------------------------------------------
// Configuration. Cap counts are intentionally generous — the v0
// crisis was "one connection at a time"; v1 ships room for 256
// simultaneous TCBs and a 32-deep backlog per listener.
// -------------------------------------------------------------------

inline constexpr u32 kTcbCap = 256;    ///< Max simultaneous TCBs.
inline constexpr u32 kTcbBuckets = 64; ///< Hash buckets for the lookup table (power of two).
inline constexpr u32 kListenBacklogMax = 32;
inline constexpr u32 kReassQueueMax = 8; ///< Out-of-order seg queue depth per TCB.
inline constexpr u32 kRtxQueueMax = 16;  ///< Retransmit queue depth per TCB.
inline constexpr u32 kRcvBufBytes = 32768;
inline constexpr u32 kSndBufBytes = 32768;
inline constexpr u32 kSegmentBytes = 1460; ///< One MSS-sized segment payload buffer.
inline constexpr u32 kDefaultMss = 1460;
inline constexpr u32 kMaxRetries = 7; ///< RFC-6298: drop the connection after 7 retransmits.

// Default RTO bounds (ms). RFC-6298 §2.4 says min 1 s for the
// initial RTO; we use 1 s to stay friendly to real networks. The
// production stack can lower this once we have a real RTT
// estimator on a loopback path that exercises microsecond timing.
inline constexpr u32 kInitialRtoMs = 1000;
inline constexpr u32 kMinRtoMs = 200;
inline constexpr u32 kMaxRtoMs = 60'000;
inline constexpr u32 kTimeWaitMs = 4000; ///< 2 * MSL, MSL = 2 s for v0.
inline constexpr u32 kDelackMs = 200;    ///< Delayed ACK timeout.

// MSL — Maximum Segment Lifetime. RFC-793 §3.3 suggests 2 minutes;
// we use 2 s in v0 because the lab + CI workloads churn TIME_WAIT
// faster than the spec assumes. Real internet workloads may need
// to lift this once IPv6 / long-haul paths land.
inline constexpr u32 kMslMs = 2000;

// -------------------------------------------------------------------
// State enum. The full RFC-793 + TIME_WAIT lifecycle. No SACK-PERMITTED
// or fast-open extensions; those are follow-up work.
// -------------------------------------------------------------------

enum class State : u8
{
    Closed = 0,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
};

const char* StateName(State s);

// -------------------------------------------------------------------
// TcbId — a stable handle into the table. Packs (index | generation)
// so a stale handle can't accidentally resurrect a freed slot.
// 0 is reserved for "no TCB".
// -------------------------------------------------------------------

using TcbId = u32;
inline constexpr TcbId kInvalidTcbId = 0;

// -------------------------------------------------------------------
// Stats — boot diagnostics + shell reporting + DRSH server status.
// Counters monotonic, snapshot under Cli.
// -------------------------------------------------------------------

struct Stats
{
    u64 segs_rx;
    u64 segs_tx;
    u64 rst_rx;
    u64 rst_tx;
    u64 retrans;
    u64 listens;
    u64 connects;
    u64 accepts;
    u64 closes;
    u64 oo_segs;          // out-of-order segments received
    u64 reass_drops;      // OOO segment dropped (queue full)
    u64 backlog_drops;    // SYN dropped — listener backlog full
    u64 timeouts;         // retransmit gave up
    u64 keepalive_probes; // keepalive probes sent
    u64 tcbs_alive;
};

Stats StatsRead();

// -------------------------------------------------------------------
// Public API — the socket layer is the only consumer (plus a small
// shell `tcp` command for diagnostics).
// -------------------------------------------------------------------

/// One-time bring-up. Spawns the tcp-timer kernel task that walks the
/// TCB table for retransmits, TIME_WAIT expiry, and keepalive probes.
/// Called from NetStackInit.
void Init();

/// Boot self-test. Drives a loopback handshake + payload + FIN through
/// the in-memory segment path, asserts the state machine lands on
/// CLOSED on both sides. Emits an explicit "[net/tcp-selftest] PASS"
/// line for CI grep.
void SelfTest();

/// Allocate a listening TCB. `local_ip = 0.0.0.0` binds the wildcard.
/// `backlog` is clamped to [1, kListenBacklogMax]. Returns
/// kInvalidTcbId on table-full / port-in-use.
TcbId Listen(u32 iface_index, Ipv4Address local_ip, u16 local_port, u32 backlog);

/// Non-blocking accept. Returns kInvalidTcbId when the backlog is
/// empty. On success, the returned TCB is in ESTABLISHED state and
/// the caller owns one reference (release with Release).
TcbId AcceptNonblocking(TcbId listener, Ipv4Address* out_peer_ip, u16* out_peer_port);

/// Wait queue the listener wakes when a SYN+ACK completes into
/// ESTABLISHED and pushes the child onto the backlog.
sched::WaitQueue* AcceptWaitQueue(TcbId listener);

/// Active open. `local_port = 0` picks an ephemeral. Returns the
/// new TCB in SYN_SENT — caller blocks on WaitConnected.
TcbId Connect(u32 iface_index, Ipv4Address dst_ip, u16 dst_port, u16 local_port);

/// Wait up to `timeout_ticks` for the TCB to land in ESTABLISHED.
/// Returns true on connected, false on timeout / refused / reset.
bool WaitConnected(TcbId id, u64 timeout_ticks);

/// Non-blocking send. Pushes onto the snd buffer and kicks TX.
/// Returns bytes accepted (0..len). Returns -1 on dead TCB or
/// shutdown(WR). The socket layer wraps this in a blocking loop.
i32 Send(TcbId id, const u8* data, u32 len);

/// Non-blocking recv. Pops from the per-TCB delivered RX buffer.
/// Returns bytes copied; 0 means "peer FIN seen and buffer drained"
/// (orderly EOF); -1 on dead TCB; -2 on temporarily empty (caller
/// blocks on RecvWaitQueue and retries).
i32 RecvNonblocking(TcbId id, u8* out, u32 cap);

/// Initiate active close. Sends FIN. Idempotent.
void Close(TcbId id);

/// Hard reset. Sends RST + drops the TCB.
void Abort(TcbId id);

/// Refcounting. Listen/Connect return with refs=1 (the caller's
/// reference). AcceptNonblocking returns the child with refs=1.
void Retain(TcbId id);
void Release(TcbId id);
bool Alive(TcbId id);

/// State accessor (diagnostics + readiness probes at the socket layer).
State GetState(TcbId id);

/// Has the peer's FIN been seen + ACK'd? True once we transition out
/// of ESTABLISHED via the peer-FIN path. Used by the socket layer to
/// report orderly EOF after the RX buffer is drained.
bool PeerClosed(TcbId id);

/// Endpoint accessors. Either out pointer may be null.
bool GetLocalEndpoint(TcbId id, Ipv4Address* out_ip, u16* out_port);
bool GetPeerEndpoint(TcbId id, Ipv4Address* out_ip, u16* out_port);

/// Wait queues for blocking I/O at the socket layer.
sched::WaitQueue* RecvWaitQueue(TcbId id);
sched::WaitQueue* SendWaitQueue(TcbId id);

/// Per-TCB options.
bool SetNoDelay(TcbId id, bool on);
bool SetKeepAlive(TcbId id, bool on);

// -------------------------------------------------------------------
// RX hook. Called from `Ipv4HandleIncoming` in stack.cpp on every
// inbound IPv4/TCP segment. The TCB-table dispatcher routes the
// segment to the matching TCB (or LISTEN parent), runs the state
// machine, and reschedules the timer task as needed.
// -------------------------------------------------------------------

void OnSegment(u32 iface_index, const MacAddress& peer_mac, Ipv4Address peer_ip, const u8* tcp, u64 tcp_len);

// -------------------------------------------------------------------
// Timer tick. The tcp-timer kernel task calls this every kTimerTickMs
// ms to walk the TCB table for RTO / TIME_WAIT / delack / keepalive.
// Exposed for selftests; production wiring is internal.
// -------------------------------------------------------------------

inline constexpr u32 kTimerTickMs = 50;

void TimerTick();

} // namespace duetos::net::tcp
