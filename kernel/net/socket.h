#pragma once

#include "net/stack.h"
#include "net/tcp.h"
#include "sched/sched.h"
#include "util/types.h"

/*
 * DuetOS — kernel socket layer.
 *
 * The shared between-Linux-and-Win32 socket pool that backs the BSD
 * socket family (Linux: socket/bind/connect/sendto/recvfrom; Win32:
 * winsock equivalents). Handlers in subsystems/linux/syscall_socket.cpp
 * and subsystems/win32/winsock_syscall.cpp own the user-pointer
 * marshaling; this layer owns the kernel-resident state and the
 * RX dispatch through net/stack.cpp's L4 paths.
 *
 * Supported family/types:
 *   AF_INET + SOCK_DGRAM  — full bind / sendto / recvfrom + connect
 *                           (so plain send/recv works on a connected
 *                           UDP socket). Multi-socket multiplexed by
 *                           local port.
 *   AF_INET + SOCK_STREAM — backed by net/tcp.cpp's TCB table. Real
 *                           multi-connection support: many listeners,
 *                           many concurrent accepted sockets. v0 used
 *                           to share a single TCP slot; v1 dropped
 *                           that limit.
 *
 * Refcounting matches the pipe/eventfd pools: dup() bumps refs;
 * close() drops refs; pool entry is freed and any RX queue drained
 * when refs hit 0.
 *
 * Threading model: every pool mutation runs under arch::Cli; SMP
 * needs a per-pool spinlock, same shape as the pipe/eventfd pools.
 *
 * RX delivery: NetUdpDispatch in stack.cpp checks the socket pool
 * via SocketUdpDispatch BEFORE the legacy UdpBinding table — once
 * a port is owned by a socket, the legacy callback path doesn't
 * fire for it. TCP RX is fully owned by net/tcp.cpp; the socket
 * layer reads via tcp::RecvNonblocking and writes via tcp::Send.
 */

namespace duetos::net
{

inline constexpr u32 kSocketPoolCap = 256;
inline constexpr u32 kSocketUdpRxQueueCap = 8;      // per-socket RX queue depth
inline constexpr u32 kSocketDgramPayloadCap = 1500; // standard MTU

inline constexpr u16 kSocketDomainInet = 2;
inline constexpr u32 kSocketTypeStream = 1;
inline constexpr u32 kSocketTypeDgram = 2;

struct SocketDgram
{
    Ipv4Address src_ip;
    u16 src_port;
    u16 _pad;
    u32 len;
    u8 payload[kSocketDgramPayloadCap];
};

struct Socket
{
    bool in_use;
    u8 _pad0[3];
    u32 refs;        // dup() bumps; close() drops
    u16 family;      // AF_INET only in v0
    u16 type;        // SOCK_DGRAM or SOCK_STREAM
    u32 iface_index; // interface this socket is anchored to (always 0 in v0)
    u32 _pad1;

    // Endpoint state.
    bool bound;
    bool connected;
    bool listening;
    u8 shutdown_flags; // bit 0 = SHUT_RD, bit 1 = SHUT_WR
    u16 local_port;
    u16 peer_port;
    Ipv4Address local_ip;
    Ipv4Address peer_ip;

    // UDP RX queue (ring of inbound datagrams).
    u32 udp_head;
    u32 udp_tail;
    u32 udp_count;
    u32 _pad2;
    SocketDgram* udp_rx; // KMalloc'd kSocketUdpRxQueueCap * sizeof(SocketDgram)

    // SOCK_STREAM — a handle into the TCB table (net/tcp.cpp). 0
    // when the socket is bound but not yet listening / connecting,
    // non-zero once Listen/Connect/Accept has populated a TCB.
    tcp::TcbId tcb;

    // Loopback short-circuit (T3-01). When a connect() targets
    // 127.x.x.x and a listener is bound to the requested port,
    // both ends are paired through two kernel pipe pool slots
    // (one ring per direction). Send/recv on a paired socket
    // bypass the on-wire TCP stack entirely.
    bool loopback_paired;
    i32 loopback_pipe_recv_idx;
    i32 loopback_pipe_send_idx;
    i32 loopback_pending_accept_idx;

    // Blocking primitives — readers wait on this when the queue /
    // TCP state isn't ready; writers / RX paths wake it.
    sched::WaitQueue read_wq;
    // Listener-only — accept() blocks here when no pending
    // connection is queued; SocketConnect's loopback path wakes
    // it after wiring the pair.
    sched::WaitQueue accept_wq;
};

/// Allocate a fresh socket (refs = 1). Returns pool index or -1 on
/// pool full / OOM.
i32 SocketAlloc(u16 domain, u16 type);

/// Increment refs (dup / fork-inherit). Idempotent on bad idx.
void SocketRetain(u32 idx);

/// Decrement refs; on last release, drain RX queue + free pool entry
/// + close any owned TCB.
void SocketRelease(u32 idx);

/// True iff `idx` is a live pool entry.
bool SocketAlive(u32 idx);

/// Accessor — read-only. Returns nullptr on dead idx.
const Socket* SocketGet(u32 idx);

/// Bind the socket to a local port. UDP: claims the port in the
/// shared port table. TCP: records the port + ip; the TCB is built
/// in SocketListen / SocketConnect. `local_ip = 0.0.0.0` means
/// "any interface".
bool SocketBind(u32 idx, Ipv4Address local_ip, u16 local_port);

/// Set peer endpoint. UDP: just records peer. TCP: kicks off the
/// active-connect state machine in tcp::Connect.
bool SocketConnect(u32 idx, Ipv4Address peer_ip, u16 peer_port);

/// Mark socket as listening (TCP). Allocates a tcp::TcbId via
/// tcp::Listen with the requested backlog (clamped to
/// tcp::kListenBacklogMax).
bool SocketListen(u32 idx, u32 backlog);

/// Accept the next ready connection. Blocks on the listener's
/// accept wait queue until one of:
///   - a loopback pair is waiting (T3-01)
///   - the TCB table delivers an ESTABLISHED child via tcp::AcceptNonblocking
/// Returns the new socket pool index (refs=1), or -1 on bad listener.
i32 SocketAccept(u32 listener_idx, Ipv4Address* out_peer_ip, u16* out_peer_port);

/// Non-blocking probe of the listener's loopback accept queue.
/// Returns the accepted socket's pool index when a paired
/// connector is pending (T3-01 loopback path), -1 otherwise.
i32 SocketAcceptLoopback(u32 listener_idx, Ipv4Address* out_peer_ip, u16* out_peer_port);

/// SOCK_DGRAM send. Builds + transmits an IPv4 UDP datagram via
/// stack.cpp::NetUdpSend; if dst_ip / dst_port are zero, falls
/// back to the connected peer. Returns bytes sent or -errno.
i64 SocketSendDgram(u32 idx, Ipv4Address dst_ip, u16 dst_port, const u8* data, u32 len);

/// SOCK_DGRAM recv. Pops the head of the RX queue, copying up to
/// `cap` bytes to `out`. Reports the original payload size in
/// `*out_len`, source endpoint via `*out_src_ip` / `*out_src_port`
/// (any may be null). Blocks until a datagram arrives. Returns
/// bytes copied or -errno.
i64 SocketRecvDgram(u32 idx, u8* out, u32 cap, u32* out_len, Ipv4Address* out_src_ip, u16* out_src_port);

/// SOCK_STREAM send. Pushes onto the TCB's snd buffer; blocks until
/// at least one byte is accepted (or until shutdown / EPIPE).
/// Returns bytes queued or -errno.
i64 SocketSendStream(u32 idx, const u8* data, u32 len);

/// SOCK_STREAM recv. Reads from the TCB's RX buffer. Returns bytes
/// copied; 0 on orderly EOF (peer FIN + buffer drained); -errno on
/// error.
i64 SocketRecvStream(u32 idx, u8* out, u32 cap);

/// shutdown(2) half-close. how: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR.
bool SocketShutdown(u32 idx, u32 how);

/// Get / set sockname endpoints.
void SocketGetLocal(u32 idx, Ipv4Address* out_ip, u16* out_port);
void SocketGetPeer(u32 idx, Ipv4Address* out_ip, u16* out_port);

/// L4 RX hook — UDP datagram dispatch. TCP is dispatched directly
/// from net/stack.cpp's IPv4 path into net/tcp.cpp::OnSegment.
bool SocketUdpDispatch(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len);

/// Async-IO readiness probe — returns a bitmask of Winsock
/// `FD_*` events currently active on `idx`. Drives the producer
/// side of `WSAEnumNetworkEvents` / `WSAWaitForMultipleEvents`.
///
/// Returned bits (mirror of Winsock FD_* constants):
///   bit 0  (0x01)  FD_READ    — recv would return data without blocking
///   bit 1  (0x02)  FD_WRITE   — send would not block
///   bit 3  (0x08)  FD_ACCEPT  — listener has a pending connection
///   bit 5  (0x20)  FD_CLOSE   — peer FIN or shutdown(RD) on this end
///
/// Returns 0 on dead idx.
u32 SocketPollEvents(u32 idx);

/// Stats accessor — boot/shell reporting.
struct SocketStats
{
    u64 allocs;
    u64 releases;
    u64 binds;
    u64 connects;
    u64 dgram_tx;
    u64 dgram_rx;
    u64 dgram_dropped;
    u64 stream_tx;
    u64 stream_rx;
};
SocketStats SocketStatsRead();

} // namespace duetos::net
