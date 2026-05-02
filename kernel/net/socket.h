#pragma once

#include "net/stack.h"
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
 * Supported family/types in v0:
 *   AF_INET + SOCK_DGRAM  — full bind / sendto / recvfrom + connect
 *                           (so plain send/recv works on a connected
 *                           UDP socket). Multi-socket multiplexed by
 *                           local port.
 *   AF_INET + SOCK_STREAM — connect / send / recv on top of the
 *                           single-slot TCP active-connect machinery
 *                           in stack.cpp. One TCP socket can be
 *                           Established at a time; concurrent
 *                           Established slots are a separate slice.
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
 * fire for it. That's intentional: UDP applications take ownership
 * by binding through socket(); the legacy table stays for kernel-
 * resident callers (DHCP / DNS / NTP).
 */

namespace duetos::net
{

inline constexpr u32 kSocketPoolCap = 8;
inline constexpr u32 kSocketUdpRxQueueCap = 8;      // per-socket RX queue depth
inline constexpr u32 kSocketDgramPayloadCap = 1500; // standard MTU
inline constexpr u32 kSocketTcpRxBufBytes = 65536;  // matches kTcpActiveBufBytes

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

    // TCP — bridges to the single-slot machine in stack.cpp. Only
    // one TCP socket can be Established at a time in v0; the
    // tcp_owner field arbitrates: if g_tcp_owner != idx + 1, this
    // socket can't read connection state.
    u32 tcp_owner_token; // 0 = doesn't own; >0 = pool idx + 1

    // Blocking primitives — readers wait on this when the queue /
    // TCP state isn't ready; writers / RX paths wake it.
    sched::WaitQueue read_wq;
};

/// Allocate a fresh socket (refs = 1). Returns pool index or -1 on
/// pool full / OOM.
i32 SocketAlloc(u16 domain, u16 type);

/// Increment refs (dup / fork-inherit). Idempotent on bad idx.
void SocketRetain(u32 idx);

/// Decrement refs; on last release, drain RX queue + free pool entry
/// + tear down any owned TCP slot.
void SocketRelease(u32 idx);

/// True iff `idx` is a live pool entry.
bool SocketAlive(u32 idx);

/// Accessor — read-only. Returns nullptr on dead idx. Pointer valid
/// until the next SocketRelease on this idx.
const Socket* SocketGet(u32 idx);

/// Bind the socket to a local port. UDP: claims the port in the
/// shared port table (returns false if already claimed by another
/// socket OR by a legacy NetUdpBindRx callback). TCP: records the
/// port + ip; TcpListen integration happens in SocketListen.
/// `local_ip = 0.0.0.0` means "any interface".
bool SocketBind(u32 idx, Ipv4Address local_ip, u16 local_port);

/// Set peer endpoint. UDP: just records peer for send()/recv()
/// without explicit destination. TCP: kicks off the active-connect
/// state machine in stack.cpp; returns false if another TCP socket
/// already owns the slot or NetTcpConnect refuses.
bool SocketConnect(u32 idx, Ipv4Address peer_ip, u16 peer_port);

/// Mark socket as listening (TCP). For now v0 stays simple: the
/// caller must already have called SocketBind. backlog parameter
/// stored but unused.
bool SocketListen(u32 idx, u32 backlog);

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

/// SOCK_STREAM send. v0 routes to the shared TCP active-connect
/// slot; only the owning socket can transmit. Returns bytes queued
/// or -errno.
i64 SocketSendStream(u32 idx, const u8* data, u32 len);

/// SOCK_STREAM recv. Reads from the shared TCP active-connect
/// buffer at the per-socket cursor. Returns bytes copied or 0 on
/// peer FIN, or -errno.
i64 SocketRecvStream(u32 idx, u8* out, u32 cap);

/// shutdown(2) half-close. how: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR.
bool SocketShutdown(u32 idx, u32 how);

/// Get / set sockname endpoints. Both copy into caller-owned out
/// pointers; either may be null.
void SocketGetLocal(u32 idx, Ipv4Address* out_ip, u16* out_port);
void SocketGetPeer(u32 idx, Ipv4Address* out_ip, u16* out_port);

/// L4 RX hook — called from stack.cpp's UDP demux BEFORE the
/// legacy UdpBinding table. Returns true if a socket consumed
/// the datagram. Safe to call from the driver's RX task context.
bool SocketUdpDispatch(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len);

/// L4 RX hook — TCP. Wakes any reader blocked on the active-
/// connect slot once new data arrived. Called from stack.cpp's
/// TCP segment handler when the canned-reply buffer grew.
void SocketTcpRxNotify();

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
