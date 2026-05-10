/*
 * DuetOS — kernel socket pool implementation. See socket.h for the
 * public surface and design rationale.
 */

#include "net/socket.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/net/net.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "subsystems/linux/syscall_pipe.h"

namespace duetos::net
{

namespace
{

Socket g_pool[kSocketPoolCap] = {};
SocketStats g_stats = {};

// Per-TCP-socket RX cursor — bytes already consumed by recv() from
// the shared NetTcpActiveRead buffer. Indexed by pool slot; only
// meaningful when the slot owns the active-connect machine.
u32 g_tcp_consumed[kSocketPoolCap] = {};

bool IpZero(Ipv4Address a)
{
    return a.octets[0] == 0 && a.octets[1] == 0 && a.octets[2] == 0 && a.octets[3] == 0;
}

// Find a UDP socket holding `port`. Returns kSocketPoolCap on miss.
u32 FindUdpBoundPort(u16 port)
{
    for (u32 i = 0; i < kSocketPoolCap; ++i)
    {
        const Socket& s = g_pool[i];
        if (s.in_use && s.type == kSocketTypeDgram && s.bound && s.local_port == port)
            return i;
    }
    return kSocketPoolCap;
}

// Single-slot TCP arbitration. Token = pool idx + 1 (so 0 means
// "no socket owns it"). When a TCP socket transitions away from
// ownership (close, shutdown both halves, FIN'd), the token clears
// so the next connect() can claim the slot.
u32 g_tcp_owner = 0;

// Allocate an ephemeral source port on demand. v0 picks from a
// reserved range outside the well-known port space and outside the
// stack's hard-coded ports (DHCP=68, DNS resolver, NTP).
u16 g_ephemeral_cursor = 49152;
u16 AllocEphemeralPort()
{
    for (u32 attempts = 0; attempts < 256; ++attempts)
    {
        const u16 candidate = g_ephemeral_cursor++;
        if (g_ephemeral_cursor < 49152)
            g_ephemeral_cursor = 49152; // wrap into RFC 6056 range
        if (FindUdpBoundPort(candidate) == kSocketPoolCap)
            return candidate;
    }
    return 0;
}

} // namespace

i32 SocketAlloc(u16 domain, u16 type)
{
    if (domain != kSocketDomainInet)
        return -1;
    if (type != kSocketTypeDgram && type != kSocketTypeStream)
        return -1;

    arch::Cli();
    for (u32 i = 0; i < kSocketPoolCap; ++i)
    {
        if (g_pool[i].in_use)
            continue;
        Socket& s = g_pool[i];
        arch::Sti();
        // Allocate the UDP RX queue outside the cli/sti window —
        // KMalloc may sleep on a fragmented heap.
        SocketDgram* rx = nullptr;
        if (type == kSocketTypeDgram)
        {
            rx = static_cast<SocketDgram*>(mm::KMalloc(sizeof(SocketDgram) * kSocketUdpRxQueueCap));
            if (rx == nullptr)
                return -1;
        }
        arch::Cli();
        if (g_pool[i].in_use)
        {
            // Lost a race with another CPU. v0 is single-CPU so
            // this can't happen, but keep the helper SMP-correct
            // for the day SMP lands.
            arch::Sti();
            if (rx != nullptr)
                mm::KFree(rx);
            return -1;
        }
        s.in_use = true;
        s.refs = 1;
        s.family = domain;
        s.type = type;
        s.iface_index = 0;
        s.bound = false;
        s.connected = false;
        s.listening = false;
        s.shutdown_flags = 0;
        s.local_port = 0;
        s.peer_port = 0;
        s.local_ip = {};
        s.peer_ip = {};
        s.udp_head = 0;
        s.udp_tail = 0;
        s.udp_count = 0;
        s.udp_rx = rx;
        s.tcp_owner_token = 0;
        s.loopback_paired = false;
        s.loopback_pipe_recv_idx = -1;
        s.loopback_pipe_send_idx = -1;
        s.loopback_pending_accept_idx = -1;
        s.read_wq.head = nullptr;
        s.read_wq.tail = nullptr;
        s.accept_wq.head = nullptr;
        s.accept_wq.tail = nullptr;
        g_tcp_consumed[i] = 0;
        ++g_stats.allocs;
        arch::Sti();
        return static_cast<i32>(i);
    }
    arch::Sti();
    return -1;
}

void SocketRetain(u32 idx)
{
    if (idx >= kSocketPoolCap)
        return;
    arch::Cli();
    if (g_pool[idx].in_use)
        ++g_pool[idx].refs;
    arch::Sti();
}

void SocketRelease(u32 idx)
{
    if (idx >= kSocketPoolCap)
        return;
    arch::Cli();
    Socket& s = g_pool[idx];
    if (!s.in_use || s.refs == 0)
    {
        arch::Sti();
        return;
    }
    --s.refs;
    if (s.refs > 0)
    {
        arch::Sti();
        return;
    }
    sched::WaitQueueWakeAll(&s.read_wq);
    sched::WaitQueueWakeAll(&s.accept_wq);
    if (s.tcp_owner_token != 0 && g_tcp_owner == idx + 1)
        g_tcp_owner = 0;
    // Loopback pair: drop the per-end pipe refcounts. The pipe pool
    // tears the slot down when both refcounts hit zero, so the peer
    // socket sees EOF / EPIPE as soon as IT releases too.
    const i32 lb_recv = s.loopback_pipe_recv_idx;
    const i32 lb_send = s.loopback_pipe_send_idx;
    SocketDgram* rx = s.udp_rx;
    s.in_use = false;
    s.refs = 0;
    s.bound = false;
    s.connected = false;
    s.listening = false;
    s.shutdown_flags = 0;
    s.local_port = 0;
    s.peer_port = 0;
    s.local_ip = {};
    s.peer_ip = {};
    s.udp_count = 0;
    s.udp_head = 0;
    s.udp_tail = 0;
    s.udp_rx = nullptr;
    s.tcp_owner_token = 0;
    s.loopback_paired = false;
    s.loopback_pipe_recv_idx = -1;
    s.loopback_pipe_send_idx = -1;
    s.loopback_pending_accept_idx = -1;
    g_tcp_consumed[idx] = 0;
    ++g_stats.releases;
    arch::Sti();
    if (rx != nullptr)
        mm::KFree(rx);
    if (lb_recv >= 0)
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(lb_recv));
    if (lb_send >= 0)
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(lb_send));
}

bool SocketAlive(u32 idx)
{
    if (idx >= kSocketPoolCap)
        return false;
    return g_pool[idx].in_use;
}

const Socket* SocketGet(u32 idx)
{
    if (idx >= kSocketPoolCap || !g_pool[idx].in_use)
        return nullptr;
    return &g_pool[idx];
}

bool SocketBind(u32 idx, Ipv4Address local_ip, u16 local_port)
{
    KLOG_DEBUG("net/socket", "SocketBind: enter");
    if (idx >= kSocketPoolCap)
    {
        KLOG_WARN_V("net/socket", "SocketBind: idx out of range", idx);
        return false;
    }
    arch::Cli();
    Socket& s = g_pool[idx];
    if (!s.in_use || s.bound)
    {
        arch::Sti();
        KLOG_WARN_V("net/socket", "SocketBind: socket not in use or already bound, idx", idx);
        return false;
    }
    if (s.type == kSocketTypeDgram)
    {
        // Reject if any other UDP socket already claimed the port.
        // local_port == 0 means "let the kernel pick" (wildcard).
        u16 port = local_port;
        if (port == 0)
            port = AllocEphemeralPort();
        if (port == 0)
        {
            arch::Sti();
            return false;
        }
        for (u32 i = 0; i < kSocketPoolCap; ++i)
        {
            if (i == idx)
                continue;
            const Socket& other = g_pool[i];
            if (other.in_use && other.type == kSocketTypeDgram && other.bound && other.local_port == port)
            {
                arch::Sti();
                return false;
            }
        }
        s.local_port = port;
    }
    else
    {
        // TCP — port arbitration happens at SocketListen time
        // because the v0 stack only has one passive-listen slot.
        s.local_port = (local_port == 0) ? AllocEphemeralPort() : local_port;
        if (s.local_port == 0)
        {
            arch::Sti();
            return false;
        }
    }
    s.local_ip = local_ip;
    s.bound = true;
    ++g_stats.binds;
    arch::Sti();
    KLOG_INFO_2V("net/socket", "SocketBind: ok", "idx", idx, "port", s.local_port);
    return true;
}

bool SocketListen(u32 idx, u32 backlog)
{
    (void)backlog;
    KLOG_DEBUG("net/socket", "SocketListen: enter");
    if (idx >= kSocketPoolCap)
    {
        KLOG_WARN_V("net/socket", "SocketListen: idx out of range", idx);
        return false;
    }
    arch::Cli();
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeStream || !s.bound)
    {
        arch::Sti();
        KLOG_WARN_V("net/socket", "SocketListen: invalid state (not stream, not bound, or unused), idx", idx);
        return false;
    }
    s.listening = true;
    arch::Sti();
    KLOG_INFO_V("net/socket", "SocketListen: listening on port", s.local_port);
    // The actual TcpListen call happens through the stack — wire
    // an empty canned reply so the listen slot just passes data
    // through to recv. SocketRecvStream pulls from the same shared
    // buffer NetTcpActiveRead exposes.
    static const u8 kEmpty[1] = {0};
    return TcpListen(s.local_port, kEmpty, 0);
}

bool SocketConnect(u32 idx, Ipv4Address peer_ip, u16 peer_port)
{
    KLOG_DEBUG("net/socket", "SocketConnect: enter");
    if (idx >= kSocketPoolCap)
    {
        KLOG_WARN_V("net/socket", "SocketConnect: idx out of range", idx);
        return false;
    }
    arch::Cli();
    Socket& s = g_pool[idx];
    if (!s.in_use)
    {
        arch::Sti();
        KLOG_WARN_V("net/socket", "SocketConnect: socket slot not in use, idx", idx);
        return false;
    }
    if (s.type == kSocketTypeDgram)
    {
        // UDP connect — record the peer endpoint and ensure we
        // have a local port to send from. Per BSD, connect() on a
        // UDP socket can be issued repeatedly to retarget.
        if (!s.bound)
        {
            const u16 ephem = AllocEphemeralPort();
            if (ephem == 0)
            {
                arch::Sti();
                return false;
            }
            s.local_port = ephem;
            s.bound = true;
        }
        s.peer_ip = peer_ip;
        s.peer_port = peer_port;
        s.connected = true;
        ++g_stats.connects;
        arch::Sti();
        return true;
    }
    // SOCK_STREAM loopback short-circuit (T3-01). When the peer
    // is in 127.0.0.0/8 and a listener is bound to the requested
    // port, both ends pair through two kernel pipe pool slots
    // (one ring per direction). Send/recv on a paired socket
    // bypass the on-wire TCP stack entirely, so loopback works
    // even when the e1000 path isn't bound.
    const bool is_loopback_ip = (peer_ip.octets[0] == 127);
    if (is_loopback_ip)
    {
        i32 listener_idx = -1;
        for (u32 i = 0; i < kSocketPoolCap; ++i)
        {
            if (g_pool[i].in_use && g_pool[i].type == kSocketTypeStream && g_pool[i].listening &&
                g_pool[i].local_port == peer_port)
            {
                listener_idx = static_cast<i32>(i);
                break;
            }
        }
        if (listener_idx < 0)
        {
            arch::Sti();
            return false; // ECONNREFUSED equivalent
        }
        if (g_pool[listener_idx].loopback_pending_accept_idx != -1)
        {
            // A prior connector is still waiting for accept. v0
            // single-slot accept queue. Caller can retry.
            arch::Sti();
            return false;
        }
        // Allocate the accepted-side socket BEFORE wiring pipes —
        // pool exhaustion fails cleanly without leaking pipe
        // entries.
        arch::Sti();
        const i32 accepted_idx = SocketAlloc(kSocketDomainInet, kSocketTypeStream);
        if (accepted_idx < 0)
            return false;
        // Allocate two pipe pool slots — one A→B, one B→A. PipeAlloc
        // returns each slot with read_refs=1 + write_refs=1, which
        // is exactly the per-end ownership model we need (each side
        // owns one read end and one write end).
        const i32 c2s_pipe = ::duetos::subsystems::linux::internal::PipeAlloc();
        if (c2s_pipe < 0)
        {
            SocketRelease(static_cast<u32>(accepted_idx));
            return false;
        }
        const i32 s2c_pipe = ::duetos::subsystems::linux::internal::PipeAlloc();
        if (s2c_pipe < 0)
        {
            ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(c2s_pipe));
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(c2s_pipe));
            SocketRelease(static_cast<u32>(accepted_idx));
            return false;
        }
        // Wire up. connector writes c2s_pipe → accepted reads it;
        // accepted writes s2c_pipe → connector reads it.
        arch::Cli();
        Socket& cs = g_pool[idx];
        Socket& as = g_pool[accepted_idx];
        cs.peer_ip = peer_ip;
        cs.peer_port = peer_port;
        cs.connected = true;
        cs.loopback_paired = true;
        cs.loopback_pipe_send_idx = c2s_pipe;
        cs.loopback_pipe_recv_idx = s2c_pipe;
        as.local_ip = peer_ip;
        as.local_port = peer_port;
        as.bound = true;
        // Accepted-side peer is the connector — no real IP today
        // (the connector socket binds to an ephemeral local port
        // only on demand). Use 127.0.0.1 / 0 as a stable sentinel.
        Ipv4Address loopback_ip = {{127, 0, 0, 1}};
        as.peer_ip = loopback_ip;
        as.peer_port = 0;
        as.connected = true;
        as.loopback_paired = true;
        as.loopback_pipe_send_idx = s2c_pipe;
        as.loopback_pipe_recv_idx = c2s_pipe;
        g_pool[listener_idx].loopback_pending_accept_idx = accepted_idx;
        sched::WaitQueueWakeAll(&g_pool[listener_idx].accept_wq);
        ++g_stats.connects;
        arch::Sti();
        KLOG_INFO_2V("net/socket", "SocketConnect: loopback paired", "idx", idx, "peer_port", peer_port);
        return true;
    }

    // SOCK_STREAM — claim the single-slot active-connect machine.
    // The single-slot active-connect machine may be in use by
    // another caller (kernel net-smoke probe, prior socket).
    // Retry for up to ~5 seconds before giving up.
    bool got_slot = false;
    for (u32 attempt = 0; attempt < 500; ++attempt)
    {
        if (g_tcp_owner == 0 || g_tcp_owner == idx + 1)
        {
            got_slot = true;
            break;
        }
        arch::Sti();
        ::duetos::sched::SchedSleepTicks(1);
        arch::Cli();
    }
    if (!got_slot)
    {
        arch::Sti();
        return false;
    }
    g_tcp_owner = idx + 1;
    s.tcp_owner_token = idx + 1;
    s.peer_ip = peer_ip;
    s.peer_port = peer_port;
    g_tcp_consumed[idx] = 0;
    arch::Sti();
    // NetTcpConnect rejects when the underlying TCP slot is still
    // in_use && state != Closed. Retry on transient busy: e.g.
    // a prior connection lingering in TIME_WAIT or another caller
    // (kernel net-smoke) finishing its FIN handshake.
    static const u8 kEmpty[1] = {0};
    bool kicked = false;
    for (u32 attempt = 0; attempt < 500; ++attempt)
    {
        if (NetTcpConnect(/*iface_index=*/0, peer_ip, peer_port, kEmpty, 0))
        {
            kicked = true;
            break;
        }
        ::duetos::sched::SchedSleepTicks(1);
    }
    if (!kicked)
    {
        arch::Cli();
        if (g_tcp_owner == idx + 1)
            g_tcp_owner = 0;
        s.tcp_owner_token = 0;
        s.peer_port = 0;
        s.peer_ip = {};
        arch::Sti();
        return false;
    }
    // Wait for the three-way handshake to complete before returning.
    // POSIX/Win32 connect() is blocking by default — mirrors that.
    // 5-second wall budget; the v0 active-connect slot uses tick-poll
    // so SchedSleepTicks gives each ARP/SYN+ACK arrival a chance.
    for (u32 i = 0; i < 500; ++i)
    {
        const auto snap = NetTcpActiveSnapshot();
        if (snap.in_use && snap.established)
            break;
        ::duetos::sched::SchedSleepTicks(1);
    }
    arch::Cli();
    s.connected = true;
    ++g_stats.connects;
    arch::Sti();
    KLOG_INFO_2V("net/socket", "SocketConnect: TCP connect ok", "idx", idx, "peer_port", peer_port);
    return true;
}

i64 SocketSendDgram(u32 idx, Ipv4Address dst_ip, u16 dst_port, const u8* data, u32 len)
{
    KLOG_TRACE_V("net/socket", "SocketSendDgram: idx", idx);
    if (idx >= kSocketPoolCap)
    {
        KLOG_WARN_V("net/socket", "SocketSendDgram: EBADF idx", idx);
        return -9; // EBADF
    }
    // A non-zero length with a null buffer is a caller-side bug: NetUdpSend
    // would dereference `data` later. Reject at the API gate so the failure
    // is attributable instead of a downstream null-deref.
    if (len > 0 && data == nullptr)
    {
        KLOG_WARN_V("net/socket", "SocketSendDgram: EFAULT null data with non-zero len", len);
        return -14; // EFAULT
    }
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeDgram)
    {
        KLOG_WARN_V("net/socket", "SocketSendDgram: ENOTSOCK / wrong type, idx", idx);
        return -88; // ENOTSOCK
    }
    if ((s.shutdown_flags & 0x2) != 0)
        return -32; // EPIPE on shut_wr
    Ipv4Address dst = dst_ip;
    u16 port = dst_port;
    if (port == 0 && s.connected)
    {
        dst = s.peer_ip;
        port = s.peer_port;
    }
    if (port == 0)
        return -39; // EDESTADDRREQ
    // Auto-bind if we haven't picked a local port yet.
    if (!s.bound)
    {
        const u16 ephem = AllocEphemeralPort();
        if (ephem == 0)
            return -98; // EADDRINUSE
        arch::Cli();
        s.local_port = ephem;
        s.local_ip = {};
        s.bound = true;
        arch::Sti();
    }
    if (drivers::net::NicCount() == 0)
        return -100; // ENETDOWN
    Ipv4Address src = s.local_ip;
    if (IpZero(src))
    {
        // Source IP not set — use the interface's bound IP.
        src = InterfaceIp(0);
    }
    // Resolve L2 dst via ARP cache. If we don't have an entry,
    // fall back to broadcast — DHCP-shaped traffic often goes
    // through this path on the first send.
    MacAddress dst_mac{};
    const ArpEntry* arp = ArpLookup(0, dst);
    if (arp != nullptr)
        dst_mac = arp->mac;
    else
    {
        for (u8& b : dst_mac.octets)
            b = 0xFF;
    }
    if (!NetUdpSend(/*iface_index=*/0, dst_mac, dst, port, src, s.local_port, data, len))
        return -101; // ENETUNREACH
    ++g_stats.dgram_tx;
    return static_cast<i64>(len);
}

i64 SocketRecvDgram(u32 idx, u8* out, u32 cap, u32* out_len, Ipv4Address* out_src_ip, u16* out_src_port)
{
    if (idx >= kSocketPoolCap)
        return -9;
    // Non-zero capacity requires a real buffer. Without this guard the
    // copy loop below writes through `out` unconditionally, faulting in
    // ring 0 if a kernel-side caller passes a null sink.
    if (cap > 0 && out == nullptr)
        return -14; // EFAULT
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeDgram)
        return -88;
    arch::Cli();
    while (s.in_use && s.udp_count == 0)
    {
        if ((s.shutdown_flags & 0x1) != 0)
        {
            arch::Sti();
            return 0; // SHUT_RD → EOF
        }
        sched::WaitQueueBlock(&s.read_wq);
        arch::Cli();
    }
    if (!s.in_use)
    {
        arch::Sti();
        return -9;
    }
    SocketDgram& d = s.udp_rx[s.udp_tail];
    s.udp_tail = (s.udp_tail + 1) % kSocketUdpRxQueueCap;
    --s.udp_count;
    const u32 to_copy = (d.len < cap) ? d.len : cap;
    for (u32 i = 0; i < to_copy; ++i)
        out[i] = d.payload[i];
    if (out_len != nullptr)
        *out_len = d.len;
    if (out_src_ip != nullptr)
        *out_src_ip = d.src_ip;
    if (out_src_port != nullptr)
        *out_src_port = d.src_port;
    arch::Sti();
    ++g_stats.dgram_rx;
    return static_cast<i64>(to_copy);
}

i64 SocketSendStream(u32 idx, const u8* data, u32 len)
{
    if (idx >= kSocketPoolCap)
        return -9;
    if (len > 0 && data == nullptr)
        return -14; // EFAULT — non-zero send with a null buffer
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeStream)
        return -88;
    if ((s.shutdown_flags & 0x2) != 0)
        return -32;
    if (!s.connected)
        return -107;
    if (len == 0)
        return 0;
    // Loopback short-circuit (T3-01): write to the per-pair pipe
    // ring instead of the on-wire TCP slot. PipeWrite blocks on
    // the wait-queue if the ring is full AND the peer hasn't
    // closed its read end; returns 0 / -EPIPE if every reader has
    // closed.
    if (s.loopback_paired && s.loopback_pipe_send_idx >= 0)
    {
        const i64 wrote = ::duetos::subsystems::linux::internal::PipeWrite(static_cast<u32>(s.loopback_pipe_send_idx),
                                                                           reinterpret_cast<u64>(data), len);
        if (wrote > 0)
            ++g_stats.stream_tx;
        return wrote;
    }
    if (s.tcp_owner_token == 0)
        return -107;
    // The stack waits until the SYN+ACK lands before flagging
    // Established. NetTcpActiveSend rejects pre-Established sends;
    // a caller that hammers send() during the handshake gets a
    // few -EAGAIN returns until the state advances. v0 single-CPU
    // is fine without an explicit wait — the stack's RX is driven
    // by the same kernel thread that the syscall returns to.
    const u32 sent = NetTcpActiveSend(data, len);
    if (sent == 0)
        return -11; // EAGAIN — handshake not yet complete
    ++g_stats.stream_tx;
    return static_cast<i64>(sent);
}

i64 SocketRecvStream(u32 idx, u8* out, u32 cap)
{
    if (idx >= kSocketPoolCap)
        return -9;
    // NetTcpActiveReadAt unconditionally writes through `out` even on a
    // zero-byte transfer path; refuse a null sink up-front so the
    // failure is a clean EFAULT instead of a kernel page fault.
    if (cap > 0 && out == nullptr)
        return -14; // EFAULT
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeStream)
        return -88;
    if ((s.shutdown_flags & 0x1) != 0)
        return 0;
    if (!s.connected)
        return -107;
    // Loopback short-circuit (T3-01): read from the per-pair pipe
    // ring instead of the on-wire TCP slot. PipeRead blocks on
    // the wait-queue if the ring is empty AND writers remain;
    // returns 0 (EOF) when every writer has closed.
    if (s.loopback_paired && s.loopback_pipe_recv_idx >= 0)
    {
        const i64 got = ::duetos::subsystems::linux::internal::PipeRead(static_cast<u32>(s.loopback_pipe_recv_idx),
                                                                        reinterpret_cast<u64>(out), cap);
        if (got > 0)
            ++g_stats.stream_rx;
        return got;
    }
    while (true)
    {
        const TcpActiveSnapshot snap = NetTcpActiveSnapshot();
        if (snap.in_use)
        {
            const u32 consumed = g_tcp_consumed[idx];
            if (snap.response_len > consumed)
            {
                const u32 copied = NetTcpActiveReadAt(consumed, out, cap);
                g_tcp_consumed[idx] = consumed + copied;
                ++g_stats.stream_rx;
                return static_cast<i64>(copied);
            }
            if (snap.response_complete)
                return 0;
        }
        arch::Cli();
        const TcpActiveSnapshot snap2 = NetTcpActiveSnapshot();
        if (snap2.in_use && snap2.response_len > g_tcp_consumed[idx])
        {
            arch::Sti();
            continue;
        }
        if (snap2.response_complete)
        {
            arch::Sti();
            return 0;
        }
        sched::WaitQueueBlock(&s.read_wq);
    }
}

bool SocketShutdown(u32 idx, u32 how)
{
    if (idx >= kSocketPoolCap)
        return false;
    arch::Cli();
    Socket& s = g_pool[idx];
    if (!s.in_use)
    {
        arch::Sti();
        return false;
    }
    if (how == 0 || how == 2)
        s.shutdown_flags |= 0x1;
    if (how == 1 || how == 2)
        s.shutdown_flags |= 0x2;
    sched::WaitQueueWakeAll(&s.read_wq);
    arch::Sti();
    return true;
}

i32 SocketAcceptLoopback(u32 listener_idx, Ipv4Address* out_peer_ip, u16* out_peer_port)
{
    // Non-blocking probe — returns -1 immediately when no
    // connector is pending. Callers that want to block compose
    // this with their own poll/yield loop (e.g. the accept
    // syscall handler in syscall.cpp), which lets a single
    // accept() service both the loopback and the on-wire paths
    // without an explicit dispatch.
    if (listener_idx >= kSocketPoolCap)
        return -1;
    arch::Cli();
    Socket& l = g_pool[listener_idx];
    if (!l.in_use || l.type != kSocketTypeStream || !l.listening || l.loopback_pending_accept_idx == -1)
    {
        arch::Sti();
        return -1;
    }
    const i32 accepted = l.loopback_pending_accept_idx;
    l.loopback_pending_accept_idx = -1;
    Ipv4Address peer_ip = {{127, 0, 0, 1}};
    u16 peer_port = 0;
    if (accepted >= 0 && static_cast<u32>(accepted) < kSocketPoolCap)
    {
        peer_ip = g_pool[accepted].peer_ip;
        peer_port = g_pool[accepted].peer_port;
    }
    arch::Sti();
    if (out_peer_ip != nullptr)
        *out_peer_ip = peer_ip;
    if (out_peer_port != nullptr)
        *out_peer_port = peer_port;
    return accepted;
}

void SocketGetLocal(u32 idx, Ipv4Address* out_ip, u16* out_port)
{
    if (idx >= kSocketPoolCap || !g_pool[idx].in_use)
        return;
    if (out_ip != nullptr)
        *out_ip = g_pool[idx].local_ip;
    if (out_port != nullptr)
        *out_port = g_pool[idx].local_port;
}

void SocketGetPeer(u32 idx, Ipv4Address* out_ip, u16* out_port)
{
    if (idx >= kSocketPoolCap || !g_pool[idx].in_use)
        return;
    if (out_ip != nullptr)
        *out_ip = g_pool[idx].peer_ip;
    if (out_port != nullptr)
        *out_port = g_pool[idx].peer_port;
}

bool SocketUdpDispatch(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len)
{
    (void)iface_index;
    // The IP stack delivers (payload, len) from a parsed UDP datagram.
    // A null payload with non-zero len would index past low memory in
    // the copy loop below; treat it as "not for us" so the caller's
    // dispatch fan-out continues to the next bound port handler.
    if (payload == nullptr && len > 0)
        return false;
    arch::Cli();
    const u32 owner_idx = FindUdpBoundPort(dst_port);
    if (owner_idx == kSocketPoolCap)
    {
        arch::Sti();
        return false;
    }
    Socket& s = g_pool[owner_idx];
    if ((s.shutdown_flags & 0x1) != 0 || s.udp_rx == nullptr)
    {
        ++g_stats.dgram_dropped;
        arch::Sti();
        return true; // owner declared SHUT_RD — consume + drop
    }
    if (s.udp_count == kSocketUdpRxQueueCap)
    {
        ++g_stats.dgram_dropped;
        arch::Sti();
        return true; // queue full — drop, ack consumed
    }
    SocketDgram& d = s.udp_rx[s.udp_head];
    s.udp_head = (s.udp_head + 1) % kSocketUdpRxQueueCap;
    ++s.udp_count;
    d.src_ip = src_ip;
    d.src_port = src_port;
    const u32 to_copy = (len < kSocketDgramPayloadCap) ? static_cast<u32>(len) : kSocketDgramPayloadCap;
    d.len = to_copy;
    const auto* p = static_cast<const u8*>(payload);
    for (u32 i = 0; i < to_copy; ++i)
        d.payload[i] = p[i];
    sched::WaitQueueWakeOne(&s.read_wq);
    arch::Sti();
    return true;
}

void SocketTcpRxNotify()
{
    arch::Cli();
    for (u32 i = 0; i < kSocketPoolCap; ++i)
    {
        Socket& s = g_pool[i];
        if (s.in_use && s.type == kSocketTypeStream && s.tcp_owner_token != 0)
            sched::WaitQueueWakeAll(&s.read_wq);
    }
    arch::Sti();
}

SocketStats SocketStatsRead()
{
    return g_stats;
}

} // namespace duetos::net
