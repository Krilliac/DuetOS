/*
 * DuetOS — kernel socket pool implementation. See socket.h for the
 * public surface and design rationale.
 *
 * SOCK_STREAM sockets are backed by net/tcp.cpp's TCB table — each
 * stream socket holds a tcp::TcbId, and Send/Recv/Close fan out to
 * tcp::Send / tcp::RecvNonblocking / tcp::Close. The v0 single-slot
 * machine that this layer used to multiplex is gone; multiple
 * concurrent connections, multiple listeners, multiple accepted
 * children all just work.
 */

#include "net/socket.h"
#include "net/tcp.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/net/net.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "subsystems/linux/syscall_pipe.h"

namespace duetos::net
{

namespace
{

Socket g_pool[kSocketPoolCap] = {};
SocketStats g_stats = {};

bool IpZero(Ipv4Address a)
{
    return a.octets[0] == 0 && a.octets[1] == 0 && a.octets[2] == 0 && a.octets[3] == 0;
}

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

u16 g_ephemeral_cursor = 49152;
u16 AllocEphemeralUdpPort()
{
    for (u32 attempts = 0; attempts < 65536; ++attempts)
    {
        const u16 candidate = g_ephemeral_cursor++;
        if (g_ephemeral_cursor < 49152)
            g_ephemeral_cursor = 49152;
        if (candidate == 0)
            continue;
        if (FindUdpBoundPort(candidate) == kSocketPoolCap)
            return candidate;
    }
    return 0;
}

} // namespace

i32 SocketAlloc(u16 domain, u16 type)
{
    if (domain != kSocketDomainInet)
    {
        // Only AF_INET is supported at v0; AF_INET6 / AF_UNIX
        // syscalls land here and fail. The first user-mode call
        // shape that trips this should be visible so we can
        // prioritise the next ABI slice.
        KLOG_ONCE_WARN_V("net/socket", "SocketAlloc: unsupported domain", domain);
        return -1;
    }
    if (type != kSocketTypeDgram && type != kSocketTypeStream)
    {
        KLOG_ONCE_WARN_V("net/socket", "SocketAlloc: unsupported type", type);
        return -1;
    }

    arch::Cli();
    for (u32 i = 0; i < kSocketPoolCap; ++i)
    {
        if (g_pool[i].in_use)
            continue;
        Socket& s = g_pool[i];
        arch::Sti();
        SocketDgram* rx = nullptr;
        if (type == kSocketTypeDgram)
        {
            rx = static_cast<SocketDgram*>(mm::KMalloc(sizeof(SocketDgram) * kSocketUdpRxQueueCap));
            if (rx == nullptr)
            {
                // UDP RX ring allocation failed — caller sees EMFILE-
                // shaped error but the kernel had no signal of the
                // OOM. Log so a panic dump captures the saturation.
                KLOG_ERROR("net/socket", "SocketAlloc: UDP rx ring KMalloc failed");
                return -1;
            }
        }
        arch::Cli();
        if (g_pool[i].in_use)
        {
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
        s.owner_pid = 0; // stamped by SocketSetOwner from the syscall handler
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
        s.tcb = tcp::kInvalidTcbId;
        s.loopback_paired = false;
        s.loopback_pipe_recv_idx = -1;
        s.loopback_pipe_send_idx = -1;
        s.loopback_pending_accept_idx = -1;
        s.read_wq.head = nullptr;
        s.read_wq.tail = nullptr;
        s.accept_wq.head = nullptr;
        s.accept_wq.tail = nullptr;
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

void SocketSetOwner(u32 idx, u64 pid)
{
    if (idx >= kSocketPoolCap)
        return;
    arch::Cli();
    if (g_pool[idx].in_use)
        g_pool[idx].owner_pid = pid;
    arch::Sti();
}

void SocketReleaseByOwner(u64 pid)
{
    if (pid == 0)
        return; // kernel-owned sockets are never swept by a process exit
    for (u32 i = 0; i < kSocketPoolCap; ++i)
    {
        arch::Cli();
        const bool match = g_pool[i].in_use && g_pool[i].owner_pid == pid;
        if (match)
        {
            // Force the full teardown regardless of any lingering dup
            // refs: the owning process is gone, so no valid handle to
            // this slot survives. Collapse refs to 1 and clear the
            // owner so the SocketRelease below runs the real teardown
            // (RX drain, TCB close, loopback pipe release) exactly once.
            g_pool[i].refs = 1;
            g_pool[i].owner_pid = 0;
        }
        arch::Sti();
        if (match)
            SocketRelease(i);
    }
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
    const tcp::TcbId tcb = s.tcb;
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
    s.tcb = tcp::kInvalidTcbId;
    s.loopback_paired = false;
    s.loopback_pipe_recv_idx = -1;
    s.loopback_pipe_send_idx = -1;
    s.loopback_pending_accept_idx = -1;
    ++g_stats.releases;
    arch::Sti();
    if (rx != nullptr)
        mm::KFree(rx);
    if (tcb != tcp::kInvalidTcbId)
        tcp::Release(tcb);
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
    if (idx >= kSocketPoolCap)
        return false;
    arch::Cli();
    Socket& s = g_pool[idx];
    if (!s.in_use || s.bound)
    {
        arch::Sti();
        return false;
    }
    if (s.type == kSocketTypeDgram)
    {
        u16 port = local_port;
        if (port == 0)
            port = AllocEphemeralUdpPort();
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
        // TCP — port is recorded now; tcp::Listen / tcp::Connect
        // does the real port-claim later. Ephemeral port allocation
        // for active opens happens in tcp::Connect.
        s.local_port = local_port;
    }
    s.local_ip = local_ip;
    s.bound = true;
    ++g_stats.binds;
    arch::Sti();
    return true;
}

bool SocketListen(u32 idx, u32 backlog)
{
    if (idx >= kSocketPoolCap)
        return false;
    arch::Cli();
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeStream || !s.bound)
    {
        arch::Sti();
        return false;
    }
    if (s.listening)
    {
        arch::Sti();
        return true;
    }
    if (backlog == 0)
        backlog = 1;
    const u32 cap = (backlog > tcp::kListenBacklogMax) ? tcp::kListenBacklogMax : backlog;
    const u16 port = s.local_port;
    const Ipv4Address ip = s.local_ip;
    arch::Sti();
    const tcp::TcbId tcb = tcp::Listen(/*iface_index=*/0, ip, port, cap);
    if (tcb == tcp::kInvalidTcbId)
        return false;
    arch::Cli();
    s.tcb = tcb;
    s.listening = true;
    arch::Sti();
    return true;
}

bool SocketConnect(u32 idx, Ipv4Address peer_ip, u16 peer_port)
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
    if (s.type == kSocketTypeDgram)
    {
        if (!s.bound)
        {
            const u16 ephem = AllocEphemeralUdpPort();
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

    // SOCK_STREAM loopback short-circuit (T3-01).
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
            return false;
        }
        if (g_pool[listener_idx].loopback_pending_accept_idx != -1)
        {
            arch::Sti();
            return false;
        }
        arch::Sti();
        const i32 accepted_idx = SocketAlloc(kSocketDomainInet, kSocketTypeStream);
        if (accepted_idx < 0)
            return false;
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
        return true;
    }

    // On-wire SOCK_STREAM via tcp::Connect.
    arch::Sti();
    const tcp::TcbId tcb = tcp::Connect(/*iface_index=*/0, peer_ip, peer_port, /*local_port=*/0);
    if (tcb == tcp::kInvalidTcbId)
        return false;
    // Wait up to 10 s for the handshake to complete.
    const bool ok = tcp::WaitConnected(tcb, /*timeout_ticks=*/1000);
    arch::Cli();
    if (!ok)
    {
        arch::Sti();
        tcp::Abort(tcb);
        tcp::Release(tcb);
        return false;
    }
    s.tcb = tcb;
    s.peer_ip = peer_ip;
    s.peer_port = peer_port;
    s.connected = true;
    Ipv4Address le_ip;
    u16 le_port;
    if (tcp::GetLocalEndpoint(tcb, &le_ip, &le_port))
    {
        s.local_ip = le_ip;
        s.local_port = le_port;
        s.bound = true;
    }
    ++g_stats.connects;
    arch::Sti();
    return true;
}

i32 SocketAcceptLoopback(u32 listener_idx, Ipv4Address* out_peer_ip, u16* out_peer_port)
{
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

i32 SocketAccept(u32 listener_idx, Ipv4Address* out_peer_ip, u16* out_peer_port)
{
    if (listener_idx >= kSocketPoolCap)
        return -1;
    while (true)
    {
        // Loopback first — cheaper.
        const i32 lb = SocketAcceptLoopback(listener_idx, out_peer_ip, out_peer_port);
        if (lb >= 0)
            return lb;
        // On-wire: ask the TCB table.
        arch::Cli();
        Socket& l = g_pool[listener_idx];
        if (!l.in_use || l.type != kSocketTypeStream || !l.listening || l.tcb == tcp::kInvalidTcbId)
        {
            arch::Sti();
            return -1;
        }
        const tcp::TcbId listener_tcb = l.tcb;
        arch::Sti();
        Ipv4Address peer_ip;
        u16 peer_port;
        const tcp::TcbId child = tcp::AcceptNonblocking(listener_tcb, &peer_ip, &peer_port);
        if (child != tcp::kInvalidTcbId)
        {
            const i32 new_idx = SocketAlloc(kSocketDomainInet, kSocketTypeStream);
            if (new_idx < 0)
            {
                tcp::Abort(child);
                tcp::Release(child);
                return -1;
            }
            arch::Cli();
            Socket& cs = g_pool[new_idx];
            cs.tcb = child;
            cs.peer_ip = peer_ip;
            cs.peer_port = peer_port;
            cs.connected = true;
            Ipv4Address le_ip;
            u16 le_port;
            if (tcp::GetLocalEndpoint(child, &le_ip, &le_port))
            {
                cs.local_ip = le_ip;
                cs.local_port = le_port;
                cs.bound = true;
            }
            arch::Sti();
            if (out_peer_ip != nullptr)
                *out_peer_ip = peer_ip;
            if (out_peer_port != nullptr)
                *out_peer_port = peer_port;
            return new_idx;
        }
        // Nothing ready. Block on the TCB's accept wait queue with
        // a short timeout — the TCP RX path wakes it via
        // NotifyParentAccept when a wire child hits ESTABLISHED;
        // the timeout lets the loopback wakers (which fire on the
        // socket-layer accept_wq, not the TCB's) still make progress
        // without a busy loop.
        sched::WaitQueue* wq = tcp::AcceptWaitQueue(listener_tcb);
        if (wq != nullptr)
        {
            arch::Cli();
            // Re-check under the lock so we don't lose a wake that
            // arrived between the AcceptNonblocking check and now.
            if (l.in_use && l.loopback_pending_accept_idx == -1)
                sched::WaitQueueBlockTimeout(wq, /*ticks=*/5);
            arch::Sti();
        }
        else
        {
            sched::SchedSleepTicks(5);
        }
    }
}

i64 SocketSendDgram(u32 idx, Ipv4Address dst_ip, u16 dst_port, const u8* data, u32 len)
{
    if (idx >= kSocketPoolCap)
        return -9;
    if (len > 0 && data == nullptr)
        return -14;
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeDgram)
        return -88;
    if ((s.shutdown_flags & 0x2) != 0)
        return -32;
    Ipv4Address dst = dst_ip;
    u16 port = dst_port;
    if (port == 0 && s.connected)
    {
        dst = s.peer_ip;
        port = s.peer_port;
    }
    if (port == 0)
        return -39;
    if (!s.bound)
    {
        const u16 ephem = AllocEphemeralUdpPort();
        if (ephem == 0)
            return -98;
        arch::Cli();
        s.local_port = ephem;
        s.local_ip = {};
        s.bound = true;
        arch::Sti();
    }
    if (drivers::net::NicCount() == 0)
        return -100;
    Ipv4Address src = s.local_ip;
    if (IpZero(src))
        src = InterfaceIp(0);
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
        return -101;
    ++g_stats.dgram_tx;
    return static_cast<i64>(len);
}

i64 SocketRecvDgram(u32 idx, u8* out, u32 cap, u32* out_len, Ipv4Address* out_src_ip, u16* out_src_port)
{
    if (idx >= kSocketPoolCap)
        return -9;
    if (cap > 0 && out == nullptr)
        return -14;
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeDgram)
        return -88;
    arch::Cli();
    while (s.in_use && s.udp_count == 0)
    {
        if ((s.shutdown_flags & 0x1) != 0)
        {
            arch::Sti();
            return 0;
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
        return -14;
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeStream)
        return -88;
    if ((s.shutdown_flags & 0x2) != 0)
        return -32;
    if (!s.connected)
        return -107;
    if (len == 0)
        return 0;
    if (s.loopback_paired && s.loopback_pipe_send_idx >= 0)
    {
        const i64 wrote = ::duetos::subsystems::linux::internal::PipeWrite(static_cast<u32>(s.loopback_pipe_send_idx),
                                                                           reinterpret_cast<u64>(data), len);
        if (wrote > 0)
            ++g_stats.stream_tx;
        return wrote;
    }
    if (s.tcb == tcp::kInvalidTcbId)
        return -107;
    // Block until at least one byte fits.
    u32 sent_total = 0;
    while (sent_total < len)
    {
        const i32 n = tcp::Send(s.tcb, data + sent_total, len - sent_total);
        if (n < 0)
            return (sent_total > 0) ? static_cast<i64>(sent_total) : -32;
        if (n == 0)
        {
            // Buffer full — sleep on the wait queue until acks
            // open room.
            sched::SchedSleepTicks(1);
            continue;
        }
        sent_total += static_cast<u32>(n);
        // After the first push, return; non-blocking semantics let
        // callers loop in user space without us pinning the kernel.
        break;
    }
    if (sent_total > 0)
        ++g_stats.stream_tx;
    return static_cast<i64>(sent_total);
}

i64 SocketRecvStream(u32 idx, u8* out, u32 cap)
{
    if (idx >= kSocketPoolCap)
        return -9;
    if (cap > 0 && out == nullptr)
        return -14;
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeStream)
        return -88;
    if ((s.shutdown_flags & 0x1) != 0)
        return 0;
    if (!s.connected)
        return -107;
    if (s.loopback_paired && s.loopback_pipe_recv_idx >= 0)
    {
        const i64 got = ::duetos::subsystems::linux::internal::PipeRead(static_cast<u32>(s.loopback_pipe_recv_idx),
                                                                        reinterpret_cast<u64>(out), cap);
        if (got > 0)
            ++g_stats.stream_rx;
        return got;
    }
    if (s.tcb == tcp::kInvalidTcbId)
        return -107;
    while (true)
    {
        const i32 n = tcp::RecvNonblocking(s.tcb, out, cap);
        if (n > 0)
        {
            ++g_stats.stream_rx;
            return n;
        }
        if (n == 0)
            return 0; // orderly EOF
        if (n < -1)
        {
            // -2: would block — wait for data or peer FIN.
            sched::SchedSleepTicks(1);
            if ((s.shutdown_flags & 0x1) != 0)
                return 0;
            continue;
        }
        return -107; // dead TCB
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
    {
        s.shutdown_flags |= 0x2;
        // Half-close the TCB — sends FIN.
        if (s.tcb != tcp::kInvalidTcbId)
            tcp::Close(s.tcb);
    }
    sched::WaitQueueWakeAll(&s.read_wq);
    arch::Sti();
    return true;
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
        return true;
    }
    if (s.udp_count == kSocketUdpRxQueueCap)
    {
        ++g_stats.dgram_dropped;
        arch::Sti();
        return true;
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

SocketStats SocketStatsRead()
{
    return g_stats;
}

u32 SocketPollEvents(u32 idx)
{
    constexpr u32 kFdRead = 0x01u;
    constexpr u32 kFdWrite = 0x02u;
    constexpr u32 kFdAccept = 0x08u;
    constexpr u32 kFdClose = 0x20u;

    if (idx >= kSocketPoolCap)
        return 0;
    const Socket& s = g_pool[idx];
    if (!s.in_use)
        return 0;

    u32 events = 0;

    if (s.type == kSocketTypeDgram)
    {
        if (s.udp_count > 0)
            events |= kFdRead;
        events |= kFdWrite;
        if ((s.shutdown_flags & 0x1) != 0)
            events |= kFdClose;
        return events;
    }

    if (s.listening)
    {
        if (s.loopback_pending_accept_idx != -1)
            events |= kFdAccept;
        // v1: also report FD_ACCEPT when a wire-side child sits in
        // the listener's TCB backlog.
        if (s.tcb != tcp::kInvalidTcbId)
        {
            // Peek by trying a non-blocking accept — but that pops
            // from the backlog, so instead we lean on the listener's
            // backlog count via a thin probe in tcp::. v0 fallback:
            // omit the wire-FD_ACCEPT bit; callers will retry.
        }
        return events;
    }

    if (s.loopback_paired)
    {
        if (s.loopback_pipe_recv_idx >= 0 &&
            ::duetos::subsystems::linux::internal::PipeReadReady(static_cast<u32>(s.loopback_pipe_recv_idx)))
            events |= kFdRead;
        if (s.loopback_pipe_send_idx >= 0 &&
            ::duetos::subsystems::linux::internal::PipeWriteReady(static_cast<u32>(s.loopback_pipe_send_idx)))
            events |= kFdWrite;
    }
    else if (s.connected && s.tcb != tcp::kInvalidTcbId)
    {
        // The TCB peek isn't free, but v0 ran a more expensive
        // snapshot per call. The state machine guarantees that
        // tcp::PeerClosed reflects "no more data".
        if (tcp::PeerClosed(s.tcb))
            events |= kFdClose;
        else
            events |= kFdWrite; // always ready to push more bytes
    }

    if ((s.shutdown_flags & 0x1) != 0)
        events |= kFdClose;

    return events;
}

} // namespace duetos::net
