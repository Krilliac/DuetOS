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
#include "sync/spinlock.h"
#include "time/tick.h"

namespace duetos::net
{

namespace
{

Socket g_pool[kSocketPoolCap] = {};
SocketStats g_stats = {};

// Guards `g_pool` and `g_stats`. Acquire disables interrupts, so the
// same lock serialises the NIC RX dispatch (SocketUdpDispatch, which
// runs from the netif IRQ tail) against task-context socket calls on
// every CPU. The v0 scheme was `arch::Cli` alone, which only excludes
// the local CPU: with per-CPU runqueues and work-stealing live, a
// SocketRelease on CPU 1 could free a socket's UDP RX ring while a
// SocketRecvDgram on CPU 0 was still copying out of it.
//
// Never held across a scheduling point (see spinlock.h's scope
// limits): a path that must wait drops the lock, blocks on the
// socket's wait queue with a bounded timeout, then re-acquires and
// re-tests its condition.
//
// Left unclassified for lockdep — the only lock nested inside it is
// the scheduler's (via WaitQueueWake{One,All}), and nothing in
// kernel/sched reaches back into the socket pool.
constinit sync::SpinLock g_sock_lock = {
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};

bool IpZero(Ipv4Address a)
{
    return a.octets[0] == 0 && a.octets[1] == 0 && a.octets[2] == 0 && a.octets[3] == 0;
}

// Caller holds g_sock_lock.
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
// Caller holds g_sock_lock.
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

    auto flags = sync::SpinLockAcquire(g_sock_lock);
    for (u32 i = 0; i < kSocketPoolCap; ++i)
    {
        if (g_pool[i].in_use)
            continue;
        Socket& s = g_pool[i];
        // KMalloc may not run under a spinlock — drop it and re-test
        // the slot on the way back in.
        sync::SpinLockRelease(g_sock_lock, flags);
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
        flags = sync::SpinLockAcquire(g_sock_lock);
        if (g_pool[i].in_use)
        {
            sync::SpinLockRelease(g_sock_lock, flags);
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
        s.recv_timeout_ticks = 0; // block forever until a caller opts in
        s.read_wq.head = nullptr;
        s.read_wq.tail = nullptr;
        s.accept_wq.head = nullptr;
        s.accept_wq.tail = nullptr;
        ++g_stats.allocs;
        sync::SpinLockRelease(g_sock_lock, flags);
        return static_cast<i32>(i);
    }
    sync::SpinLockRelease(g_sock_lock, flags);
    return -1;
}

void SocketRetain(u32 idx)
{
    if (idx >= kSocketPoolCap)
        return;
    sync::SpinLockGuard guard(g_sock_lock);
    if (g_pool[idx].in_use)
        ++g_pool[idx].refs;
}

void SocketSetOwner(u32 idx, u64 pid)
{
    if (idx >= kSocketPoolCap)
        return;
    sync::SpinLockGuard guard(g_sock_lock);
    if (g_pool[idx].in_use)
        g_pool[idx].owner_pid = pid;
}

void SocketReleaseByOwner(u64 pid)
{
    if (pid == 0)
        return; // kernel-owned sockets are never swept by a process exit
    for (u32 i = 0; i < kSocketPoolCap; ++i)
    {
        auto flags = sync::SpinLockAcquire(g_sock_lock);
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
        // SocketRelease takes g_sock_lock itself, and the lock is not
        // recursive — drop it before the teardown call.
        sync::SpinLockRelease(g_sock_lock, flags);
        if (match)
            SocketRelease(i);
    }
}

void SocketRelease(u32 idx)
{
    if (idx >= kSocketPoolCap)
        return;
    auto flags = sync::SpinLockAcquire(g_sock_lock);
    Socket& s = g_pool[idx];
    if (!s.in_use || s.refs == 0)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
        return;
    }
    --s.refs;
    if (s.refs > 0)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
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
    // Only now is the ring unreachable: every reader either holds the
    // lock (and sees `in_use == false` / `udp_rx == nullptr`) or is
    // parked on read_wq, which was drained above.
    sync::SpinLockRelease(g_sock_lock, flags);
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
    sync::SpinLockGuard guard(g_sock_lock);
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
    sync::SpinLockGuard guard(g_sock_lock);
    Socket& s = g_pool[idx];
    if (!s.in_use || s.bound)
        return false;
    if (s.type == kSocketTypeDgram)
    {
        u16 port = local_port;
        if (port == 0)
            port = AllocEphemeralUdpPort();
        if (port == 0)
            return false;
        for (u32 i = 0; i < kSocketPoolCap; ++i)
        {
            if (i == idx)
                continue;
            const Socket& other = g_pool[i];
            if (other.in_use && other.type == kSocketTypeDgram && other.bound && other.local_port == port)
                return false;
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
    return true;
}

bool SocketListen(u32 idx, u32 backlog)
{
    if (idx >= kSocketPoolCap)
        return false;
    auto flags = sync::SpinLockAcquire(g_sock_lock);
    Socket& s = g_pool[idx];
    if (!s.in_use || s.type != kSocketTypeStream || !s.bound)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
        return false;
    }
    if (s.listening)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
        return true;
    }
    if (backlog == 0)
        backlog = 1;
    const u32 cap = (backlog > tcp::kListenBacklogMax) ? tcp::kListenBacklogMax : backlog;
    const u16 port = s.local_port;
    const Ipv4Address ip = s.local_ip;
    sync::SpinLockRelease(g_sock_lock, flags);
    const tcp::TcbId tcb = tcp::Listen(/*iface_index=*/0, ip, port, cap);
    if (tcb == tcp::kInvalidTcbId)
        return false;
    flags = sync::SpinLockAcquire(g_sock_lock);
    // The pool lock was dropped across tcp::Listen — a close or a
    // racing listen on another CPU may have landed meanwhile, and
    // overwriting s.tcb here would strand the other TCB.
    if (!s.in_use || s.listening)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
        tcp::Release(tcb);
        return false;
    }
    s.tcb = tcb;
    s.listening = true;
    sync::SpinLockRelease(g_sock_lock, flags);
    return true;
}

bool SocketConnect(u32 idx, Ipv4Address peer_ip, u16 peer_port)
{
    if (idx >= kSocketPoolCap)
        return false;
    auto flags = sync::SpinLockAcquire(g_sock_lock);
    Socket& s = g_pool[idx];
    if (!s.in_use)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
        return false;
    }
    if (s.type == kSocketTypeDgram)
    {
        if (!s.bound)
        {
            const u16 ephem = AllocEphemeralUdpPort();
            if (ephem == 0)
            {
                sync::SpinLockRelease(g_sock_lock, flags);
                return false;
            }
            s.local_port = ephem;
            s.bound = true;
        }
        s.peer_ip = peer_ip;
        s.peer_port = peer_port;
        s.connected = true;
        ++g_stats.connects;
        sync::SpinLockRelease(g_sock_lock, flags);
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
            sync::SpinLockRelease(g_sock_lock, flags);
            return false;
        }
        if (g_pool[listener_idx].loopback_pending_accept_idx != -1)
        {
            sync::SpinLockRelease(g_sock_lock, flags);
            return false;
        }
        // SocketAlloc / PipeAlloc both allocate, so the lock has to go
        // before either; the pairing below re-validates both ends.
        sync::SpinLockRelease(g_sock_lock, flags);
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
        flags = sync::SpinLockAcquire(g_sock_lock);
        if (!g_pool[idx].in_use || !g_pool[listener_idx].in_use ||
            g_pool[listener_idx].loopback_pending_accept_idx != -1)
        {
            // Either end went away (or another connector won the
            // listener's single pending slot) while the lock was down.
            sync::SpinLockRelease(g_sock_lock, flags);
            ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(c2s_pipe));
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(c2s_pipe));
            ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(s2c_pipe));
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(s2c_pipe));
            SocketRelease(static_cast<u32>(accepted_idx));
            return false;
        }
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
        sync::SpinLockRelease(g_sock_lock, flags);
        return true;
    }

    // On-wire SOCK_STREAM via tcp::Connect.
    sync::SpinLockRelease(g_sock_lock, flags);
    const tcp::TcbId tcb = tcp::Connect(/*iface_index=*/0, peer_ip, peer_port, /*local_port=*/0);
    if (tcb == tcp::kInvalidTcbId)
        return false;
    // Wait up to 10 s for the handshake to complete.
    const bool ok = tcp::WaitConnected(tcb, /*timeout_ticks=*/1000);
    flags = sync::SpinLockAcquire(g_sock_lock);
    // The handshake wait is long; the socket can be closed under us.
    if (!ok || !s.in_use)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
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
    sync::SpinLockRelease(g_sock_lock, flags);
    return true;
}

i32 SocketAcceptLoopback(u32 listener_idx, Ipv4Address* out_peer_ip, u16* out_peer_port)
{
    if (listener_idx >= kSocketPoolCap)
        return -1;
    auto flags = sync::SpinLockAcquire(g_sock_lock);
    Socket& l = g_pool[listener_idx];
    if (!l.in_use || l.type != kSocketTypeStream || !l.listening || l.loopback_pending_accept_idx == -1)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
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
    sync::SpinLockRelease(g_sock_lock, flags);
    if (out_peer_ip != nullptr)
        *out_peer_ip = peer_ip;
    if (out_peer_port != nullptr)
        *out_peer_port = peer_port;
    return accepted;
}

i32 SocketAcceptNonblocking(u32 listener_idx, Ipv4Address* out_peer_ip, u16* out_peer_port)
{
    if (listener_idx >= kSocketPoolCap)
        return -1;
    // Loopback first — cheaper.
    const i32 lb = SocketAcceptLoopback(listener_idx, out_peer_ip, out_peer_port);
    if (lb >= 0)
        return lb;
    // On-wire: ask the TCB table.
    auto flags = sync::SpinLockAcquire(g_sock_lock);
    Socket& l = g_pool[listener_idx];
    if (!l.in_use || l.type != kSocketTypeStream || !l.listening || l.tcb == tcp::kInvalidTcbId)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
        return -1;
    }
    const tcp::TcbId listener_tcb = l.tcb;
    sync::SpinLockRelease(g_sock_lock, flags);
    Ipv4Address peer_ip;
    u16 peer_port;
    const tcp::TcbId child = tcp::AcceptNonblocking(listener_tcb, &peer_ip, &peer_port);
    if (child == tcp::kInvalidTcbId)
        return -11; // EAGAIN

    const i32 new_idx = SocketAlloc(kSocketDomainInet, kSocketTypeStream);
    if (new_idx < 0)
    {
        tcp::Abort(child);
        tcp::Release(child);
        return -1;
    }
    Ipv4Address le_ip;
    u16 le_port;
    const bool have_local_endpoint = tcp::GetLocalEndpoint(child, &le_ip, &le_port);
    flags = sync::SpinLockAcquire(g_sock_lock);
    Socket& cs = g_pool[new_idx];
    cs.tcb = child;
    cs.peer_ip = peer_ip;
    cs.peer_port = peer_port;
    cs.connected = true;
    if (have_local_endpoint)
    {
        cs.local_ip = le_ip;
        cs.local_port = le_port;
        cs.bound = true;
    }
    sync::SpinLockRelease(g_sock_lock, flags);
    if (out_peer_ip != nullptr)
        *out_peer_ip = peer_ip;
    if (out_peer_port != nullptr)
        *out_peer_port = peer_port;
    return new_idx;
}

i32 SocketAccept(u32 listener_idx, Ipv4Address* out_peer_ip, u16* out_peer_port)
{
    if (listener_idx >= kSocketPoolCap)
        return -1;
    while (true)
    {
        const i32 accepted = SocketAcceptNonblocking(listener_idx, out_peer_ip, out_peer_port);
        if (accepted != -11)
            return accepted;

        // Nothing ready. Block on the TCB's accept wait queue with
        // a short timeout — the TCP RX path wakes it via
        // NotifyParentAccept when a wire child hits ESTABLISHED;
        // the timeout lets loopback wakers (which fire on the
        // socket-layer accept_wq, not the TCB's) still make progress
        // without a busy loop.
        auto flags = sync::SpinLockAcquire(g_sock_lock);
        Socket& l = g_pool[listener_idx];
        if (!l.in_use || l.type != kSocketTypeStream || !l.listening || l.tcb == tcp::kInvalidTcbId)
        {
            sync::SpinLockRelease(g_sock_lock, flags);
            return -1;
        }
        const tcp::TcbId listener_tcb = l.tcb;
        sync::SpinLockRelease(g_sock_lock, flags);
        sched::WaitQueue* wq = tcp::AcceptWaitQueue(listener_tcb);
        if (wq != nullptr)
        {
            // Re-check under the pool lock so we don't lose a wake that
            // arrived between the AcceptNonblocking check and now. The
            // park itself runs after the lock is dropped — a spinlock
            // must not be held across a scheduling point — so the
            // timeout, not the lock, is what bounds the residual race.
            flags = sync::SpinLockAcquire(g_sock_lock);
            const bool park = g_pool[listener_idx].in_use && g_pool[listener_idx].loopback_pending_accept_idx == -1;
            sync::SpinLockRelease(g_sock_lock, flags);
            if (park)
            {
                arch::Cli();
                sched::WaitQueueBlockTimeout(wq, /*ticks=*/5);
                arch::Sti();
            }
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
        // Claim + record under one lock hold: AllocEphemeralUdpPort
        // scans the pool for a free port, so splitting the two halves
        // lets a peer on another CPU bind the same port in between.
        sync::SpinLockGuard guard(g_sock_lock);
        const u16 ephem = AllocEphemeralUdpPort();
        if (ephem == 0)
            return -98;
        s.local_port = ephem;
        s.local_ip = {};
        s.bound = true;
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
    {
        sync::SpinLockGuard guard(g_sock_lock);
        ++g_stats.dgram_tx;
    }
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
    auto flags = sync::SpinLockAcquire(g_sock_lock);
    // The type re-test matters on every pass: the slot can be released
    // and re-allocated as a SOCK_STREAM socket while we wait, which
    // leaves udp_rx null and udp_count pinned at 0 forever.
    while (s.in_use && s.type == kSocketTypeDgram && s.udp_count == 0)
    {
        if ((s.shutdown_flags & 0x1) != 0)
        {
            sync::SpinLockRelease(g_sock_lock, flags);
            return 0;
        }
        // A spinlock must not be held across a scheduling point, so
        // drop it before parking. That leaves a window in which
        // SocketUdpDispatch on another CPU can push a datagram and
        // wake an empty queue, so the park is bounded rather than
        // untimed: the worst case is one late tick, not a reader
        // stuck until the NEXT datagram arrives.
        sync::SpinLockRelease(g_sock_lock, flags);
        arch::Cli();
        sched::WaitQueueBlockTimeout(&s.read_wq, /*ticks=*/5);
        arch::Sti();
        flags = sync::SpinLockAcquire(g_sock_lock);
    }
    if (!s.in_use || s.type != kSocketTypeDgram || s.udp_rx == nullptr)
    {
        sync::SpinLockRelease(g_sock_lock, flags);
        return -9;
    }
    // The copy-out stays under the lock: SocketRelease frees udp_rx
    // the moment it can observe the slot free, and `out` is the
    // syscall handler's kernel staging buffer, so the copy can't
    // fault or block.
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
    ++g_stats.dgram_rx;
    sync::SpinLockRelease(g_sock_lock, flags);
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
        // Kernel-buffer variant: `data` is the syscall handler's kernel
        // staging buffer, not a user pointer — the user-pointer PipeWrite
        // would CopyFromUser it and fail the user-range check (-EFAULT).
        const i64 wrote = ::duetos::subsystems::linux::internal::PipeWriteKernel(
            static_cast<u32>(s.loopback_pipe_send_idx), data, len);
        if (wrote > 0)
        {
            sync::SpinLockGuard guard(g_sock_lock);
            ++g_stats.stream_tx;
        }
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
    {
        sync::SpinLockGuard guard(g_sock_lock);
        ++g_stats.stream_tx;
    }
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
        // Kernel-buffer variant: `out` is the syscall handler's kernel
        // staging buffer (the handler CopyToUser's it afterwards), so the
        // user-pointer PipeRead would CopyToUser it and fail (-EFAULT).
        const i64 got =
            ::duetos::subsystems::linux::internal::PipeReadKernel(static_cast<u32>(s.loopback_pipe_recv_idx), out, cap);
        if (got > 0)
        {
            sync::SpinLockGuard guard(g_sock_lock);
            ++g_stats.stream_rx;
        }
        return got;
    }
    if (s.tcb == tcp::kInvalidTcbId)
        return -107;
    // Receive-timeout deadline, armed lazily on the first would-block so a
    // recv that returns data immediately never reads the clock. 0 timeout
    // = block forever (the default); see SocketSetRecvTimeout.
    const u64 timeout = s.recv_timeout_ticks;
    bool deadline_armed = false;
    u64 deadline = 0;
    while (true)
    {
        const i32 n = tcp::RecvNonblocking(s.tcb, out, cap);
        if (n > 0)
        {
            sync::SpinLockGuard guard(g_sock_lock);
            ++g_stats.stream_rx;
            return n;
        }
        if (n == 0)
            return 0; // orderly EOF
        if (n < -1)
        {
            // -2: would block — wait for data or peer FIN. Bound the wait
            // by the socket's recv timeout (if set) so an established-but-
            // silent peer can't hang the caller forever.
            if (timeout != 0)
            {
                const u64 now = ::duetos::time::TickCount();
                if (!deadline_armed)
                {
                    deadline = now + timeout;
                    deadline_armed = true;
                }
                else if (now >= deadline)
                {
                    return -110; // -ETIMEDOUT: peer silent past recv timeout
                }
            }
            sched::SchedSleepTicks(1);
            if ((s.shutdown_flags & 0x1) != 0)
                return 0;
            continue;
        }
        return -107; // dead TCB
    }
}

void SocketSetRecvTimeout(u32 idx, u64 ticks)
{
    if (idx >= kSocketPoolCap)
        return;
    g_pool[idx].recv_timeout_ticks = ticks;
}

bool SocketShutdown(u32 idx, u32 how)
{
    if (idx >= kSocketPoolCap)
        return false;
    tcp::TcbId half_close = tcp::kInvalidTcbId;
    {
        sync::SpinLockGuard guard(g_sock_lock);
        Socket& s = g_pool[idx];
        if (!s.in_use)
            return false;
        if (how == 0 || how == 2)
            s.shutdown_flags |= 0x1;
        if (how == 1 || how == 2)
        {
            s.shutdown_flags |= 0x2;
            half_close = s.tcb;
        }
        sched::WaitQueueWakeAll(&s.read_wq);
    }
    // Half-close the TCB — sends FIN. Deliberately outside the pool
    // lock: tcp::Close runs its own arch::Cli/Sti pair, and that
    // unconditional Sti would re-enable interrupts while we still
    // held a non-recursive spinlock the RX path also takes.
    if (half_close != tcp::kInvalidTcbId)
        tcp::Close(half_close);
    return true;
}

void SocketGetLocal(u32 idx, Ipv4Address* out_ip, u16* out_port)
{
    if (idx >= kSocketPoolCap)
        return;
    sync::SpinLockGuard guard(g_sock_lock);
    if (!g_pool[idx].in_use)
        return;
    if (out_ip != nullptr)
        *out_ip = g_pool[idx].local_ip;
    if (out_port != nullptr)
        *out_port = g_pool[idx].local_port;
}

void SocketGetPeer(u32 idx, Ipv4Address* out_ip, u16* out_port)
{
    if (idx >= kSocketPoolCap)
        return;
    sync::SpinLockGuard guard(g_sock_lock);
    if (!g_pool[idx].in_use)
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
    sync::SpinLockGuard guard(g_sock_lock);
    const u32 owner_idx = FindUdpBoundPort(dst_port);
    if (owner_idx == kSocketPoolCap)
        return false;
    Socket& s = g_pool[owner_idx];
    if ((s.shutdown_flags & 0x1) != 0 || s.udp_rx == nullptr)
    {
        ++g_stats.dgram_dropped;
        return true;
    }
    if (s.udp_count == kSocketUdpRxQueueCap)
    {
        ++g_stats.dgram_dropped;
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
    return true;
}

SocketStats SocketStatsRead()
{
    sync::SpinLockGuard guard(g_sock_lock);
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
