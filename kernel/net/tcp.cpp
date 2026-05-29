/*
 * DuetOS — TCP v1 implementation: TCB table + public API.
 *
 * See tcp.h for the public surface, and wiki/networking/TCP-State-Machine.md
 * for the design + RFC mapping. This TU owns the TCB table, the
 * lookup helpers, allocation/release, and the user-facing Listen /
 * Connect / Accept / Send / Recv / Close API. The state machine
 * (segment dispatcher + RFC-793 transitions) lives in tcp_segment.cpp;
 * the periodic timer in tcp_timer.cpp; the selftest in tcp_selftest.cpp.
 *
 * Concurrency: every public entry grabs arch::Cli on entry and
 * releases on exit. The state machine and timer use the same single
 * global IRQ-off window. SMP migration is a follow-up: each bucket
 * gets a spinlock, the table generation becomes atomic.
 */

#include "net/tcp.h"
#include "net/tcp_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "drivers/net/net.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "time/tick.h"
#include "util/string.h"
#include "util/compiler.h"

namespace duetos::net::tcp
{

namespace internal
{

// constinit: these live in a header (tcp_internal.h) and are touched on
// early boot paths; constant (zero) initialization is required because the
// kernel only walks .init_array after the heap is online.
constinit Tcb g_tcbs[kTcbCap] = {};
constinit u8 g_buckets[kTcbBuckets] = {};
constinit Stats g_stats = {};
constinit bool g_initialised = false;

// Ephemeral port pool — kicked off above the well-known + reserved
// range. Wraps in RFC-6056 dynamic range. Allocated under Cli.
constinit u16 g_ephemeral_cursor = 49152;

u64 NowTicks()
{
    return ::duetos::time::TickCount();
}

u32 MsToTicks(u32 ms)
{
    return (ms + 9) / 10;
}

bool IpEq(Ipv4Address a, Ipv4Address b)
{
    for (u64 i = 0; i < 4; ++i)
        if (a.octets[i] != b.octets[i])
            return false;
    return true;
}

bool IpZero(Ipv4Address a)
{
    return a.octets[0] == 0 && a.octets[1] == 0 && a.octets[2] == 0 && a.octets[3] == 0;
}

DUETOS_NO_SANITIZE_WRAP u32 BucketHash(u32 iface, Ipv4Address local_ip, u16 local_port, Ipv4Address peer_ip,
                                       u16 peer_port)
{
    u32 h = 5381u;
    h = ((h << 5) + h) + iface;
    h = ((h << 5) + h) + local_port;
    h = ((h << 5) + h) + peer_port;
    for (u32 i = 0; i < 4; ++i)
        h = ((h << 5) + h) + local_ip.octets[i];
    for (u32 i = 0; i < 4; ++i)
        h = ((h << 5) + h) + peer_ip.octets[i];
    return h & (kTcbBuckets - 1);
}

TcbId MakeId(u32 idx, u8 generation)
{
    // Bits[31:24] = generation, bits[23:0] = idx + 1 (so idx 0 is
    // a valid handle and TcbId == 0 still means "invalid").
    return (u32(generation) << 24) | ((idx + 1) & 0x00FFFFFFu);
}

bool DecodeId(TcbId id, u32* out_idx)
{
    if (id == kInvalidTcbId)
        return false;
    const u32 idx_plus_one = id & 0x00FFFFFFu;
    if (idx_plus_one == 0 || idx_plus_one > kTcbCap)
        return false;
    const u32 idx = idx_plus_one - 1;
    if (!g_tcbs[idx].in_use)
        return false;
    if (g_tcbs[idx].generation != u8(id >> 24))
        return false;
    *out_idx = idx;
    return true;
}

Tcb* TcbFromId(TcbId id)
{
    u32 idx;
    if (!DecodeId(id, &idx))
        return nullptr;
    return &g_tcbs[idx];
}

void BucketInsert(u32 idx)
{
    Tcb& t = g_tcbs[idx];
    const u32 h = BucketHash(t.iface_index, t.local_ip, t.local_port, t.peer_ip, t.peer_port);
    t.bucket_next = g_buckets[h];
    g_buckets[h] = u8(idx);
}

void BucketRemove(u32 idx)
{
    Tcb& t = g_tcbs[idx];
    const u32 h = BucketHash(t.iface_index, t.local_ip, t.local_port, t.peer_ip, t.peer_port);
    u8* prev = &g_buckets[h];
    while (*prev != kBucketNone)
    {
        if (*prev == u8(idx))
        {
            *prev = t.bucket_next;
            t.bucket_next = kBucketNone;
            return;
        }
        prev = &g_tcbs[*prev].bucket_next;
    }
}

u32 LookupExact(u32 iface, Ipv4Address local_ip, u16 local_port, Ipv4Address peer_ip, u16 peer_port)
{
    const u32 h = BucketHash(iface, local_ip, local_port, peer_ip, peer_port);
    u8 idx = g_buckets[h];
    while (idx != kBucketNone)
    {
        Tcb& t = g_tcbs[idx];
        if (t.in_use && !t.is_listener && t.iface_index == iface && t.local_port == local_port &&
            t.peer_port == peer_port && IpEq(t.local_ip, local_ip) && IpEq(t.peer_ip, peer_ip))
            return idx;
        idx = t.bucket_next;
    }
    return kTcbCap;
}

u32 LookupListener(u16 local_port)
{
    for (u32 i = 0; i < kTcbCap; ++i)
    {
        Tcb& t = g_tcbs[i];
        if (t.in_use && t.is_listener && t.local_port == local_port)
            return i;
    }
    return kTcbCap;
}

u32 AllocSlot()
{
    for (u32 i = 0; i < kTcbCap; ++i)
        if (!g_tcbs[i].in_use)
            return i;
    return kTcbCap;
}

u16 AllocEphemeralPort()
{
    for (u32 attempts = 0; attempts < 65536; ++attempts)
    {
        u16 candidate = g_ephemeral_cursor;
        ++g_ephemeral_cursor;
        if (g_ephemeral_cursor < 49152 || g_ephemeral_cursor == 0)
            g_ephemeral_cursor = 49152;
        if (candidate == 0)
            continue;
        // Make sure no listener / connected TCB owns this port.
        bool in_use = false;
        for (u32 i = 0; i < kTcbCap; ++i)
        {
            if (g_tcbs[i].in_use && g_tcbs[i].local_port == candidate)
            {
                in_use = true;
                break;
            }
        }
        if (!in_use)
            return candidate;
    }
    return 0;
}

void ResetTcbStorage(Tcb& t)
{
    // Zero non-pointer fields. We can't memset the whole struct
    // because the heap-backed buffers (sndbuf/rcvbuf/rtx/oo) outlive
    // a state reset; they're freed only on FreeTcbBuffers.
    t.in_use = false;
    t.is_listener = false;
    t.state = State::Closed;
    t.retries = 0;
    t.iface_index = 0;
    t.local_ip = {};
    t.peer_ip = {};
    t.local_port = 0;
    t.peer_port = 0;
    for (u32 i = 0; i < 6; ++i)
        t.peer_mac.octets[i] = 0;
    t.refs = 0;
    t.backlog_max = 0;
    t.backlog_count = 0;
    t.backlog_head = 0;
    t.backlog_tail = 0;
    for (u32 i = 0; i < kListenBacklogMax; ++i)
        t.backlog_ring[i] = 0;
    t.accept_wq.head = nullptr;
    t.accept_wq.tail = nullptr;
    t.parent_listener = 0;
    t.iss = 0;
    t.irs = 0;
    t.snd_una = 0;
    t.snd_nxt = 0;
    t.snd_wnd = 65535;
    t.rcv_nxt = 0;
    t.rcv_wnd = kRcvBufBytes;
    t.snd_wscale = 0;
    t.rcv_wscale = 0;
    t.peer_supports_wscale = false;
    t.peer_supports_timestamps = false;
    t.peer_supports_sack = false;
    t.ecn_ok = false;
    t.peer_ce_pending = false;
    t.sent_cwr = false;
    t.ts_recent = 0;
    t.ts_recent_age_ticks = 0;
    t.mss_send = kDefaultMss;
    t.cwnd = 4u * kDefaultMss; // IW=4 (RFC-3390 lower bound is fine for v0)
    t.ssthresh = 0x7FFFFFFFu;
    t.dup_acks = 0;
    t.in_fast_recovery = false;
    t.rtt_have_sample = false;
    t.srtt_ticks = 0;
    t.rttvar_ticks = 0;
    t.rto_ticks = MsToTicks(kInitialRtoMs);
    t.rtx_deadline = 0;
    t.timewait_deadline = 0;
    t.delack_deadline = 0;
    t.keepalive_deadline = 0;
    t.persist_deadline = 0;
    t.persist_backoff_ticks = 0;
    t.delack_pending = false;
    t.keepalive_on = false;
    t.nodelay = false;
    t.peer_fin_seen = false;
    t.peer_fin_seq = 0;
    t.tx_closed = false;
    t.read_wq.head = nullptr;
    t.read_wq.tail = nullptr;
    t.write_wq.head = nullptr;
    t.write_wq.tail = nullptr;
    t.connect_wq.head = nullptr;
    t.connect_wq.tail = nullptr;
    t.bucket_next = kBucketNone;
    t.sndbuf_head = 0;
    t.sndbuf_tail = 0;
    t.sndbuf_count = 0;
    t.rcvbuf_head = 0;
    t.rcvbuf_tail = 0;
    t.rcvbuf_count = 0;
    t.rtx_count = 0;
    for (u32 i = 0; i < kReassQueueMax; ++i)
        t.oo_queue[i].in_use = false;
}

bool AllocTcbBuffers(Tcb& t)
{
    t.sndbuf = static_cast<u8*>(mm::KMalloc(kSndBufBytes));
    if (t.sndbuf == nullptr)
        return false;
    t.rcvbuf = static_cast<u8*>(mm::KMalloc(kRcvBufBytes));
    if (t.rcvbuf == nullptr)
    {
        mm::KFree(t.sndbuf);
        t.sndbuf = nullptr;
        return false;
    }
    t.rtx_queue = static_cast<SegmentBuf*>(mm::KMalloc(sizeof(SegmentBuf) * kRtxQueueMax));
    if (t.rtx_queue == nullptr)
    {
        mm::KFree(t.rcvbuf);
        mm::KFree(t.sndbuf);
        t.rcvbuf = nullptr;
        t.sndbuf = nullptr;
        return false;
    }
    for (u32 i = 0; i < kRtxQueueMax; ++i)
        t.rtx_queue[i].len = 0;
    return true;
}

void FreeTcbBuffers(Tcb& t)
{
    if (t.sndbuf != nullptr)
    {
        mm::KFree(t.sndbuf);
        t.sndbuf = nullptr;
    }
    if (t.rcvbuf != nullptr)
    {
        mm::KFree(t.rcvbuf);
        t.rcvbuf = nullptr;
    }
    if (t.rtx_queue != nullptr)
    {
        mm::KFree(t.rtx_queue);
        t.rtx_queue = nullptr;
    }
}

} // namespace internal

const char* StateName(State s)
{
    switch (s)
    {
    case State::Closed:
        return "CLOSED";
    case State::Listen:
        return "LISTEN";
    case State::SynSent:
        return "SYN_SENT";
    case State::SynRcvd:
        return "SYN_RCVD";
    case State::Established:
        return "ESTABLISHED";
    case State::FinWait1:
        return "FIN_WAIT_1";
    case State::FinWait2:
        return "FIN_WAIT_2";
    case State::CloseWait:
        return "CLOSE_WAIT";
    case State::Closing:
        return "CLOSING";
    case State::LastAck:
        return "LAST_ACK";
    case State::TimeWait:
        return "TIME_WAIT";
    }
    return "?";
}

Stats StatsRead()
{
    arch::Cli();
    Stats s = internal::g_stats;
    u64 alive = 0;
    for (u32 i = 0; i < kTcbCap; ++i)
        if (internal::g_tcbs[i].in_use)
            ++alive;
    s.tcbs_alive = alive;
    arch::Sti();
    return s;
}

// -------------------------------------------------------------------
// Public API — Listen / Accept / Connect / Send / Recv / Close.
// All grab arch::Cli on entry and release on every exit path.
// -------------------------------------------------------------------

TcbId Listen(u32 iface_index, Ipv4Address local_ip, u16 local_port, u32 backlog)
{
    using namespace internal;
    if (backlog == 0)
        backlog = 1;
    if (backlog > kListenBacklogMax)
        backlog = kListenBacklogMax;
    if (local_port == 0)
        return kInvalidTcbId;

    arch::Cli();
    if (LookupListener(local_port) != kTcbCap)
    {
        arch::Sti();
        return kInvalidTcbId;
    }
    const u32 idx = AllocSlot();
    if (idx == kTcbCap)
    {
        arch::Sti();
        return kInvalidTcbId;
    }
    Tcb& t = g_tcbs[idx];
    const u8 gen = u8(t.generation + 1);
    ResetTcbStorage(t);
    t.generation = gen;
    t.in_use = true;
    t.is_listener = true;
    t.state = State::Listen;
    t.iface_index = iface_index;
    t.local_ip = local_ip;
    t.local_port = local_port;
    t.backlog_max = backlog;
    t.refs = 1;
    // Listener doesn't go into the 5-tuple bucket — it'd collide
    // with future children that share its local_port. LookupListener
    // does a linear scan, fast enough at v0 cap.
    t.bucket_next = kBucketNone;
    ++g_stats.listens;
    arch::Sti();
    return MakeId(idx, gen);
}

TcbId AcceptNonblocking(TcbId listener, Ipv4Address* out_peer_ip, u16* out_peer_port)
{
    using namespace internal;
    arch::Cli();
    Tcb* lp = TcbFromId(listener);
    if (lp == nullptr || !lp->is_listener)
    {
        arch::Sti();
        return kInvalidTcbId;
    }
    if (lp->backlog_count == 0)
    {
        arch::Sti();
        return kInvalidTcbId;
    }
    const TcbId child_id = lp->backlog_ring[lp->backlog_tail];
    lp->backlog_tail = (lp->backlog_tail + 1) % kListenBacklogMax;
    --lp->backlog_count;
    Tcb* ct = TcbFromId(child_id);
    if (ct != nullptr)
    {
        if (out_peer_ip != nullptr)
            *out_peer_ip = ct->peer_ip;
        if (out_peer_port != nullptr)
            *out_peer_port = ct->peer_port;
    }
    ++g_stats.accepts;
    arch::Sti();
    return child_id;
}

sched::WaitQueue* AcceptWaitQueue(TcbId listener)
{
    using namespace internal;
    Tcb* lp = TcbFromId(listener);
    if (lp == nullptr || !lp->is_listener)
        return nullptr;
    return &lp->accept_wq;
}

TcbId Connect(u32 iface_index, Ipv4Address dst_ip, u16 dst_port, u16 local_port)
{
    using namespace internal;
    arch::Cli();
    if (local_port == 0)
    {
        local_port = AllocEphemeralPort();
        if (local_port == 0)
        {
            arch::Sti();
            return kInvalidTcbId;
        }
    }
    // Source IP — bind to the iface's IP. The caller may pass 0.
    Ipv4Address local_ip = InterfaceIp(iface_index);
    if (LookupExact(iface_index, local_ip, local_port, dst_ip, dst_port) != kTcbCap)
    {
        arch::Sti();
        return kInvalidTcbId;
    }
    const u32 idx = AllocSlot();
    if (idx == kTcbCap)
    {
        arch::Sti();
        return kInvalidTcbId;
    }
    Tcb& t = g_tcbs[idx];
    const u8 gen = u8(t.generation + 1);
    arch::Sti();
    if (!AllocTcbBuffers(t))
        return kInvalidTcbId;
    arch::Cli();
    ResetTcbStorage(t);
    t.generation = gen;
    t.in_use = true;
    t.is_listener = false;
    t.state = State::SynSent;
    t.iface_index = iface_index;
    t.local_ip = local_ip;
    t.peer_ip = dst_ip;
    t.local_port = local_port;
    t.peer_port = dst_port;
    t.refs = 1;
    // Random-ish ISN. Real stacks use a high-entropy source +
    // monotonic clock per RFC-6528; v0 uses NowTicks * a prime
    // to mix bits. Good enough until KASLR's RNG is wired into
    // the net stack.
    const u64 mix = NowTicks() * 1103515245u + 12345u;
    t.iss = u32(mix);
    t.snd_una = t.iss;
    t.snd_nxt = t.iss + 1; // SYN consumes one
    t.rcv_wnd = kRcvBufBytes;
    t.mss_send = kDefaultMss;
    BucketInsert(idx);
    ++g_stats.connects;
    // Send the SYN with options (MSS, WS, TS, SACK-Permitted) +
    // RFC-3168 ECN-Setup-SYN flags (ECE=1, CWR=1). The peer's
    // SYN-ACK confirms ECN by echoing ECE=1, CWR=0; a peer that
    // doesn't know ECN clears both bits and the connection runs
    // as classic TCP. Either way the protocol negotiation is
    // backward-compatible.
    SendSegment(t, kFlagSyn | kFlagEce | kFlagCwr, t.iss, 0, nullptr, 0);
    // Arm retransmit.
    t.rtx_deadline = NowTicks() + t.rto_ticks;
    arch::Sti();
    return MakeId(idx, gen);
}

bool WaitConnected(TcbId id, u64 timeout_ticks)
{
    using namespace internal;
    const u64 deadline = NowTicks() + timeout_ticks;
    while (true)
    {
        arch::Cli();
        Tcb* t = TcbFromId(id);
        if (t == nullptr)
        {
            arch::Sti();
            return false;
        }
        if (t->state == State::Established)
        {
            arch::Sti();
            return true;
        }
        if (t->state == State::Closed)
        {
            arch::Sti();
            return false;
        }
        const u64 now = NowTicks();
        if (now >= deadline)
        {
            arch::Sti();
            return false;
        }
        const u64 wait = deadline - now;
        const u64 step = (wait < 5) ? wait : 5;
        arch::Sti();
        sched::SchedSleepTicks(step);
    }
}

i32 Send(TcbId id, const u8* data, u32 len)
{
    using namespace internal;
    if (data == nullptr && len > 0)
        return -1;
    arch::Cli();
    Tcb* t = TcbFromId(id);
    if (t == nullptr || t->is_listener)
    {
        arch::Sti();
        return -1;
    }
    if (t->tx_closed)
    {
        arch::Sti();
        return -1;
    }
    if (t->state != State::Established && t->state != State::CloseWait)
    {
        arch::Sti();
        return -1;
    }
    const u32 free_bytes = kSndBufBytes - t->sndbuf_count;
    const u32 take = (len < free_bytes) ? len : free_bytes;
    for (u32 i = 0; i < take; ++i)
    {
        t->sndbuf[t->sndbuf_head] = data[i];
        t->sndbuf_head = (t->sndbuf_head + 1) % kSndBufBytes;
    }
    t->sndbuf_count += take;
    DrainSendBuffer(*t);
    arch::Sti();
    return i32(take);
}

i32 RecvNonblocking(TcbId id, u8* out, u32 cap)
{
    using namespace internal;
    if (cap > 0 && out == nullptr)
        return -1;
    arch::Cli();
    Tcb* t = TcbFromId(id);
    if (t == nullptr || t->is_listener)
    {
        arch::Sti();
        return -1;
    }
    if (t->rcvbuf_count == 0)
    {
        // Peer FIN consumed and buffer drained → orderly EOF.
        if (t->peer_fin_seen)
        {
            arch::Sti();
            return 0;
        }
        if (t->state == State::Closed)
        {
            arch::Sti();
            return 0;
        }
        arch::Sti();
        return -2; // would block
    }
    const u32 take = (cap < t->rcvbuf_count) ? cap : t->rcvbuf_count;
    for (u32 i = 0; i < take; ++i)
    {
        out[i] = t->rcvbuf[t->rcvbuf_tail];
        t->rcvbuf_tail = (t->rcvbuf_tail + 1) % kRcvBufBytes;
    }
    t->rcvbuf_count -= take;
    // Advance the advertised window — peer can send more now.
    const u32 free_bytes = kRcvBufBytes - t->rcvbuf_count;
    if (free_bytes > t->rcv_wnd && (free_bytes - t->rcv_wnd) >= t->mss_send)
    {
        t->rcv_wnd = free_bytes;
        // Window opened — send an ACK so the peer learns.
        SendSegment(*t, kFlagAck, t->snd_nxt, t->rcv_nxt, nullptr, 0);
    }
    arch::Sti();
    return i32(take);
}

void Close(TcbId id)
{
    using namespace internal;
    arch::Cli();
    Tcb* t = TcbFromId(id);
    if (t == nullptr)
    {
        arch::Sti();
        return;
    }
    if (t->is_listener)
    {
        DropTcb(u32(t - &g_tcbs[0]));
        arch::Sti();
        return;
    }
    if (t->tx_closed)
    {
        arch::Sti();
        return;
    }
    t->tx_closed = true;
    // Flush any queued data first; the FIN follows.
    DrainSendBuffer(*t);
    // Send FIN+ACK after the last data byte.
    if (t->state == State::Established)
    {
        SendSegment(*t, kFlagAck | kFlagFin, t->snd_nxt, t->rcv_nxt, nullptr, 0);
        ++t->snd_nxt; // FIN consumes one
        t->state = State::FinWait1;
        t->rtx_deadline = NowTicks() + t->rto_ticks;
    }
    else if (t->state == State::CloseWait)
    {
        SendSegment(*t, kFlagAck | kFlagFin, t->snd_nxt, t->rcv_nxt, nullptr, 0);
        ++t->snd_nxt;
        t->state = State::LastAck;
        t->rtx_deadline = NowTicks() + t->rto_ticks;
    }
    arch::Sti();
}

void Abort(TcbId id)
{
    using namespace internal;
    arch::Cli();
    Tcb* t = TcbFromId(id);
    if (t == nullptr)
    {
        arch::Sti();
        return;
    }
    if (!t->is_listener && t->state != State::Closed && t->state != State::Listen)
    {
        SendSegment(*t, kFlagRst | kFlagAck, t->snd_nxt, t->rcv_nxt, nullptr, 0);
        ++g_stats.rst_tx;
    }
    DropTcb(u32(t - &g_tcbs[0]));
    arch::Sti();
}

void Retain(TcbId id)
{
    using namespace internal;
    arch::Cli();
    Tcb* t = TcbFromId(id);
    if (t != nullptr)
        ++t->refs;
    arch::Sti();
}

void Release(TcbId id)
{
    using namespace internal;
    arch::Cli();
    Tcb* t = TcbFromId(id);
    if (t == nullptr)
    {
        arch::Sti();
        return;
    }
    if (t->refs > 0)
        --t->refs;
    if (t->refs == 0)
    {
        // Listener, or a connection already past the handshake
        // (Closed/TimeWait): tear down immediately. An otherwise-live
        // connected TCB triggers a close so the four-way handshake
        // runs first; the timer + segment paths eventually call DropTcb.
        if (t->is_listener || t->state == State::Closed || t->state == State::TimeWait)
        {
            DropTcb(u32(t - &g_tcbs[0]));
        }
        else if (!t->tx_closed)
        {
            // Inject a FIN if the user hadn't already half-closed.
            t->tx_closed = true;
            DrainSendBuffer(*t);
            if (t->state == State::Established)
            {
                SendSegment(*t, kFlagAck | kFlagFin, t->snd_nxt, t->rcv_nxt, nullptr, 0);
                ++t->snd_nxt;
                t->state = State::FinWait1;
                t->rtx_deadline = NowTicks() + t->rto_ticks;
            }
            else if (t->state == State::CloseWait)
            {
                SendSegment(*t, kFlagAck | kFlagFin, t->snd_nxt, t->rcv_nxt, nullptr, 0);
                ++t->snd_nxt;
                t->state = State::LastAck;
                t->rtx_deadline = NowTicks() + t->rto_ticks;
            }
        }
    }
    arch::Sti();
}

bool Alive(TcbId id)
{
    using namespace internal;
    u32 idx;
    return DecodeId(id, &idx);
}

State GetState(TcbId id)
{
    using namespace internal;
    Tcb* t = TcbFromId(id);
    if (t == nullptr)
        return State::Closed;
    return t->state;
}

bool PeerClosed(TcbId id)
{
    using namespace internal;
    Tcb* t = TcbFromId(id);
    if (t == nullptr)
        return true;
    return t->peer_fin_seen && t->rcvbuf_count == 0;
}

bool GetLocalEndpoint(TcbId id, Ipv4Address* out_ip, u16* out_port)
{
    using namespace internal;
    Tcb* t = TcbFromId(id);
    if (t == nullptr)
        return false;
    if (out_ip != nullptr)
        *out_ip = t->local_ip;
    if (out_port != nullptr)
        *out_port = t->local_port;
    return true;
}

bool GetPeerEndpoint(TcbId id, Ipv4Address* out_ip, u16* out_port)
{
    using namespace internal;
    Tcb* t = TcbFromId(id);
    if (t == nullptr)
        return false;
    if (out_ip != nullptr)
        *out_ip = t->peer_ip;
    if (out_port != nullptr)
        *out_port = t->peer_port;
    return true;
}

sched::WaitQueue* RecvWaitQueue(TcbId id)
{
    using namespace internal;
    Tcb* t = TcbFromId(id);
    return (t == nullptr) ? nullptr : &t->read_wq;
}

sched::WaitQueue* SendWaitQueue(TcbId id)
{
    using namespace internal;
    Tcb* t = TcbFromId(id);
    return (t == nullptr) ? nullptr : &t->write_wq;
}

bool SetNoDelay(TcbId id, bool on)
{
    using namespace internal;
    Tcb* t = TcbFromId(id);
    if (t == nullptr)
        return false;
    t->nodelay = on;
    return true;
}

bool SetKeepAlive(TcbId id, bool on)
{
    using namespace internal;
    Tcb* t = TcbFromId(id);
    if (t == nullptr)
        return false;
    t->keepalive_on = on;
    if (on)
        t->keepalive_deadline = NowTicks() + MsToTicks(60'000);
    else
        t->keepalive_deadline = 0;
    return true;
}

} // namespace duetos::net::tcp
