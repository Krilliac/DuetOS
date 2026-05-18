/*
 * DuetOS — TCP v1 segment dispatcher + state machine.
 *
 * Owns:
 *   - SendSegment: builds + transmits an L2/L3/L4 frame for one TCB.
 *   - OnSegment:   the public RX hook called from Ipv4HandleIncoming.
 *   - DeliverSegment: the per-TCB RFC-793 state machine.
 *   - Option encode/decode (MSS, window scale, timestamps).
 *   - Reassembly queue insertion.
 *   - DrainSendBuffer / Retransmit helpers used by the public API
 *     and the timer task.
 *
 * Everything in here runs under arch::Cli (single-CPU lock). Callers
 * that re-enter the state machine through the public API are
 * responsible for the lock.
 */

#include "net/tcp.h"
#include "net/tcp_internal.h"

#include "arch/x86_64/cpu.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "net/firewall.h"
#include "sched/sched.h"
#include "time/tick.h"
#include "util/string.h"

namespace duetos::net::tcp
{

namespace internal
{

// Forward declaration of IfaceTx-equivalent — stack.cpp has the
// firewall-gated egress path. We don't reach past the gate.
extern "C" bool DuetosNetIfaceTx(u32 iface_index, const void* frame, u64 frame_len);

// Pseudo-header TCP checksum (RFC-793).
u16 ChecksumTcp(Ipv4Address src, Ipv4Address dst, const u8* tcp, u64 tcp_len)
{
    u32 sum = 0;
    sum += (u32(src.octets[0]) << 8) | u32(src.octets[1]);
    sum += (u32(src.octets[2]) << 8) | u32(src.octets[3]);
    sum += (u32(dst.octets[0]) << 8) | u32(dst.octets[1]);
    sum += (u32(dst.octets[2]) << 8) | u32(dst.octets[3]);
    sum += kIpProtoTcp;
    sum += u32(tcp_len);
    for (u64 i = 0; i + 1 < tcp_len; i += 2)
        sum += (u32(tcp[i]) << 8) | u32(tcp[i + 1]);
    if ((tcp_len & 1) != 0)
        sum += u32(tcp[tcp_len - 1]) << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return u16(~sum & 0xFFFF);
}

// Build options for an outgoing segment. Returns the option-block
// length (multiple of 4). `flags` decides which options are valid:
// SYN includes MSS + window scale + SACK-permitted + timestamps;
// ESTABLISHED only includes timestamps.
u32 BuildOptions(const Tcb& t, u8 flags, u8* opts)
{
    u32 i = 0;
    const bool syn = (flags & kFlagSyn) != 0;
    if (syn)
    {
        // MSS
        opts[i++] = kOptMss;
        opts[i++] = 4;
        const u16 mss = kDefaultMss;
        opts[i++] = u8(mss >> 8);
        opts[i++] = u8(mss & 0xFF);
        // Window scale (RFC-7323). We always advertise 0 on SYN —
        // the peer's reply tells us whether they support it; if so,
        // we still scale our rcv window by zero (no shift). Future
        // slice: bump to 7 when rcvbuf grows past 64 KiB.
        opts[i++] = kOptNop;
        opts[i++] = kOptWindowScale;
        opts[i++] = 3;
        opts[i++] = 0; // shift count
        // SACK-permitted — advertised even though v0 doesn't emit
        // SACK blocks; the option signals the peer that future
        // ranges may use it without renegotiation.
        opts[i++] = kOptSackPermitted;
        opts[i++] = 2;
    }
    if (t.peer_supports_timestamps || syn)
    {
        // 12-byte timestamp option, NOP+NOP-padded.
        opts[i++] = kOptNop;
        opts[i++] = kOptNop;
        opts[i++] = kOptTimestamp;
        opts[i++] = 10;
        const u32 tsval = u32(NowTicks() & 0xFFFFFFFFu);
        opts[i++] = u8(tsval >> 24);
        opts[i++] = u8(tsval >> 16);
        opts[i++] = u8(tsval >> 8);
        opts[i++] = u8(tsval);
        const u32 tsecr = t.peer_supports_timestamps ? t.ts_recent : 0;
        opts[i++] = u8(tsecr >> 24);
        opts[i++] = u8(tsecr >> 16);
        opts[i++] = u8(tsecr >> 8);
        opts[i++] = u8(tsecr);
    }
    // Pad to a 4-byte boundary with NOPs.
    while ((i & 3) != 0)
        opts[i++] = kOptNop;
    return i;
}

// Parse inbound options. Updates the TCB's peer_supports_* fields
// on SYN and absorbs the timestamp on every segment that carries
// one. Caller passes `is_syn` because some option semantics differ.
struct ParsedOptions
{
    u16 mss;
    u8 wscale;
    bool has_wscale;
    bool sack_permitted;
    bool has_timestamp;
    u32 tsval;
    u32 tsecr;
};

ParsedOptions ParseOptions(const u8* opts, u32 opts_len)
{
    ParsedOptions po = {};
    u32 i = 0;
    while (i < opts_len)
    {
        const u8 kind = opts[i];
        if (kind == kOptEnd)
            break;
        if (kind == kOptNop)
        {
            ++i;
            continue;
        }
        if (i + 1 >= opts_len)
            break;
        const u8 len = opts[i + 1];
        if (len < 2 || i + len > opts_len)
            break;
        switch (kind)
        {
        case kOptMss:
            if (len == 4)
                po.mss = (u16(opts[i + 2]) << 8) | u16(opts[i + 3]);
            break;
        case kOptWindowScale:
            if (len == 3)
            {
                po.has_wscale = true;
                po.wscale = opts[i + 2];
                if (po.wscale > 14)
                    po.wscale = 14;
            }
            break;
        case kOptSackPermitted:
            if (len == 2)
                po.sack_permitted = true;
            break;
        case kOptTimestamp:
            if (len == 10)
            {
                po.has_timestamp = true;
                po.tsval =
                    (u32(opts[i + 2]) << 24) | (u32(opts[i + 3]) << 16) | (u32(opts[i + 4]) << 8) | u32(opts[i + 5]);
                po.tsecr =
                    (u32(opts[i + 6]) << 24) | (u32(opts[i + 7]) << 16) | (u32(opts[i + 8]) << 8) | u32(opts[i + 9]);
            }
            break;
        default:
            break;
        }
        i += len;
    }
    return po;
}

bool SendSegment(Tcb& t, u8 flags, u32 seq, u32 ack, const u8* payload, u32 payload_len)
{
    if (payload_len > kSegmentBytes)
        return false;
    u8 opt_block[40];
    const u32 opt_len = BuildOptions(t, flags, opt_block);
    const u32 tcp_header_len = 20 + opt_len;
    const u32 frame_len = 14 + 20 + tcp_header_len + payload_len;
    if (frame_len > kEthFrameMaxBytes)
        return false;
    u8 frame[kEthFrameMaxBytes];
    // Ethernet.
    for (u32 i = 0; i < 6; ++i)
        frame[i] = t.peer_mac.octets[i];
    MacAddress local_mac = InterfaceMac(t.iface_index);
    for (u32 i = 0; i < 6; ++i)
        frame[6 + i] = local_mac.octets[i];
    frame[12] = 0x08;
    frame[13] = 0x00;
    // IPv4.
    u8* ip = frame + 14;
    ip[0] = 0x45;
    ip[1] = 0x00;
    const u16 ip_total = u16(20 + tcp_header_len + payload_len);
    ip[2] = u8(ip_total >> 8);
    ip[3] = u8(ip_total & 0xFF);
    ip[4] = 0x00;
    ip[5] = 0x00;
    ip[6] = 0x40; // DF
    ip[7] = 0x00;
    ip[8] = 64;
    ip[9] = kIpProtoTcp;
    ip[10] = 0;
    ip[11] = 0;
    for (u32 i = 0; i < 4; ++i)
        ip[12 + i] = t.local_ip.octets[i];
    for (u32 i = 0; i < 4; ++i)
        ip[16 + i] = t.peer_ip.octets[i];
    const u16 ip_ck = Ipv4HeaderChecksum(ip, 20);
    ip[10] = u8(ip_ck >> 8);
    ip[11] = u8(ip_ck & 0xFF);
    // TCP.
    u8* tcp = ip + 20;
    tcp[0] = u8(t.local_port >> 8);
    tcp[1] = u8(t.local_port & 0xFF);
    tcp[2] = u8(t.peer_port >> 8);
    tcp[3] = u8(t.peer_port & 0xFF);
    tcp[4] = u8(seq >> 24);
    tcp[5] = u8(seq >> 16);
    tcp[6] = u8(seq >> 8);
    tcp[7] = u8(seq);
    tcp[8] = u8(ack >> 24);
    tcp[9] = u8(ack >> 16);
    tcp[10] = u8(ack >> 8);
    tcp[11] = u8(ack);
    tcp[12] = u8((tcp_header_len / 4) << 4);
    tcp[13] = flags;
    // Advertise rcv_wnd shifted by rcv_wscale. The header field is
    // 16 bits; we shift our internal window down so the peer
    // reconstructs it after applying the scale option.
    const u32 advertised = t.rcv_wnd >> t.rcv_wscale;
    const u16 win = (advertised > 0xFFFF) ? 0xFFFF : u16(advertised);
    tcp[14] = u8(win >> 8);
    tcp[15] = u8(win & 0xFF);
    tcp[16] = 0;
    tcp[17] = 0;
    tcp[18] = 0;
    tcp[19] = 0;
    for (u32 i = 0; i < opt_len; ++i)
        tcp[20 + i] = opt_block[i];
    for (u32 i = 0; i < payload_len; ++i)
        tcp[tcp_header_len + i] = payload[i];
    const u16 ck = ChecksumTcp(t.local_ip, t.peer_ip, tcp, tcp_header_len + payload_len);
    tcp[16] = u8(ck >> 8);
    tcp[17] = u8(ck & 0xFF);

    const bool ok = DuetosNetIfaceTx(t.iface_index, frame, frame_len);
    if (ok)
    {
        ++g_stats.segs_tx;
        if ((flags & kFlagRst) != 0)
            ++g_stats.rst_tx;
    }
    return ok;
}

void SendStandaloneRst(u32 iface_index, const MacAddress& peer_mac, Ipv4Address peer_ip, u16 peer_port, u16 local_port,
                       u32 peer_seq, u32 peer_ack, u8 peer_flags)
{
    // Build a synthetic TCB just to drive SendSegment. The TCB is
    // a local stack object — does NOT touch the table.
    Tcb t = {};
    t.iface_index = iface_index;
    t.local_ip = InterfaceIp(iface_index);
    t.peer_ip = peer_ip;
    t.local_port = local_port;
    t.peer_port = peer_port;
    t.peer_mac = peer_mac;
    t.rcv_wnd = 0;
    // RFC-793 §3.4: if ACK was on the incoming segment, RST carries
    // (SEQ=ACK_in, no-ACK). Otherwise RST carries SEQ=0 + ACK=peer_seq +
    // len; we use the second form so the peer's half-open state can
    // tear down without needing to validate our ACK.
    u32 seq;
    u32 ack;
    u8 flags;
    if ((peer_flags & kFlagAck) != 0)
    {
        seq = peer_ack;
        ack = 0;
        flags = kFlagRst;
    }
    else
    {
        seq = 0;
        ack = peer_seq + 1;
        flags = kFlagRst | kFlagAck;
    }
    SendSegment(t, flags, seq, ack, nullptr, 0);
}

// Push contiguous bytes from sndbuf onto the wire, honoring snd_wnd,
// cwnd, and rtx queue depth. Each chunk gets a SegmentBuf entry +
// rtx_deadline arm.
void DrainSendBuffer(Tcb& t)
{
    if (t.state != State::Established && t.state != State::CloseWait)
        return;
    while (t.sndbuf_count > 0 && t.rtx_count < kRtxQueueMax)
    {
        // How many bytes are still allowed by the receiver window
        // and the congestion window combined?
        const u32 in_flight = t.snd_nxt - t.snd_una;
        const u32 wnd = (t.snd_wnd < t.cwnd) ? t.snd_wnd : t.cwnd;
        if (in_flight >= wnd)
            break;
        const u32 send_room = wnd - in_flight;
        u32 take = t.sndbuf_count;
        if (take > t.mss_send)
            take = t.mss_send;
        if (take > send_room)
            take = send_room;
        if (take == 0)
            break;
        // Slice into a SegmentBuf for retransmit. Find the first
        // empty slot.
        u32 slot = kRtxQueueMax;
        for (u32 i = 0; i < kRtxQueueMax; ++i)
        {
            if (t.rtx_queue[i].len == 0)
            {
                slot = i;
                break;
            }
        }
        if (slot == kRtxQueueMax)
            break;
        SegmentBuf& sb = t.rtx_queue[slot];
        sb.seq = t.snd_nxt;
        sb.len = take;
        sb.flags = kFlagAck | kFlagPsh;
        sb.ticks_sent = NowTicks();
        for (u32 i = 0; i < take; ++i)
        {
            sb.data[i] = t.sndbuf[t.sndbuf_tail];
            t.sndbuf_tail = (t.sndbuf_tail + 1) % kSndBufBytes;
        }
        t.sndbuf_count -= take;
        ++t.rtx_count;
        t.snd_nxt += take;
        SendSegment(t, sb.flags, sb.seq, t.rcv_nxt, sb.data, sb.len);
        if (t.rtx_deadline == 0)
            t.rtx_deadline = NowTicks() + t.rto_ticks;
    }
    // Wake any waiter blocked on space.
    if (kSndBufBytes - t.sndbuf_count >= t.mss_send)
        sched::WaitQueueWakeAll(&t.write_wq);
}

void ArmRtxTimer(Tcb& t)
{
    if (t.rtx_count == 0)
    {
        t.rtx_deadline = 0;
        return;
    }
    t.rtx_deadline = NowTicks() + t.rto_ticks;
}

void EnterTimeWait(Tcb& t)
{
    t.state = State::TimeWait;
    t.timewait_deadline = NowTicks() + MsToTicks(kTimeWaitMs);
    // Drop the retransmit queue — TIME_WAIT only needs to ACK
    // peer retransmits.
    t.rtx_count = 0;
    for (u32 i = 0; i < kRtxQueueMax; ++i)
        t.rtx_queue[i].len = 0;
    t.rtx_deadline = 0;
    sched::WaitQueueWakeAll(&t.read_wq);
    sched::WaitQueueWakeAll(&t.write_wq);
}

void NotifyParentAccept(Tcb& child)
{
    if (child.parent_listener == 0)
        return;
    Tcb* parent = TcbFromId(child.parent_listener);
    if (parent == nullptr || !parent->is_listener)
        return;
    if (parent->backlog_count >= parent->backlog_max)
    {
        ++g_stats.backlog_drops;
        return;
    }
    parent->backlog_ring[parent->backlog_head] = MakeId(u32(&child - &g_tcbs[0]), child.generation);
    parent->backlog_head = (parent->backlog_head + 1) % kListenBacklogMax;
    ++parent->backlog_count;
    child.parent_listener = 0; // one-shot push
    sched::WaitQueueWakeAll(&parent->accept_wq);
}

void DropTcb(u32 idx)
{
    Tcb& t = g_tcbs[idx];
    if (!t.in_use)
        return;
    if (!t.is_listener)
        BucketRemove(idx);
    sched::WaitQueueWakeAll(&t.read_wq);
    sched::WaitQueueWakeAll(&t.write_wq);
    sched::WaitQueueWakeAll(&t.connect_wq);
    sched::WaitQueueWakeAll(&t.accept_wq);
    FreeTcbBuffers(t);
    const u8 gen = u8(t.generation + 1);
    t.in_use = false;
    t.generation = gen;
    t.state = State::Closed;
    ++g_stats.closes;
}

// -------------------------------------------------------------------
// State machine.
//
// Per-segment processing follows RFC-793 §3.9, simplified for the
// v0 -> v1 transition:
//   - LISTEN: SYN → carve a child TCB, send SYN+ACK.
//   - SYN_RCVD: ACK matching our SYN+ACK → ESTABLISHED.
//   - SYN_SENT: SYN+ACK → ESTABLISHED + ACK.
//   - ESTABLISHED: deliver data, ACK, advance window; peer FIN →
//                  CLOSE_WAIT.
//   - FIN_WAIT_1: ACK of our FIN → FIN_WAIT_2 (or CLOSING / TIME_WAIT
//                 on simultaneous close paths).
//   - FIN_WAIT_2: peer FIN → TIME_WAIT.
//   - CLOSE_WAIT: user Close() → LAST_ACK.
//   - LAST_ACK: peer ACK of our FIN → CLOSED.
//   - TIME_WAIT: stays until 2*MSL.
// -------------------------------------------------------------------

// Compute the SEQ field of an inbound ACK relative to snd_una/snd_nxt.
// Returns false on a duplicate or out-of-window ACK (i.e. caller
// should drop the ACK without advancing state).
bool AckInWindow(u32 ack, u32 snd_una, u32 snd_nxt)
{
    // unsigned wrap: ack is "newer" iff (ack - snd_una) <
    // (snd_nxt - snd_una) inclusive on both ends.
    const u32 una_to_ack = ack - snd_una;
    const u32 una_to_nxt = snd_nxt - snd_una;
    return una_to_ack <= una_to_nxt;
}

// Drop segments from the retransmit queue that the peer's ACK has
// covered. Returns the number of new bytes acked (for RTT sample).
u32 ProcessAck(Tcb& t, u32 ack, bool has_timestamp, u32 tsecr)
{
    u32 acked = 0;
    for (u32 i = 0; i < kRtxQueueMax; ++i)
    {
        SegmentBuf& sb = t.rtx_queue[i];
        if (sb.len == 0)
            continue;
        const u32 end = sb.seq + sb.len;
        if (AckInWindow(end, t.snd_una, ack))
        {
            // Fully acked.
            acked += sb.len;
            // RTT sample — RFC-6298 §3 + Karn's algorithm: only
            // sample segments that were never retransmitted.
            // Approximation: trust the timestamp echo if present.
            if (has_timestamp && tsecr != 0)
            {
                const u64 now = NowTicks();
                const u64 sent = u64(tsecr);
                if (now >= sent)
                {
                    const u32 rtt = u32(now - sent);
                    if (!t.rtt_have_sample)
                    {
                        t.srtt_ticks = rtt;
                        t.rttvar_ticks = rtt / 2;
                        t.rtt_have_sample = true;
                    }
                    else
                    {
                        // RFC-6298: SRTT = SRTT + (1/8) * (R - SRTT),
                        // RTTVAR = RTTVAR + (1/4) * (|R-SRTT| - RTTVAR)
                        const u32 diff = (rtt > t.srtt_ticks) ? (rtt - t.srtt_ticks) : (t.srtt_ticks - rtt);
                        t.rttvar_ticks = t.rttvar_ticks - (t.rttvar_ticks >> 2) + (diff >> 2);
                        t.srtt_ticks = t.srtt_ticks - (t.srtt_ticks >> 3) + (rtt >> 3);
                    }
                    t.rto_ticks = t.srtt_ticks + (t.rttvar_ticks << 2);
                    if (t.rto_ticks < MsToTicks(kMinRtoMs))
                        t.rto_ticks = MsToTicks(kMinRtoMs);
                    if (t.rto_ticks > MsToTicks(kMaxRtoMs))
                        t.rto_ticks = MsToTicks(kMaxRtoMs);
                }
            }
            sb.len = 0;
            --t.rtx_count;
        }
    }
    if (acked > 0)
    {
        t.snd_una = ack;
        // Congestion-control: slow-start while cwnd < ssthresh; then
        // CA. Increment by MSS per RTT in CA (1 MSS * MSS / cwnd
        // per ACK).
        if (t.cwnd < t.ssthresh)
            t.cwnd += t.mss_send;
        else
            t.cwnd += (u32(t.mss_send) * t.mss_send) / (t.cwnd == 0 ? 1 : t.cwnd);
        if (t.cwnd > 0x7FFFFFFFu)
            t.cwnd = 0x7FFFFFFFu;
        t.retries = 0;
        t.dup_acks = 0;
    }
    // Wake any writer blocked on snd buf space.
    if (t.rtx_count == 0)
        t.rtx_deadline = 0;
    else
        t.rtx_deadline = NowTicks() + t.rto_ticks;
    return acked;
}

// Try to integrate an OOO segment into the rcv buffer + reassembly
// queue. Returns true if anything was delivered (caller should ACK).
bool DeliverPayload(Tcb& t, u32 seq, const u8* data, u32 len)
{
    if (len == 0)
        return false;
    // Drop anything fully past rcv_wnd from the right edge.
    const u32 rcv_end = t.rcv_nxt + t.rcv_wnd;
    if (u32(seq - t.rcv_nxt) > t.rcv_wnd)
    {
        ++g_stats.reass_drops;
        return false;
    }
    // In-order: copy directly into rcvbuf.
    if (seq == t.rcv_nxt)
    {
        const u32 free_bytes = kRcvBufBytes - t.rcvbuf_count;
        const u32 take = (len < free_bytes) ? len : free_bytes;
        for (u32 i = 0; i < take; ++i)
        {
            t.rcvbuf[t.rcvbuf_head] = data[i];
            t.rcvbuf_head = (t.rcvbuf_head + 1) % kRcvBufBytes;
        }
        t.rcvbuf_count += take;
        t.rcv_nxt += take;
        // Try to coalesce any OOO segments that now line up.
        bool progressed = true;
        while (progressed)
        {
            progressed = false;
            for (u32 i = 0; i < kReassQueueMax; ++i)
            {
                OoSegment& oo = t.oo_queue[i];
                if (!oo.in_use)
                    continue;
                if (oo.seq == t.rcv_nxt)
                {
                    const u32 room = kRcvBufBytes - t.rcvbuf_count;
                    const u32 oot = (oo.len < room) ? oo.len : room;
                    for (u32 j = 0; j < oot; ++j)
                    {
                        t.rcvbuf[t.rcvbuf_head] = oo.data[j];
                        t.rcvbuf_head = (t.rcvbuf_head + 1) % kRcvBufBytes;
                    }
                    t.rcvbuf_count += oot;
                    t.rcv_nxt += oot;
                    oo.in_use = false;
                    progressed = true;
                }
                else if (u32(t.rcv_nxt - oo.seq) <= oo.len)
                {
                    // Old segment now entirely below rcv_nxt — drop.
                    oo.in_use = false;
                    progressed = true;
                }
            }
        }
        // Shrink advertised window by the bytes we hold.
        const u32 free_after = kRcvBufBytes - t.rcvbuf_count;
        t.rcv_wnd = free_after;
        sched::WaitQueueWakeAll(&t.read_wq);
        return true;
    }
    // Out-of-order — stash in oo_queue.
    (void)rcv_end;
    for (u32 i = 0; i < kReassQueueMax; ++i)
    {
        OoSegment& oo = t.oo_queue[i];
        if (oo.in_use && oo.seq == seq)
            return true; // duplicate, just ACK
    }
    for (u32 i = 0; i < kReassQueueMax; ++i)
    {
        OoSegment& oo = t.oo_queue[i];
        if (!oo.in_use)
        {
            oo.in_use = true;
            oo.seq = seq;
            oo.len = (len < kSegmentBytes) ? len : kSegmentBytes;
            for (u32 j = 0; j < oo.len; ++j)
                oo.data[j] = data[j];
            ++g_stats.oo_segs;
            return true;
        }
    }
    ++g_stats.reass_drops;
    return false;
}

void DeliverSegment(u32 idx, const MacAddress& peer_mac, Ipv4Address peer_ip, const u8* tcp, u64 tcp_len)
{
    Tcb& t = g_tcbs[idx];
    (void)peer_ip;
    const u16 src_port = (u16(tcp[0]) << 8) | u16(tcp[1]);
    const u16 dst_port = (u16(tcp[2]) << 8) | u16(tcp[3]);
    const u32 seq = (u32(tcp[4]) << 24) | (u32(tcp[5]) << 16) | (u32(tcp[6]) << 8) | u32(tcp[7]);
    const u32 ack = (u32(tcp[8]) << 24) | (u32(tcp[9]) << 16) | (u32(tcp[10]) << 8) | u32(tcp[11]);
    const u8 data_off_bytes = (tcp[12] >> 4) * 4;
    const u8 flags = tcp[13];
    const u16 win = (u16(tcp[14]) << 8) | u16(tcp[15]);
    (void)src_port;
    (void)dst_port;
    if (data_off_bytes < 20 || data_off_bytes > tcp_len)
    {
        ++g_stats.reass_drops;
        return;
    }
    const u8* opts = tcp + 20;
    const u32 opts_len = data_off_bytes - 20;
    const u8* payload = tcp + data_off_bytes;
    const u32 payload_len = u32(tcp_len - data_off_bytes);
    ParsedOptions po = ParseOptions(opts, opts_len);
    if (po.has_timestamp)
    {
        t.peer_supports_timestamps = true;
        t.ts_recent = po.tsval;
        t.ts_recent_age_ticks = NowTicks();
    }
    // RST processing — drop the connection unconditionally if the
    // 4-tuple matched (we've already filtered by exact lookup).
    if ((flags & kFlagRst) != 0)
    {
        ++g_stats.rst_rx;
        DropTcb(idx);
        return;
    }
    // Refresh peer MAC (might've changed if the router learned a
    // new neighbor entry while we were idle).
    t.peer_mac = peer_mac;
    // Snd_wnd update — always, even on a duplicate ACK.
    const u8 ws = t.peer_supports_wscale ? t.snd_wscale : 0;
    t.snd_wnd = u32(win) << ws;

    // SYN_SENT → ESTABLISHED on SYN+ACK.
    if (t.state == State::SynSent)
    {
        if ((flags & kFlagSyn) != 0 && (flags & kFlagAck) != 0 && AckInWindow(ack, t.snd_una, t.snd_nxt))
        {
            t.irs = seq;
            t.rcv_nxt = seq + 1;
            t.peer_supports_wscale = po.has_wscale;
            t.snd_wscale = po.has_wscale ? po.wscale : 0;
            if (po.mss > 0 && po.mss < t.mss_send)
                t.mss_send = po.mss;
            // Mark our SYN as acked.
            t.snd_una = ack;
            t.rtx_count = 0;
            for (u32 i = 0; i < kRtxQueueMax; ++i)
                t.rtx_queue[i].len = 0;
            t.rtx_deadline = 0;
            t.state = State::Established;
            SendSegment(t, kFlagAck, t.snd_nxt, t.rcv_nxt, nullptr, 0);
            sched::WaitQueueWakeAll(&t.connect_wq);
            // Kick any queued data.
            DrainSendBuffer(t);
        }
        else if ((flags & kFlagSyn) != 0 && (flags & kFlagAck) == 0)
        {
            // Simultaneous open. Move to SYN_RCVD.
            t.irs = seq;
            t.rcv_nxt = seq + 1;
            t.state = State::SynRcvd;
            SendSegment(t, kFlagSyn | kFlagAck, t.iss, t.rcv_nxt, nullptr, 0);
        }
        return;
    }

    // SYN_RCVD: expect ACK for our SYN+ACK.
    if (t.state == State::SynRcvd)
    {
        if ((flags & kFlagAck) != 0 && AckInWindow(ack, t.snd_una, t.snd_nxt))
        {
            t.snd_una = ack;
            t.rtx_count = 0;
            for (u32 i = 0; i < kRtxQueueMax; ++i)
                t.rtx_queue[i].len = 0;
            t.rtx_deadline = 0;
            t.state = State::Established;
            NotifyParentAccept(t);
            sched::WaitQueueWakeAll(&t.connect_wq);
            // Fall through to data processing.
        }
        else
        {
            return;
        }
    }

    // ESTABLISHED / FIN_WAIT_1 / FIN_WAIT_2 / CLOSE_WAIT / CLOSING /
    // LAST_ACK / TIME_WAIT: process ACK + data + FIN.
    if ((flags & kFlagAck) != 0)
    {
        if (AckInWindow(ack, t.snd_una, t.snd_nxt))
        {
            if (ack == t.snd_una && payload_len == 0 && t.rtx_count > 0)
            {
                // Duplicate ACK — accumulate; on third dup, fast
                // retransmit the first unacked segment.
                ++t.dup_acks;
                if (t.dup_acks == 3 && !t.in_fast_recovery)
                {
                    t.in_fast_recovery = true;
                    t.ssthresh = (t.cwnd / 2 < 2u * t.mss_send) ? 2u * t.mss_send : t.cwnd / 2;
                    t.cwnd = t.ssthresh + 3u * t.mss_send;
                    // Resend first unacked.
                    for (u32 i = 0; i < kRtxQueueMax; ++i)
                    {
                        SegmentBuf& sb = t.rtx_queue[i];
                        if (sb.len != 0 && sb.seq == t.snd_una)
                        {
                            SendSegment(t, sb.flags, sb.seq, t.rcv_nxt, sb.data, sb.len);
                            ++g_stats.retrans;
                            break;
                        }
                    }
                }
                else if (t.in_fast_recovery)
                {
                    t.cwnd += t.mss_send;
                }
            }
            else
            {
                if (t.in_fast_recovery && ack != t.snd_una)
                {
                    t.in_fast_recovery = false;
                    t.cwnd = t.ssthresh;
                }
                (void)ProcessAck(t, ack, po.has_timestamp, po.tsecr);
            }
            // Did this ACK clear our FIN?
            if (t.state == State::FinWait1 && t.rtx_count == 0)
            {
                if (t.peer_fin_seen)
                    EnterTimeWait(t);
                else
                    t.state = State::FinWait2;
            }
            else if (t.state == State::Closing && t.rtx_count == 0)
            {
                EnterTimeWait(t);
            }
            else if (t.state == State::LastAck && t.rtx_count == 0)
            {
                DropTcb(idx);
                return;
            }
        }
    }

    if (payload_len > 0)
    {
        DeliverPayload(t, seq, payload, payload_len);
    }

    if ((flags & kFlagFin) != 0 && !t.peer_fin_seen)
    {
        // Only honour FIN if it's at rcv_nxt (in-order). Real stacks
        // queue out-of-order FINs too; v0 keeps it simple.
        const u32 fin_seq = seq + payload_len;
        if (fin_seq == t.rcv_nxt)
        {
            t.peer_fin_seen = true;
            t.peer_fin_seq = fin_seq;
            t.rcv_nxt = fin_seq + 1;
            sched::WaitQueueWakeAll(&t.read_wq);
            switch (t.state)
            {
            case State::Established:
                t.state = State::CloseWait;
                break;
            case State::FinWait1:
                if (t.rtx_count == 0)
                    EnterTimeWait(t);
                else
                    t.state = State::Closing;
                break;
            case State::FinWait2:
                EnterTimeWait(t);
                break;
            default:
                break;
            }
        }
    }

    // Send an ACK if the segment carried data or a FIN. Delayed-ACK
    // optimisation: pure-data ACKs are deferred up to kDelackMs;
    // FIN / fast retransmit / window updates send immediately.
    if (payload_len > 0 || (flags & kFlagFin) != 0)
    {
        if ((flags & kFlagFin) != 0 || payload_len >= t.mss_send)
        {
            SendSegment(t, kFlagAck, t.snd_nxt, t.rcv_nxt, nullptr, 0);
            t.delack_pending = false;
            t.delack_deadline = 0;
        }
        else
        {
            // Schedule a delayed ACK (or immediate if one is already pending).
            if (t.delack_pending)
            {
                SendSegment(t, kFlagAck, t.snd_nxt, t.rcv_nxt, nullptr, 0);
                t.delack_pending = false;
                t.delack_deadline = 0;
            }
            else
            {
                t.delack_pending = true;
                t.delack_deadline = NowTicks() + MsToTicks(kDelackMs);
            }
        }
    }
    // Wake any sender if peer window opened up.
    if (t.snd_wnd > 0)
        sched::WaitQueueWakeAll(&t.write_wq);
}

void HandleListenSyn(u32 listener_idx, u32 iface_index, const MacAddress& peer_mac, Ipv4Address peer_ip, u16 peer_port,
                     u16 local_port, u32 peer_seq, const ParsedOptions& po)
{
    Tcb& parent = g_tcbs[listener_idx];
    if (parent.backlog_count >= parent.backlog_max)
    {
        ++g_stats.backlog_drops;
        // SYN-flood defense — drop silently. Future: SYN cookies.
        return;
    }
    const u32 idx = AllocSlot();
    if (idx == kTcbCap)
    {
        ++g_stats.backlog_drops;
        return;
    }
    Tcb& child = g_tcbs[idx];
    const u8 gen = u8(child.generation + 1);
    if (!AllocTcbBuffers(child))
    {
        ++g_stats.backlog_drops;
        return;
    }
    ResetTcbStorage(child);
    child.generation = gen;
    child.in_use = true;
    child.is_listener = false;
    child.state = State::SynRcvd;
    child.iface_index = iface_index;
    child.local_ip = InterfaceIp(iface_index);
    child.peer_ip = peer_ip;
    child.local_port = local_port;
    child.peer_port = peer_port;
    child.peer_mac = peer_mac;
    child.refs = 1;
    child.parent_listener = MakeId(listener_idx, parent.generation);
    const u64 mix = NowTicks() * 1103515245u + 12345u;
    child.iss = u32(mix);
    child.snd_una = child.iss;
    child.snd_nxt = child.iss + 1;
    child.irs = peer_seq;
    child.rcv_nxt = peer_seq + 1;
    child.mss_send = (po.mss > 0 && po.mss < kDefaultMss) ? po.mss : kDefaultMss;
    child.peer_supports_wscale = po.has_wscale;
    child.snd_wscale = po.has_wscale ? po.wscale : 0;
    child.peer_supports_timestamps = po.has_timestamp;
    if (po.has_timestamp)
        child.ts_recent = po.tsval;
    BucketInsert(idx);
    SendSegment(child, kFlagSyn | kFlagAck, child.iss, child.rcv_nxt, nullptr, 0);
    child.rtx_deadline = NowTicks() + child.rto_ticks;
}

} // namespace internal

void OnSegment(u32 iface_index, const MacAddress& peer_mac, Ipv4Address peer_ip, const u8* tcp, u64 tcp_len)
{
    using namespace internal;
    if (tcp == nullptr || tcp_len < 20)
        return;
    arch::Cli();
    ++g_stats.segs_rx;
    const u16 src_port = (u16(tcp[0]) << 8) | u16(tcp[1]);
    const u16 dst_port = (u16(tcp[2]) << 8) | u16(tcp[3]);
    const u32 seq = (u32(tcp[4]) << 24) | (u32(tcp[5]) << 16) | (u32(tcp[6]) << 8) | u32(tcp[7]);
    const u32 ack = (u32(tcp[8]) << 24) | (u32(tcp[9]) << 16) | (u32(tcp[10]) << 8) | u32(tcp[11]);
    const u8 data_off_bytes = (tcp[12] >> 4) * 4;
    const u8 flags = tcp[13];
    if (data_off_bytes < 20 || data_off_bytes > tcp_len)
    {
        arch::Sti();
        return;
    }
    Ipv4Address local_ip = InterfaceIp(iface_index);

    // Look up an existing TCB by exact 5-tuple.
    const u32 idx = LookupExact(iface_index, local_ip, dst_port, peer_ip, src_port);
    if (idx != kTcbCap)
    {
        DeliverSegment(idx, peer_mac, peer_ip, tcp, tcp_len);
        arch::Sti();
        return;
    }

    // No matching TCB. If it's a SYN aimed at a listener, accept.
    if ((flags & kFlagSyn) != 0 && (flags & kFlagAck) == 0)
    {
        const u32 lidx = LookupListener(dst_port);
        if (lidx != kTcbCap)
        {
            const u8* opts = tcp + 20;
            const u32 opts_len = data_off_bytes - 20;
            ParsedOptions po = ParseOptions(opts, opts_len);
            HandleListenSyn(lidx, iface_index, peer_mac, peer_ip, src_port, dst_port, seq, po);
            arch::Sti();
            return;
        }
    }

    // Anything else gets an RST (unless it itself is an RST).
    if ((flags & kFlagRst) == 0)
        SendStandaloneRst(iface_index, peer_mac, peer_ip, src_port, dst_port, seq, ack, flags);
    arch::Sti();
}

} // namespace duetos::net::tcp
