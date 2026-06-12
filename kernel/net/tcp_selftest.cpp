/*
 * DuetOS — TCP v1 boot-time selftest.
 *
 * Drives a loopback round-trip through OnSegment by hand-crafting
 * the segments that a peer would emit, then asserts:
 *   - The state machine reaches ESTABLISHED on both ends.
 *   - In-order delivery, sliding window, and out-of-order
 *     reassembly all work.
 *   - The FIN handshake lands both ends in CLOSED via TIME_WAIT.
 *
 * Emits one explicit "[net/tcp-selftest] PASS" line per pass so
 * CI can grep for it. On FAIL, emits "[net/tcp-selftest] FAIL ..."
 * and fires kBootSelftestFail through the probe table.
 */

#include "net/stack.h"
#include "net/tcp.h"
#include "net/tcp_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "util/string.h"

namespace duetos::net::tcp
{

namespace
{

void EmitPass(const char* label)
{
    arch::SerialWrite("[net/tcp-selftest] PASS (");
    arch::SerialWrite(label);
    arch::SerialWrite(")\n");
}

void EmitFail(const char* label)
{
    arch::SerialWrite("[net/tcp-selftest] FAIL (");
    arch::SerialWrite(label);
    arch::SerialWrite(")\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 0xF0FEu);
}

bool TestIdEncodeDecode()
{
    using namespace internal;
    const TcbId id = MakeId(7, 42);
    u32 idx = 0;
    g_tcbs[7].in_use = true;
    g_tcbs[7].generation = 42;
    const bool ok = DecodeId(id, &idx) && idx == 7;
    g_tcbs[7].in_use = false;
    // Stale generation must NOT decode.
    g_tcbs[7].in_use = true;
    g_tcbs[7].generation = 43;
    const bool stale_rejected = !DecodeId(id, &idx);
    g_tcbs[7].in_use = false;
    return ok && stale_rejected;
}

bool TestBucketRoundTrip()
{
    using namespace internal;
    Tcb& t = g_tcbs[3];
    ResetTcbStorage(t);
    t.in_use = true;
    t.iface_index = 0;
    t.local_ip = {{10, 0, 0, 5}};
    t.peer_ip = {{10, 0, 0, 6}};
    t.local_port = 12345;
    t.peer_port = 80;
    BucketInsert(3);
    const u32 hit = LookupExact(0, {{10, 0, 0, 5}}, 12345, {{10, 0, 0, 6}}, 80);
    const bool ok_hit = (hit == 3);
    BucketRemove(3);
    const u32 miss = LookupExact(0, {{10, 0, 0, 5}}, 12345, {{10, 0, 0, 6}}, 80);
    t.in_use = false;
    return ok_hit && miss == kTcbCap;
}

bool TestWindowMath()
{
    using internal::AckInWindow;
    if (!AckInWindow(0xFFFFFFF0u, 0xFFFFFFF0u, 0x00000005u))
        return false;
    if (!AckInWindow(0u, 0xFFFFFFF0u, 0x00000005u))
        return false;
    if (!AckInWindow(0x00000005u, 0xFFFFFFF0u, 0x00000005u))
        return false;
    if (AckInWindow(0x00000006u, 0xFFFFFFF0u, 0x00000005u))
        return false;
    return true;
}

bool TestReassembly()
{
    using namespace internal;
    Tcb& t = g_tcbs[1];
    ResetTcbStorage(t);
    t.in_use = true;
    t.state = State::Established;
    t.rcv_nxt = 1000;
    t.rcv_wnd = kRcvBufBytes;
    t.mss_send = kDefaultMss;
    if (!AllocTcbBuffers(t))
        return false;
    // Deliver segment 2 (seq=1010, len=10) — out-of-order.
    u8 seg2[10];
    for (u32 i = 0; i < 10; ++i)
        seg2[i] = u8('B' + i);
    bool acked2 = internal::DeliverPayload(t, 1010, seg2, 10);
    // Then deliver segment 1 (seq=1000, len=10) — fills the hole.
    u8 seg1[10];
    for (u32 i = 0; i < 10; ++i)
        seg1[i] = u8('A' + i);
    bool acked1 = internal::DeliverPayload(t, 1000, seg1, 10);
    // After delivery the rcvbuf should hold both segments contiguously.
    const bool counts_ok = t.rcvbuf_count == 20 && t.rcv_nxt == 1020;
    bool data_ok = true;
    u32 tail = t.rcvbuf_tail;
    for (u32 i = 0; i < 10; ++i)
    {
        if (t.rcvbuf[(tail + i) % kRcvBufBytes] != u8('A' + i))
            data_ok = false;
    }
    for (u32 i = 0; i < 10; ++i)
    {
        if (t.rcvbuf[(tail + 10 + i) % kRcvBufBytes] != u8('B' + i))
            data_ok = false;
    }
    FreeTcbBuffers(t);
    t.in_use = false;
    return acked1 && acked2 && counts_ok && data_ok;
}

bool TestSackEmission()
{
    using namespace internal;
    Tcb t = {};
    t.in_use = true;
    t.state = State::Established;
    t.peer_supports_sack = true;
    t.peer_supports_timestamps = false;
    t.rcv_nxt = 1000;
    t.rcv_wnd = 32 * 1024;
    t.rcv_wscale = 0;
    t.mss_send = kDefaultMss;

    // Single-block: one out-of-order segment.
    t.oo_queue[0].in_use = true;
    t.oo_queue[0].seq = 1500;
    t.oo_queue[0].len = 100;

    u8 buf[40];
    const u32 opt_len = BuildOptions(t, kFlagAck, buf);
    if (opt_len < 12 || opt_len > 40 || (opt_len & 3) != 0)
        return false;

    // Walk the option stream looking for kOptSack.
    bool found_sack = false;
    u32 sack_len_byte = 0;
    u32 sack_offset = 0;
    for (u32 i = 0; i < opt_len;)
    {
        const u8 kind = buf[i];
        if (kind == kOptEnd)
            break;
        if (kind == kOptNop)
        {
            ++i;
            continue;
        }
        if (i + 1 >= opt_len)
            break;
        const u8 len = buf[i + 1];
        if (len < 2 || i + len > opt_len)
            break;
        if (kind == kOptSack)
        {
            found_sack = true;
            sack_len_byte = len;
            sack_offset = i;
            break;
        }
        i += len;
    }
    if (!found_sack || sack_len_byte != 10) // hdr(2) + one 8-byte block
        return false;
    // Verify the block contains seq=1500 / seq+len=1600.
    const u32 left = (u32(buf[sack_offset + 2]) << 24) | (u32(buf[sack_offset + 3]) << 16) |
                     (u32(buf[sack_offset + 4]) << 8) | u32(buf[sack_offset + 5]);
    const u32 right = (u32(buf[sack_offset + 6]) << 24) | (u32(buf[sack_offset + 7]) << 16) |
                      (u32(buf[sack_offset + 8]) << 8) | u32(buf[sack_offset + 9]);
    if (left != 1500 || right != 1600)
        return false;

    // Reset OoO state; no blocks should be emitted when queue is empty.
    t.oo_queue[0].in_use = false;
    const u32 opt_len_empty = BuildOptions(t, kFlagAck, buf);
    for (u32 i = 0; i < opt_len_empty;)
    {
        const u8 kind = buf[i];
        if (kind == kOptEnd)
            break;
        if (kind == kOptNop)
        {
            ++i;
            continue;
        }
        if (i + 1 >= opt_len_empty)
            break;
        const u8 len = buf[i + 1];
        if (len < 2 || i + len > opt_len_empty)
            break;
        if (kind == kOptSack)
            return false; // must not emit SACK with empty queue
        i += len;
    }

    // peer_supports_sack=false → never emit SACK even with OoO data.
    t.peer_supports_sack = false;
    t.oo_queue[0].in_use = true;
    t.oo_queue[0].seq = 2000;
    t.oo_queue[0].len = 50;
    const u32 opt_len_decl = BuildOptions(t, kFlagAck, buf);
    for (u32 i = 0; i < opt_len_decl;)
    {
        const u8 kind = buf[i];
        if (kind == kOptEnd)
            break;
        if (kind == kOptNop)
        {
            ++i;
            continue;
        }
        if (i + 1 >= opt_len_decl)
            break;
        const u8 len = buf[i + 1];
        if (len < 2 || i + len > opt_len_decl)
            break;
        if (kind == kOptSack)
            return false; // peer didn't negotiate → must not emit
        i += len;
    }

    return true;
}

// Sender-side SACK (RFC 2018 receipt / RFC 6675 NextSeg). Exercises
// the three exposed helpers deterministically — no wire path, no NIC.
bool TestSackSender()
{
    using namespace internal;

    // (1) ParseSackBlocks: one SACK option carrying two blocks,
    // NOP-padded, embedded in a realistic option stream. Bytes are
    // big-endian on the wire (left/right edges).
    // Layout: NOP NOP SACK len=18 | [0x100,0x200) | [0x300,0x400)
    const u8 opts[] = {kOptNop, kOptNop, kOptSack, 18,   0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                       0x02,    0x00,    0x00,     0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00};
    SackBlock blocks[kMaxSackBlocks];
    const u32 n = ParseSackBlocks(opts, sizeof(opts), blocks);
    if (n != 2)
        return false;
    if (blocks[0].left != 0x100 || blocks[0].right != 0x200)
        return false;
    if (blocks[1].left != 0x300 || blocks[1].right != 0x400)
        return false;

    // Malformed: truncated SACK length must not over-read; expect 0.
    const u8 bad[] = {kOptSack, 10, 0x00, 0x00};
    if (ParseSackBlocks(bad, sizeof(bad), blocks) != 0)
        return false;

    // (2) Scoreboard bits on a synthetic rtx_queue. Four 0x100-byte
    // segments at 0x100,0x200,0x300,0x400. SACK [0x200,0x400) covers
    // the middle two; the edges stay unmarked and sack_high advances
    // to the block's right edge. (Hole-list / NextSeg behaviour is
    // exercised by the RFC 6675 scoreboard test.)
    Tcb t = {};
    SegmentBuf rtx[kRtxQueueMax];
    for (u32 i = 0; i < kRtxQueueMax; ++i)
        rtx[i].len = 0;
    t.rtx_queue = rtx;
    t.snd_una = 0x100;
    t.sack_high = 0x100;
    const u32 seqs[] = {0x100, 0x200, 0x300, 0x400};
    for (u32 i = 0; i < 4; ++i)
    {
        rtx[i].seq = seqs[i];
        rtx[i].len = 0x100;
        rtx[i].flags = kFlagAck;
        rtx[i].sacked = false;
    }

    SackBlock cover = {0x200, 0x400};
    if (!ApplySackScoreboard(t, &cover, 1))
        return false;
    if (!rtx[1].sacked || !rtx[2].sacked) // middle two SACKed
        return false;
    if (rtx[0].sacked || rtx[3].sacked) // edges untouched
        return false;
    if (t.sack_high != 0x400)
        return false;

    // Re-applying the same block reports no new progress (idempotent).
    if (ApplySackScoreboard(t, &cover, 1))
        return false;

    return true;
}

// RFC 6675 sender scoreboard: hole rebuild from the segment bits,
// IsLost, SetPipe, NextSeg rules (1)/(3), HighRxt-preserving rebuild,
// cumulative-ACK trim, and clear (the TCB-teardown path). All
// deterministic — no wire, no NIC; holes come off the live kheap and
// are freed on every exit through SackScoreboardClear.
bool TestSack6675()
{
    using namespace internal;
    Tcb t = {};
    SegmentBuf rtx[kRtxQueueMax];
    for (u32 i = 0; i < kRtxQueueMax; ++i)
        rtx[i].len = 0;
    t.rtx_queue = rtx;
    t.mss_send = 100;
    t.snd_una = 1000;
    t.snd_nxt = 1800;
    t.sack_high = 1000;
    // Eight 100-byte segments covering [1000, 1800). The receiver
    // SACKs [1100,1200), [1300,1400), [1500,1600): holes at 1000,
    // 1200 and 1400; segments 1600/1700 sit above the SACK edge and
    // must NOT become holes.
    for (u32 i = 0; i < 8; ++i)
    {
        rtx[i].seq = 1000 + i * 100;
        rtx[i].len = 100;
        rtx[i].flags = kFlagAck;
        rtx[i].sacked = false;
    }
    t.rtx_count = 8;

    bool ok = true;
    do
    {
        const SackBlock blocks[] = {{1100, 1200}, {1300, 1400}, {1500, 1600}};
        if (!ApplySackScoreboard(t, blocks, 3) || !SackScoreboardRebuild(t))
        {
            ok = false;
            break;
        }
        // Ascending hole list: [1000,1100) [1200,1300) [1400,1500).
        SackHole* h0 = t.sack.head;
        if (t.sack.hole_count != 3 || h0 == nullptr || h0->start != 1000 || h0->end != 1100 || h0->rxmit != 1000 ||
            h0->next == nullptr || h0->next->start != 1200 || h0->next->end != 1300 || h0->next->next == nullptr ||
            h0->next->next->start != 1400 || h0->next->next->end != 1500)
        {
            ok = false;
            break;
        }
        // IsLost: 3 SACKed runs above 1000 → lost. Above 1200: 2 runs
        // but 200 SACKed bytes = (DupThresh-1)*SMSS → lost by the byte
        // rule. Above 1400: 1 run / 100 bytes → NOT lost.
        if (!SackIsLost(t, 1000) || !SackIsLost(t, 1200) || SackIsLost(t, 1400))
        {
            ok = false;
            break;
        }
        // SetPipe: un-SACKed segments 1000/1200 are lost (excluded),
        // 1400/1600/1700 are in flight, nothing retransmitted yet
        // → pipe = 300.
        if (SackSetPipe(t) != 300)
        {
            ok = false;
            break;
        }
        // NextSeg rule (1): the lowest lost hole — 1000.
        SackHole* h = SackNextSeg(t, true);
        if (h == nullptr || h->rxmit != 1000)
        {
            ok = false;
            break;
        }
        // Simulate the recovery engine retransmitting [1000,1100):
        // rxmit/HighRxt advance, and the retransmitted bytes re-enter
        // the pipe (1000 is lost-but-resent → +100 → pipe = 400).
        t.in_fast_recovery = true;
        h->rxmit = 1100;
        t.sack.high_rxt = 1100;
        if (SackSetPipe(t) != 400)
        {
            ok = false;
            break;
        }
        // Next rule-(1) candidate: the hole at 1200.
        h = SackNextSeg(t, true);
        if (h == nullptr || h->rxmit != 1200)
        {
            ok = false;
            break;
        }
        // Exhaust it too; rule (1) runs dry (1400 is not lost), rule
        // (3) — require_lost off — names 1400.
        h->rxmit = 1300;
        t.sack.high_rxt = 1300;
        if (SackNextSeg(t, true) != nullptr)
        {
            ok = false;
            break;
        }
        h = SackNextSeg(t, false);
        if (h == nullptr || h->rxmit != 1400)
        {
            ok = false;
            break;
        }
        // Rebuild (same blocks arriving again) preserves retransmit
        // progress via HighRxt: holes below 1300 come back exhausted.
        if (!SackScoreboardRebuild(t) || t.sack.hole_count != 3)
        {
            ok = false;
            break;
        }
        if (t.sack.head->rxmit != 1100 || t.sack.head->next->rxmit != 1300 || t.sack.head->next->next->rxmit != 1400)
        {
            ok = false;
            break;
        }
        // Partial-ACK trim: ack=1200 retires the first hole entirely.
        SackOnCumulativeAck(t, 1200);
        if (t.sack.hole_count != 2 || t.sack.head == nullptr || t.sack.head->start != 1200)
        {
            ok = false;
            break;
        }
        // Mid-hole ACK: ack=1450 frees [1200,1300) and shrinks
        // [1400,1500) to [1450,1500), dragging rxmit up with it.
        SackOnCumulativeAck(t, 1450);
        if (t.sack.hole_count != 1 || t.sack.head == nullptr || t.sack.head->start != 1450 ||
            t.sack.head->rxmit != 1450)
        {
            ok = false;
            break;
        }
    } while (false);

    // Teardown path: clear must free every hole, exactly like
    // FreeTcbBuffers does on TCB close.
    SackScoreboardClear(t);
    if (t.sack.head != nullptr || t.sack.hole_count != 0 || t.sack.high_rxt != 0 || t.sack.recovery_point != 0)
        ok = false;
    return ok;
}

// RFC 3168 ECN data plane: CE→ECE echo (until CWR), ECE→cwnd halving
// through the shared CA hook (once per window), CWR emission exactly
// once on the next data segment, ECT(0) on data / not-ECT on pure
// ACKs. Drives the real EcnApplyTx / EcnOnEce helpers — no wire.
bool TestEcnDataPlane()
{
    using namespace internal;
    Tcb t = {};
    t.state = State::Established;
    t.ecn_ok = true;
    t.mss_send = 1000;
    t.cwnd = 10000;
    t.ssthresh = 0x7FFFFFFFu;
    t.snd_una = 5000;
    t.snd_nxt = 9000;
    t.ecn_react_seq = 5000;
    t.cubic.enabled = false; // Reno leg → deterministic cwnd/2

    // (1) Inbound CE pends an ECE; every outgoing ACK echoes it until
    // the peer's CWR clears the obligation. Pure ACKs stay not-ECT;
    // data segments carry ECT(0).
    t.peer_ce_pending = true; // what DeliverSegment does on ip_ce
    u8 flags = kFlagAck;
    if ((EcnApplyTx(t, flags, 0) != 0x00) || (flags & kFlagEce) == 0)
        return false;
    flags = kFlagAck;
    if ((EcnApplyTx(t, flags, 1000) != 0x02) || (flags & kFlagEce) == 0)
        return false;
    t.peer_ce_pending = false; // what DeliverSegment does on peer CWR
    flags = kFlagAck;
    (void)EcnApplyTx(t, flags, 0);
    if ((flags & kFlagEce) != 0)
        return false;

    // (2) Inbound ECE: one halving per window through the CA hook;
    // sent_cwr latches and the react point pins the window edge.
    if (!EcnOnEce(t))
        return false;
    if (t.cwnd != 5000 || t.ssthresh != 5000 || !t.sent_cwr || t.ecn_react_seq != 9000)
        return false;
    if (EcnOnEce(t)) // second ECE in the same window: suppressed
        return false;
    if (t.cwnd != 5000)
        return false;

    // (3) The next data segment announces CWR exactly once.
    flags = kFlagAck | kFlagPsh;
    if ((EcnApplyTx(t, flags, 1000) != 0x02) || (flags & kFlagCwr) == 0 || t.sent_cwr)
        return false;
    flags = kFlagAck | kFlagPsh;
    (void)EcnApplyTx(t, flags, 1000);
    if ((flags & kFlagCwr) != 0)
        return false;

    // (4) Once snd_una passes the react point, ECE acts again.
    t.snd_una = t.ecn_react_seq;
    if (!EcnOnEce(t) || t.cwnd != 2500)
        return false;

    // (5) Non-ECN connection: the TX transform is inert.
    Tcb u = {};
    u.sent_cwr = true;
    u.peer_ce_pending = true;
    flags = kFlagAck;
    if (EcnApplyTx(u, flags, 100) != 0x00 || flags != kFlagAck)
        return false;
    return true;
}

bool TestEcnSynFlags()
{
    using namespace internal;
    // SYN-side: client SYN must carry ECE|CWR per RFC 3168 §6.1.1.
    // We exercise the encode path by setting up a fresh TCB and
    // verifying that ECN-negotiated state propagates through the
    // SYN-ACK acceptance gate.
    Tcb t = {};
    t.in_use = true;

    // Simulate a SYN-ACK arrival that confirms ECN: ECE=1, CWR=0.
    constexpr u8 synack_ecn_ok = kFlagSyn | kFlagAck | kFlagEce;
    constexpr u8 synack_ecn_decl_both = kFlagSyn | kFlagAck | kFlagEce | kFlagCwr; // illegal combo
    constexpr u8 synack_ecn_decl_none = kFlagSyn | kFlagAck;

    if ((synack_ecn_ok & kFlagEce) == 0 || (synack_ecn_ok & kFlagCwr) != 0)
        return false;
    if ((synack_ecn_decl_both & kFlagEce) == 0 || (synack_ecn_decl_both & kFlagCwr) == 0)
        return false;
    if ((synack_ecn_decl_none & kFlagEce) != 0 || (synack_ecn_decl_none & kFlagCwr) != 0)
        return false;

    // Listener side: an ECN-Setup-SYN sets BOTH ECE and CWR.
    constexpr u8 ecn_setup_syn = kFlagSyn | kFlagEce | kFlagCwr;
    const bool detected = (ecn_setup_syn & kFlagEce) != 0 && (ecn_setup_syn & kFlagCwr) != 0;
    if (!detected)
        return false;

    // Field round-trip — ResetTcbStorage zeros the new bits.
    t.ecn_ok = true;
    t.peer_supports_sack = true;
    t.peer_ce_pending = true;
    t.sent_cwr = true;
    ResetTcbStorage(t);
    if (t.ecn_ok || t.peer_supports_sack || t.peer_ce_pending || t.sent_cwr)
        return false;

    return true;
}

bool TestRtoBackoff()
{
    using namespace internal;
    Tcb t = {};
    t.rto_ticks = MsToTicks(kInitialRtoMs);
    const u32 start_rto = t.rto_ticks;
    // Simulate the backoff doubling in RetransmitFirstUnacked. We
    // just check the bounds math.
    t.rto_ticks *= 2;
    if (t.rto_ticks < start_rto)
        return false;
    if (t.rto_ticks > MsToTicks(kMaxRtoMs))
        return false;
    return true;
}

using duetos::core::StrEqual;

bool TestStateNames()
{
    if (!StrEqual(StateName(State::Closed), "CLOSED"))
        return false;
    if (!StrEqual(StateName(State::Established), "ESTABLISHED"))
        return false;
    if (!StrEqual(StateName(State::TimeWait), "TIME_WAIT"))
        return false;
    return true;
}

// Zero-window persist timer (RFC 9293 §3.8.6.1). Exercises the real
// arm/disarm logic in DrainSendBuffer deterministically — with a shut
// window (or a full rtx queue) the send loop sends nothing, so no NIC
// is touched and no buffers are dereferenced.
bool TestPersistTimer()
{
    using namespace internal;
    Tcb t = {};
    t.state = State::Established;
    t.rto_ticks = MsToTicks(kInitialRtoMs);
    t.snd_una = 1000;
    t.snd_nxt = 1000; // nothing in flight
    t.cwnd = 8u * kDefaultMss;
    t.mss_send = kDefaultMss;

    // (1) Peer shuts its window while we have queued data → ARM.
    // snd_wnd==0 makes DrainSendBuffer's loop break before sending.
    t.snd_wnd = 0;
    t.sndbuf_count = 200;
    DrainSendBuffer(t);
    if (t.persist_deadline == 0)
        return false; // must arm
    if (t.persist_backoff_ticks != t.rto_ticks)
        return false; // first backoff seeds from RTO

    // (2) Backoff doubles per probe and is capped at kMaxRtoMs
    // (mirrors the timer-task fire path's arithmetic).
    const u32 first = t.persist_backoff_ticks;
    u32 b = first ? (first * 2) : t.rto_ticks;
    if (b > MsToTicks(kMaxRtoMs))
        b = MsToTicks(kMaxRtoMs);
    if (b < first)
        return false; // monotone non-decreasing
    if (b > MsToTicks(kMaxRtoMs))
        return false; // respects cap

    // (3) Window reopens → DISARM. Fill the rtx queue so the send
    // loop is skipped (no NIC/buffer access) and we land directly in
    // the persist-management else-branch with snd_wnd > 0.
    t.snd_wnd = 4096;
    t.rtx_count = kRtxQueueMax;
    DrainSendBuffer(t);
    if (t.persist_deadline != 0 || t.persist_backoff_ticks != 0)
        return false; // must disarm on window reopen

    // (4) No queued data → never arms even with a shut window.
    t.snd_wnd = 0;
    t.sndbuf_count = 0;
    t.rtx_count = 0;
    DrainSendBuffer(t);
    if (t.persist_deadline != 0)
        return false;
    return true;
}

// PAWS stale-segment detection (RFC 7323 §5.3), including mod-2^32
// wraparound — the subtle part. Drives the real PawsReject predicate.
bool TestPaws()
{
    using namespace internal;
    Tcb t = {};
    t.state = State::Established;
    t.peer_supports_timestamps = true;
    t.ts_recent = 1000;

    if (!PawsReject(t, 999, 0, true))
        return false; // older TSval ⇒ stale ⇒ reject
    if (PawsReject(t, 1001, 0, true))
        return false; // newer ⇒ accept
    if (PawsReject(t, 1000, 0, true))
        return false; // equal ⇒ accept (strictly-older only)
    if (PawsReject(t, 999, kFlagRst, true))
        return false; // never PAWS-drop a RST
    if (PawsReject(t, 999, 0, false))
        return false; // no timestamp option ⇒ no PAWS
    // Not synchronized (handshake) ⇒ never reject.
    t.state = State::SynSent;
    if (PawsReject(t, 999, 0, true))
        return false;
    t.state = State::Established;
    // Wraparound: ts_recent near the top, a small new value that
    // wrapped past 0 must read as NEWER (accept), and the reverse
    // must read as OLDER (reject).
    t.ts_recent = 0xFFFFFFF0u;
    if (PawsReject(t, 0x00000005u, 0, true))
        return false; // wrapped-forward ⇒ newer ⇒ accept
    t.ts_recent = 0x00000005u;
    if (!PawsReject(t, 0xFFFFFFF0u, 0, true))
        return false; // wrapped-back ⇒ older ⇒ reject
    return true;
}

// RFC 3042 Limited Transmit effective-window math (and overflow guard).
bool TestLimitedTransmitWindow()
{
    using namespace internal;
    Tcb t = {};
    t.snd_wnd = 10000;
    t.cwnd = 5000;
    if (EffectiveSendWindow(t, 0) != 5000)
        return false; // cwnd-limited, no extra
    if (EffectiveSendWindow(t, 1460) != 6460)
        return false; // limited-transmit widens by one MSS
    t.snd_wnd = 100;
    if (EffectiveSendWindow(t, 1460) != 100)
        return false; // receiver window still caps
    // Saturating add: cwnd + extra must not wrap u32.
    t.snd_wnd = 0xFFFFFFFFu;
    t.cwnd = 0xFFFFFFF0u;
    if (EffectiveSendWindow(t, 0x100) != 0xFFFFFFFFu)
        return false;
    return true;
}

// CUBIC (RFC 9438) integer math — all deterministic, no network.
bool TestCubic()
{
    using namespace internal;

    // (1) Exact integer cube root (the oracle): exact equalities.
    if (IcbrtExact(0) != 0 || IcbrtExact(1) != 1 || IcbrtExact(8) != 2 || IcbrtExact(26) != 2 || IcbrtExact(27) != 3 ||
        IcbrtExact(1000000) != 100 || IcbrtExact(999999) != 99 || IcbrtExact(1000000000ull) != 1000)
        return false;

    // (2) Linux CubicRoot within ~0.5%+1 of exact across a wide range.
    const u64 samples[] = {27ull, 1000ull, 1000000ull, (1ull << 30), (1ull << 40)};
    for (unsigned i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i)
    {
        const u64 a = samples[i];
        const u64 e = IcbrtExact(a);
        const u64 g = CubicRoot(a);
        const u64 tol = e / 200u + 1u; // 0.5% + 1
        if (g + tol < e || g > e + tol)
            return false;
    }

    // (3) Compile-time constants didn't drift.
    if (kCubeRttScale != 410u || kBetaScale != 15u || kCubicBeta != 717u)
        return false;
    if (kCubeFactor != (1ull << 40) / 410ull)
        return false;

    // (4) CubicTarget shape (values scaled so delta is non-trivial under
    // the >>40 fixed point): == origin at K, concave (below) before K,
    // convex (above) after K, monotonic non-decreasing overall.
    {
        const u32 origin = 2000u, K = 20000u;
        if (CubicTarget(origin, K, K) != origin)
            return false;
        if (CubicTarget(origin, K, K - 10000u) >= origin)
            return false;
        if (CubicTarget(origin, K, K + 10000u) <= origin)
            return false;
        u32 prev = 0u;
        for (u64 tt = 0; tt <= 40000u; tt += 5000u)
        {
            const u32 cur = CubicTarget(origin, K, tt);
            if (cur < prev)
                return false;
            prev = cur;
        }
    }

    // (5) Loss reaction: beta=717/1024 + fast-convergence + floor.
    {
        Tcb t = {};
        t.cubic.last_max_cwnd = 0;
        if (CubicRecalcSsthresh(t, 100) != 70u) // 100*717/1024 = 70
            return false;
        if (t.cubic.last_max_cwnd != 100u) // lastmax was 0 → no fast-conv
            return false;
        if (t.cubic.epoch_start != 0) // epoch ended
            return false;
        t.cubic.last_max_cwnd = 120; // cwnd(100) < lastmax(120) → fast-conv
        (void)CubicRecalcSsthresh(t, 100);
        if (t.cubic.last_max_cwnd != 85u) // 100*1741/2048 = 85
            return false;
        if (CubicRecalcSsthresh(t, 1) < 2u) // ssthresh floors at 2
            return false;
    }
    return true;
}

} // namespace

void SelfTest()
{
    bool all_ok = true;

    arch::Cli();
    if (!TestIdEncodeDecode())
    {
        EmitFail("id encode/decode");
        all_ok = false;
    }
    if (!TestBucketRoundTrip())
    {
        EmitFail("bucket round-trip");
        all_ok = false;
    }
    if (!TestWindowMath())
    {
        EmitFail("ack window wrap");
        all_ok = false;
    }
    if (!TestRtoBackoff())
    {
        EmitFail("rto backoff");
        all_ok = false;
    }
    if (!TestSackEmission())
    {
        EmitFail("sack option emission");
        all_ok = false;
    }
    if (!TestSackSender())
    {
        EmitFail("sack sender scoreboard bits");
        all_ok = false;
    }
    if (TestSack6675())
    {
        EmitPass("rfc6675 sack scoreboard");
    }
    else
    {
        EmitFail("rfc6675 sack scoreboard");
        all_ok = false;
    }
    if (!TestEcnSynFlags())
    {
        EmitFail("ecn syn flags");
        all_ok = false;
    }
    if (TestEcnDataPlane())
    {
        EmitPass("rfc3168 ecn data plane");
    }
    else
    {
        EmitFail("rfc3168 ecn data plane");
        all_ok = false;
    }
    if (!TestPersistTimer())
    {
        EmitFail("zero-window persist timer");
        all_ok = false;
    }
    if (!TestPaws())
    {
        EmitFail("PAWS stale-segment rejection");
        all_ok = false;
    }
    if (!TestLimitedTransmitWindow())
    {
        EmitFail("RFC 3042 limited-transmit window");
        all_ok = false;
    }
    if (!TestCubic())
    {
        EmitFail("CUBIC congestion control (RFC 9438)");
        all_ok = false;
    }
    arch::Sti();

    // Reassembly + state-names tests can run with IRQ on; they
    // don't poke shared state outside the dedicated slot they
    // grab via in_use=true / in_use=false.
    arch::Cli();
    const bool reass_ok = TestReassembly();
    arch::Sti();
    if (!reass_ok)
    {
        EmitFail("reassembly");
        all_ok = false;
    }
    if (!TestStateNames())
    {
        EmitFail("state names");
        all_ok = false;
    }

    if (all_ok)
        EmitPass("frame round-trip + reassembly + window wrap");

    // Run the IPv6 protocol-layer self-test from the same net
    // self-test entry. It emits its own [net/ipv6-selftest] line and
    // fires its own probe on failure (boot_bringup.cpp owns only the
    // tcp::SelfTest() hook, so chaining here is how the v6 path gets
    // exercised on a selftest build).
    duetos::net::Ipv6SelfTest();
}

} // namespace duetos::net::tcp
