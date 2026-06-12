/*
 * DuetOS — TCP sender-side SACK loss recovery (RFC 6675).
 *
 * Owns the per-TCB hole scoreboard (layout contract in tcp_sack.h)
 * and the recovery-episode engine:
 *
 *   - SackScoreboardRebuild: derives the ascending hole list from
 *     the rtx_queue's per-segment `sacked` bits (single source of
 *     truth, marked by ApplySackScoreboard in tcp_segment.cpp).
 *   - SackIsLost / SackSetPipe / SackNextSeg: the RFC 6675 §3-§4
 *     primitives over that list.
 *   - SackEnterRecovery / SackRecoveryTransmit: the §5 algorithm —
 *     retransmit the first presumed-lost segment, then keep filling
 *     holes (and clocking out new data) while cwnd − pipe ≥ SMSS.
 *
 * Holes are segment-granular by construction: ApplySackScoreboard
 * only marks fully-covered SegmentBufs, so hole edges (and rxmit
 * advancement) always land on rtx_queue segment boundaries.
 *
 * Runs under the same arch::Cli net-stack lock as the sibling TCP
 * TUs. Reference: RFC 6675; FreeBSD sys/netinet/tcp_sack.c.
 */

#include "net/tcp.h"
#include "net/tcp_internal.h"

#include "mm/kheap.h"
#include "util/compiler.h"

namespace duetos::net::tcp
{

namespace internal
{

namespace
{

// Mod-2^32 sequence-space compares (same signed-difference idiom as
// AckInWindow / SegCoveredByBlock).
DUETOS_NO_SANITIZE_WRAP bool SeqGeq(u32 a, u32 b)
{
    return static_cast<i32>(a - b) >= 0;
}

DUETOS_NO_SANITIZE_WRAP bool SeqGt(u32 a, u32 b)
{
    return static_cast<i32>(a - b) > 0;
}

void FreeHoles(SackScoreboard& sb)
{
    SackHole* h = sb.head;
    while (h != nullptr)
    {
        SackHole* next = h->next;
        mm::KFree(h);
        h = next;
    }
    sb.head = nullptr;
    sb.hole_count = 0;
}

// Slot of the rtx_queue segment containing `seq`, or kRtxQueueMax.
DUETOS_NO_SANITIZE_WRAP u32 RtxSlotForSeq(const Tcb& t, u32 seq)
{
    for (u32 i = 0; i < kRtxQueueMax; ++i)
    {
        const SegmentBuf& sb = t.rtx_queue[i];
        if (sb.len == 0)
            continue;
        if (SeqGeq(seq, sb.seq) && SeqGt(sb.seq + sb.len, seq))
            return i;
    }
    return kRtxQueueMax;
}

// Retransmit the segment at hole->rxmit, advance rxmit + HighRxt.
// Returns false when the hole turned out stale (no live segment
// backs it any more — e.g. a cumulative ACK retired it between
// scoreboard rebuilds); the hole is marked exhausted so callers
// cannot spin on it.
DUETOS_NO_SANITIZE_WRAP bool SackRetransmitHole(Tcb& t, SackHole* hole)
{
    const u32 slot = RtxSlotForSeq(t, hole->rxmit);
    if (slot == kRtxQueueMax)
    {
        hole->rxmit = hole->end;
        return false;
    }
    SegmentBuf& sb = t.rtx_queue[slot];
    SendSegment(t, sb.flags, sb.seq, t.rcv_nxt, sb.data, sb.len);
    sb.ticks_sent = NowTicks();
    ++g_stats.retrans;
    hole->rxmit = sb.seq + sb.len;
    if (SeqGt(hole->rxmit, t.sack.high_rxt))
        t.sack.high_rxt = hole->rxmit;
    return true;
}

} // namespace

void SackScoreboardClear(Tcb& t)
{
    FreeHoles(t.sack);
    t.sack.high_rxt = 0;
    t.sack.recovery_point = 0;
}

DUETOS_NO_SANITIZE_WRAP bool SackScoreboardRebuild(Tcb& t)
{
    FreeHoles(t.sack);
    if (t.rtx_queue == nullptr)
        return false;
    // Collect un-SACKed segments lying wholly below the highest
    // SACKed edge — genuine gaps the receiver reports missing.
    u32 order[kRtxQueueMax];
    u32 n = 0;
    for (u32 i = 0; i < kRtxQueueMax; ++i)
    {
        const SegmentBuf& sb = t.rtx_queue[i];
        if (sb.len == 0 || sb.sacked)
            continue;
        if (!SeqGeq(sb.seq, t.snd_una))
            continue;
        if (!SeqGeq(t.sack_high, sb.seq + sb.len))
            continue;
        order[n++] = i;
    }
    // Insertion sort ascending by offset from snd_una (n ≤ 16).
    for (u32 i = 1; i < n; ++i)
    {
        const u32 v = order[i];
        const u32 key = t.rtx_queue[v].seq - t.snd_una;
        u32 j = i;
        while (j > 0 && (t.rtx_queue[order[j - 1]].seq - t.snd_una) > key)
        {
            order[j] = order[j - 1];
            --j;
        }
        order[j] = v;
    }
    // Coalesce contiguous segments into holes; tail-append keeps the
    // list ascending.
    SackHole* tail = nullptr;
    for (u32 i = 0; i < n; ++i)
    {
        const SegmentBuf& sb = t.rtx_queue[order[i]];
        const u32 seg_end = sb.seq + sb.len;
        if (tail != nullptr && tail->end == sb.seq)
        {
            tail->end = seg_end;
            continue;
        }
        if (t.sack.hole_count >= kSackHoleMax)
            break;
        SackHole* h = static_cast<SackHole*>(mm::KMalloc(sizeof(SackHole)));
        if (h == nullptr)
            break; // heap pressure: a shorter scoreboard only makes
                   // recovery more conservative, never wrong.
        h->start = sb.seq;
        h->end = seg_end;
        h->rxmit = sb.seq;
        h->next = nullptr;
        if (tail == nullptr)
            t.sack.head = h;
        else
            tail->next = h;
        tail = h;
        ++t.sack.hole_count;
    }
    // Restore retransmit progress: NextSeg retransmits strictly
    // ascending, so anything below HighRxt already went out this
    // recovery episode.
    if (t.in_fast_recovery)
    {
        for (SackHole* h = t.sack.head; h != nullptr; h = h->next)
        {
            if (SeqGeq(t.sack.high_rxt, h->end))
                h->rxmit = h->end;
            else if (SeqGt(t.sack.high_rxt, h->start))
                h->rxmit = t.sack.high_rxt;
        }
    }
    return t.sack.head != nullptr;
}

DUETOS_NO_SANITIZE_WRAP void SackOnCumulativeAck(Tcb& t, u32 ack)
{
    SackHole** prev = &t.sack.head;
    while (*prev != nullptr)
    {
        SackHole* h = *prev;
        if (!SeqGt(h->end, ack))
        {
            // Fully covered by the cumulative ACK — retire.
            *prev = h->next;
            mm::KFree(h);
            --t.sack.hole_count;
            continue;
        }
        if (SeqGt(ack, h->start))
        {
            h->start = ack;
            if (SeqGt(ack, h->rxmit))
                h->rxmit = ack;
        }
        prev = &h->next;
    }
    // snd_una catching up to the SACK edge retires the scoreboard's
    // upper bound too.
    if (SeqGt(ack, t.sack_high))
        t.sack_high = ack;
}

void SackOnRto(Tcb& t)
{
    SackScoreboardClear(t);
    if (t.rtx_queue != nullptr)
    {
        for (u32 i = 0; i < kRtxQueueMax; ++i)
            t.rtx_queue[i].sacked = false;
    }
    t.sack_high = t.snd_una;
}

DUETOS_NO_SANITIZE_WRAP bool SackIsLost(const Tcb& t, u32 seq)
{
    if (t.rtx_queue == nullptr)
        return false;
    u32 sacked_bytes = 0;
    u32 sacked_runs = 0;
    for (u32 i = 0; i < kRtxQueueMax; ++i)
    {
        const SegmentBuf& sb = t.rtx_queue[i];
        if (sb.len == 0 || !sb.sacked || !SeqGeq(sb.seq, seq))
            continue;
        sacked_bytes += sb.len;
        // A run starts where no other SACKed segment ends — counting
        // run-starts counts the discontiguous SACKed sequences of the
        // RFC 6675 IsLost() definition.
        bool run_start = true;
        for (u32 j = 0; j < kRtxQueueMax; ++j)
        {
            const SegmentBuf& pj = t.rtx_queue[j];
            if (j != i && pj.len != 0 && pj.sacked && pj.seq + pj.len == sb.seq)
            {
                run_start = false;
                break;
            }
        }
        if (run_start)
            ++sacked_runs;
    }
    const u32 mss = t.mss_send ? t.mss_send : 1u;
    return sacked_runs >= kSackDupThresh || sacked_bytes >= (kSackDupThresh - 1) * mss;
}

DUETOS_NO_SANITIZE_WRAP u32 SackSetPipe(const Tcb& t)
{
    if (t.rtx_queue == nullptr)
        return t.snd_nxt - t.snd_una;
    u32 pipe = 0;
    for (u32 i = 0; i < kRtxQueueMax; ++i)
    {
        const SegmentBuf& sb = t.rtx_queue[i];
        if (sb.len == 0 || sb.sacked)
            continue;
        // RFC 6675 §4 SetPipe: an un-SACKed octet counts once when it
        // is not (yet) judged lost, and once more when it has been
        // retransmitted this episode (it is below HighRxt).
        if (!SackIsLost(t, sb.seq))
            pipe += sb.len;
        if (t.in_fast_recovery && SeqGt(t.sack.high_rxt, sb.seq))
            pipe += sb.len;
    }
    return pipe;
}

SackHole* SackNextSeg(Tcb& t, bool require_lost)
{
    // List is ascending, so the first qualifying hole is the lowest
    // sequence — rule (1) when require_lost, rule (3) otherwise.
    for (SackHole* h = t.sack.head; h != nullptr; h = h->next)
    {
        if (!SeqGt(h->end, h->rxmit))
            continue; // exhausted
        if (!SeqGt(t.sack_high, h->rxmit))
            continue; // (1.b): only below the highest SACKed octet
        if (require_lost && !SackIsLost(t, h->rxmit))
            continue; // (1.c)
        return h;
    }
    return nullptr;
}

void SackRecoveryTransmit(Tcb& t)
{
    if (t.rtx_queue == nullptr)
        return;
    bool sent = false;
    // Hard iteration bound: each pass retransmits one segment, drains
    // new data, or breaks — 2× the queue depth covers the worst case.
    for (u32 iter = 0; iter < 2 * kRtxQueueMax; ++iter)
    {
        const u32 pipe = SackSetPipe(t);
        if (pipe >= t.cwnd || t.cwnd - pipe < t.mss_send)
            break; // §5 (4): stop when cwnd − pipe < 1 SMSS
        // Rule (1): the lowest hole already judged lost.
        SackHole* hole = SackNextSeg(t, true);
        if (hole == nullptr)
        {
            // Rule (2): new data, window permitting. The pipe credit
            // (in_flight − pipe) widens DrainSendBuffer's effective
            // window so its in-flight check degrades to pipe < cwnd.
            const u32 in_flight = t.snd_nxt - t.snd_una;
            if (t.sndbuf_count > 0 && in_flight >= pipe)
            {
                const u32 before = t.snd_nxt;
                DrainSendBuffer(t, in_flight - pipe);
                if (t.snd_nxt != before)
                {
                    sent = true;
                    continue;
                }
            }
            // Rule (3): a hole not yet past DupThresh — better than
            // idling the window.
            hole = SackNextSeg(t, false);
        }
        if (hole == nullptr)
            break;
        if (SackRetransmitHole(t, hole))
            sent = true;
    }
    if (sent)
        ArmRtxTimer(t);
}

void SackEnterRecovery(Tcb& t)
{
    t.sack.recovery_point = t.snd_nxt;
    t.sack.high_rxt = t.snd_una;
    // §5 step (3): unconditionally retransmit the first segment
    // presumed dropped — the lowest hole (it starts at snd_una).
    SackHole* h = SackNextSeg(t, true);
    if (h == nullptr)
        h = SackNextSeg(t, false);
    if (h != nullptr)
    {
        (void)SackRetransmitHole(t, h);
        ArmRtxTimer(t);
    }
    SackRecoveryTransmit(t);
}

} // namespace internal

} // namespace duetos::net::tcp
