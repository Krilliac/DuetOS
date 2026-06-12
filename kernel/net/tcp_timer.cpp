/*
 * DuetOS — TCP v1 periodic timer.
 *
 * Spawned as a kernel task by tcp::Init. Sleeps kTimerTickMs ms,
 * grabs the global net-stack lock, walks every TCB, and fires:
 *   - retransmits when rtx_deadline expired
 *   - the delayed-ACK timer
 *   - TIME_WAIT expiry → DropTcb
 *   - keepalive probes
 *
 * Stays small — the heavy state-machine logic is in tcp_segment.cpp.
 */

#include "net/tcp.h"
#include "net/tcp_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "time/tick.h"
#include "util/random.h"

namespace duetos::net::tcp
{

namespace internal
{

void RetransmitFirstUnacked(Tcb& t)
{
    SegmentBuf* sb = nullptr;
    u32 best = 0xFFFFFFFFu;
    for (u32 i = 0; i < kRtxQueueMax; ++i)
    {
        if (t.rtx_queue[i].len == 0)
            continue;
        const u32 off = t.rtx_queue[i].seq - t.snd_una;
        if (off < best)
        {
            best = off;
            sb = &t.rtx_queue[i];
        }
    }
    if (sb == nullptr)
        return;
    // RFC 2018 §8 / RFC 6675 §5.1: the receiver may have reneged —
    // flush the SACK scoreboard (holes + per-segment bits) so the
    // post-RTO recovery starts from wire truth only.
    SackOnRto(t);
    // RFC-6298 §5: collapse cwnd to one MSS, multiply RTO by two,
    // re-arm the timer. Karn's algorithm: don't sample RTT off this
    // retransmit.
    if (t.cubic.enabled)
    {
        // CUBIC RTO reaction: record W_max (fast-convergence) and end
        // the epoch via CubicRecalcSsthresh; cwnd still collapses to 1.
        const u32 mss = t.mss_send ? t.mss_send : 1u;
        const u32 ssh_pkts = CubicRecalcSsthresh(t, t.cwnd / mss ? t.cwnd / mss : 1u);
        t.ssthresh = ssh_pkts * mss;
        if (t.ssthresh < 2u * t.mss_send)
            t.ssthresh = 2u * t.mss_send;
    }
    else
    {
        t.ssthresh = (t.snd_nxt - t.snd_una) / 2;
        if (t.ssthresh < 2u * t.mss_send)
            t.ssthresh = 2u * t.mss_send;
    }
    t.cwnd = t.mss_send;
    t.in_fast_recovery = false;
    t.rto_ticks = t.rto_ticks * 2;
    if (t.rto_ticks > MsToTicks(kMaxRtoMs))
        t.rto_ticks = MsToTicks(kMaxRtoMs);
    SendSegment(t, sb->flags, sb->seq, t.rcv_nxt, sb->data, sb->len);
    sb->ticks_sent = NowTicks();
    ++g_stats.retrans;
    ++t.retries;
}

} // namespace internal

void TimerTick()
{
    using namespace internal;
    arch::Cli();
    const u64 now = NowTicks();
    for (u32 i = 0; i < kTcbCap; ++i)
    {
        Tcb& t = g_tcbs[i];
        if (!t.in_use)
            continue;
        if (t.is_listener)
            continue;

        // TIME_WAIT expiry.
        if (t.state == State::TimeWait && t.timewait_deadline != 0 && now >= t.timewait_deadline)
        {
            DropTcb(i);
            continue;
        }

        // Retransmit.
        if (t.rtx_count > 0 && t.rtx_deadline != 0 && now >= t.rtx_deadline)
        {
            if (t.retries >= kMaxRetries)
            {
                ++g_stats.timeouts;
                // Give up: drop with RST so the peer notices.
                SendSegment(t, kFlagRst | kFlagAck, t.snd_nxt, t.rcv_nxt, nullptr, 0);
                ++g_stats.rst_tx;
                DropTcb(i);
                continue;
            }
            RetransmitFirstUnacked(t);
            t.rtx_deadline = now + t.rto_ticks;
        }

        // Retransmit a SYN / SYN+ACK / FIN that's stuck.
        if ((t.state == State::SynSent || t.state == State::SynRcvd) && t.rtx_deadline != 0 && now >= t.rtx_deadline)
        {
            if (t.retries >= kMaxRetries)
            {
                ++g_stats.timeouts;
                DropTcb(i);
                continue;
            }
            ++t.retries;
            t.rto_ticks = t.rto_ticks * 2;
            if (t.rto_ticks > MsToTicks(kMaxRtoMs))
                t.rto_ticks = MsToTicks(kMaxRtoMs);
            const u8 flags = (t.state == State::SynSent) ? kFlagSyn : u8(kFlagSyn | kFlagAck);
            const u32 seq = t.iss;
            const u32 ack = (t.state == State::SynRcvd) ? t.rcv_nxt : 0u;
            SendSegment(t, flags, seq, ack, nullptr, 0);
            ++g_stats.retrans;
            t.rtx_deadline = now + t.rto_ticks;
        }

        // FinWait1 / LastAck retransmit FIN if not acked.
        if ((t.state == State::FinWait1 || t.state == State::LastAck) && t.rtx_count == 0 && t.rtx_deadline != 0 &&
            now >= t.rtx_deadline)
        {
            if (t.retries >= kMaxRetries)
            {
                ++g_stats.timeouts;
                DropTcb(i);
                continue;
            }
            ++t.retries;
            t.rto_ticks = t.rto_ticks * 2;
            if (t.rto_ticks > MsToTicks(kMaxRtoMs))
                t.rto_ticks = MsToTicks(kMaxRtoMs);
            SendSegment(t, kFlagAck | kFlagFin, t.snd_nxt - 1, t.rcv_nxt, nullptr, 0);
            ++g_stats.retrans;
            t.rtx_deadline = now + t.rto_ticks;
        }

        // Delayed ACK timer.
        if (t.delack_pending && t.delack_deadline != 0 && now >= t.delack_deadline)
        {
            SendSegment(t, kFlagAck, t.snd_nxt, t.rcv_nxt, nullptr, 0);
            t.delack_pending = false;
            t.delack_deadline = 0;
        }

        // Keepalive.
        if (t.keepalive_on && t.state == State::Established && t.keepalive_deadline != 0 && now >= t.keepalive_deadline)
        {
            // Probe: send an empty ACK with a stale sequence number
            // (snd_una - 1). The peer's reply confirms the connection
            // is alive.
            SendSegment(t, kFlagAck, t.snd_una - 1, t.rcv_nxt, nullptr, 0);
            ++g_stats.keepalive_probes;
            t.keepalive_deadline = now + MsToTicks(60'000);
        }

        // Zero-window persist probe (RFC 9293 §3.8.6.1 / RFC 1122
        // §4.2.2.17). Armed by DrainSendBuffer when the peer shut its
        // window while we still have queued data. The probe is an ACK at
        // the stale sequence snd_una-1 (same shape as keepalive): it is
        // unacceptable to the peer, so per RFC 9293 §3.10 the peer MUST
        // reply with an ACK — which carries its CURRENT window. If that
        // window is non-zero, the inbound-ACK path's DrainSendBuffer
        // disarms this timer and resumes sending, breaking the deadlock
        // a lost window-reopening ACK would otherwise cause. Re-arm with
        // exponential backoff capped at kMaxRtoMs.
        if ((t.state == State::Established || t.state == State::CloseWait) && t.snd_wnd == 0 && t.sndbuf_count > 0 &&
            t.persist_deadline != 0 && now >= t.persist_deadline)
        {
            SendSegment(t, kFlagAck, t.snd_una - 1, t.rcv_nxt, nullptr, 0);
            ++g_stats.persist_probes;
            t.persist_backoff_ticks = t.persist_backoff_ticks ? (t.persist_backoff_ticks * 2) : t.rto_ticks;
            if (t.persist_backoff_ticks > MsToTicks(kMaxRtoMs))
                t.persist_backoff_ticks = MsToTicks(kMaxRtoMs);
            t.persist_deadline = now + t.persist_backoff_ticks;
        }
    }
    arch::Sti();
}

namespace
{

void TcpTimerEntry(void*)
{
    while (true)
    {
        sched::SchedSleepTicks(internal::MsToTicks(kTimerTickMs));
        TimerTick();
    }
}

} // namespace

namespace internal
{

void StartTimerTask()
{
    sched::SchedCreate(TcpTimerEntry, nullptr, "tcp-timer");
}

} // namespace internal

void Init()
{
    if (internal::g_initialised)
        return;
    arch::Cli();
    for (u32 i = 0; i < kTcbCap; ++i)
        internal::g_tcbs[i].in_use = false;
    for (u32 i = 0; i < kTcbBuckets; ++i)
        internal::g_buckets[i] = internal::kBucketNone;
    internal::g_stats = {};
    // ML-02 (net-0): seed the per-boot ISN secret from the CSPRNG once.
    internal::g_isn_secret = ::duetos::core::RandomU64();
    internal::g_initialised = true;
    arch::Sti();
    internal::StartTimerTask();
}

} // namespace duetos::net::tcp
