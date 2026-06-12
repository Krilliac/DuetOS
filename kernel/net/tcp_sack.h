#pragma once

#include "net/tcp.h"
#include "util/types.h"

/*
 * DuetOS — TCP sender-side SACK scoreboard (RFC 6675).
 *
 * FreeBSD-style hole list (sys/netinet/tcp_sack.c studied as prior
 * art, not taken as a dependency): each SackHole is one contiguous
 * un-SACKed gap below the highest SACKed edge (`sack_high` on the
 * TCB). The list is kept ascending and is rebuilt from the
 * rtx_queue's per-segment `sacked` bits whenever an ACK delivers new
 * SACK blocks — the bits (marked by ApplySackScoreboard in
 * tcp_segment.cpp) are the single source of truth; the hole list is
 * the recovery-algorithm view derived from them, so the two cannot
 * drift.
 *
 * Memory: holes come from mm::KMalloc (~24 B each, capped at
 * kSackHoleMax) and are freed on cumulative-ACK coverage, RTO flush,
 * TIME_WAIT entry and TCB teardown — every teardown path funnels
 * through SackScoreboardClear via FreeTcbBuffers / ResetTcbStorage.
 *
 * Implemented in tcp_sack.cpp; call sites live in tcp_segment.cpp
 * (ACK path) and tcp_timer.cpp (RTO flush). All entry points assume
 * the caller holds the net-stack arch::Cli lock, like every other
 * TCP internal.
 */

namespace duetos::net::tcp::internal
{

struct Tcb;

/// RFC 6675 DupThresh — the duplicate-ACK / SACKed-run count that
/// declares a sequence number lost.
inline constexpr u32 kSackDupThresh = 3;

/// Hard cap on outstanding holes. Bounds hostile-SACK-driven heap
/// growth; there can never be more holes than un-SACKed rtx_queue
/// segments anyway.
inline constexpr u32 kSackHoleMax = kRtxQueueMax;

/// One contiguous un-SACKed gap [start, end). `rxmit` is the next
/// sequence inside the hole to retransmit in the current recovery
/// episode; rxmit == end means the hole is fully retransmitted.
struct SackHole
{
    u32 start;
    u32 end;
    u32 rxmit;
    SackHole* next;
};

/// Per-TCB scoreboard head (~24 B). `high_rxt` is RFC 6675 HighRxt —
/// the highest sequence retransmitted in the current recovery
/// episode. `recovery_point` is snd_nxt captured at recovery entry:
/// the full-vs-partial-ACK discriminator of §5.1.
struct SackScoreboard
{
    SackHole* head;
    u32 hole_count;
    u32 high_rxt;
    u32 recovery_point;
};

/// Free every hole and reset the head. Idempotent and safe on a
/// zero-initialised TCB. Called on TCB teardown, TIME_WAIT entry,
/// state reset, and (via SackOnRto) the RTO flush.
void SackScoreboardClear(Tcb& t);

/// Rebuild the ascending hole list from the rtx_queue `sacked` bits
/// + `sack_high`. Call after ApplySackScoreboard absorbed new blocks.
/// Returns true when the scoreboard holds at least one hole.
bool SackScoreboardRebuild(Tcb& t);

/// Trim away (or shrink) holes the cumulative ACK now covers.
void SackOnCumulativeAck(Tcb& t, u32 ack);

/// RFC 2018 §8 / RFC 6675 §5.1: after an RTO the receiver may have
/// reneged — every `sacked` bit and derived hole is untrustworthy.
/// Drops the scoreboard, clears the segment bits, resets sack_high.
void SackOnRto(Tcb& t);

/// RFC 6675 IsLost(): true when kSackDupThresh discontiguous SACKed
/// runs, or (kSackDupThresh - 1) * SMSS SACKed bytes, lie above `seq`.
bool SackIsLost(const Tcb& t, u32 seq);

/// RFC 6675 SetPipe(): octets judged in flight — un-SACKed bytes
/// that are not lost, plus bytes retransmitted this episode (below
/// HighRxt).
u32 SackSetPipe(const Tcb& t);

/// RFC 6675 NextSeg() rules (1) and (3): the lowest hole eligible
/// for retransmission (`require_lost` toggles the IsLost criterion
/// between the two rules). Rule (2) — new data — is the caller's
/// DrainSendBuffer leg. Returns nullptr when no hole qualifies.
SackHole* SackNextSeg(Tcb& t, bool require_lost);

/// RFC 6675 §5 recovery entry: record RecoveryPoint / HighRxt,
/// unconditionally retransmit the first presumed-lost segment
/// (step 3), then run the pipe-driven transmission loop.
void SackEnterRecovery(Tcb& t);

/// RFC 6675 §5 step (4) transmission loop: while cwnd − pipe ≥ SMSS,
/// retransmit NextSeg() holes (rule 1), then clock out new data
/// (rule 2), then not-yet-lost holes (rule 3). Owns rxmit / HighRxt
/// advancement and re-arms the retransmit timer when it sends.
void SackRecoveryTransmit(Tcb& t);

} // namespace duetos::net::tcp::internal
