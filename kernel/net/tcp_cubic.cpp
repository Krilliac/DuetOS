/*
 * DuetOS — CUBIC congestion control (RFC 9438), integer-only port of
 * Linux tcp_cubic.c. Sits beside the simplified NewReno path; the CA
 * call site (tcp_segment.cpp) takes max(cubic, reno) so CUBIC can never
 * grow slower than NewReno, and tcb.cubic.enabled is a kill switch.
 *
 * All window math is in MSS-PACKETS to reuse the reference fixed-point
 * scaling verbatim; the caller converts to/from cwnd (BYTES). No float
 * anywhere — every constant is a compile-time integer (see
 * tcp_internal.h). Time is the kernel's 100 Hz tick clock; HZ=100 is
 * substituted in the one BICTCP time-scaling divide.
 *
 * Reference: RFC 9438; Linux net/ipv4/tcp_cubic.c.
 */

#include "net/tcp.h"
#include "net/tcp_internal.h"

namespace duetos::net::tcp
{
namespace internal
{

// 1-based index of the highest set bit; 0 for a==0 (Linux fls64).
u32 Fls64(u64 a)
{
    if (a == 0)
        return 0;
    return 64u - static_cast<u32>(__builtin_clzll(a));
}

// Exact floor(cube root of a) for a in [0, 2^64). Bit-by-bit, no float,
// no division — the deterministic oracle the self-test compares against.
u64 IcbrtExact(u64 a)
{
    u64 x = 0;
    // 2642245^3 < 2^64 <= 2642246^3, so the result is at most 22 bits.
    for (int bit = 21; bit >= 0; --bit)
    {
        const u64 t = x | (1ull << bit);
        if (t <= 2642245ull && t * t * t <= a)
            x = t;
    }
    return x;
}

// Linux cubic_root: 64-entry table seed + one Newton-Raphson step.
// Avg error ~0.195% — plenty for CUBIC's K. Used on the live path.
u32 CubicRoot(u64 a)
{
    static const u8 v[] = {
        0,   54,  54,  54,  118, 118, 118, 118, 123, 129, 134, 138, 143, 147, 151, 156, 157, 161, 164, 168, 170, 173,
        176, 179, 181, 185, 187, 190, 192, 194, 197, 199, 200, 202, 204, 206, 209, 211, 213, 215, 217, 219, 221, 222,
        224, 225, 227, 229, 231, 232, 234, 236, 237, 239, 240, 242, 244, 245, 246, 248, 250, 251, 252, 254,
    };

    u32 b = Fls64(a);
    if (b < 7)
        return (static_cast<u32>(v[static_cast<u32>(a)]) + 35u) >> 6;

    b = ((b * 84u) >> 8) - 1u;
    const u32 shift = static_cast<u32>(a >> (b * 3u));
    u32 x = ((static_cast<u32>(v[shift]) + 10u) << b) >> 6;

    if (x < 2u)
        x = 2u; // guard the Newton denominator x*(x-1) against 0
    x = 2u * x + static_cast<u32>(a / (static_cast<u64>(x) * static_cast<u64>(x - 1u)));
    x = (x * 341u) >> 10;
    return x;
}

// Pure CUBIC target: W(t) = origin ± (cube_rtt_scale * |tt-K|^3) >> 40.
// `tt` is the BICTCP_HZ-scaled time since epoch start (+ delay_min).
// Concave (below origin) for tt<K, convex (above) for tt>K. Exposed so
// the self-test can pin the shape without a clock.
u32 CubicTarget(u32 origin_pkts, u32 bic_K, u64 tt)
{
    const u64 offs = (tt < bic_K) ? (static_cast<u64>(bic_K) - tt) : (tt - static_cast<u64>(bic_K));
    // cube_rtt_scale(410) * offs^3 >> (10 + 3*BICTCP_HZ). offs is bounded
    // by K (~cube_root of a <2^53 product), so 410*offs^3 stays < 2^63.
    const u64 delta = (static_cast<u64>(kCubeRttScale) * offs * offs * offs) >> (10 + 3 * kBictcpHz);
    if (tt < bic_K)
    {
        const u64 target = (delta < origin_pkts) ? (origin_pkts - delta) : 0u;
        return static_cast<u32>(target);
    }
    return static_cast<u32>(static_cast<u64>(origin_pkts) + delta);
}

// Per-ACK CA update: recompute cubic.cnt (ACKs needed per +1 packet),
// applying the TCP-friendly (Reno) floor so growth is never slower than
// Reno. Mirrors Linux bictcp_update().
void CubicUpdate(Tcb& t, u32 cwnd_pkts, u32 acked_pkts)
{
    auto& c = t.cubic;
    if (cwnd_pkts == 0)
        cwnd_pkts = 1;
    c.ack_cnt += acked_pkts;

    if (c.epoch_start == 0)
    {
        c.epoch_start = NowTicks();
        c.ack_cnt = acked_pkts;
        c.tcp_cwnd = cwnd_pkts;
        if (c.last_max_cwnd <= cwnd_pkts)
        {
            c.bic_K = 0;
            c.bic_origin_point = cwnd_pkts;
        }
        else
        {
            c.bic_K = CubicRoot(kCubeFactor * static_cast<u64>(c.last_max_cwnd - cwnd_pkts));
            c.bic_origin_point = c.last_max_cwnd;
        }
    }

    // t = (now - epoch_start) + delay_min, in 100 Hz ticks, BICTCP-scaled.
    u64 tt = static_cast<u64>(NowTicks() - c.epoch_start) + static_cast<u64>(c.delay_min_ticks);
    tt <<= kBictcpHz;
    tt /= 100u; // HZ = 100 on DuetOS

    const u32 bic_target = CubicTarget(c.bic_origin_point, c.bic_K, tt);

    if (bic_target > cwnd_pkts)
        c.cnt = cwnd_pkts / (bic_target - cwnd_pkts);
    else
        c.cnt = 100u * cwnd_pkts; // target at/below cwnd → grow very slowly

    if (c.last_max_cwnd == 0 && c.cnt > 20u)
        c.cnt = 20u; // cap growth in the very first epoch

    // TCP-friendly region: advance the Reno estimate and clamp cnt so we
    // never grow slower than Reno.
    const u32 d = (cwnd_pkts * kBetaScale) >> 3;
    while (d != 0u && c.ack_cnt > d)
    {
        c.ack_cnt -= d;
        c.tcp_cwnd++;
    }
    if (c.tcp_cwnd > cwnd_pkts)
    {
        const u32 dd = c.tcp_cwnd - cwnd_pkts;
        const u32 max_cnt = cwnd_pkts / dd;
        if (c.cnt > max_cnt)
            c.cnt = max_cnt;
    }

    if (c.cnt < 2u)
        c.cnt = 2u;
}

// Loss reaction (Linux bictcp_recalc_ssthresh): set W_max with
// fast-convergence, end the epoch, return ssthresh (pkts) = cwnd*beta.
u32 CubicRecalcSsthresh(Tcb& t, u32 cwnd_pkts)
{
    auto& c = t.cubic;
    c.epoch_start = 0;
    if (cwnd_pkts == 0)
        cwnd_pkts = 1;

    if (cwnd_pkts < c.last_max_cwnd)
        // fast convergence: cwnd * (1024+717) / 2048 ≈ cwnd * 0.85
        c.last_max_cwnd =
            static_cast<u32>((static_cast<u64>(cwnd_pkts) * (kBictcpBetaScale + kCubicBeta)) / (2u * kBictcpBetaScale));
    else
        c.last_max_cwnd = cwnd_pkts;

    const u32 s = static_cast<u32>((static_cast<u64>(cwnd_pkts) * kCubicBeta) / kBictcpBetaScale);
    return (s < 2u) ? 2u : s;
}

} // namespace internal
} // namespace duetos::net::tcp
