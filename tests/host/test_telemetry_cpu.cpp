// test_telemetry_cpu.cpp — hosted unit test for the telemetry
// percentage math shared by the Task Manager performance view, sysmon
// and resmon.
//
// Covers kernel/diag/telemetry_math.h:
//   BusyPercent           — delta -> percent, with torn-read clamping
//   CounterDelta          — monotonic delta, saturating at 0
//   AggregateBusyPercent  — summed-delta aggregate (NOT a mean of
//                           per-core percentages)
//   UsedPercent           — used/total clamp
//
// The aggregate cases are the load-bearing ones: the whole reason this
// math has a single home is that a system-wide CPU figure derived
// independently of the per-core figures drifts out of agreement with
// them, and users notice when the summary disagrees with the bars
// underneath it.

#include "host_test_helper.h"

#include "diag/telemetry_math.h"

using namespace duetos_host_test;
namespace tm = duetos::diag::telemetry_math;

using duetos::u64;
using duetos::u8;

int main()
{
    // --- BusyPercent: basic arithmetic --------------------------------
    EXPECT_EQ(static_cast<int>(tm::BusyPercent(100, 0)), 100); // fully busy
    EXPECT_EQ(static_cast<int>(tm::BusyPercent(100, 100)), 0); // fully idle
    EXPECT_EQ(static_cast<int>(tm::BusyPercent(100, 25)), 75);
    EXPECT_EQ(static_cast<int>(tm::BusyPercent(8, 6)), 25);

    // Integer division truncates toward zero — pin it so nobody
    // "fixes" it into rounding and shifts every reading by a point.
    EXPECT_EQ(static_cast<int>(tm::BusyPercent(3, 2)), 33);

    // --- BusyPercent: no data vs zero ---------------------------------
    // total_delta == 0 means no tick landed. The function returns 0,
    // but callers gate on this separately — an idle CPU still ticks, so
    // a real 0% reading always comes with total_delta > 0.
    EXPECT_EQ(static_cast<int>(tm::BusyPercent(0, 0)), 0);

    // --- BusyPercent: torn-read clamping ------------------------------
    // idle > total is arithmetically impossible but observable when the
    // two counters are read without a lock and a tick lands between the
    // loads. Must clamp to 0%, never underflow to a huge busy value.
    EXPECT_EQ(static_cast<int>(tm::BusyPercent(100, 150)), 0);
    EXPECT_EQ(static_cast<int>(tm::BusyPercent(1, 0xFFFFFFFFFFFFFFFFULL)), 0);

    // --- CounterDelta -------------------------------------------------
    EXPECT_EQ(tm::CounterDelta(500, 100), 400ULL);
    EXPECT_EQ(tm::CounterDelta(100, 100), 0ULL);
    // Going backwards (torn read, or a CPU that came online between
    // samples) saturates at 0 rather than wrapping to ~2^64, which
    // would render as a pegged 100% forever.
    EXPECT_EQ(tm::CounterDelta(100, 500), 0ULL);
    EXPECT_EQ(tm::CounterDelta(0, 0xFFFFFFFFFFFFFFFFULL), 0ULL);

    // --- Aggregate: summed deltas, not a mean of percentages ----------
    // Two CPUs, equal tick counts: 100% and 0% -> 50% either way.
    {
        const u64 total = 100 + 100;
        const u64 idle = 0 + 100;
        EXPECT_EQ(static_cast<int>(tm::AggregateBusyPercent(total, idle)), 50);
    }

    // The case that distinguishes the two formulas. CPU A ticked 1000
    // times and was fully idle; CPU B ticked twice and was fully busy
    // (it just came online). Mean-of-percentages would say 50% — wildly
    // wrong, a two-tick CPU swinging the system figure as hard as one
    // with a thousand. Summed deltas say 2/1002 -> 0%.
    {
        const u64 total = 1000 + 2;
        const u64 idle = 1000 + 0;
        EXPECT_EQ(static_cast<int>(tm::AggregateBusyPercent(total, idle)), 0);
    }

    // Mirror image: A busy over a long window, B idle over a tiny one.
    // Mean would say 50%; weighted truth is ~99%.
    {
        const u64 total = 1000 + 2;
        const u64 idle = 0 + 2;
        EXPECT_EQ(static_cast<int>(tm::AggregateBusyPercent(total, idle)), 99);
    }

    // Four fully-busy cores aggregate to 100%, not 400%.
    {
        const u64 total = 250ULL * 4;
        const u64 idle = 0;
        EXPECT_EQ(static_cast<int>(tm::AggregateBusyPercent(total, idle)), 100);
    }

    // No CPU reported ticks -> 0, and the caller's `valid` flag is what
    // distinguishes this from a real idle system.
    EXPECT_EQ(static_cast<int>(tm::AggregateBusyPercent(0, 0)), 0);

    // --- Aggregate agrees with the per-core breakdown -----------------
    // The consistency property that motivates the shared helper: for
    // equal-weight cores, the aggregate equals the mean of the per-core
    // percentages. Build 4 cores with known busy fractions and check
    // both routes land on the same number.
    {
        const u64 per_core_total = 100;
        const u64 idles[4] = {0, 25, 50, 75}; // 100%, 75%, 50%, 25%
        u64 sum_total = 0;
        u64 sum_idle = 0;
        int sum_pct = 0;
        for (int i = 0; i < 4; ++i)
        {
            sum_total += per_core_total;
            sum_idle += idles[i];
            sum_pct += static_cast<int>(tm::BusyPercent(per_core_total, idles[i]));
        }
        EXPECT_EQ(static_cast<int>(tm::AggregateBusyPercent(sum_total, sum_idle)), 62);
        EXPECT_EQ(sum_pct / 4, 62);
    }

    // --- Large counters: no overflow in the *100 multiply -------------
    // Lifetime tick deltas stay small, but a long window on a fast
    // clock can still be large. 2^56 busy ticks must not overflow.
    {
        const u64 big = 1ULL << 56;
        EXPECT_EQ(static_cast<int>(tm::BusyPercent(big, 0)), 100);
        EXPECT_EQ(static_cast<int>(tm::BusyPercent(big, big / 2)), 50);
    }

    // --- UsedPercent ---------------------------------------------------
    EXPECT_EQ(static_cast<int>(tm::UsedPercent(512, 1024)), 50);
    EXPECT_EQ(static_cast<int>(tm::UsedPercent(0, 1024)), 0);
    EXPECT_EQ(static_cast<int>(tm::UsedPercent(1024, 1024)), 100);
    // total == 0 -> nothing measurable, not a divide-by-zero.
    EXPECT_EQ(static_cast<int>(tm::UsedPercent(5, 0)), 0);
    // used > total clamps instead of exceeding 100.
    EXPECT_EQ(static_cast<int>(tm::UsedPercent(2048, 1024)), 100);

    // --- PresentFpsX10 -------------------------------------------------
    // 60 frames over 100 ticks at 100Hz == exactly 1s == 60.0 fps.
    EXPECT_EQ(static_cast<int>(tm::PresentFpsX10(60, 100, 100)), 600);
    // Half a second's worth of window still reports the rate, not the
    // raw count: 30 frames in 50 ticks is still 60.0 fps.
    EXPECT_EQ(static_cast<int>(tm::PresentFpsX10(30, 50, 100)), 600);
    // The tenth actually resolves: 1 frame in 100 ticks == 1.0.
    EXPECT_EQ(static_cast<int>(tm::PresentFpsX10(1, 100, 100)), 10);
    // 1 frame in 200 ticks == 0.5 fps -- the idle pump, and the case a
    // whole-number rate would have flattened to 0.
    EXPECT_EQ(static_cast<int>(tm::PresentFpsX10(1, 200, 100)), 5);
    // An idle window with no presents is a real 0.0, distinct from the
    // no-window case below.
    EXPECT_EQ(static_cast<int>(tm::PresentFpsX10(0, 100, 100)), 0);
    // Zero-length window / zero tick rate must not divide.
    EXPECT_EQ(static_cast<int>(tm::PresentFpsX10(60, 0, 100)), 0);
    EXPECT_EQ(static_cast<int>(tm::PresentFpsX10(60, 100, 0)), 0);
    // Clamped so a torn counter read cannot render wider than the pill
    // reserved for. 10000 frames in 1s would be 1000.0.
    EXPECT_EQ(static_cast<int>(tm::PresentFpsX10(10000, 100, 100)), 9999);
    // The multiply happens before the divide, so a large-but-real
    // frame count keeps its precision rather than truncating to 0.
    EXPECT_EQ(static_cast<int>(tm::PresentFpsX10(3, 400, 100)), 7); // 0.75 -> 0.7

    std::printf("[telemetry-cpu-host] PASS\n");
    return 0;
}
