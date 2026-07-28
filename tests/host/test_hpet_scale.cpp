// test_hpet_scale.cpp — hosted unit test for the HPET tick->ns scaling
// core.
//
// Covers:
//   kernel/time/hpet_scale.h  (HpetTicksToNs, used by
//   kernel/time/timekeeper.cpp's HPET clocksource read, which backs
//   time::MonotonicNs())
//
// Pins the fix for the audit finding "HPET clocksource read overflows
// u64 after ~5.12 hours of uptime, making time::MonotonicNs() jump
// backwards". The naive expression `counter * period_fs / 1'000'000`
// wraps because the PRODUCT exceeds u64 long before either operand
// does; these cases lock in that the split-multiply form is (a)
// identical to the naive form everywhere the naive form is still
// valid, and (b) still monotonic well past the point it wrapped.

#include "host_test_helper.h"

#include "time/hpet_scale.h"

#include <cstdio>

using duetos::time::HpetTicksToNs;

namespace
{

// QEMU / typical PC HPET: 14.318180 MHz => 69'841'279 fs per tick.
constexpr duetos::u64 kPeriodFs14MHz = 69'841'279ULL;
// A round 10 MHz part => 100'000'000 fs per tick (exercises r == 0).
constexpr duetos::u64 kPeriodFs10MHz = 100'000'000ULL;

constexpr duetos::u64 kTicksPerSec14MHz = 14'318'180ULL;

// The pre-fix expression, kept here ONLY as the reference oracle for
// the range where it is still correct.
duetos::u64 NaiveTicksToNs(duetos::u64 counter, duetos::u64 period_fs)
{
    return (counter * period_fs) / 1'000'000ULL;
}

} // namespace

int main()
{
    // --- degenerate: no HPET enumerated -------------------------------
    EXPECT_EQ(HpetTicksToNs(0, 0), 0ULL);
    EXPECT_EQ(HpetTicksToNs(12345, 0), 0ULL);

    // --- exactness vs the naive form, well inside its valid range -----
    // Anything below ~2.6e11 ticks cannot overflow the naive product,
    // so the two must agree BIT-FOR-BIT, including truncation.
    const duetos::u64 safe_counters[] = {
        0ULL,          1ULL,           999'999ULL,        1'000'000ULL,       1'000'001ULL,
        14'318'180ULL, 123'456'789ULL, 10'000'000'000ULL, 100'000'000'000ULL,
    };
    for (duetos::u64 c : safe_counters)
    {
        EXPECT_EQ(HpetTicksToNs(c, kPeriodFs14MHz), NaiveTicksToNs(c, kPeriodFs14MHz));
        EXPECT_EQ(HpetTicksToNs(c, kPeriodFs10MHz), NaiveTicksToNs(c, kPeriodFs10MHz));
    }

    // --- sanity: one second of ticks is ~1e9 ns -----------------------
    // 14'318'180 * 69'841'279 / 1e6 == 999'999'993 ns (the part is not
    // exactly 14.31818 MHz), so allow a small tolerance rather than
    // asserting a round 1e9.
    const duetos::u64 one_sec = HpetTicksToNs(kTicksPerSec14MHz, kPeriodFs14MHz);
    EXPECT_TRUE(one_sec > 999'000'000ULL);
    EXPECT_TRUE(one_sec < 1'001'000'000ULL);

    // --- the regression itself ---------------------------------------
    // 5.12 hours in, the naive product has wrapped. Pick a counter just
    // past the wrap point and show the naive form goes BACKWARDS while
    // the fixed form does not.
    const duetos::u64 wrap_ticks = 0xFFFFFFFFFFFFFFFFULL / kPeriodFs14MHz; // last safe counter
    const duetos::u64 before = wrap_ticks - 1'000'000ULL;
    const duetos::u64 after = wrap_ticks + 1'000'000ULL;

    // Precondition for the test to be meaningful: the naive form really
    // does regress here. If this ever fails the oracle changed, not us.
    EXPECT_TRUE(NaiveTicksToNs(after, kPeriodFs14MHz) < NaiveTicksToNs(before, kPeriodFs14MHz));

    // The fix must stay strictly increasing across that same boundary.
    EXPECT_TRUE(HpetTicksToNs(after, kPeriodFs14MHz) > HpetTicksToNs(before, kPeriodFs14MHz));

    // And that boundary really is ~5.12 hours of uptime.
    const duetos::u64 wrap_seconds = wrap_ticks / kTicksPerSec14MHz;
    EXPECT_TRUE(wrap_seconds > 18'000ULL); // > 5.0 h
    EXPECT_TRUE(wrap_seconds < 19'000ULL); // < 5.3 h

    // --- monotonicity sweep far past the old wrap ---------------------
    // Walk a decade of uptime in ~1-hour steps; every step must be
    // strictly greater than the previous one.
    duetos::u64 prev = 0;
    const duetos::u64 hour_ticks = kTicksPerSec14MHz * 3600ULL;
    for (duetos::u64 h = 1; h <= 24ULL * 365ULL * 10ULL; h += 137ULL)
    {
        const duetos::u64 ns = HpetTicksToNs(h * hour_ticks, kPeriodFs14MHz);
        EXPECT_TRUE(ns > prev);
        prev = ns;
    }

    // --- r == 0 path stays exact --------------------------------------
    // period_fs = 1e8 divides 1e6 evenly (q=100, r=0), so the result is
    // just counter*100 with no remainder term.
    EXPECT_EQ(HpetTicksToNs(1'234'567ULL, kPeriodFs10MHz), 1'234'567ULL * 100ULL);

    std::printf("[hpet-scale-host] PASS\n");
    return 0;
}
