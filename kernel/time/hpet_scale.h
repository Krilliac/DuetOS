#pragma once

#include "util/types.h"

/*
 * HPET tick -> nanosecond scaling.
 *
 * Freestanding on purpose: no kernel state, no MMIO, no allocation, so
 * the arithmetic can be pinned by a hosted unit test
 * (tests/host/test_hpet_scale.cpp) instead of only being exercised on a
 * booted machine 5 hours in. Used by kernel/time/timekeeper.cpp's
 * HPET clocksource read.
 */

namespace duetos::time
{

/// Convert an HPET counter reading to nanoseconds, given the HPET's
/// period in femtoseconds (its `COUNTER_CLK_PERIOD` capability field).
///
/// The naive form `counter * period_fs / 1'000'000` OVERFLOWS u64 long
/// before either operand does: a 14.318 MHz HPET reports period_fs
/// ~= 69'841'279, so the product wraps at ~2.6e11 ticks -- roughly
/// 18'438 s, i.e. **5.12 hours** of uptime. Past that the result jumps
/// backwards, breaking every deadline, timeout and elapsed-time
/// computation layered on MonotonicNs().
///
/// This splits the multiply using an exact integer identity, so no
/// intermediate can wrap for any representable timestamp:
///
///   counter*P/M == counter*(P/M) + (counter/M)*(P%M) + ((counter%M)*(P%M))/M
///
/// With M = 1e6 the only term that can still wrap is `counter * q`, and
/// with q ~= 69 that needs ~2.7e17 ticks (~590 years) -- beyond the
/// point a u64 nanosecond count overflows anyway, so the conversion is
/// exact across the whole representable range. `hi * r` is < counter by
/// construction and `lo * r` is < 1e12.
///
/// Deliberately NOT __uint128_t: a 128-bit divide lowers to a
/// __udivti3 call into compiler-rt, which the kernel does not link.
///
/// Returns 0 when `period_fs` is 0 (HPET absent / not enumerated),
/// matching the caller's existing "no clocksource" contract.
constexpr u64 HpetTicksToNs(u64 counter, u64 period_fs)
{
    if (period_fs == 0)
    {
        return 0;
    }
    constexpr u64 kMicro = 1'000'000ULL;
    const u64 q = period_fs / kMicro;
    const u64 r = period_fs % kMicro;
    const u64 hi = counter / kMicro;
    const u64 lo = counter % kMicro;
    return (counter * q) + (hi * r) + ((lo * r) / kMicro);
}

} // namespace duetos::time
