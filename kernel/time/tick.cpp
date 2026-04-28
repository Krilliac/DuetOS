/*
 * DuetOS — portable scheduler-tick wrapper, v0 (plan A2-followup).
 *
 * See `tick.h` for the public contract. This TU is intentionally
 * thin: every function either forwards to `arch::TimerTicks` or
 * is a header-defined `constexpr` accessor. The TU exists for
 * the self-test + to give the arch forward-declaration a single
 * source of truth.
 */

#include "time/tick.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "core/panic.h"

namespace duetos::time
{

u64 TickCount()
{
    return arch::TimerTicks();
}

void TickSelfTest()
{
    arch::SerialWrite("[time] tick self-test: round-trip + monotonic advance\n");

    // Round-trip on whole-tick values must be lossless.
    for (u64 t = 0; t <= 100; ++t)
    {
        const u64 ns = TicksToNs(t);
        const u64 back = NsToTicks(ns);
        if (back != t)
        {
            core::Panic("time/tick", "round-trip lost a tick");
        }
    }

    // Frequency / period invariant: TickHz * TickPeriodNs == 1e9.
    if (TickHz() * TickPeriodNs() != 1'000'000'000ULL)
    {
        core::Panic("time/tick", "TickHz * TickPeriodNs != 1e9");
    }

    // TickCount is monotonic across reads. Don't busy-wait here
    // — a back-to-back read could legitimately return the same
    // value (the LAPIC tick hasn't fired in the few cycles
    // between calls). Just confirm a second read is >= the first.
    const u64 t0 = TickCount();
    const u64 t1 = TickCount();
    if (t1 < t0)
    {
        core::Panic("time/tick", "TickCount went backwards");
    }

    arch::SerialWrite("[time] tick self-test OK (round-trip + monotonic).\n");
}

} // namespace duetos::time
