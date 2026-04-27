/*
 * DuetOS — high-level time API implementation, v0 (plan A2).
 *
 * Registers HPET as the default monotonic clocksource and exposes
 * a one-line `MonotonicNs()` accessor. Existing inline
 * `HpetReadCounter() * period_fs / 1e6` call sites are NOT
 * migrated here — that's a follow-up. The new accessor is
 * additive.
 */

#include "time/timekeeper.h"

#include "arch/x86_64/hpet.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "time/clocksource.h"
#include "util/types.h"

namespace duetos::time
{

namespace
{

// HPET-backed clocksource glue. The math (counter * period_fs /
// 1e6) lives here, not in DoNowNs's syscall handler, so any
// future caller using `time::MonotonicNs()` gets the same value.
u64 HpetClocksourceReadNs()
{
    const u64 counter = arch::HpetReadCounter();
    const u64 period_fs = arch::HpetPeriodFemtoseconds();
    if (period_fs == 0)
    {
        return 0;
    }
    return (counter * period_fs) / 1'000'000ULL;
}

u64 HpetClocksourceResolutionNs()
{
    const u64 period_fs = arch::HpetPeriodFemtoseconds();
    if (period_fs == 0)
    {
        return 0;
    }
    // Resolution = one tick in ns, rounded up. period_fs / 1e6
    // truncates (the resolution is at least one tick); add one to
    // err on the conservative side for callers comparing against
    // it.
    return (period_fs / 1'000'000ULL) + 1;
}

constinit Clocksource g_hpet_clocksource = {
    "hpet",
    HpetClocksourceReadNs,
    HpetClocksourceResolutionNs,
    /* monotonic = */ true,
    /* rating   = */ 250,
};

} // namespace

void TimekeeperInit()
{
    if (arch::HpetPeriodFemtoseconds() == 0)
    {
        // HPET wasn't initialised (no ACPI HPET table or HpetInit
        // hasn't run yet). Don't register a stub source — the
        // caller's MonotonicNs() will return 0, which is the
        // correct "not available" signal.
        KLOG_WARN("time", "TimekeeperInit: HPET not available, no clocksource registered");
        return;
    }

    auto r = ClocksourceRegister(&g_hpet_clocksource);
    if (!r.has_value())
    {
        KLOG_ERROR_V("time", "ClocksourceRegister(hpet) failed", static_cast<u64>(r.error()));
        return;
    }

    ClocksourceRefreshCurrent();
    const Clocksource* picked = ClocksourceCurrent();
    if (picked == nullptr)
    {
        KLOG_ERROR("time", "TimekeeperInit: no clocksource selected after register");
        return;
    }

    KLOG_INFO_S("time", "clocksource selected", "name", picked->name);
}

u64 MonotonicNs()
{
    const Clocksource* cs = ClocksourceCurrent();
    if (cs == nullptr || cs->read_ns == nullptr)
    {
        return 0;
    }
    return cs->read_ns();
}

u64 ResolutionNs()
{
    const Clocksource* cs = ClocksourceCurrent();
    if (cs == nullptr || cs->resolution_ns == nullptr)
    {
        return 0;
    }
    return cs->resolution_ns();
}

u64 BoottimeNs()
{
    // v0 alias — CLOCK_BOOTTIME == CLOCK_MONOTONIC until a real
    // suspend/resume path exists.
    return MonotonicNs();
}

u64 RealtimeFiletime()
{
    // Sample CMOS RTC, convert to Windows FILETIME (100-ns ticks
    // since 1601-01-01 UTC). Same algorithm previously inlined in
    // syscall/time_syscall.cpp::RtcToFileTime; that one stays for
    // SYSTEMTIME ↔ FILETIME conversions (DoStToFt) and is also
    // updated to forward into this body once it's safe to remove
    // arch::RtcRead from that TU.
    arch::RtcTime t = {};
    arch::RtcRead(&t);

    auto is_leap = [](u32 y) { return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0); };
    constexpr u32 kDaysBeforeMonth[12] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

    u64 days = 0;
    for (u32 y = 1970; y < t.year; ++y)
        days += is_leap(y) ? 366 : 365;
    const u32 m = (t.month >= 1 && t.month <= 12) ? (t.month - 1) : 0;
    days += kDaysBeforeMonth[m];
    if (m >= 2 && is_leap(t.year))
        days += 1;
    days += (t.day >= 1) ? (t.day - 1) : 0;

    constexpr u64 k1970To1601Days = 134774;
    const u64 total_days = days + k1970To1601Days;

    const u64 seconds = total_days * 86400ULL + u64(t.hour) * 3600 + u64(t.minute) * 60 + u64(t.second);
    return seconds * 10'000'000ULL;
}

namespace
{

// Zeller's congruence, normal form: dow 0=Sun..6=Sat. Same formula
// the taskbar date widget + AML calendar popup use; previously
// lived in syscall/time_syscall.cpp.
u16 ComputeDayOfWeek(u16 year, u8 month, u8 day)
{
    if (month < 1 || month > 12)
        return 0;
    u32 wy = year;
    u32 wm = month;
    if (wm < 3)
    {
        wm += 12;
        --wy;
    }
    const u32 K = wy % 100;
    const u32 J = wy / 100;
    const u32 h = (u32(day) + (13 * (wm + 1)) / 5 + K + K / 4 + J / 4 + 5 * J) % 7;
    return u16((h + 6) % 7);
}

} // namespace

void RealtimeBrokenDown(BrokenDownTime* out)
{
    if (out == nullptr)
    {
        return;
    }
    arch::RtcTime t = {};
    arch::RtcRead(&t);
    out->year = t.year;
    out->month = t.month;
    out->day = t.day;
    out->hour = t.hour;
    out->minute = t.minute;
    out->second = t.second;
    out->milliseconds = 0;
    out->day_of_week = ComputeDayOfWeek(t.year, t.month, t.day);
}

void TimekeeperSelfTest()
{
    arch::SerialWrite("[time] timekeeper self-test: monotonic read + resolution\n");

    if (ClocksourceCurrent() == nullptr)
    {
        // HPET not on this platform — TimekeeperInit logged the
        // warning. Nothing to verify; return without panic so a
        // headless ARM64 / no-HPET configuration still boots.
        arch::SerialWrite("[time] timekeeper self-test SKIPPED (no clocksource).\n");
        return;
    }

    const u64 t0 = MonotonicNs();
    if (t0 == 0)
    {
        core::Panic("time/timekeeper self-test", "MonotonicNs returned 0 with active clocksource");
    }

    // Tiny busy-wait — 1000 reads of HPET counter is plenty to
    // tick at least once on real hardware AND on QEMU.
    for (u64 i = 0; i < 1000; ++i)
    {
        (void)arch::HpetReadCounter();
    }

    const u64 t1 = MonotonicNs();
    if (t1 <= t0)
    {
        core::Panic("time/timekeeper self-test", "MonotonicNs did not advance across busy-wait");
    }

    const u64 res = ResolutionNs();
    if (res == 0)
    {
        core::Panic("time/timekeeper self-test", "ResolutionNs returned 0 with active clocksource");
    }

    arch::SerialWrite("[time] timekeeper self-test OK (monotonic + resolution verified).\n");
}

} // namespace duetos::time
