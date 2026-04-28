#include "syscall/time_syscall.h"

#include "arch/x86_64/rtc.h"
#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "syscall/syscall.h"
#include "time/tick.h"
#include "time/timekeeper.h"

namespace duetos::core
{

// Convert an RtcTime (Gregorian date + UTC time-of-day) to a
// Windows FILETIME — 100-nanosecond ticks since 1601-01-01
// 00:00:00 UTC. Pure arithmetic; no MSR / HPET reads.
//
// Algorithm: day-of-Gregorian computation by the classic "civil
// from days" family. We compute days since 1970-01-01 (Unix
// epoch), then add the fixed 1970→1601 offset (134 774 days =
// 369 years × 365 + 89 leap days between 1601..1969) to land
// at the Windows epoch.
u64 RtcToFileTime(const arch::RtcTime& t)
{
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

void DoPerfCounter(arch::TrapFrame* frame)
{
    // No args. Return the kernel tick counter — monotonically
    // increasing u64 at 100 Hz. Drives QPC + GetTickCount stubs.
    if (frame == nullptr)
    {
        KLOG_ONCE_WARN("syscall/time", "DoPerfCounter: null trap frame");
        return;
    }
    KLOG_TRACE("syscall/time", "DoPerfCounter: read kernel tick counter");
    frame->rax = ::duetos::time::TickCount();
}

void DoNowNs(arch::TrapFrame* frame)
{
    // No args. Return monotonic ns since boot from the active
    // clocksource (HPET in v0; TSC will register at a higher rating
    // once its calibration lands). The conversion math used to live
    // here as `counter * period_fs / 1e6`; now it's owned by
    // `time::MonotonicNs()` so every consumer reads the same source.
    if (frame == nullptr)
    {
        KLOG_ONCE_WARN("syscall/time", "DoNowNs: null trap frame");
        return;
    }
    KLOG_TRACE("syscall/time", "DoNowNs: sample monotonic clocksource");
    frame->rax = ::duetos::time::MonotonicNs();
}

void DoGetTimeFt(arch::TrapFrame* frame)
{
    // No args. Returns wall-clock FILETIME in rax. Sourced from
    // `time::RealtimeFiletime()` so any future migration to a more
    // accurate wall-clock path (NTP-disciplined RTC, TSC + RTC
    // delta sampling, …) takes effect here automatically.
    if (frame == nullptr)
    {
        KLOG_ONCE_WARN("syscall/time", "DoGetTimeFt: null trap frame");
        return;
    }
    KLOG_TRACE("syscall/time", "DoGetTimeFt: sample wall-clock FILETIME");
    frame->rax = ::duetos::time::RealtimeFiletime();
}

namespace
{

// Shared SYSTEMTIME layout — 8 WORDs (year/month/dow/day/hour/
// minute/second/ms). Not exposed in the header because it's an
// implementation detail of the ST conversions; callers use the
// Win32 SYSTEMTIME* they already have.
struct alignas(2) SystemTime
{
    u16 year;
    u16 month;
    u16 day_of_week;
    u16 day;
    u16 hour;
    u16 minute;
    u16 second;
    u16 milliseconds;
};
static_assert(sizeof(SystemTime) == 16, "SYSTEMTIME ABI is 16 bytes");

// Zeller's-congruence helper used to live here as a fallback for
// the ST↔FT conversion paths, but those don't actually need it
// (DoFtToSt walks days-since-1601 directly + DoStToFt computes
// seconds-since-1601 from a SYSTEMTIME's date fields, neither
// touching day-of-week). The DoGetTimeSt path that did need it
// migrated to `time::RealtimeBrokenDown` in an earlier
// A2-followup. Kept the comment as a breadcrumb so a future
// reader knows where to find the canonical implementation
// (kernel/time/timekeeper.cpp).

} // namespace

void DoGetTimeSt(arch::TrapFrame* frame)
{
    // rdi = user SYSTEMTIME* out. The Win32 SYSTEMTIME ABI shape
    // (16 bytes, 8 packed u16s) is layout-compatible with
    // `time::BrokenDownTime`; sample directly into the user's slot
    // via a kernel-side staging copy. The Zeller's-congruence DOW
    // computation moved into time/timekeeper.cpp with this slice.
    KLOG_TRACE_V("syscall/time", "DoGetTimeSt: user SYSTEMTIME* out", frame->rdi);
    ::duetos::time::BrokenDownTime bdt = {};
    ::duetos::time::RealtimeBrokenDown(&bdt);
    static_assert(sizeof(bdt) == 16, "BrokenDownTime must match Win32 SYSTEMTIME's 16-byte ABI");
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rdi), &bdt, sizeof(bdt)))
    {
        KLOG_WARN_V("syscall/time", "DoGetTimeSt: CopyToUser failed for SYSTEMTIME out", frame->rdi);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = 0;
}

void DoStToFt(arch::TrapFrame* frame)
{
    // rdi = user SYSTEMTIME* in, rsi = user FILETIME* out.
    KLOG_TRACE_V("syscall/time", "DoStToFt: SYSTEMTIME -> FILETIME conversion", frame->rdi);
    SystemTime st = {};
    if (!mm::CopyFromUser(&st, reinterpret_cast<const void*>(frame->rdi), sizeof(st)))
    {
        KLOG_WARN_V("syscall/time", "DoStToFt: CopyFromUser failed for SYSTEMTIME in", frame->rdi);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    if (st.year < 1601 || st.month == 0 || st.month > 12 || st.day == 0 || st.day > 31)
    {
        KLOG_WARN_V("syscall/time", "DoStToFt: SYSTEMTIME out of range, year", st.year);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    arch::RtcTime t = {};
    t.year = st.year;
    t.month = u8(st.month);
    t.day = u8(st.day);
    t.hour = u8(st.hour);
    t.minute = u8(st.minute);
    t.second = u8(st.second);
    const u64 ft = RtcToFileTime(t) + u64(st.milliseconds) * 10'000ULL;
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), &ft, sizeof(ft)))
    {
        KLOG_WARN_V("syscall/time", "DoStToFt: CopyToUser failed for FILETIME out", frame->rsi);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    KLOG_TRACE_V("syscall/time", "DoStToFt: produced FILETIME ticks", ft);
    frame->rax = 0;
}

void DoFtToSt(arch::TrapFrame* frame)
{
    // rdi = user FILETIME* in, rsi = user SYSTEMTIME* out.
    KLOG_TRACE_V("syscall/time", "DoFtToSt: FILETIME -> SYSTEMTIME conversion", frame->rdi);
    u64 ft = 0;
    if (!mm::CopyFromUser(&ft, reinterpret_cast<const void*>(frame->rdi), sizeof(ft)))
    {
        KLOG_WARN_V("syscall/time", "DoFtToSt: CopyFromUser failed for FILETIME in", frame->rdi);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 ticks_per_sec = 10'000'000ULL;
    const u16 ms = u16((ft % ticks_per_sec) / 10'000ULL);
    const u64 seconds_total = ft / ticks_per_sec;
    const u64 days_from_1601 = seconds_total / 86400ULL;
    const u64 tod = seconds_total % 86400ULL;
    const u16 hour = u16(tod / 3600);
    const u16 minute = u16((tod % 3600) / 60);
    const u16 second = u16(tod % 60);

    auto is_leap = [](u32 y) { return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0); };
    u32 year = 1601;
    u64 remaining = days_from_1601;
    while (true)
    {
        const u32 year_days = is_leap(year) ? 366 : 365;
        if (remaining < year_days)
            break;
        remaining -= year_days;
        ++year;
        if (year > 9999)
            break;
    }
    static const u32 kDaysInMonthCommon[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    u32 month = 1;
    for (; month <= 12; ++month)
    {
        u32 md = kDaysInMonthCommon[month - 1];
        if (month == 2 && is_leap(year))
            md = 29;
        if (remaining < md)
            break;
        remaining -= md;
    }
    if (month > 12)
        month = 12;
    const u16 day = u16(remaining + 1);
    // 1601-01-01 was a Monday (dow=1 in Sun=0 convention).
    const u16 dow = u16((days_from_1601 + 1) % 7);

    SystemTime st = {};
    st.year = u16(year);
    st.month = u16(month);
    st.day_of_week = dow;
    st.day = day;
    st.hour = hour;
    st.minute = minute;
    st.second = second;
    st.milliseconds = ms;
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), &st, sizeof(st)))
    {
        KLOG_WARN_V("syscall/time", "DoFtToSt: CopyToUser failed for SYSTEMTIME out", frame->rsi);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    KLOG_TRACE_V("syscall/time", "DoFtToSt: produced SYSTEMTIME year", year);
    frame->rax = 0;
}

} // namespace duetos::core
