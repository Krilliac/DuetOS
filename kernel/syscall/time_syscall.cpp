#include "syscall/time_syscall.h"

#include "arch/x86_64/hpet.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/traps.h"
#include "mm/paging.h"
#include "syscall/syscall.h"

namespace duetos::arch
{
u64 TimerTicks();
} // namespace duetos::arch

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
    frame->rax = arch::TimerTicks();
}

void DoNowNs(arch::TrapFrame* frame)
{
    // No args. Return HPET counter × period_fs / 1e6 = ns since
    // boot. Counter × period_fs fits in u64 for any realistic
    // uptime (14.3 MHz × 70 kfs ≈ ~10^16 saturating at ~22 Gyr).
    const u64 counter = arch::HpetReadCounter();
    const u64 period_fs = arch::HpetPeriodFemtoseconds();
    frame->rax = (counter * period_fs) / 1'000'000ULL;
}

void DoGetTimeFt(arch::TrapFrame* frame)
{
    // No args. Sample CMOS RTC, return FILETIME in rax.
    arch::RtcTime t = {};
    arch::RtcRead(&t);
    frame->rax = RtcToFileTime(t);
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

// Zeller's congruence, normal form: dow 0=Sun..6=Sat. Same
// formula the taskbar date widget + AML calendar popup use.
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

void DoGetTimeSt(arch::TrapFrame* frame)
{
    // rdi = user SYSTEMTIME* out. Fill from RTC + computed dow.
    arch::RtcTime t = {};
    arch::RtcRead(&t);
    SystemTime st = {};
    st.year = t.year;
    st.month = t.month;
    st.day = t.day;
    st.hour = t.hour;
    st.minute = t.minute;
    st.second = t.second;
    st.milliseconds = 0;
    st.day_of_week = ComputeDayOfWeek(t.year, t.month, t.day);
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rdi), &st, sizeof(st)))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = 0;
}

void DoStToFt(arch::TrapFrame* frame)
{
    // rdi = user SYSTEMTIME* in, rsi = user FILETIME* out.
    SystemTime st = {};
    if (!mm::CopyFromUser(&st, reinterpret_cast<const void*>(frame->rdi), sizeof(st)))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    if (st.year < 1601 || st.month == 0 || st.month > 12 || st.day == 0 || st.day > 31)
    {
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
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = 0;
}

void DoFtToSt(arch::TrapFrame* frame)
{
    // rdi = user FILETIME* in, rsi = user SYSTEMTIME* out.
    u64 ft = 0;
    if (!mm::CopyFromUser(&ft, reinterpret_cast<const void*>(frame->rdi), sizeof(ft)))
    {
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
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = 0;
}

} // namespace duetos::core
