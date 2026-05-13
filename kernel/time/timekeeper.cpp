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
#include "arch/x86_64/timer.h"
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

// =====================================================================
// TSC clocksource (plan A2-followup, 2026-04-28).
//
// Registered conditionally — the TSC is only a sensible clocksource
// on CPUs that advertise the invariant-TSC bit (CPUID 0x80000007
// EDX[8]). Without that bit, TSC drifts across P-state / C-state
// transitions and is not monotonic across sleep, which would
// silently violate Clocksource's contract.
//
// Calibration: count TSC ticks elapsed across a known HPET-derived
// interval (~50 ms is enough to swamp single-tick noise). The
// resulting `g_tsc_freq_hz` lets the read-side convert TSC deltas
// to ns. Read math uses divmod to keep `tsc_delta * 1e9` from
// overflowing u64 — at 4 GHz, the naive multiply overflows at
// ~4.6 s of uptime, which is far below typical session lengths.
// =====================================================================

constinit u64 g_tsc_boot = 0;    ///< TSC value at calibration time.
constinit u64 g_tsc_freq_hz = 0; ///< Calibrated frequency; 0 = "TSC not registered".
constinit u64 g_tsc_resolution_ns = 0;

u64 TscClocksourceReadNs()
{
    if (g_tsc_freq_hz == 0)
    {
        return 0;
    }
    const u64 delta = ReadTsc() - g_tsc_boot;
    // Divmod form to avoid u64 overflow on `delta * 1e9`. quot
    // counts whole seconds; rem * 1e9 / freq is the sub-second
    // fraction in ns. At any plausible TSC frequency, the
    // intermediate `rem * 1e9` fits in u64 (rem < freq < 1e10).
    constexpr u64 kNsPerSec = 1'000'000'000ULL;
    const u64 quot = delta / g_tsc_freq_hz;
    const u64 rem = delta % g_tsc_freq_hz;
    return quot * kNsPerSec + (rem * kNsPerSec) / g_tsc_freq_hz;
}

u64 TscClocksourceResolutionNs()
{
    return g_tsc_resolution_ns;
}

constinit Clocksource g_tsc_clocksource = {
    "tsc",
    TscClocksourceReadNs,
    TscClocksourceResolutionNs,
    /* monotonic = */ true,
    /* rating   = */ 300,
};

bool CpuHasInvariantTsc()
{
    // CPUID extended max leaf check first — leaf 0x80000007 only
    // exists if leaf 0x80000000 says so.
    u32 max_ext, dummy_b, dummy_c, dummy_d;
    asm volatile("cpuid" : "=a"(max_ext), "=b"(dummy_b), "=c"(dummy_c), "=d"(dummy_d) : "a"(0x80000000U));
    if (max_ext < 0x80000007U)
    {
        return false;
    }
    u32 a, b, c, d;
    asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x80000007U));
    return (d & (1U << 8)) != 0;
}

// Calibrate TSC frequency by counting TSC ticks across a known
// HPET-derived window. ~50 ms is enough to swamp scheduler-tick
// noise without stalling boot. Returns 0 on failure.
u64 CalibrateTscFreqHz()
{
    if (arch::HpetPeriodFemtoseconds() == 0)
    {
        return 0;
    }
    const u64 hpet_start = HpetClocksourceReadNs();
    const u64 tsc_start = ReadTsc();

    // Spin until ~50 ms of HPET time has passed. The loop reads
    // HPET each iteration; that's the sole synchronization with
    // wall time.
    constexpr u64 kCalibrationNs = 50'000'000ULL;
    while (HpetClocksourceReadNs() - hpet_start < kCalibrationNs)
    {
        // Empty body — the read serves as the spin. asm volatile
        // is implicit in HpetClocksourceReadNs's MMIO load.
    }

    const u64 tsc_end = ReadTsc();
    const u64 hpet_end = HpetClocksourceReadNs();
    const u64 tsc_delta = tsc_end - tsc_start;
    const u64 ns_elapsed = hpet_end - hpet_start;
    if (ns_elapsed == 0)
    {
        return 0;
    }
    // freq_hz = tsc_delta / (ns_elapsed / 1e9) = tsc_delta * 1e9 / ns_elapsed
    // tsc_delta * 1e9 overflows u64 around tsc_delta ~ 1.8e10 →
    // for 50 ms at any plausible frequency (< 100 GHz) we have
    // tsc_delta < 5e9 so the multiply is safe.
    constexpr u64 kNsPerSec = 1'000'000'000ULL;
    return (tsc_delta * kNsPerSec) / ns_elapsed;
}

} // namespace

u64 ReadTsc()
{
    return ::duetos::arch::TscRead();
}

u64 TscToNanos(u64 cycles)
{
    if (g_tsc_freq_hz == 0)
    {
        return 0;
    }
    // Same divmod trick as TscClocksourceReadNs above — the naive
    // `cycles * 1e9` overflows u64 around ~4.6 s of accumulated
    // TSC ticks at 4 GHz, which a long-running benchmark can hit.
    constexpr u64 kNsPerSec = 1'000'000'000ULL;
    const u64 quot = cycles / g_tsc_freq_hz;
    const u64 rem = cycles % g_tsc_freq_hz;
    return quot * kNsPerSec + (rem * kNsPerSec) / g_tsc_freq_hz;
}

bool TscCalibrated()
{
    return g_tsc_freq_hz != 0;
}

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

    // TSC clocksource (plan A2-followup). Registered only if the
    // CPU advertises the invariant-TSC bit AND the calibration
    // produced a non-zero frequency. Rating 300 outranks HPET so
    // a successful registration causes ClocksourceSelectBest to
    // pick TSC; falling back to HPET on older silicon is
    // automatic.
    if (CpuHasInvariantTsc())
    {
        const u64 freq_hz = CalibrateTscFreqHz();
        if (freq_hz > 0)
        {
            g_tsc_freq_hz = freq_hz;
            g_tsc_boot = ReadTsc();
            // Resolution: one tick in ns, rounded up. At 4 GHz
            // this is 0 ns + 1 = 1 ns; at slower frequencies it
            // grows correspondingly.
            g_tsc_resolution_ns = (1'000'000'000ULL / freq_hz) + 1;
            auto tr = ClocksourceRegister(&g_tsc_clocksource);
            if (!tr.has_value())
            {
                KLOG_ERROR_V("time", "ClocksourceRegister(tsc) failed", static_cast<u64>(tr.error()));
            }
            else
            {
                KLOG_INFO_V("time", "tsc clocksource registered, freq_hz", freq_hz);
            }
        }
        else
        {
            KLOG_WARN("time", "TSC calibration failed; staying on HPET");
        }
    }
    else
    {
        KLOG_INFO("time", "no invariant TSC; staying on HPET");
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
