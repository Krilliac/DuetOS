/*
 * DuetOS — Linux ABI: time / clock handlers.
 *
 * Sibling TU of syscall.cpp. Houses NowNs (the HPET-derived
 * nanoseconds-since-boot reading every Linux clock currently
 * bottoms out in) plus clock_gettime / gettimeofday / time /
 * nanosleep / times / clock_getres / clock_nanosleep.
 *
 * v0 has no RTC integration, so CLOCK_REALTIME ≈ boot. Real
 * epoch tracking waits for the RTC driver to lock on. Sleeps
 * round up to whole 10 ms scheduler ticks; nothing can interrupt
 * a sleep mid-flight (no signal delivery yet).
 */

#include "syscall_internal.h"

#include "../../arch/x86_64/hpet.h"
#include "../../arch/x86_64/timer.h"
#include "../../core/process.h"
#include "../../mm/address_space.h"
#include "../../sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Read the CPU timestamp counter. Used as a seed for the tiny
// PRNG path elsewhere in the subsystem — kept here so the
// freestanding header doesn't pull `rdtsc` into every consumer.
[[maybe_unused]] u64 ReadTsc()
{
    u32 lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<u64>(hi) << 32) | lo;
}

} // namespace

// Current nanoseconds since boot, derived from the HPET main
// counter. Returns 0 if HPET didn't init (rare on modern x86).
u64 NowNs()
{
    const u64 counter = arch::HpetReadCounter();
    const u32 period_fs = arch::HpetPeriodFemtoseconds();
    if (period_fs == 0)
        return 0;
    // ns = counter * period_fs / 1_000_000 — split to avoid u64 overflow:
    // (counter / 1_000_000) * period_fs + ((counter % 1_000_000) * period_fs) / 1_000_000.
    // counter is typically < 2^40 and period_fs < 2^28, so direct
    // multiply fits in u64 as long as counter < 2^36 — guard with
    // the split form for safety over boot-time scales.
    const u64 million = 1000000ull;
    const u64 hi = (counter / million) * period_fs;
    const u64 lo = ((counter % million) * period_fs) / million;
    return hi + lo;
}

// Linux: clock_gettime(clk_id, ts). Fills struct timespec
// {tv_sec (i64), tv_nsec (i64)} with current time. v0 returns
// nanoseconds-since-boot for every clock id — musl uses this
// for relative-time primitives (monotonic deltas, sleep offsets)
// and tolerates the REALTIME-since-boot approximation when there's
// no RTC integration. Calendar time needs the RTC driver's UNIX
// epoch — separate slice.
i64 DoClockGetTime(u64 clk_id, u64 user_ts)
{
    (void)clk_id;
    const u64 ns = NowNs();
    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } ts;
    ts.tv_sec = static_cast<i64>(ns / 1'000'000'000ull);
    ts.tv_nsec = static_cast<i64>(ns % 1'000'000'000ull);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_ts), &ts, sizeof(ts)))
        return kEFAULT;
    return 0;
}

// Linux: gettimeofday(tv, tz). tz is obsolete and ignored by modern
// kernels; we follow that contract and only fill timeval if non-null.
i64 DoGettimeofday(u64 user_tv, u64 user_tz)
{
    (void)user_tz;
    if (user_tv == 0)
        return 0;
    const u64 ns = NowNs();
    struct
    {
        i64 tv_sec;
        i64 tv_usec;
    } tv;
    tv.tv_sec = static_cast<i64>(ns / 1'000'000'000ull);
    tv.tv_usec = static_cast<i64>((ns / 1000ull) % 1'000'000ull);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_tv), &tv, sizeof(tv)))
        return kEFAULT;
    return 0;
}

// Linux: time(tloc). Returns seconds-since-epoch; if tloc is
// non-null, writes the value there too. Without an RTC we return
// seconds-since-boot — matches the "CLOCK_REALTIME = boot" call
// above. Real epoch tracking waits for the RTC driver to lock on.
i64 DoTime(u64 user_tloc)
{
    const u64 secs = NowNs() / 1'000'000'000ull;
    if (user_tloc != 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_tloc), &secs, sizeof(secs)))
            return kEFAULT;
    }
    return static_cast<i64>(secs);
}

// Linux: nanosleep(req, rem). v0 rounds the request up to whole
// scheduler ticks (10 ms each at 100 Hz). The `rem` output — how
// much time is left if interrupted — is always zeroed; DuetOS
// doesn't deliver signals yet, so nothing can interrupt a sleep
// mid-flight.
i64 DoNanosleep(u64 user_req, u64 user_rem)
{
    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } req;
    if (!mm::CopyFromUser(&req, reinterpret_cast<const void*>(user_req), sizeof(req)))
        return kEFAULT;
    if (req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= 1'000'000'000)
        return kEINVAL;
    const u64 ns = static_cast<u64>(req.tv_sec) * 1'000'000'000ull + static_cast<u64>(req.tv_nsec);
    // Scheduler tick = 10 ms = 10_000_000 ns. Round up so a sub-
    // tick sleep doesn't become zero.
    const u64 ticks = (ns + 9'999'999ull) / 10'000'000ull;
    if (ticks > 0)
        sched::SchedSleepTicks(ticks);
    if (user_rem != 0)
    {
        struct
        {
            i64 tv_sec;
            i64 tv_nsec;
        } zero{0, 0};
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_rem), &zero, sizeof(zero)))
            return kEFAULT;
    }
    return 0;
}

// Linux: times(buf). Returns the kernel's tick counter and fills
// buf->utime with the caller's accumulated ticks (stime/cutime/
// cstime stay zero — we don't track kernel-vs-user split or child
// times). The returned tick counter matches arch::TimerTicks at
// our 100 Hz scheduler rate.
i64 DoTimes(u64 user_buf)
{
    const u64 t = arch::TimerTicks();
    if (user_buf != 0)
    {
        u64 utime = 0;
        const core::Process* p = core::CurrentProcess();
        if (p != nullptr)
            utime = p->ticks_used;
        struct
        {
            u64 utime;
            u64 stime;
            u64 cutime;
            u64 cstime;
        } tms = {utime, 0, 0, 0};
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &tms, sizeof(tms)))
            return kEFAULT;
    }
    return static_cast<i64>(t);
}

// clock_getres(clk_id, res): clock resolution. Scheduler tick is
// 10 ms; HPET-backed clocks are ~70 ns (see DoClockGetTime comment).
// Use the coarser scheduler grain as the reported resolution.
i64 DoClockGetres(u64 clk_id, u64 user_res)
{
    (void)clk_id;
    if (user_res == 0)
        return 0;
    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } ts = {0, 10'000'000}; // 10 ms
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_res), &ts, sizeof(ts)))
        return kEFAULT;
    return 0;
}

// clock_nanosleep(clk_id, flags, req, rem): absolute or relative
// sleep. Ignore flags (TIMER_ABSTIME would need monotonic-clock
// diff math; we treat everything as relative for v0) and route
// through DoNanosleep.
i64 DoClockNanosleep(u64 clk_id, u64 flags, u64 user_req, u64 user_rem)
{
    (void)clk_id;
    (void)flags;
    return DoNanosleep(user_req, user_rem);
}

} // namespace duetos::subsystems::linux::internal
