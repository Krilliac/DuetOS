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

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/hpet.h"
#include "arch/x86_64/timer.h"
#include "time/tick.h"
#include "time/timekeeper.h"
#include "proc/process.h"
#include "mm/address_space.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Read the CPU timestamp counter. Forwards to the canonical
// `arch::TscRead()` so the entropy seeding paths here, in
// `kernel/util/random.cpp`, and in `kernel/diag/boot_progress.cpp`
// all read TSC the same way.
[[maybe_unused]] u64 ReadTsc()
{
    return ::duetos::arch::TscRead();
}

// Wall-clock adjustment for CLOCK_REALTIME readers. Signed because
// settimeofday can shift the wall clock backwards. Steady-state v0
// has no adjustments — the offset stays 0 and `RealtimeNs()` derives
// every read from the canonical `time::RealtimeFiletime()` so the
// Linux and Win32 (SYS_GETTIME_FT) wall-clock surfaces always agree.
// Aligned i64 writes are atomic on x86_64; no spinlock needed.
i64 g_realtime_offset_ns = 0;

constexpr u64 kClockRealtime = 0;
constexpr u64 kClockMonotonic = 1;
constexpr u64 kClockProcessCputime = 2;
constexpr u64 kClockThreadCputime = 3;
constexpr u64 kClockMonotonicRaw = 4;
constexpr u64 kClockRealtimeCoarse = 5;
constexpr u64 kClockMonotonicCoarse = 6;
constexpr u64 kClockBoottime = 7;

// True iff `clk_id` advances with wall-clock time (settable).
// CLOCK_REALTIME and CLOCK_REALTIME_COARSE follow the offset;
// every other clock is monotonic / boot-relative and reads NowNs()
// directly.
bool ClockHonorsOffset(u64 clk_id)
{
    return clk_id == kClockRealtime || clk_id == kClockRealtimeCoarse;
}

// Canonical wall-clock ns derived from the kernel's
// `time::RealtimeFiletime()`. Returns 0 if RTC is unreadable so
// callers can distinguish the failure from a legitimate Epoch-equal
// reading.
//
// FILETIME = 100-ns ticks since 1601-01-01 UTC. Unix epoch starts
// 11644473600 seconds later.
u64 CanonicalRealtimeUnixNs()
{
    constexpr u64 kFiletimeUnixDeltaSec = 11644473600ULL;
    constexpr u64 kFiletimePerSec = 10000000ULL;
    const u64 ft = ::duetos::time::RealtimeFiletime();
    if (ft == 0)
        return 0;
    const u64 unix_sec = (ft / kFiletimePerSec) - kFiletimeUnixDeltaSec;
    return unix_sec * 1'000'000'000ULL + (ft % kFiletimePerSec) * 100ULL;
}

// Compose the wall-clock reading from the canonical
// `time::RealtimeFiletime()` plus the settimeofday adjustment.
// Single source of truth shared with the Win32 SYS_GETTIME_FT path
// — both observe the same RTC sample without a per-subsystem cache
// that could drift.
u64 RealtimeNs()
{
    const u64 unix_ns = CanonicalRealtimeUnixNs();
    if (unix_ns == 0)
    {
        // RTC unreadable — fall back to the monotonic counter so
        // callers don't observe time-since-1601 chaos.
        return NowNs();
    }
    const i64 off = g_realtime_offset_ns;
    if (off >= 0)
        return unix_ns + static_cast<u64>(off);
    const u64 neg = static_cast<u64>(-off);
    return (unix_ns > neg) ? (unix_ns - neg) : 0;
}

// CAP_SYS_TIME analog. v0 has no dedicated kCapTimeSet — kCapDebug
// is the closest admin-flavored cap (trusted profiles already hold
// it; sandboxed profiles do not). Untrusted callers see -EPERM,
// matching the pre-slice behaviour. Returns 0 on allow, kEPERM on
// deny (and records a sandbox denial so the audit log stays
// truthful).
i64 CheckTimeSetCap()
{
    const core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    if (!core::CapSetHas(p->caps, core::kCapDebug))
    {
        core::RecordSandboxDenial(core::kCapDebug);
        return kEPERM;
    }
    return 0;
}

} // namespace

i64 LinuxRealtimeOffsetNs()
{
    return g_realtime_offset_ns;
}

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
// {tv_sec (i64), tv_nsec (i64)} with current time. CLOCK_REALTIME and
// CLOCK_REALTIME_COARSE route through `RealtimeNs()`, which derives
// from the canonical `time::RealtimeFiletime()` so this surface and
// the Win32 SYS_GETTIME_FT surface always observe the same RTC.
// Every other clock id reads the HPET monotonic counter directly.
i64 DoClockGetTime(u64 clk_id, u64 user_ts)
{
    const u64 ns = ClockHonorsOffset(clk_id) ? RealtimeNs() : NowNs();
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
// Always reports CLOCK_REALTIME (offset-adjusted) — that's the
// gettimeofday contract.
i64 DoGettimeofday(u64 user_tv, u64 user_tz)
{
    (void)user_tz;
    if (user_tv == 0)
        return 0;
    const u64 ns = RealtimeNs();
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
// non-null, writes the value there too. Honors the realtime
// offset (CLOCK_REALTIME contract).
i64 DoTime(u64 user_tloc)
{
    const u64 secs = RealtimeNs() / 1'000'000'000ull;
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
// times). The returned tick counter matches time::TickCount at
// our 100 Hz scheduler rate.
i64 DoTimes(u64 user_buf)
{
    const u64 t = ::duetos::time::TickCount();
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

// Linux: clock_settime(clk_id, ts). Sets the wall-clock reading
// for CLOCK_REALTIME by stashing a signed offset between the
// requested wall-clock value and the current monotonic counter.
// CLOCK_MONOTONIC and boot-relative clocks return -EINVAL — they
// are not settable on Linux either.
i64 DoClockSettime(u64 clk_id, u64 user_ts)
{
    if (const i64 perm = CheckTimeSetCap(); perm != 0)
        return perm;
    if (clk_id == kClockMonotonic || clk_id == kClockMonotonicRaw || clk_id == kClockMonotonicCoarse ||
        clk_id == kClockBoottime || clk_id == kClockProcessCputime || clk_id == kClockThreadCputime)
        return kEINVAL;
    if (!ClockHonorsOffset(clk_id))
        return kEINVAL;
    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } ts;
    if (!mm::CopyFromUser(&ts, reinterpret_cast<const void*>(user_ts), sizeof(ts)))
        return kEFAULT;
    if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1'000'000'000)
        return kEINVAL;
    const u64 want_ns = static_cast<u64>(ts.tv_sec) * 1'000'000'000ull + static_cast<u64>(ts.tv_nsec);
    const u64 canon = CanonicalRealtimeUnixNs();
    const u64 base = (canon != 0) ? canon : NowNs();
    g_realtime_offset_ns = static_cast<i64>(want_ns) - static_cast<i64>(base);
    return 0;
}

// Linux: settimeofday(tv, tz). tz is obsolete; we accept-and-ignore
// per the kernel's modern contract. tv is converted to a timespec
// and routed through clock_settime(CLOCK_REALTIME).
i64 DoSettimeofday(u64 user_tv, u64 user_tz)
{
    (void)user_tz;
    if (const i64 perm = CheckTimeSetCap(); perm != 0)
        return perm;
    if (user_tv == 0)
        return 0;
    struct
    {
        i64 tv_sec;
        i64 tv_usec;
    } tv;
    if (!mm::CopyFromUser(&tv, reinterpret_cast<const void*>(user_tv), sizeof(tv)))
        return kEFAULT;
    if (tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= 1'000'000)
        return kEINVAL;
    const u64 want_ns = static_cast<u64>(tv.tv_sec) * 1'000'000'000ull + static_cast<u64>(tv.tv_usec) * 1000ull;
    const u64 canon = CanonicalRealtimeUnixNs();
    const u64 base = (canon != 0) ? canon : NowNs();
    g_realtime_offset_ns = static_cast<i64>(want_ns) - static_cast<i64>(base);
    return 0;
}

// Linux struct timex layout (x86_64, 64-bit long). 200 bytes.
// We only act on a handful of fields; the rest are accept-and-store
// (status / constant / tick) or accept-and-ignore (NTP-discipline
// state we have no machinery for: freq / PLL counters).
struct LinuxTimex
{
    u32 modes;
    u32 _pad0;
    i64 offset;
    i64 freq;
    i64 maxerror;
    i64 esterror;
    i32 status;
    u32 _pad1;
    i64 constant;
    i64 precision;
    i64 tolerance;
    i64 time_tv_sec;
    i64 time_tv_usec;
    i64 tick;
    i64 ppsfreq;
    i64 jitter;
    i32 shift;
    u32 _pad2;
    i64 stabil;
    i64 jitcnt;
    i64 calcnt;
    i64 errcnt;
    i64 stbcnt;
    i32 tai;
    u32 _pad3;
    u8 reserved[32];
};
static_assert(sizeof(LinuxTimex) == 200, "struct timex must be 200 bytes on x86_64");

// adjtimex / clock_adjtime mode bits (subset we recognise).
constexpr u32 kAdjOffset = 0x0001;
constexpr u32 kAdjFrequency = 0x0002;
constexpr u32 kAdjMaxerror = 0x0004;
constexpr u32 kAdjEsterror = 0x0008;
constexpr u32 kAdjStatus = 0x0010;
constexpr u32 kAdjTimeconst = 0x0020;
constexpr u32 kAdjTai = 0x0080;
constexpr u32 kAdjSetoffset = 0x0100;
constexpr u32 kAdjMicro = 0x1000;
constexpr u32 kAdjNano = 0x2000;
constexpr u32 kAdjTick = 0x4000;

// Linux time-state return value from adjtimex(2). We always return
// TIME_ERROR (5) — the clock is unsynchronised because we have no
// NTP discipline. TIME_OK (0) is the value we'd return once a
// real discipline source lands.
constexpr i64 kTimeError = 5;

// Status-flag subset. STA_UNSYNC is the live signal: we have no NTP
// discipline, so callers that respect this flag (chrony, ntpd) will
// know not to trust the wall clock.
constexpr i32 kStaUnsync = 0x0040;

// Persisted NTP-shadow state. Real Linux derives `time` from the
// running clock and `offset/freq/...` from the kernel's PLL; we
// just remember whatever the caller wrote so a follow-up read sees
// it (matches Linux semantics for fields the kernel doesn't reject).
i32 g_ntp_status = kStaUnsync;
i64 g_ntp_constant = 2;
i64 g_ntp_tick = 10000; // 10 ms — matches our scheduler tick (100 Hz)
i32 g_ntp_tai = 0;

i64 DoClockAdjtime(u64 clk_id, u64 user_buf)
{
    // Only CLOCK_REALTIME accepts adjustments. Other clocks read OK
    // but mode-set bits return EINVAL — matches Linux contract.
    const bool clock_settable = (clk_id == kClockRealtime);

    if (user_buf == 0)
        return kEFAULT;

    LinuxTimex tx;
    if (!mm::CopyFromUser(&tx, reinterpret_cast<const void*>(user_buf), sizeof(tx)))
        return kEFAULT;

    const u32 modes = tx.modes;

    // Any mode bit that tries to mutate state needs the cap. A
    // pure-read query (modes == 0) is allowed for everyone — that
    // matches Linux, which lets unprivileged readers observe
    // STA_UNSYNC / current time without CAP_SYS_TIME.
    constexpr u32 kAnyMutate = kAdjOffset | kAdjFrequency | kAdjMaxerror | kAdjEsterror | kAdjStatus | kAdjTimeconst |
                               kAdjTick | kAdjTai | kAdjSetoffset;
    if (modes & kAnyMutate)
    {
        if (const i64 perm = CheckTimeSetCap(); perm != 0)
            return perm;
        if (!clock_settable)
            return kEINVAL;
    }

    // ADJ_SETOFFSET: time field carries an addend to apply to the
    // wall-clock offset. ADJ_NANO selects ns; default is us.
    if (modes & kAdjSetoffset)
    {
        const i64 sec = tx.time_tv_sec;
        const i64 frac = tx.time_tv_usec;
        const i64 frac_ns = (modes & kAdjNano) ? frac : frac * 1000;
        if (frac_ns < 0 || frac_ns >= 1'000'000'000)
            return kEINVAL;
        const i64 add_ns = sec * 1'000'000'000ll + frac_ns;
        g_realtime_offset_ns += add_ns;
    }

    // ADJ_OFFSET: a one-shot phase nudge. Real Linux feeds it into
    // the PLL; we have no PLL, so we just apply it directly to the
    // realtime offset (best behaviour we can offer without slewing).
    if (modes & kAdjOffset)
    {
        const i64 raw = tx.offset;
        const i64 add_ns = (modes & kAdjNano) ? raw : raw * 1000;
        g_realtime_offset_ns += add_ns;
    }

    // Bookkeeping fields — accept-and-store so a follow-up read sees
    // the same value back. Frequency / PLL fields are accept-and-
    // ignore (we have no discipline machinery).
    if (modes & kAdjStatus)
        g_ntp_status = (tx.status & ~kStaUnsync) | kStaUnsync; // can't clear UNSYNC
    if (modes & kAdjTimeconst)
        g_ntp_constant = tx.constant;
    if (modes & kAdjTick)
        g_ntp_tick = tx.tick;
    if (modes & kAdjTai)
        g_ntp_tai = tx.tai;

    // Fill read-back fields. `time` reports current wall clock at
    // the moment of the call; the rest reflect persisted state.
    const u64 now_real_ns = RealtimeNs();
    LinuxTimex out{};
    out.modes = modes;
    out.offset = 0; // we don't accumulate a phase residual
    out.freq = 0;
    out.maxerror = 0;
    out.esterror = 0;
    out.status = g_ntp_status;
    out.constant = g_ntp_constant;
    out.precision = 1;
    out.tolerance = 0;
    out.time_tv_sec = static_cast<i64>(now_real_ns / 1'000'000'000ull);
    out.time_tv_usec = static_cast<i64>((now_real_ns / 1000ull) % 1'000'000ull);
    if (modes & kAdjMicro)
        out.time_tv_usec = static_cast<i64>((now_real_ns / 1000ull) % 1'000'000ull);
    if (modes & kAdjNano)
        out.time_tv_usec = static_cast<i64>(now_real_ns % 1'000'000'000ull);
    out.tick = g_ntp_tick;
    out.tai = g_ntp_tai;

    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &out, sizeof(out)))
        return kEFAULT;

    // Always TIME_ERROR while unsynced — chrony / ntpd treat this as
    // "I am the discipline source, please don't slew off me."
    return kTimeError;
}

i64 DoAdjtimex(u64 user_buf)
{
    return DoClockAdjtime(kClockRealtime, user_buf);
}

} // namespace duetos::subsystems::linux::internal
