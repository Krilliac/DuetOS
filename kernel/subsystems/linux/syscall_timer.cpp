/*
 * DuetOS — Linux ABI: alarm + interval timers + POSIX timers.
 *
 * Real implementation backed by per-process state:
 *   linux_alarm_deadline_ns — absolute MonotonicNs deadline for
 *       the ITIMER_REAL slot. SIGALRM (signum 14) is raised
 *       when the deadline is reached.
 *   linux_alarm_interval_ns — auto-rearm interval (0 = one-shot).
 *
 * Delivery model: v0 has no per-tick callback hook in the
 * scheduler, so the deadline is checked at every syscall
 * return inside LinuxSyscallDispatch (see CheckAlarmDeadline
 * in this file, called from the dispatcher). When the deadline
 * has passed, SIGALRM is OR'd into linux_pending_signals and
 * the next LinuxSignalCheckAndDeliver run picks it up. The
 * latency is "next syscall the process makes" rather than
 * "exactly at deadline" — fine for the SIGALRM common case
 * where callers issue read/poll/sleep in a loop.
 *
 * ITIMER_VIRTUAL / ITIMER_PROF are accepted but never fire —
 * we don't track per-process user/system CPU time at the
 * granularity needed for them. That's a documented sub-GAP.
 *
 * POSIX timers (timer_create / timer_settime etc.) need a
 * timer table per Process. The v0 Process struct doesn't have
 * one yet; the handlers here return -ENOSYS for create and
 * -EINVAL for ops on a non-existent timerid (which is every
 * timerid since we never hand any out). When per-process
 * timer storage lands, those handlers become real.
 */

#include "subsystems/linux/syscall_internal.h"

#include "mm/paging.h"
#include "proc/process.h"
#include "time/timekeeper.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr u64 kNsPerSec = 1000000000ULL;
constexpr u64 kSigAlrm = 14; // POSIX SIGALRM number.

// Linux's struct itimerval: two timeval pairs (it_interval,
// it_value), each {sec, usec}. 32 bytes total on 64-bit.
struct UserItimerval
{
    i64 it_interval_sec;
    i64 it_interval_usec;
    i64 it_value_sec;
    i64 it_value_usec;
};

// Linux's struct timespec: {sec, nsec}.
struct UserTimespec
{
    i64 sec;
    i64 nsec;
};

u64 NsFromTimevalParts(i64 sec, i64 usec)
{
    if (sec < 0)
        sec = 0;
    if (usec < 0)
        usec = 0;
    return static_cast<u64>(sec) * kNsPerSec + static_cast<u64>(usec) * 1000ULL;
}

void NsToTimevalParts(u64 ns, i64& sec, i64& usec)
{
    sec = static_cast<i64>(ns / kNsPerSec);
    usec = static_cast<i64>((ns % kNsPerSec) / 1000ULL);
}

constexpr u64 kItimerReal = 0;
constexpr u64 kItimerVirtual = 1;
constexpr u64 kItimerProf = 2;

} // namespace

// Called by the dispatcher after each syscall returns and
// before LinuxSignalCheckAndDeliver. If the alarm deadline
// has been reached, raise SIGALRM (and re-arm if interval
// timer). Also walks the per-process POSIX timer table and
// fires each elapsed timer's configured signal.
void LinuxAlarmCheckAndRaise(::duetos::core::Process* p)
{
    if (p == nullptr)
        return;
    const u64 now = ::duetos::time::MonotonicNs();

    // ITIMER_REAL slot.
    if (p->linux_alarm_deadline_ns != 0 && now >= p->linux_alarm_deadline_ns)
    {
        p->linux_pending_signals |= (1ULL << kSigAlrm);
        if (p->linux_alarm_interval_ns > 0)
        {
            u64 missed = (now - p->linux_alarm_deadline_ns) / p->linux_alarm_interval_ns + 1;
            p->linux_alarm_deadline_ns += missed * p->linux_alarm_interval_ns;
        }
        else
        {
            p->linux_alarm_deadline_ns = 0;
        }
    }

    // POSIX per-process timer table.
    for (u32 i = 0; i < ::duetos::core::Process::kLinuxTimerCap; ++i)
    {
        auto& t = p->linux_posix_timers[i];
        if (!t.in_use || t.deadline_ns == 0 || now < t.deadline_ns)
            continue;
        // Fire — OR signal into pending and tick the overrun
        // counter for every interval the process slept past
        // the deadline (Linux's "overrun" semantics).
        const u32 signo = (t.signo == 0) ? static_cast<u32>(kSigAlrm) : t.signo;
        if (signo < 64)
            p->linux_pending_signals |= (1ULL << signo);
        if (t.interval_ns > 0)
        {
            const u64 missed = (now - t.deadline_ns) / t.interval_ns + 1;
            t.overrun += static_cast<u32>(missed > 0xFFFFFFFFu ? 0xFFFFFFFFu : missed);
            t.deadline_ns += missed * t.interval_ns;
        }
        else
        {
            t.deadline_ns = 0;
        }
    }
}

// alarm(seconds) — schedule SIGALRM after `seconds`. Returns
// the seconds remaining on the prior alarm (0 if none). 0
// cancels any pending alarm.
i64 DoAlarm(u64 seconds)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return 0;
    const u64 now = ::duetos::time::MonotonicNs();

    // Compute remaining seconds on the prior alarm.
    u64 prior_remaining_sec = 0;
    if (p->linux_alarm_deadline_ns > now)
        prior_remaining_sec = (p->linux_alarm_deadline_ns - now + kNsPerSec - 1) / kNsPerSec;

    if (seconds == 0)
    {
        p->linux_alarm_deadline_ns = 0;
        p->linux_alarm_interval_ns = 0;
    }
    else
    {
        p->linux_alarm_deadline_ns = now + seconds * kNsPerSec;
        p->linux_alarm_interval_ns = 0; // alarm(2) is one-shot
    }
    return static_cast<i64>(prior_remaining_sec);
}

// getitimer(which, value) — read the current interval timer.
// Only ITIMER_REAL has real state; the other two report a
// zeroed itimerval.
i64 DoGetitimer(u64 which, u64 user_value)
{
    if (which > kItimerProf)
        return kEINVAL;
    auto* p = ::duetos::core::CurrentProcess();
    UserItimerval out = {};
    if (which == kItimerReal && p != nullptr)
    {
        const u64 now = ::duetos::time::MonotonicNs();
        u64 remaining = 0;
        if (p->linux_alarm_deadline_ns > now)
            remaining = p->linux_alarm_deadline_ns - now;
        NsToTimevalParts(remaining, out.it_value_sec, out.it_value_usec);
        NsToTimevalParts(p->linux_alarm_interval_ns, out.it_interval_sec, out.it_interval_usec);
    }
    if (user_value != 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_value), &out, sizeof(out)))
            return kEFAULT;
    }
    return 0;
}

// setitimer(which, new_value, old_value) — install a new
// interval timer. ITIMER_REAL fires SIGALRM via the
// dispatcher hook; the other two are accepted but never
// fire (sub-GAP).
i64 DoSetitimer(u64 which, u64 user_new, u64 user_old)
{
    if (which > kItimerProf)
        return kEINVAL;
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEINVAL;

    UserItimerval new_val = {};
    if (user_new != 0)
    {
        if (!mm::CopyFromUser(&new_val, reinterpret_cast<const void*>(user_new), sizeof(new_val)))
            return kEFAULT;
    }

    // Capture the prior state for old_value before mutating.
    UserItimerval old_val = {};
    const u64 now = ::duetos::time::MonotonicNs();
    if (which == kItimerReal)
    {
        u64 remaining = 0;
        if (p->linux_alarm_deadline_ns > now)
            remaining = p->linux_alarm_deadline_ns - now;
        NsToTimevalParts(remaining, old_val.it_value_sec, old_val.it_value_usec);
        NsToTimevalParts(p->linux_alarm_interval_ns, old_val.it_interval_sec, old_val.it_interval_usec);

        const u64 new_value_ns = NsFromTimevalParts(new_val.it_value_sec, new_val.it_value_usec);
        const u64 new_interval_ns = NsFromTimevalParts(new_val.it_interval_sec, new_val.it_interval_usec);
        if (new_value_ns == 0)
        {
            p->linux_alarm_deadline_ns = 0;
            p->linux_alarm_interval_ns = 0;
        }
        else
        {
            p->linux_alarm_deadline_ns = now + new_value_ns;
            p->linux_alarm_interval_ns = new_interval_ns;
        }
    }
    // ITIMER_VIRTUAL / ITIMER_PROF: accept silently, no state.

    if (user_old != 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), &old_val, sizeof(old_val)))
            return kEFAULT;
    }
    return 0;
}

// =============================================================
// POSIX timers (timer_create / timer_settime / ...). Real
// implementation backed by Process::linux_posix_timers[8].
// Each timer carries a deadline + interval + signo; the
// LinuxAlarmCheckAndRaise hook above walks the table on
// every syscall return and fires elapsed timers.
// =============================================================

namespace
{

// struct sigevent layout — 64 bytes on 64-bit. We only read
// sigev_signo (offset 0) and sigev_notify (offset 4); the
// notify_function / notify_attributes / notify_thread_id
// fields are advisory (we don't fork a notification thread
// in v0).
struct UserSigevent
{
    u32 sigev_signo;
    u32 sigev_notify;
    u64 sigev_value;
    u64 _pad[6];
};

struct UserItimerspec
{
    UserTimespec it_interval;
    UserTimespec it_value;
};

i32 AllocTimerSlot(::duetos::core::Process* p)
{
    for (u32 i = 0; i < ::duetos::core::Process::kLinuxTimerCap; ++i)
    {
        if (!p->linux_posix_timers[i].in_use)
            return static_cast<i32>(i);
    }
    return -1;
}

bool ValidTimerId(::duetos::core::Process* p, u64 timerid)
{
    return timerid < ::duetos::core::Process::kLinuxTimerCap && p->linux_posix_timers[timerid].in_use;
}

} // namespace

// timer_create(clockid, sevp, &timer_id) — allocate a slot,
// stash the configured signo (default SIGALRM if sevp NULL),
// hand back the slot index as the timer_id. The timer is
// disarmed (deadline_ns=0) until timer_settime arms it.
i64 DoTimerCreate(u64 clockid, u64 sevp, u64 user_timerid)
{
    (void)clockid; // We treat all clockids as CLOCK_MONOTONIC for the deadline check.
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    const i32 slot = AllocTimerSlot(p);
    if (slot < 0)
        return kEAGAIN;

    u32 signo = static_cast<u32>(kSigAlrm);
    if (sevp != 0)
    {
        UserSigevent sev = {};
        if (!mm::CopyFromUser(&sev, reinterpret_cast<const void*>(sevp), sizeof(sev)))
            return kEFAULT;
        if (sev.sigev_signo > 0 && sev.sigev_signo < 64)
            signo = sev.sigev_signo;
    }

    auto& t = p->linux_posix_timers[slot];
    t.deadline_ns = 0;
    t.interval_ns = 0;
    t.signo = signo;
    t.overrun = 0;
    t.in_use = 1;

    if (user_timerid != 0)
    {
        const u64 id = static_cast<u64>(slot);
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_timerid), &id, sizeof(id)))
        {
            t.in_use = 0;
            return kEFAULT;
        }
    }
    return 0;
}

// timer_settime(timerid, flags, new_value, old_value) — arm /
// disarm. flags: 0 = relative new_value.it_value, TIMER_ABSTIME
// (1) = absolute. old_value (if non-NULL) reports prior remaining
// + interval.
i64 DoTimerSettime(u64 timerid, u64 flags, u64 user_new, u64 user_old)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr || !ValidTimerId(p, timerid))
        return kEINVAL;

    UserItimerspec new_val = {};
    if (user_new == 0)
        return kEFAULT;
    if (!mm::CopyFromUser(&new_val, reinterpret_cast<const void*>(user_new), sizeof(new_val)))
        return kEFAULT;

    auto& t = p->linux_posix_timers[timerid];
    const u64 now = ::duetos::time::MonotonicNs();

    // Capture old state first.
    if (user_old != 0)
    {
        UserItimerspec old_val = {};
        u64 remaining = 0;
        if (t.deadline_ns > now)
            remaining = t.deadline_ns - now;
        NsToTimevalParts(remaining, old_val.it_value.sec, old_val.it_value.nsec);
        // Note: it_value.nsec stores nsec already (timespec is sec+nsec, not sec+usec).
        old_val.it_value.nsec = static_cast<i64>(remaining % kNsPerSec);
        old_val.it_value.sec = static_cast<i64>(remaining / kNsPerSec);
        old_val.it_interval.sec = static_cast<i64>(t.interval_ns / kNsPerSec);
        old_val.it_interval.nsec = static_cast<i64>(t.interval_ns % kNsPerSec);
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), &old_val, sizeof(old_val)))
            return kEFAULT;
    }

    const u64 new_value_ns =
        static_cast<u64>(new_val.it_value.sec) * kNsPerSec + static_cast<u64>(new_val.it_value.nsec);
    const u64 new_interval_ns =
        static_cast<u64>(new_val.it_interval.sec) * kNsPerSec + static_cast<u64>(new_val.it_interval.nsec);

    if (new_value_ns == 0)
    {
        t.deadline_ns = 0;
        t.interval_ns = 0;
    }
    else
    {
        constexpr u64 kTimerAbstime = 1;
        if ((flags & kTimerAbstime) != 0)
            t.deadline_ns = new_value_ns; // absolute monotonic time
        else
            t.deadline_ns = now + new_value_ns;
        t.interval_ns = new_interval_ns;
        t.overrun = 0;
    }
    return 0;
}

// timer_gettime(timerid, curr_value) — read remaining + interval.
i64 DoTimerGettime(u64 timerid, u64 user_curr)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr || !ValidTimerId(p, timerid))
        return kEINVAL;
    if (user_curr == 0)
        return kEFAULT;

    auto& t = p->linux_posix_timers[timerid];
    const u64 now = ::duetos::time::MonotonicNs();
    u64 remaining = 0;
    if (t.deadline_ns > now)
        remaining = t.deadline_ns - now;
    UserItimerspec out = {};
    out.it_value.sec = static_cast<i64>(remaining / kNsPerSec);
    out.it_value.nsec = static_cast<i64>(remaining % kNsPerSec);
    out.it_interval.sec = static_cast<i64>(t.interval_ns / kNsPerSec);
    out.it_interval.nsec = static_cast<i64>(t.interval_ns % kNsPerSec);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_curr), &out, sizeof(out)))
        return kEFAULT;
    return 0;
}

// timer_getoverrun(timerid) — drain the missed-fires count for
// the most recent expiration. Linux returns the count and resets
// the per-timer counter to zero.
i64 DoTimerGetoverrun(u64 timerid)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr || !ValidTimerId(p, timerid))
        return kEINVAL;
    const u32 n = p->linux_posix_timers[timerid].overrun;
    p->linux_posix_timers[timerid].overrun = 0;
    return static_cast<i64>(n);
}

// timer_delete(timerid) — release the slot.
i64 DoTimerDelete(u64 timerid)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr || !ValidTimerId(p, timerid))
        return kEINVAL;
    p->linux_posix_timers[timerid].in_use = 0;
    p->linux_posix_timers[timerid].deadline_ns = 0;
    p->linux_posix_timers[timerid].interval_ns = 0;
    p->linux_posix_timers[timerid].overrun = 0;
    return 0;
}

} // namespace duetos::subsystems::linux::internal
