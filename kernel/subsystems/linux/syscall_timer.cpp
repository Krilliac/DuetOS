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
// timer).
void LinuxAlarmCheckAndRaise(::duetos::core::Process* p)
{
    if (p == nullptr || p->linux_alarm_deadline_ns == 0)
        return;
    const u64 now = ::duetos::time::MonotonicNs();
    if (now < p->linux_alarm_deadline_ns)
        return;
    // Deadline reached — raise SIGALRM.
    p->linux_pending_signals |= (1ULL << kSigAlrm);
    if (p->linux_alarm_interval_ns > 0)
    {
        // Auto-rearm. Round forward by integer multiples of
        // the interval so we don't re-fire 100 times in a row
        // for a long-blocked process.
        u64 missed = (now - p->linux_alarm_deadline_ns) / p->linux_alarm_interval_ns + 1;
        p->linux_alarm_deadline_ns += missed * p->linux_alarm_interval_ns;
    }
    else
    {
        p->linux_alarm_deadline_ns = 0;
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
// POSIX timers (timer_create / timer_settime / ...).
// =============================================================

// timer_create needs a per-process timer table to allocate ids
// from. v0 doesn't have one yet; -ENOSYS is the documented
// Linux response when CONFIG_POSIX_TIMERS is off, and is what
// glibc handles by falling back to alarm/setitimer (which we
// DO implement properly). When per-process timer storage
// lands, this becomes a real allocation.
i64 DoTimerCreate(u64 clockid, u64 sevp, u64 user_timerid)
{
    (void)clockid;
    (void)sevp;
    (void)user_timerid;
    return kENOSYS;
}

// timer_settime / timer_gettime / timer_getoverrun / timer_delete:
// since timer_create returns -ENOSYS, no valid timerid exists;
// any reference is invalid -> -EINVAL.
i64 DoTimerSettime(u64 timerid, u64 flags, u64 user_new, u64 user_old)
{
    (void)timerid;
    (void)flags;
    (void)user_new;
    (void)user_old;
    return kEINVAL;
}
i64 DoTimerGettime(u64 timerid, u64 user_curr)
{
    (void)timerid;
    (void)user_curr;
    return kEINVAL;
}
i64 DoTimerGetoverrun(u64 timerid)
{
    (void)timerid;
    return kEINVAL;
}
i64 DoTimerDelete(u64 timerid)
{
    (void)timerid;
    return kEINVAL;
}

} // namespace duetos::subsystems::linux::internal
