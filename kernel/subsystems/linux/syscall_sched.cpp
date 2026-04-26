/*
 * DuetOS — Linux ABI: scheduler-policy handlers.
 *
 * Sibling TU of syscall.cpp. Houses sched_setaffinity /
 * sched_getaffinity / sched_{get,set}scheduler /
 * sched_{get,set}param / sched_get_priority_{max,min} /
 * sched_rr_get_interval. v0 has one real scheduler (round-robin
 * kernel threads) and BSP-only SMP, so every handler reports
 * SCHED_OTHER on CPU 0 and rejects real-time class transitions
 * with -EPERM.
 *
 * sched_yield lives with the rest of the process-control entry
 * points; this TU is exclusively the policy / affinity surface.
 */

#include "syscall_internal.h"

#include "../../mm/address_space.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Linux scheduling-policy constants (uapi/linux/sched.h). Kept
// TU-private here so the sched handlers stay self-contained.
constexpr i64 kSchedNormal = 0; // SCHED_OTHER
constexpr i64 kSchedFifo = 1;
constexpr i64 kSchedRr = 2;
constexpr i64 kSchedBatch = 3;
constexpr i64 kSchedIdle = 5;

} // namespace

// sched_setaffinity(pid, cpusetsize, mask): pin to CPU set.
// SMP is BSP-only in v0; CPU 0 is the only valid affinity.
// Accept any mask; the call is a no-op.
i64 DoSchedSetaffinity(u64 pid, u64 cpusetsize, u64 user_mask)
{
    (void)pid;
    (void)cpusetsize;
    (void)user_mask;
    return 0;
}

// sched_getaffinity: return a mask with only CPU 0 set. Linux's
// returns the number of bytes actually written (usually 8).
i64 DoSchedGetaffinity(u64 pid, u64 cpusetsize, u64 user_mask)
{
    (void)pid;
    if (user_mask == 0)
        return kEFAULT;
    // Write 8 bytes: bit 0 set for CPU 0, rest zero.
    const u64 bytes = (cpusetsize < 8) ? cpusetsize : 8;
    if (bytes == 0)
        return kEINVAL;
    u8 mask[8] = {0x01, 0, 0, 0, 0, 0, 0, 0};
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_mask), mask, bytes))
        return kEFAULT;
    return static_cast<i64>(bytes);
}

// sched_getscheduler(pid): which policy is this task on. We have
// one real scheduler (round-robin kernel threads) and no policy
// classes. Returning SCHED_OTHER matches what every nice-aware
// program expects for a "default" task.
i64 DoSchedGetscheduler(u64 pid)
{
    (void)pid;
    return kSchedNormal;
}

// sched_setscheduler(pid, policy, param). Only SCHED_OTHER /
// SCHED_BATCH / SCHED_IDLE accepted (the non-RT classes); RT
// classes refuse with -EPERM since we have no RT runqueue. Param
// is read for input validation but otherwise ignored.
i64 DoSchedSetscheduler(u64 pid, u64 policy, u64 user_param)
{
    (void)pid;
    if (user_param != 0)
    {
        i32 prio = 0;
        if (!mm::CopyFromUser(&prio, reinterpret_cast<const void*>(user_param), sizeof(prio)))
            return kEFAULT;
        // Only SCHED_OTHER / BATCH / IDLE accept prio==0.
        if (prio != 0 && (policy == kSchedNormal || policy == kSchedBatch || policy == kSchedIdle))
            return kEINVAL;
    }
    switch (policy)
    {
    case kSchedNormal:
    case kSchedBatch:
    case kSchedIdle:
        return 0;
    case kSchedFifo:
    case kSchedRr:
        return kEPERM;
    default:
        return kEINVAL;
    }
}

// sched_getparam(pid, param): read the task's nice param. Flat
// scheduler → prio is always 0.
i64 DoSchedGetparam(u64 pid, u64 user_param)
{
    (void)pid;
    if (user_param == 0)
        return kEFAULT;
    i32 prio = 0;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_param), &prio, sizeof(prio)))
        return kEFAULT;
    return 0;
}

// sched_setparam(pid, param): write nice. Only prio==0 is valid
// for SCHED_OTHER (the only class we support); anything else is
// -EINVAL.
i64 DoSchedSetparam(u64 pid, u64 user_param)
{
    (void)pid;
    if (user_param == 0)
        return kEFAULT;
    i32 prio = 0;
    if (!mm::CopyFromUser(&prio, reinterpret_cast<const void*>(user_param), sizeof(prio)))
        return kEFAULT;
    if (prio != 0)
        return kEINVAL;
    return 0;
}

// sched_get_priority_max/min(policy): static priority range for
// the policy. SCHED_OTHER has 0..0; SCHED_FIFO/RR would have
// 1..99 on Linux but we reject those classes — return a sane
// 0 anyway so a probing libc doesn't trip an assert.
i64 DoSchedGetPriorityMax(u64 policy)
{
    switch (policy)
    {
    case kSchedNormal:
    case kSchedBatch:
    case kSchedIdle:
        return 0;
    case kSchedFifo:
    case kSchedRr:
        // Report the canonical Linux range so probes see a sane
        // answer even though setscheduler will refuse.
        return 99;
    default:
        return kEINVAL;
    }
}
i64 DoSchedGetPriorityMin(u64 policy)
{
    switch (policy)
    {
    case kSchedNormal:
    case kSchedBatch:
    case kSchedIdle:
        return 0;
    case kSchedFifo:
    case kSchedRr:
        return 1;
    default:
        return kEINVAL;
    }
}

// sched_rr_get_interval(pid, tp): the SCHED_RR time-slice. Our
// preemptive timer fires at 100 Hz → 10 ms.
i64 DoSchedRrGetInterval(u64 pid, u64 user_ts)
{
    (void)pid;
    if (user_ts == 0)
        return kEFAULT;
    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } ts = {0, 10'000'000};
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_ts), &ts, sizeof(ts)))
        return kEFAULT;
    return 0;
}

} // namespace duetos::subsystems::linux::internal
