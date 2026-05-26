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

#include "subsystems/linux/syscall_internal.h"

#include "diag/fix_journal.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "sched/sched.h"

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

// Resolve `pid` (Linux thread id; 0 means "the calling thread") to
// a target Task, applying the cross-thread-group permission check.
// On success, returns the target Task and, when a Process retain was
// taken, sets `*retained` to the owner Process so the caller can
// `core::ProcessRelease` it once the affinity write has committed.
// On any failure, returns nullptr with `*errno_out` set to the Linux
// errno to surface (kESRCH / kEPERM).
//
// Same lookup shape as SYS_THREAD_OPEN (kernel/syscall/syscall.cpp).
// The window between `SchedFindTaskByTid` returning and
// `ProcessRetain` taking the reference is small and matches the
// existing accepted risk for foreign-thread handle acquisition.
namespace
{
sched::Task* ResolveAffinityTarget(u64 pid, core::Process** retained, i64* errno_out)
{
    *retained = nullptr;
    if (pid == 0)
    {
        sched::Task* self = sched::CurrentTask();
        if (self == nullptr)
        {
            *errno_out = kEINVAL;
            return nullptr;
        }
        return self;
    }
    sched::Task* found = sched::SchedFindTaskByTid(pid);
    if (found == nullptr)
    {
        *errno_out = kESRCH;
        return nullptr;
    }
    core::Process* owner = sched::TaskProcess(found);
    if (owner == nullptr)
    {
        // Kernel-only Task — no Linux thread identity.
        *errno_out = kESRCH;
        return nullptr;
    }
    if (owner != core::CurrentProcess())
    {
        // Cross-thread-group affinity requires CAP_SYS_NICE on
        // Linux; kCapDebug is our closest analog.
        core::Process* caller = core::CurrentProcess();
        if (caller == nullptr || !core::CapSetHas(caller->caps, core::kCapDebug))
        {
            *errno_out = kEPERM;
            return nullptr;
        }
    }
    core::ProcessRetain(owner);
    *retained = owner;
    return found;
}
} // namespace

// sched_setaffinity(pid, cpusetsize, mask): hard-pin the target
// thread to a CPU set. The kernel cpumask is 32 bits wide
// (acpi::kMaxCpus); we consume the low 4 bytes of the user
// cpu_set_t and hand them to the scheduler, which intersects with
// the online set and rejects an empty result.
i64 DoSchedSetaffinity(u64 pid, u64 cpusetsize, u64 user_mask)
{
    if (user_mask == 0)
        return kEFAULT;
    if (cpusetsize == 0)
        return kEINVAL;
    u8 raw[8] = {0};
    const u64 to_copy = cpusetsize < sizeof(raw) ? cpusetsize : sizeof(raw);
    if (!mm::CopyFromUser(raw, reinterpret_cast<const void*>(user_mask), to_copy))
        return kEFAULT;
    u32 mask = 0;
    for (u32 i = 0; i < to_copy && i < 4u; ++i)
        mask |= static_cast<u32>(raw[i]) << (i * 8u);
    if (mask == 0)
        return kEINVAL;
    core::Process* retained = nullptr;
    i64 errno_out = 0;
    sched::Task* target = ResolveAffinityTarget(pid, &retained, &errno_out);
    if (target == nullptr)
        return errno_out;
    // SchedSetAffinityMask intersects with the online set and
    // fails when nothing is left — surface that as -EINVAL, the
    // errno Linux returns for a mask with no usable CPU.
    const bool ok = sched::SchedSetAffinityMask(target, mask);
    if (retained != nullptr)
        core::ProcessRelease(retained);
    if (!ok)
        return kEINVAL;
    return 0;
}

// sched_getaffinity: report the target thread's effective mask.
// Linux returns the number of bytes written into the user buffer.
i64 DoSchedGetaffinity(u64 pid, u64 cpusetsize, u64 user_mask)
{
    if (user_mask == 0)
        return kEFAULT;
    const u64 bytes = (cpusetsize < 8) ? cpusetsize : 8;
    if (bytes == 0)
        return kEINVAL;
    core::Process* retained = nullptr;
    i64 errno_out = 0;
    sched::Task* target = ResolveAffinityTarget(pid, &retained, &errno_out);
    if (target == nullptr)
        return errno_out;
    const u32 m = sched::SchedGetAffinityMask(target);
    if (retained != nullptr)
        core::ProcessRelease(retained);
    u8 out[8] = {0};
    for (u32 i = 0; i < 4u; ++i)
        out[i] = static_cast<u8>((m >> (i * 8u)) & 0xFFu);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_mask), out, bytes))
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
