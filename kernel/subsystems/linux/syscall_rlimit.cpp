/*
 * DuetOS — Linux ABI: resource-limit handlers.
 *
 * Sibling TU of syscall.cpp. Houses getrlimit / setrlimit /
 * prlimit64. v0 has no per-process limit policy, so the values
 * come from a fixed RlimitDefaultsFor table reflecting the real
 * ceilings the kernel currently honours (NOFILE 16, NPROC 64,
 * STACK 64 KiB, NICE 20) and RLIM_INFINITY for everything else.
 *
 * The dispatcher in syscall.cpp calls these via the
 * `internal::Do*` declarations in syscall_internal.h.
 */

#include "syscall_internal.h"

#include "../../mm/address_space.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Linux RLIMIT_* values per the kernel uapi/linux/resource.h.
// Kept TU-private here so the rlimit handlers below stay self-
// contained; these are stable ABI numbers, not adjustable.
constexpr u64 kRlimitCpu = 0;
constexpr u64 kRlimitFsize = 1;
constexpr u64 kRlimitData = 2;
constexpr u64 kRlimitStack = 3;
constexpr u64 kRlimitCore = 4;
constexpr u64 kRlimitRss = 5;
constexpr u64 kRlimitNproc = 6;
constexpr u64 kRlimitNofile = 7;
constexpr u64 kRlimitMemlock = 8;
constexpr u64 kRlimitAs = 9;
constexpr u64 kRlimitLocks = 10;
constexpr u64 kRlimitSigpending = 11;
constexpr u64 kRlimitMsgqueue = 12;
constexpr u64 kRlimitNice = 13;
constexpr u64 kRlimitRtprio = 14;
constexpr u64 kRlimitRttime = 15;
constexpr u64 kRlimitNlimits = 16;

constexpr u64 kRlimInfinity = 0xFFFFFFFFFFFFFFFFull;

// Resolve a Linux RLIMIT_* into the (cur, max) pair this kernel
// honours. The numbers reflect actual capacities where we have one
// (linux_fds[16] → NOFILE 16, MAX_SCHED_TASKS → NPROC 64), and
// "no policy in v0" otherwise (RLIM_INFINITY). Matches the shape
// glibc / musl / libcap probe at startup so static-musl programs
// aren't surprised by a mismatched limit.
void RlimitDefaultsFor(u64 resource, u64& cur, u64& max)
{
    switch (resource)
    {
    case kRlimitNofile:
        cur = 16;
        max = 16;
        return;
    case kRlimitNproc:
        cur = 64;
        max = 64;
        return;
    case kRlimitStack:
        // 64 KiB matches the ring-3 stack the loader maps per task;
        // a future grow-on-fault stack would raise this to 8 MiB.
        cur = 64 * 1024;
        max = 64 * 1024;
        return;
    case kRlimitCore:
        // No core dumps written from user-mode (we have crash-dump
        // for the kernel; ring-3 dumps are a future slice).
        cur = 0;
        max = kRlimInfinity;
        return;
    case kRlimitNice:
        // Linux reports RLIMIT_NICE as `20 - nice_floor`. Flat
        // scheduler → nice 0 → ceiling 20.
        cur = 20;
        max = 20;
        return;
    case kRlimitRtprio:
        // No real-time priority class yet.
        cur = 0;
        max = 0;
        return;
    case kRlimitCpu:
    case kRlimitFsize:
    case kRlimitData:
    case kRlimitRss:
    case kRlimitMemlock:
    case kRlimitAs:
    case kRlimitLocks:
    case kRlimitSigpending:
    case kRlimitMsgqueue:
    case kRlimitRttime:
        cur = kRlimInfinity;
        max = kRlimInfinity;
        return;
    default:
        cur = kRlimInfinity;
        max = kRlimInfinity;
        return;
    }
}

} // namespace

// Linux: getrlimit(resource, rlim). Returns the per-resource
// (cur, max) pair. v0 has no per-process policy state, so the
// values come straight from RlimitDefaultsFor — they're constants
// for the lifetime of the kernel.
i64 DoGetrlimit(u64 resource, u64 user_old)
{
    if (resource >= kRlimitNlimits)
        return kEINVAL;
    if (user_old == 0)
        return kEFAULT;
    struct
    {
        u64 cur;
        u64 max;
    } old{};
    RlimitDefaultsFor(resource, old.cur, old.max);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), &old, sizeof(old)))
        return kEFAULT;
    return 0;
}

// Linux: prlimit64(pid, resource, new_limit, old_limit). pid==0
// means "this process". v0 only knows about the calling process,
// so any non-zero pid that doesn't match the caller is -ESRCH —
// but we don't track pid->process either, so accept any pid.
// Hard cap on writable resources: anything tightening max below
// our actual capacity (NOFILE down from 16, NPROC down from 64)
// is rejected with -EINVAL because the kernel can't honour it.
i64 DoPrlimit64(u64 pid, u64 resource, u64 user_new, u64 user_old)
{
    (void)pid;
    if (resource >= kRlimitNlimits)
        return kEINVAL;
    if (user_old != 0)
    {
        struct
        {
            u64 cur;
            u64 max;
        } old{};
        RlimitDefaultsFor(resource, old.cur, old.max);
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), &old, sizeof(old)))
            return kEFAULT;
    }
    if (user_new != 0)
    {
        struct
        {
            u64 cur;
            u64 max;
        } new_lim{};
        if (!mm::CopyFromUser(&new_lim, reinterpret_cast<const void*>(user_new), sizeof(new_lim)))
            return kEFAULT;
        if (new_lim.cur > new_lim.max)
            return kEINVAL;
        // Reject attempts to raise max above our hard cap for the
        // resources where we have a real ceiling.
        u64 def_cur = 0, def_max = 0;
        RlimitDefaultsFor(resource, def_cur, def_max);
        if (def_max != kRlimInfinity && new_lim.max > def_max)
            return kEPERM;
        // Accept the call but keep no per-process record — next
        // getrlimit will report defaults again.
    }
    return 0;
}

// Linux: setrlimit(resource, new). Routes through the prlimit64
// path (no old_limit, pid=self).
i64 DoSetrlimit(u64 resource, u64 user_new)
{
    return DoPrlimit64(0, resource, user_new, 0);
}

} // namespace duetos::subsystems::linux::internal
