/*
 * Win32 Job objects (NtCreateJobObject family).
 *
 * 8-job global pool. Each job is a refcounted container that
 * pins a list of Process pointers. AssignProcessToJobObject
 * pins; QueryInformationJobObject reports basic counters;
 * TerminateJobObject calls SchedKillByProcess on every member.
 * Handles run kJobHandleBase + idx (= 0xC00..0xC07).
 *
 * Ownership: the job handle space is a tiny global integer range,
 * not a per-process handle table. Every job records the pid of its
 * creator (`owner_pid`) and EVERY operation rejects a caller that
 * is not the owner. Without this, any PE holding kCapSpawnThread
 * could guess a handle in 0xC00..0xC07 and terminate / inspect /
 * close a job created by a different process — i.e. kill arbitrary
 * processes it has no handle to, which a native DuetOS process
 * cannot do (SYS_PROCESS_TERMINATE requires kCapDebug).
 *
 * Locking: `g_job_lock` (a real spinlock) serialises all pool
 * access. `arch::Cli/Sti` only masks interrupts on the local CPU,
 * so on SMP a peer CPU running SysJobClose could ProcessRelease a
 * member's Process* between Terminate's snapshot and its
 * SchedKillByProcess — a use-after-free. The kill happens OUTSIDE
 * the lock (SchedKillByProcess may block / take scheduler locks),
 * with each victim ProcessRetain'd before the lock drops so it
 * survives the unlocked window.
 *
 * (Formerly the job half of iocp_job.cpp — the IOCP half
 * migrated to the KObject-shaped ipc::IocpPort + kobj_handles;
 * see iocp_syscall.cpp.)
 *
 * Sub-GAPs:
 *   - JobObject information classes other than
 *     BasicProcessIdList / BasicAccountingInformation /
 *     BasicAndIoAccountingInformation return -EINVAL.
 *   - Job per-resource limits (CpuRate / WorkingSet / etc.)
 *     stored but not enforced.
 */

#include "subsystems/win32/job_syscall.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u32 kJobPoolCap = 8;
constexpr u32 kJobMaxProcs = 32;
constexpr u64 kJobHandleBase = 0xC00ULL;

struct JobMember
{
    bool in_use;
    u8 _pad[7];
    core::Process* proc; // refcount held while in_use
};

struct JobObject
{
    bool in_use;
    bool terminated;
    u8 _pad[2];
    u32 refs;       // open handles
    u32 proc_count; // current member count
    u32 total_terminated_procs;
    u32 _pad2;
    u64 owner_pid;            // creator pid — only the owner may operate on the job
    u64 active_process_limit; // 0 = unlimited
    u64 cpu_seconds_limit;    // 0 = unlimited
    JobMember members[kJobMaxProcs];
};

JobObject g_job_pool[kJobPoolCap];
sync::SpinLock g_job_lock{};

// Resolve a job handle to its pool slot IFF it is live AND owned by
// `caller`. MUST be called with g_job_lock held. Returns nullptr on a
// bad handle, a dead slot, or a foreign owner.
JobObject* ResolveOwnedJobLocked(u64 job_handle, const core::Process* caller)
{
    if (caller == nullptr)
        return nullptr;
    if (job_handle < kJobHandleBase || job_handle >= kJobHandleBase + kJobPoolCap)
        return nullptr;
    const u32 idx = static_cast<u32>(job_handle - kJobHandleBase);
    JobObject& j = g_job_pool[idx];
    if (!j.in_use)
        return nullptr;
    if (j.owner_pid != static_cast<u64>(caller->pid))
        return nullptr;
    return &j;
}

i32 JobAlloc(u64 owner_pid)
{
    sync::SpinLockGuard guard(g_job_lock);
    for (u32 i = 0; i < kJobPoolCap; ++i)
    {
        if (!g_job_pool[i].in_use)
        {
            JobObject& j = g_job_pool[i];
            j.in_use = true;
            j.terminated = false;
            j.refs = 1;
            j.proc_count = 0;
            j.total_terminated_procs = 0;
            j.owner_pid = owner_pid;
            j.active_process_limit = 0;
            j.cpu_seconds_limit = 0;
            for (u32 m = 0; m < kJobMaxProcs; ++m)
                j.members[m].in_use = false;
            return static_cast<i32>(i);
        }
    }
    return -1;
}

} // namespace

i64 SysJobCreate()
{
    using ::duetos::core::kCapSpawnThread;
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return -1;
    if (!core::ProcessHasCap(proc, kCapSpawnThread))
    {
        core::RecordSandboxDenial(kCapSpawnThread);
        return -1;
    }
    const i32 idx = JobAlloc(static_cast<u64>(proc->pid));
    if (idx < 0)
        return -1;
    arch::SerialWrite("[win32/job] create handle=");
    arch::SerialWriteHex(static_cast<u64>(idx) + kJobHandleBase);
    arch::SerialWrite("\n");
    return static_cast<i64>(idx) + static_cast<i64>(kJobHandleBase);
}

i64 SysJobAssign(u64 job_handle, u64 process_handle)
{
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return -1;
    // Resolve process handle. Self (NtCurrentProcess() = -1) → caller.
    core::Process* target = nullptr;
    if (process_handle == static_cast<u64>(-1))
        target = caller;
    else if (process_handle >= core::Process::kWin32ProcessBase &&
             process_handle < core::Process::kWin32ProcessBase + core::Process::kWin32ProcessCap)
    {
        const u64 slot = process_handle - core::Process::kWin32ProcessBase;
        auto& h = caller->win32_proc_handles[slot];
        if (!h.in_use)
            return -1;
        target = h.target;
    }
    else
        return -1;
    if (target == nullptr)
        return -1;

    sync::SpinLockGuard guard(g_job_lock);
    JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
    if (jp == nullptr || jp->terminated)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobAssign job_handle bad/foreign", job_handle);
        return -1;
    }
    JobObject& j = *jp;
    if (j.active_process_limit > 0 && j.proc_count >= j.active_process_limit)
        return -1;
    // Check it isn't already a member.
    for (u32 m = 0; m < kJobMaxProcs; ++m)
        if (j.members[m].in_use && j.members[m].proc == target)
            return 0;
    for (u32 m = 0; m < kJobMaxProcs; ++m)
    {
        if (!j.members[m].in_use)
        {
            j.members[m].in_use = true;
            j.members[m].proc = target;
            ++j.proc_count;
            core::ProcessRetain(target);
            return 0;
        }
    }
    return -1;
}

i64 SysJobIsProcessIn(u64 job_handle, u64 process_handle, u64 user_out)
{
    bool in_job = false;
    if (job_handle == 0)
    {
        // "Is the process in ANY job?" — search every job.
        // For v0 we treat this as "no" since real Linux doesn't
        // attach jobs without explicit AssignProcess.
    }
    else
    {
        core::Process* caller = core::CurrentProcess();
        core::Process* target = nullptr;
        if (process_handle == static_cast<u64>(-1) || process_handle == 0)
            target = caller;
        else if (caller != nullptr && process_handle >= core::Process::kWin32ProcessBase &&
                 process_handle < core::Process::kWin32ProcessBase + core::Process::kWin32ProcessCap)
        {
            const u64 slot = process_handle - core::Process::kWin32ProcessBase;
            auto& h = caller->win32_proc_handles[slot];
            target = h.in_use ? h.target : nullptr;
        }
        if (target != nullptr)
        {
            sync::SpinLockGuard guard(g_job_lock);
            JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
            if (jp != nullptr)
            {
                for (u32 m = 0; m < kJobMaxProcs; ++m)
                    if (jp->members[m].in_use && jp->members[m].proc == target)
                    {
                        in_job = true;
                        break;
                    }
            }
        }
    }
    const u32 out = in_job ? 1u : 0u;
    if (user_out != 0)
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_out), &out, sizeof(out)))
            return -1;
    return 0;
}

i64 SysJobTerminate(u64 job_handle, u64 exit_code)
{
    (void)exit_code;
    core::Process* caller = core::CurrentProcess();

    // Snapshot the members under the lock, retaining each so it
    // survives the unlocked SchedKillByProcess window even if a peer
    // CPU closes the job concurrently.
    core::Process* snap[kJobMaxProcs];
    u32 nsnap = 0;
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
        if (jp == nullptr)
        {
            KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobTerminate job_handle bad/foreign", job_handle);
            return -1;
        }
        jp->terminated = true;
        for (u32 m = 0; m < kJobMaxProcs; ++m)
        {
            if (jp->members[m].in_use && jp->members[m].proc != nullptr)
            {
                core::ProcessRetain(jp->members[m].proc);
                snap[nsnap++] = jp->members[m].proc;
            }
        }
    }

    u32 killed = 0;
    for (u32 m = 0; m < nsnap; ++m)
    {
        sched::SchedKillByProcess(snap[m]);
        ++killed;
        core::ProcessRelease(snap[m]); // balance the retain above
    }

    if (killed > 0)
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
        if (jp != nullptr)
            jp->total_terminated_procs += killed;
    }
    return 0;
}

i64 SysJobQuery(u64 job_handle, u64 info_class, u64 user_buf, u64 buf_len)
{
    core::Process* caller = core::CurrentProcess();
    // info_class:
    //   2 = JobObjectBasicProcessIdList
    //   3 = JobObjectBasicAndIoAccountingInformation (subset)
    //   8 = JobObjectBasicAccountingInformation
    if (info_class == 2)
    {
        // struct JOBOBJECT_BASIC_PROCESS_ID_LIST {
        //   ULONG NumberOfAssignedProcesses;
        //   ULONG NumberOfProcessIdsInList;
        //   ULONG_PTR ProcessIdList[];  // up to NumberOfProcessIdsInList
        // }
        u64 list[2 + kJobMaxProcs];
        u64 needed = 0;
        {
            sync::SpinLockGuard guard(g_job_lock);
            JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
            if (jp == nullptr)
            {
                KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobQuery job_handle bad/foreign", job_handle);
                return -1;
            }
            list[0] = jp->proc_count;
            list[1] = 0;
            for (u32 m = 0; m < kJobMaxProcs; ++m)
                if (jp->members[m].in_use && jp->members[m].proc != nullptr)
                {
                    list[2 + list[1]] = jp->members[m].proc->pid;
                    ++list[1];
                }
            needed = (2 + list[1]) * sizeof(u64);
        }
        if (buf_len < needed)
            return -1;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), list, needed))
            return -1;
        return static_cast<i64>(needed);
    }
    if (info_class == 3 || info_class == 8)
    {
        // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION (40 bytes):
        //   LARGE_INTEGER TotalUserTime;            (0)
        //   LARGE_INTEGER TotalKernelTime;          (8)
        //   LARGE_INTEGER ThisPeriodTotalUserTime;  (16)
        //   LARGE_INTEGER ThisPeriodTotalKernelTime;(24)
        //   ULONG TotalPageFaultCount;              (32)
        //   ULONG TotalProcesses;                   (36)
        //   ULONG ActiveProcesses;                  (40)
        //   ULONG TotalTerminatedProcesses;         (44)
        // = 48 bytes
        u8 stage[112];
        for (u32 i = 0; i < sizeof(stage); ++i)
            stage[i] = 0;
        auto put32 = [&](u64 off, u32 v)
        {
            for (u32 i = 0; i < 4; ++i)
                stage[off + i] = static_cast<u8>((v >> (i * 8)) & 0xFF);
        };
        {
            sync::SpinLockGuard guard(g_job_lock);
            JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
            if (jp == nullptr)
            {
                KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobQuery job_handle bad/foreign", job_handle);
                return -1;
            }
            put32(36, jp->proc_count); // TotalProcesses (best-effort)
            put32(40, jp->proc_count); // ActiveProcesses
            put32(44, jp->total_terminated_procs);
        }
        const u64 needed = (info_class == 3) ? 112 : 48;
        if (buf_len < needed)
            return -1;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, needed))
            return -1;
        return static_cast<i64>(needed);
    }
    return -1;
}

i64 SysJobClose(u64 job_handle)
{
    core::Process* caller = core::CurrentProcess();

    // Release every member's process refcount AFTER dropping the lock
    // (ProcessRelease may run a destructor that takes other locks).
    core::Process* snap[kJobMaxProcs];
    u32 nsnap = 0;
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
        if (jp == nullptr || jp->refs == 0)
        {
            KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobClose job_handle bad/foreign", job_handle);
            return -1;
        }
        --jp->refs;
        if (jp->refs == 0)
        {
            for (u32 m = 0; m < kJobMaxProcs; ++m)
                if (jp->members[m].in_use && jp->members[m].proc != nullptr)
                    snap[nsnap++] = jp->members[m].proc;
            jp->in_use = false;
            jp->proc_count = 0;
            for (u32 m = 0; m < kJobMaxProcs; ++m)
                jp->members[m].in_use = false;
        }
    }
    for (u32 m = 0; m < nsnap; ++m)
        core::ProcessRelease(snap[m]);
    return 0;
}

} // namespace duetos::subsystems::win32
