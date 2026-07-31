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
#include "core/panic.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/string.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u32 kJobMaxProcs = 32;
constexpr u64 kJobGenerationMax = ((~0ULL) >> 1) >> 12;

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
    u64 generation;
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

u64 MakeJobHandle(u32 index, u64 generation)
{
    return (generation << 12) | (kJobHandleBase + index);
}

// Resolve a job handle to its pool slot IFF it is live AND owned by
// `caller`. MUST be called with g_job_lock held. Returns nullptr on a
// bad handle, a dead slot, or a foreign owner.
JobObject* ResolveOwnedJobLocked(u64 job_handle, const core::Process* caller)
{
    if (caller == nullptr)
        return nullptr;
    if (!IsJobHandle(job_handle))
        return nullptr;
    const u64 tag = job_handle & kJobHandleTagMask;
    const u32 idx = static_cast<u32>(tag - kJobHandleBase);
    const u64 generation = job_handle >> 12;
    JobObject& j = g_job_pool[idx];
    if (!j.in_use || j.generation != generation)
        return nullptr;
    if (j.owner_pid != static_cast<u64>(caller->pid))
        return nullptr;
    return &j;
}

i64 JobAlloc(u64 owner_pid)
{
    sync::SpinLockGuard guard(g_job_lock);
    for (u32 i = 0; i < kJobPoolCap; ++i)
    {
        if (!g_job_pool[i].in_use && g_job_pool[i].generation < kJobGenerationMax)
        {
            JobObject& j = g_job_pool[i];
            ++j.generation;
            j.in_use = true;
            j.terminated = false;
            j.refs = 1;
            j.proc_count = 0;
            j.total_terminated_procs = 0;
            j.owner_pid = owner_pid;
            j.active_process_limit = 0;
            j.cpu_seconds_limit = 0;
            for (u32 m = 0; m < kJobMaxProcs; ++m)
            {
                j.members[m].in_use = false;
                j.members[m].proc = nullptr;
            }
            return static_cast<i64>(MakeJobHandle(i, j.generation));
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
    const i64 handle = JobAlloc(static_cast<u64>(proc->pid));
    if (handle < 0)
        return -1;
    arch::SerialWrite("[win32/job] create handle=");
    arch::SerialWriteHex(static_cast<u64>(handle));
    arch::SerialWrite("\n");
    return handle;
}

i64 SysJobAssign(u64 job_handle, u64 process_handle)
{
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return -1;

    // Resolve and pin the target before taking g_job_lock. A concurrent
    // CloseHandle can detach the caller's slot immediately afterward,
    // but this operation keeps its own reference until it either transfers
    // that reference to the job membership or finishes unsuccessfully.
    core::Process* target = nullptr;
    if (process_handle == static_cast<u64>(-1))
    {
        target = caller;
        core::ProcessRetain(target);
    }
    else
    {
        target = core::ProcessLookupWin32ProcessHandleRetained(caller, process_handle);
    }
    if (target == nullptr)
        return -1;

    i64 result = -1;
    bool bad_job = false;
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
        if (jp == nullptr || jp->terminated)
        {
            bad_job = true;
        }
        else
        {
            JobObject& j = *jp;
            // Assignment is idempotent even when the active-process limit
            // is already full. Check existing membership before applying
            // the admission limit to a genuinely new member.
            for (u32 m = 0; m < kJobMaxProcs; ++m)
            {
                if (j.members[m].in_use && j.members[m].proc == target)
                {
                    result = 0;
                    break;
                }
            }
            if (result != 0 && (j.active_process_limit == 0 || j.proc_count < j.active_process_limit))
            {
                for (u32 m = 0; m < kJobMaxProcs; ++m)
                {
                    if (!j.members[m].in_use)
                    {
                        j.members[m].in_use = true;
                        j.members[m].proc = target;
                        ++j.proc_count;
                        target = nullptr; // membership adopts the pinned ref
                        result = 0;
                        break;
                    }
                }
            }
        }
    }
    if (bad_job)
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobAssign job_handle bad/foreign", job_handle);
    // Never run Process destruction beneath g_job_lock.
    core::ProcessRelease(target);
    return result;
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
        if (caller != nullptr && (process_handle == static_cast<u64>(-1) || process_handle == 0))
        {
            target = caller;
            core::ProcessRetain(target);
        }
        else if (caller != nullptr)
        {
            target = core::ProcessLookupWin32ProcessHandleRetained(caller, process_handle);
        }
        if (target != nullptr)
        {
            {
                sync::SpinLockGuard guard(g_job_lock);
                JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
                if (jp != nullptr)
                {
                    for (u32 m = 0; m < kJobMaxProcs; ++m)
                    {
                        if (jp->members[m].in_use && jp->members[m].proc == target)
                        {
                            in_job = true;
                            break;
                        }
                    }
                }
            }
            core::ProcessRelease(target);
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
    bool bad_job = false;
    bool already_terminated = false;
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
        if (jp == nullptr)
        {
            bad_job = true;
        }
        else if (jp->terminated)
        {
            already_terminated = true;
        }
        else
        {
            jp->terminated = true;
            for (u32 m = 0; m < kJobMaxProcs; ++m)
            {
                if (jp->members[m].in_use && jp->members[m].proc != nullptr)
                {
                    core::ProcessRetain(jp->members[m].proc);
                    snap[nsnap++] = jp->members[m].proc;
                }
            }
            // Account against this exact row while its slot identity is
            // locked. Re-resolving a slot-only handle after the kills can
            // otherwise charge a concurrently reallocated Job.
            jp->total_terminated_procs += nsnap;
        }
    }
    if (bad_job)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobTerminate job_handle bad/foreign", job_handle);
        return -1;
    }
    if (already_terminated)
        return 0;

    for (u32 m = 0; m < nsnap; ++m)
    {
        sched::SchedKillByProcess(snap[m]);
        core::ProcessRelease(snap[m]); // balance the retain above
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
        u8 list[8 + kJobMaxProcs * sizeof(u64)]{};
        auto put32 = [&](u64 off, u32 value)
        {
            for (u32 i = 0; i < sizeof(u32); ++i)
                list[off + i] = static_cast<u8>(value >> (i * 8));
        };
        auto put64 = [&](u64 off, u64 value)
        {
            for (u32 i = 0; i < sizeof(u64); ++i)
                list[off + i] = static_cast<u8>(value >> (i * 8));
        };
        u64 needed = 0;
        bool bad_job = false;
        {
            sync::SpinLockGuard guard(g_job_lock);
            JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
            if (jp == nullptr)
            {
                bad_job = true;
            }
            else
            {
                u32 listed = 0;
                for (u32 m = 0; m < kJobMaxProcs; ++m)
                    if (jp->members[m].in_use && jp->members[m].proc != nullptr)
                    {
                        put64(8 + static_cast<u64>(listed) * sizeof(u64), jp->members[m].proc->pid);
                        ++listed;
                    }
                put32(0, jp->proc_count);
                put32(4, listed);
                needed = 8 + static_cast<u64>(listed) * sizeof(u64);
            }
        }
        if (bad_job)
        {
            KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobQuery job_handle bad/foreign", job_handle);
            return -1;
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
        bool bad_job = false;
        {
            sync::SpinLockGuard guard(g_job_lock);
            JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
            if (jp == nullptr)
            {
                bad_job = true;
            }
            else
            {
                put32(36, jp->proc_count); // TotalProcesses (best-effort)
                put32(40, jp->proc_count); // ActiveProcesses
                put32(44, jp->total_terminated_procs);
            }
        }
        if (bad_job)
        {
            KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobQuery job_handle bad/foreign", job_handle);
            return -1;
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
    bool bad_job = false;
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobObject* jp = ResolveOwnedJobLocked(job_handle, caller);
        if (jp == nullptr || jp->refs == 0)
        {
            bad_job = true;
        }
        else
        {
            --jp->refs;
            if (jp->refs == 0)
            {
                for (u32 m = 0; m < kJobMaxProcs; ++m)
                {
                    if (jp->members[m].in_use && jp->members[m].proc != nullptr)
                        snap[nsnap++] = jp->members[m].proc;
                    jp->members[m].proc = nullptr;
                }
                jp->in_use = false;
                jp->terminated = false;
                jp->refs = 0;
                jp->proc_count = 0;
                jp->total_terminated_procs = 0;
                jp->owner_pid = 0;
                jp->active_process_limit = 0;
                jp->cpu_seconds_limit = 0;
                for (u32 m = 0; m < kJobMaxProcs; ++m)
                    jp->members[m].in_use = false;
            }
        }
    }
    if (bad_job)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobClose job_handle bad/foreign", job_handle);
        return -1;
    }
    for (u32 m = 0; m < nsnap; ++m)
        core::ProcessRelease(snap[m]);
    return 0;
}

void JobDrainOwnedByProcess(core::Process* owner)
{
    if (owner == nullptr)
        return;

    // A process can own every pool row, each with every member slot live.
    // Fixed storage keeps the detach bounded and allocation-free while the
    // spinlock is held. Duplicate pointers are intentional: each membership
    // owns an independent reference and therefore needs one matching release.
    core::Process* detached[kJobPoolCap * kJobMaxProcs]{};
    u32 detached_count = 0;
    {
        sync::SpinLockGuard guard(g_job_lock);
        for (u32 i = 0; i < kJobPoolCap; ++i)
        {
            JobObject& job = g_job_pool[i];
            if (!job.in_use || job.owner_pid != static_cast<u64>(owner->pid))
                continue;

            for (u32 m = 0; m < kJobMaxProcs; ++m)
            {
                JobMember& member = job.members[m];
                if (member.in_use && member.proc != nullptr)
                    detached[detached_count++] = member.proc;
                member.in_use = false;
                member.proc = nullptr;
            }
            job.in_use = false;
            job.terminated = false;
            job.refs = 0;
            job.proc_count = 0;
            job.total_terminated_procs = 0;
            job.owner_pid = 0;
            job.active_process_limit = 0;
            job.cpu_seconds_limit = 0;
        }
    }

    for (u32 i = 0; i < detached_count; ++i)
        core::ProcessRelease(detached[i]);
}

void JobOwnerExitSelfTest()
{
    auto* owner = static_cast<core::Process*>(mm::KMalloc(sizeof(core::Process)));
    if (owner == nullptr)
        core::Panic("subsystems/win32/job", "owner-exit self-test fixture allocation failed");
    memset(owner, 0, sizeof(core::Process));
    owner->pid = 0x4A4F4254; // "JOBT", outside the monotonic live PID source
    owner->refcount = 2;     // one synthetic task ref + one job-member ref

    const i64 handle = JobAlloc(static_cast<u64>(owner->pid));
    if (handle < 0)
        core::Panic("subsystems/win32/job", "owner-exit self-test could not allocate job");
    const u32 idx = static_cast<u32>((static_cast<u64>(handle) & kJobHandleTagMask) - kJobHandleBase);
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobObject& job = g_job_pool[idx];
        job.members[0].in_use = true;
        job.members[0].proc = owner;
        job.proc_count = 1;
    }

    JobDrainOwnedByProcess(owner);
    JobDrainOwnedByProcess(owner);
    if (__atomic_load_n(&owner->refcount, __ATOMIC_ACQUIRE) != 1)
        core::Panic("subsystems/win32/job", "owner-exit self-test reference imbalance");
    {
        sync::SpinLockGuard guard(g_job_lock);
        if (g_job_pool[idx].in_use || g_job_pool[idx].proc_count != 0)
            core::Panic("subsystems/win32/job", "owner-exit self-test job remained live");
    }

    mm::KFree(owner);
    arch::SerialWrite("[win32/job] owner-exit self-test PASS\n");
}

} // namespace duetos::subsystems::win32
