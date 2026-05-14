/*
 * Win32 IOCP (NtCreateIoCompletion family) + Job objects
 * (NtCreateJobObject family).
 *
 * IOCP — async I/O completion ports:
 *   8-port global pool. Each port owns a 16-packet ring of
 *   { CompletionKey, ApcContext, IoStatus, Information } (the
 *   four-tuple a Win32 GetQueuedCompletionStatus caller reads).
 *   Blocking via per-port WaitQueue. SetIoCompletion enqueues;
 *   Remove* dequeues (single packet → NtRemoveIoCompletion;
 *   batch → NtRemoveIoCompletionEx with caller-supplied count).
 *   Handles run kWin32IocpBase + idx (= 0xB00..0xB07).
 *
 * Job objects:
 *   8-job global pool. Each job is a refcounted container that
 *   pins a list of Process pointers. AssignProcessToJobObject
 *   pins; QueryInformationJobObject reports basic counters;
 *   TerminateJobObject calls SchedKillByProcess on every member.
 *   Handles run kWin32JobBase + idx (= 0xC00..0xC07).
 *
 * Sub-GAPs:
 *   - IOCP NumberOfConcurrentThreads accepted but ignored
 *     (no thread-affinity model).
 *   - IOCP Timeout argument honoured only as "block forever"
 *     (the timer-driven NtRemoveIoCompletion timeout would
 *     need WaitQueueBlockTimeout integration).
 *   - IOCP file-handle association (associating a completion
 *     port with a file handle so its async I/O auto-enqueues
 *     completion packets) is its own slice — current API
 *     supports manual SetIoCompletion only.
 *   - JobObject information classes other than
 *     BasicProcessIdList / BasicAccountingInformation /
 *     BasicAndIoAccountingInformation return -EINVAL.
 *   - Job per-resource limits (CpuRate / WorkingSet / etc.)
 *     stored but not enforced.
 */

#include "subsystems/win32/iocp_job.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u32 kIocpPoolCap = 8;
constexpr u32 kIocpPacketsPerPort = 16;
constexpr u64 kIocpHandleBase = 0xB00ULL;

constexpr u32 kJobPoolCap = 8;
constexpr u32 kJobMaxProcs = 32;
constexpr u64 kJobHandleBase = 0xC00ULL;

struct IocpPacket
{
    u64 completion_key;
    u64 apc_context;
    u64 io_status;   // packed into u64 — caller's IO_STATUS_BLOCK[0]
    u64 information; // bytes_transferred (IO_STATUS_BLOCK[1])
};

struct IocpPort
{
    bool in_use;
    u8 _pad[3];
    u32 refs;
    u32 head;
    u32 tail;
    u32 count;
    u32 _pad2;
    IocpPacket ring[kIocpPacketsPerPort];
    sched::WaitQueue read_wq;
};

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
    u64 active_process_limit; // 0 = unlimited
    u64 cpu_seconds_limit;    // 0 = unlimited
    JobMember members[kJobMaxProcs];
};

IocpPort g_iocp_pool[kIocpPoolCap];
JobObject g_job_pool[kJobPoolCap];

i32 IocpAlloc()
{
    arch::Cli();
    for (u32 i = 0; i < kIocpPoolCap; ++i)
    {
        if (!g_iocp_pool[i].in_use)
        {
            IocpPort& p = g_iocp_pool[i];
            p.in_use = true;
            p.refs = 1;
            p.head = 0;
            p.tail = 0;
            p.count = 0;
            p.read_wq.head = nullptr;
            p.read_wq.tail = nullptr;
            arch::Sti();
            return static_cast<i32>(i);
        }
    }
    arch::Sti();
    return -1;
}

i32 JobAlloc()
{
    arch::Cli();
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
            j.active_process_limit = 0;
            j.cpu_seconds_limit = 0;
            for (u32 m = 0; m < kJobMaxProcs; ++m)
                j.members[m].in_use = false;
            arch::Sti();
            return static_cast<i32>(i);
        }
    }
    arch::Sti();
    return -1;
}

} // namespace

// =====================================================
// IOCP
// =====================================================

i64 SysIocpCreate()
{
    using ::duetos::core::CapSetHas;
    using ::duetos::core::kCapSpawnThread;
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return -1;
    if (!CapSetHas(proc->caps, kCapSpawnThread))
    {
        core::RecordSandboxDenial(kCapSpawnThread);
        return -1;
    }
    const i32 idx = IocpAlloc();
    if (idx < 0)
        return -1;
    arch::SerialWrite("[win32/iocp] create handle=");
    arch::SerialWriteHex(static_cast<u64>(idx) + kIocpHandleBase);
    arch::SerialWrite("\n");
    return static_cast<i64>(idx) + static_cast<i64>(kIocpHandleBase);
}

i64 SysIocpSet(u64 handle, u64 completion_key, u64 apc_context, u64 status, u64 information)
{
    if (handle < kIocpHandleBase || handle >= kIocpHandleBase + kIocpPoolCap)
    {
        // First user-mode IOCP-handle escape lands in the boot
        // log so a regression in the Win32 thunk's handle-mint
        // path is visible. Subsequent fires from any user task
        // are dropped (the user already gets STATUS_INVALID_HANDLE
        // via the -1 return).
        KLOG_ONCE_WARN_V("subsystems/win32/iocp", "SysIocpSet handle out of range", handle);
        return -1;
    }
    const u32 idx = static_cast<u32>(handle - kIocpHandleBase);
    arch::Cli();
    IocpPort& p = g_iocp_pool[idx];
    if (!p.in_use)
    {
        arch::Sti();
        return -1;
    }
    if (p.count == kIocpPacketsPerPort)
    {
        // Drop oldest on overflow (sub-GAP — Linux IOCP has the
        // same shape; v0 doesn't surface STATUS_BUFFER_OVERFLOW).
        p.tail = (p.tail + 1) % kIocpPacketsPerPort;
        --p.count;
    }
    IocpPacket& pkt = p.ring[p.head];
    pkt.completion_key = completion_key;
    pkt.apc_context = apc_context;
    pkt.io_status = status;
    pkt.information = information;
    p.head = (p.head + 1) % kIocpPacketsPerPort;
    ++p.count;
    sched::WaitQueueWakeOne(&p.read_wq);
    arch::Sti();
    return 0;
}

// Returns: 1 packet dequeued, 0 timeout / no packet, -1 bad handle.
// Writes into the four out-pointers (completion_key, apc_context,
// io_status, information). All can be null.
i64 SysIocpRemove(u64 handle, u64 user_key, u64 user_apc, u64 user_iosb, u64 timeout_ms)
{
    if (handle < kIocpHandleBase || handle >= kIocpHandleBase + kIocpPoolCap)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/iocp", "SysIocpRemove handle out of range", handle);
        return -1;
    }
    const u32 idx = static_cast<u32>(handle - kIocpHandleBase);
    IocpPort& p = g_iocp_pool[idx];
    arch::Cli();
    while (p.in_use && p.count == 0)
    {
        if (timeout_ms == 0)
        {
            arch::Sti();
            return 0; // immediate non-blocking probe
        }
        sched::WaitQueueBlock(&p.read_wq);
        arch::Cli();
        // Sub-GAP: timeout argument other than 0 / infinite (-1)
        // not honoured precisely; we block until wake.
    }
    if (!p.in_use)
    {
        arch::Sti();
        return -1;
    }
    IocpPacket pkt = p.ring[p.tail];
    p.tail = (p.tail + 1) % kIocpPacketsPerPort;
    --p.count;
    arch::Sti();
    if (user_key != 0)
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_key), &pkt.completion_key, sizeof(pkt.completion_key)))
            return -1;
    if (user_apc != 0)
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_apc), &pkt.apc_context, sizeof(pkt.apc_context)))
            return -1;
    if (user_iosb != 0)
    {
        u64 iosb[2] = {pkt.io_status, pkt.information};
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_iosb), iosb, sizeof(iosb)))
            return -1;
    }
    return 1;
}

i64 SysIocpClose(u64 handle)
{
    if (handle < kIocpHandleBase || handle >= kIocpHandleBase + kIocpPoolCap)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/iocp", "SysIocpClose handle out of range", handle);
        return -1;
    }
    const u32 idx = static_cast<u32>(handle - kIocpHandleBase);
    arch::Cli();
    IocpPort& p = g_iocp_pool[idx];
    if (p.in_use && p.refs > 0)
    {
        --p.refs;
        if (p.refs == 0)
        {
            p.in_use = false;
            p.count = 0;
            sched::WaitQueueWakeAll(&p.read_wq);
        }
    }
    arch::Sti();
    return 0;
}

// =====================================================
// JobObject
// =====================================================

i64 SysJobCreate()
{
    using ::duetos::core::CapSetHas;
    using ::duetos::core::kCapSpawnThread;
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return -1;
    if (!CapSetHas(proc->caps, kCapSpawnThread))
    {
        core::RecordSandboxDenial(kCapSpawnThread);
        return -1;
    }
    const i32 idx = JobAlloc();
    if (idx < 0)
        return -1;
    arch::SerialWrite("[win32/job] create handle=");
    arch::SerialWriteHex(static_cast<u64>(idx) + kJobHandleBase);
    arch::SerialWrite("\n");
    return static_cast<i64>(idx) + static_cast<i64>(kJobHandleBase);
}

i64 SysJobAssign(u64 job_handle, u64 process_handle)
{
    if (job_handle < kJobHandleBase || job_handle >= kJobHandleBase + kJobPoolCap)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobAssign job_handle out of range", job_handle);
        return -1;
    }
    const u32 idx = static_cast<u32>(job_handle - kJobHandleBase);
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
    arch::Cli();
    JobObject& j = g_job_pool[idx];
    if (!j.in_use || j.terminated)
    {
        arch::Sti();
        return -1;
    }
    if (j.active_process_limit > 0 && j.proc_count >= j.active_process_limit)
    {
        arch::Sti();
        return -1;
    }
    // Check it isn't already a member.
    for (u32 m = 0; m < kJobMaxProcs; ++m)
        if (j.members[m].in_use && j.members[m].proc == target)
        {
            arch::Sti();
            return 0;
        }
    for (u32 m = 0; m < kJobMaxProcs; ++m)
    {
        if (!j.members[m].in_use)
        {
            j.members[m].in_use = true;
            j.members[m].proc = target;
            ++j.proc_count;
            core::ProcessRetain(target);
            arch::Sti();
            arch::SerialWrite("[win32/job] assign job=");
            arch::SerialWriteHex(job_handle);
            arch::SerialWrite(" pid=");
            arch::SerialWriteHex(target->pid);
            arch::SerialWrite("\n");
            return 0;
        }
    }
    arch::Sti();
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
    else if (job_handle >= kJobHandleBase && job_handle < kJobHandleBase + kJobPoolCap)
    {
        const u32 idx = static_cast<u32>(job_handle - kJobHandleBase);
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
            arch::Cli();
            JobObject& j = g_job_pool[idx];
            if (j.in_use)
            {
                for (u32 m = 0; m < kJobMaxProcs; ++m)
                    if (j.members[m].in_use && j.members[m].proc == target)
                    {
                        in_job = true;
                        break;
                    }
            }
            arch::Sti();
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
    if (job_handle < kJobHandleBase || job_handle >= kJobHandleBase + kJobPoolCap)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobTerminate job_handle out of range", job_handle);
        return -1;
    }
    const u32 idx = static_cast<u32>(job_handle - kJobHandleBase);
    arch::Cli();
    JobObject& j = g_job_pool[idx];
    if (!j.in_use)
    {
        arch::Sti();
        return -1;
    }
    j.terminated = true;
    JobMember snap[kJobMaxProcs];
    for (u32 m = 0; m < kJobMaxProcs; ++m)
        snap[m] = j.members[m];
    arch::Sti();
    u32 killed = 0;
    for (u32 m = 0; m < kJobMaxProcs; ++m)
    {
        if (!snap[m].in_use)
            continue;
        if (snap[m].proc != nullptr)
        {
            sched::SchedKillByProcess(snap[m].proc);
            ++killed;
        }
    }
    arch::Cli();
    j.total_terminated_procs += killed;
    arch::Sti();
    return 0;
}

i64 SysJobQuery(u64 job_handle, u64 info_class, u64 user_buf, u64 buf_len)
{
    if (job_handle < kJobHandleBase || job_handle >= kJobHandleBase + kJobPoolCap)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobQuery job_handle out of range", job_handle);
        return -1;
    }
    const u32 idx = static_cast<u32>(job_handle - kJobHandleBase);
    arch::Cli();
    JobObject& j = g_job_pool[idx];
    if (!j.in_use)
    {
        arch::Sti();
        return -1;
    }
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
        list[0] = j.proc_count;
        list[1] = 0;
        for (u32 m = 0; m < kJobMaxProcs; ++m)
            if (j.members[m].in_use && j.members[m].proc != nullptr)
            {
                list[2 + list[1]] = j.members[m].proc->pid;
                ++list[1];
            }
        const u64 needed = (2 + list[1]) * sizeof(u64);
        arch::Sti();
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
        put32(36, j.proc_count); // TotalProcesses (best-effort)
        put32(40, j.proc_count); // ActiveProcesses
        put32(44, j.total_terminated_procs);
        const u64 needed = (info_class == 3) ? 112 : 48;
        arch::Sti();
        if (buf_len < needed)
            return -1;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, needed))
            return -1;
        return static_cast<i64>(needed);
    }
    arch::Sti();
    return -1;
}

i64 SysJobClose(u64 job_handle)
{
    if (job_handle < kJobHandleBase || job_handle >= kJobHandleBase + kJobPoolCap)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/job", "SysJobClose job_handle out of range", job_handle);
        return -1;
    }
    const u32 idx = static_cast<u32>(job_handle - kJobHandleBase);
    arch::Cli();
    JobObject& j = g_job_pool[idx];
    if (!j.in_use || j.refs == 0)
    {
        arch::Sti();
        return -1;
    }
    --j.refs;
    if (j.refs == 0)
    {
        // Release every member's process refcount.
        JobMember snap[kJobMaxProcs];
        for (u32 m = 0; m < kJobMaxProcs; ++m)
            snap[m] = j.members[m];
        j.in_use = false;
        j.proc_count = 0;
        for (u32 m = 0; m < kJobMaxProcs; ++m)
            j.members[m].in_use = false;
        arch::Sti();
        for (u32 m = 0; m < kJobMaxProcs; ++m)
            if (snap[m].in_use && snap[m].proc != nullptr)
                core::ProcessRelease(snap[m].proc);
        return 0;
    }
    arch::Sti();
    return 0;
}

} // namespace duetos::subsystems::win32
