/*
 * SYS_MUTEX_* dispatch — backs Win32 CreateMutexW /
 * WaitForSingleObject(mutex_handle) / ReleaseMutex.
 *
 * Routes through the unified `Process::kobj_handles` table + the
 * concrete `KMutex` / `HandleTable` infrastructure in `kernel/ipc/`.
 * Win32 ABI is preserved at the syscall boundary (kWaitObject0 /
 * kWaitTimeout return values; recursive acquire; FIFO hand-off);
 * the per-process `Win32MutexHandle` fixed-size array that this
 * surface used to inhabit was removed alongside this slice — the
 * KMutex layer's wait-time + holder refcounting carries the
 * equivalent storage-lifetime guarantees safely.
 */

#include "subsystems/win32/mutex_syscall.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "arch/x86_64/traps.h"
#include "ipc/handle_table.h"
#include "ipc/kmutex.h"
#include "ipc/kobject.h"
#include "log/klog.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "subsystems/win32/custom.h"
#include "syscall/syscall.h"
#include "time/tick.h"

namespace duetos::subsystems::win32
{

namespace
{
constexpr u64 kInfiniteMs = 0xFFFFFFFFu;
constexpr u64 kWaitObject0 = 0;
constexpr u64 kWaitTimeout = 0x102;
constexpr u64 kMsPerTick = 10; // scheduler runs at 100 Hz

// Map a Win32 mutex handle to a kobj_handles slot id, or
// `ipc::kHandleInvalid` if the value is out of range. The
// translation is a flat subtraction of the per-type base so a
// PE that DuplicateHandle'd from another DuetOS process sees the
// same opaque value.
ipc::Handle Win32HandleToIpc(u64 handle)
{
    if (handle < core::Process::kWin32MutexBase ||
        handle >= core::Process::kWin32MutexBase + core::Process::kWin32MutexCap)
    {
        return ipc::kHandleInvalid;
    }
    return static_cast<ipc::Handle>(handle - core::Process::kWin32MutexBase);
}
} // namespace

void DoMutexCreate(arch::TrapFrame* frame)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/mutex", "NtCreateMutant ENTRY; bInitialOwner", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    auto create_r = ipc::KMutexCreate();
    if (!create_r.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex", "create OOM in pid", proc->pid);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KMutex* m = create_r.value();

    // Initial-owner semantics: if rdi == 1, the calling task owns
    // the new mutex with recursion = 1. KMutexAcquire takes its
    // own holder-ref atomically with becoming the owner so the
    // refcount accounting stays balanced if the table-insert
    // below fails.
    const bool initial_owner = (frame->rdi != 0);
    if (initial_owner)
    {
        ipc::KMutexAcquire(m);
    }

    auto insert_r = ipc::HandleTableInsert(proc->kobj_handles, &m->base);
    if (!insert_r.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex", "create: kobj_handles full in pid", proc->pid);
        if (initial_owner)
        {
            ipc::KMutexRelease(m);
        }
        // Drop the create-time reference; KMutexDestroy fires.
        ipc::KObjectRelease(&m->base);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const ipc::Handle ipc_h = insert_r.value();
    const u64 handle = core::Process::kWin32MutexBase + ipc_h;
    KLOG_INFO_AV(::duetos::core::LogArea::Win32, "win32/mutex", "NtCreateMutant OK; handle", handle);
    custom::OnHandleAlloc(proc, handle, static_cast<u32>(core::SYS_MUTEX_CREATE), frame->rip);
    if (initial_owner)
    {
        custom::OnMutexAcquire(proc, static_cast<u32>(ipc_h));
    }
    frame->rax = handle;
}

void DoMutexWait(arch::TrapFrame* frame)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/mutex", "NtWaitForSingleObject(mutex) ENTRY; handle",
                  frame->rdi);
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/mutex", "  timeout_ms", frame->rsi & 0xFFFFFFFFu);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    const ipc::Handle ipc_h = Win32HandleToIpc(handle);
    if (ipc_h == ipc::kHandleInvalid)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex", "NtWaitForSingleObject: bad mutex handle; handle",
                     handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Per-handle rights gate — the process-level cap check
    // (SyscallGate) already ran upstream as the ceiling; this is
    // the narrower per-handle floor. A handle minted with reduced
    // rights cannot waive its way back up by re-entering the
    // syscall. Mutex acquire == Wait.
    if (!ipc::HandleCheckRight(proc->kobj_handles, ipc_h, ipc::kHandleRightWait))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex",
                     "NtWaitForSingleObject: handle lacks Wait right; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Pin the kernel object across the wait — closing every
    // handle in parallel cannot free the storage while we hold
    // this reference. KMutexAcquire/AcquireTimed also take
    // their own wait-ref defensively, but acquiring the lookup
    // ref here ensures the type-checked KObject* stays valid
    // through the call regardless.
    ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Mutex);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex",
                     "NtWaitForSingleObject: bad/closed mutex handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto* m = reinterpret_cast<ipc::KMutex*>(obj);

    const u64 timeout_ms = frame->rsi & 0xFFFFFFFFu;
    sched::Task* me = sched::CurrentTask();

    // Re-entrant + uncontended fast paths inside KMutexAcquire
    // already short-circuit; we still drive deadlock-detect /
    // contention bookkeeping by sampling the holder edge BEFORE
    // the call. Owner-sample is racy under SMP — that's acceptable
    // for a diagnostic edge.
    sched::Task* current_owner = ipc::KMutexOwner(m);
    const bool will_block = (current_owner != nullptr) && (current_owner != me);
    const u64 holder_tid = (current_owner != nullptr) ? sched::TaskId(current_owner) : 0;
    if (will_block)
    {
        custom::OnMutexWaitStart(proc, static_cast<u32>(ipc_h), handle, holder_tid, proc->pid);
    }
    const u64 wait_start = ::duetos::time::TickCount();

    bool got;
    if (timeout_ms == kInfiniteMs)
    {
        ipc::KMutexAcquire(m);
        got = true;
    }
    else
    {
        const u64 ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
        got = ipc::KMutexAcquireTimed(m, ticks);
    }

    const u64 wait_end = ::duetos::time::TickCount();
    if (will_block)
    {
        custom::OnMutexWaitEnd(proc, static_cast<u32>(ipc_h), wait_end - wait_start);
    }
    if (got)
    {
        custom::OnMutexAcquire(proc, static_cast<u32>(ipc_h));
        frame->rax = kWaitObject0;
    }
    else
    {
        frame->rax = kWaitTimeout;
    }
    ipc::KObjectRelease(obj); // drop the lookup ref taken above
}

void DoMutexRelease(arch::TrapFrame* frame)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/mutex", "NtReleaseMutant ENTRY; handle", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    const ipc::Handle ipc_h = Win32HandleToIpc(handle);
    if (ipc_h == ipc::kHandleInvalid)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex", "NtReleaseMutant: bad handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    // Per-handle rights gate — release is the signalling side of
    // a mutex (hands off ownership), so kHandleRightSignal gates it.
    if (!ipc::HandleCheckRight(proc->kobj_handles, ipc_h, ipc::kHandleRightSignal))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex",
                     "NtReleaseMutant: handle lacks Signal right; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Mutex);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex", "NtReleaseMutant: bad/closed handle; handle",
                     handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto* m = reinterpret_cast<ipc::KMutex*>(obj);
    if (ipc::KMutexOwner(m) != sched::CurrentTask())
    {
        // Not-owner release is a legitimate API failure mode — the
        // caller is expected to handle the -1 return. Real Windows
        // returns WAIT_FAILED without surfacing the case. Demote to
        // DEBUG so contended-mutex stress tests don't flood the
        // console at default log levels.
        KLOG_DEBUG_AS(::duetos::core::LogArea::Win32, "win32/mutex", "NtReleaseMutant rejected", "reason", "not_owner");
        ipc::KObjectRelease(obj);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KMutexRelease(m);
    ipc::KObjectRelease(obj); // drop the lookup ref
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
