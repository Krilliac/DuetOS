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
constexpr u64 kWaitAbandoned0 = 0x80;
constexpr u64 kWaitTimeout = 0x102;
constexpr u64 kMsPerTick = 10; // scheduler runs at 100 Hz

// Validate and decode the generation-preserving Win32 type tag.
// The internal token still carries both slot and generation.
ipc::Handle Win32HandleToIpc(u64 handle)
{
    ipc::Handle decoded = ipc::kHandleInvalid;
    return ipc::HandleDecodeTagged(handle, static_cast<u32>(core::Process::kWin32MutexBase), &decoded)
               ? decoded
               : ipc::kHandleInvalid;
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
    bool initial_owner_acquired = false;
    if (initial_owner)
    {
        const ipc::KMutexWaitResult wait_result = ipc::KMutexAcquire(m);
        initial_owner_acquired =
            wait_result == ipc::KMutexWaitResult::Acquired || wait_result == ipc::KMutexWaitResult::Abandoned;
        if (!initial_owner_acquired)
        {
            ipc::KObjectRelease(&m->base);
            frame->rax = static_cast<u64>(-1);
            return;
        }
    }

    const u64 rights = ipc::HandleRightsForProcess(ipc::KObjectType::Mutex, core::ProcessCapsSnapshot(proc));
    auto insert_r = ipc::HandleTableInsert(proc->kobj_handles, &m->base, rights);
    if (!insert_r.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex", "create: kobj_handles full in pid", proc->pid);
        if (initial_owner_acquired)
        {
            ipc::KMutexRelease(m);
        }
        // Drop the create-time reference; KMutexDestroy fires.
        ipc::KObjectRelease(&m->base);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const ipc::Handle ipc_h = insert_r.value();
    u64 handle = 0;
    if (!ipc::HandleEncodeTagged(ipc_h, static_cast<u32>(core::Process::kWin32MutexBase), &handle))
    {
        // Keep the impossible-today encoding rollback ownership-complete:
        // initial ownership carries a holder ref independent of the table ref.
        if (initial_owner_acquired)
            ipc::KMutexRelease(m);
        (void)ipc::HandleTableRemove(proc->kobj_handles, ipc_h);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    KLOG_INFO_AV(::duetos::core::LogArea::Win32, "win32/mutex", "NtCreateMutant OK; handle", handle);
    custom::OnHandleAlloc(proc, handle, static_cast<u32>(core::SYS_MUTEX_CREATE), frame->rip);
    if (initial_owner_acquired)
    {
        custom::OnMutexAcquire(proc, ipc::HandleSlotIndex(ipc_h));
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
    // Pin the kernel object across the wait — closing every
    // handle in parallel cannot free the storage while we hold
    // this reference. KMutexAcquire/AcquireTimed also take
    // their own wait-ref defensively, but acquiring the lookup
    // ref here ensures the type-checked KObject* stays valid
    // through the call regardless.
    ipc::KObject* obj =
        ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Mutex, ipc::kHandleRightWait);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex",
                     "NtWaitForSingleObject: bad/closed mutex handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto* m = reinterpret_cast<ipc::KMutex*>(obj);

    const u64 timeout_ms = frame->rsi & 0xFFFFFFFFu;
    const u64 me_tid = sched::CurrentTaskId();

    // Re-entrant + uncontended fast paths inside KMutexAcquire
    // already short-circuit; we still drive deadlock-detect /
    // contention bookkeeping by sampling the holder edge BEFORE
    // the call. Owner-sample is racy under SMP — that's acceptable
    // for a diagnostic edge.
    const bool currently_held = ipc::KMutexHeld(m);
    const u64 holder_tid = ipc::KMutexOwnerTid(m);
    const bool will_block = currently_held && holder_tid != me_tid;
    if (will_block)
    {
        custom::OnMutexWaitStart(proc, ipc::HandleSlotIndex(ipc_h), handle, holder_tid, proc->pid);
    }
    const u64 wait_start = ::duetos::time::TickCount();

    ipc::KMutexWaitResult wait_result;
    if (timeout_ms == kInfiniteMs)
    {
        wait_result = ipc::KMutexAcquire(m);
    }
    else
    {
        const u64 ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
        wait_result = ipc::KMutexAcquireTimed(m, ticks);
    }

    const u64 wait_end = ::duetos::time::TickCount();
    if (will_block)
    {
        custom::OnMutexWaitEnd(proc, ipc::HandleSlotIndex(ipc_h), wait_end - wait_start);
    }
    if (wait_result == ipc::KMutexWaitResult::Acquired)
    {
        custom::OnMutexAcquire(proc, ipc::HandleSlotIndex(ipc_h));
        frame->rax = kWaitObject0;
    }
    else if (wait_result == ipc::KMutexWaitResult::Abandoned)
    {
        custom::OnMutexAcquire(proc, ipc::HandleSlotIndex(ipc_h));
        frame->rax = kWaitAbandoned0;
    }
    else if (wait_result == ipc::KMutexWaitResult::TimedOut)
    {
        frame->rax = kWaitTimeout;
    }
    else
    {
        // Cancelled returns only so the dispatcher can unwind its references;
        // the outer cancellation boundary exits the task before user mode.
        frame->rax = static_cast<u64>(-1);
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
    ipc::KObject* obj =
        ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Mutex, ipc::kHandleRightSignal);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/mutex", "NtReleaseMutant: bad/closed handle; handle",
                     handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto* m = reinterpret_cast<ipc::KMutex*>(obj);
    if (!ipc::KMutexRelease(m))
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
    ipc::KObjectRelease(obj); // drop the lookup ref
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
