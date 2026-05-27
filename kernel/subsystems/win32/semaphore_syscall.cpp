/*
 * SYS_SEM_* dispatch — backs Win32 CreateSemaphoreW /
 * WaitForSingleObject(semaphore_handle) / ReleaseSemaphore.
 *
 * Routes through the unified `Process::kobj_handles` table + the
 * concrete `KSemaphore` infrastructure in `kernel/ipc/`. Win32 ABI
 * is preserved at the syscall boundary (kWaitObject0 / kWaitTimeout
 * return values; previous-count return on Release; overflow → -1
 * = ERROR_TOO_MANY_POSTS); the per-process `Win32SemaphoreHandle`
 * fixed-size array that this surface used to inhabit was removed
 * alongside this slice — KSemaphore's condvar-backed wait + the
 * refcounted handle-table lookup carry the equivalent storage-
 * lifetime guarantees safely.
 */

#include "subsystems/win32/semaphore_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "ipc/ksemaphore.h"
#include "log/klog.h"
#include "proc/process.h"
#include "subsystems/win32/custom.h"
#include "syscall/syscall.h"

namespace duetos::subsystems::win32
{

namespace
{
constexpr u64 kInfiniteMs = 0xFFFFFFFFu;
constexpr u64 kWaitObject0 = 0;
constexpr u64 kWaitTimeout = 0x102;
constexpr u64 kMsPerTick = 10; // scheduler runs at 100 Hz

ipc::Handle Win32HandleToIpc(u64 handle)
{
    if (handle < core::Process::kWin32SemaphoreBase ||
        handle >= core::Process::kWin32SemaphoreBase + core::Process::kWin32SemaphoreCap)
    {
        return ipc::kHandleInvalid;
    }
    return static_cast<ipc::Handle>(handle - core::Process::kWin32SemaphoreBase);
}
} // namespace

void DoSemCreate(arch::TrapFrame* frame)
{
    // rdi = initial count, rsi = max count.
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/sem", "NtCreateSemaphore ENTRY; initial", frame->rdi);
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/sem", "NtCreateSemaphore ENTRY; max", frame->rsi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const i64 initial_signed = static_cast<i64>(frame->rdi);
    const i64 max_signed = static_cast<i64>(frame->rsi);
    if (max_signed <= 0 || initial_signed < 0 || initial_signed > max_signed || max_signed > 0xFFFFFFFFLL ||
        initial_signed > 0xFFFFFFFFLL)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem", "create rejected: bad initial/max in pid", proc->pid);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u32 initial_count = static_cast<u32>(initial_signed);
    const u32 max_count = static_cast<u32>(max_signed);

    auto create_r = ipc::KSemaphoreCreate(initial_count, max_count);
    if (!create_r.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem", "create OOM in pid", proc->pid);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KSemaphore* s = create_r.value();

    auto insert_r = ipc::HandleTableInsert(proc->kobj_handles, &s->base);
    if (!insert_r.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem", "create: kobj_handles full in pid", proc->pid);
        ipc::KObjectRelease(&s->base);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const ipc::Handle ipc_h = insert_r.value();
    const u64 handle = core::Process::kWin32SemaphoreBase + ipc_h;
    KLOG_INFO_AV(::duetos::core::LogArea::Win32, "win32/sem", "NtCreateSemaphore OK; handle", handle);
    custom::OnHandleAlloc(proc, handle, static_cast<u32>(core::SYS_SEM_CREATE), frame->rip);
    frame->rax = handle;
}

void DoSemWait(arch::TrapFrame* frame)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/sem", "NtWaitForSingleObject(sem) ENTRY; handle", frame->rdi);
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/sem", "  timeout_ms", frame->rsi & 0xFFFFFFFFu);
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
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem", "NtWaitForSingleObject: bad sem handle; handle",
                     handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    // Per-handle rights gate — WaitForSingleObject on a semaphore
    // is a decrementing acquire == Wait.
    if (!ipc::HandleCheckRight(proc->kobj_handles, ipc_h, ipc::kHandleRightWait))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem",
                     "NtWaitForSingleObject(sem): handle lacks Wait right; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Semaphore);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem",
                     "NtWaitForSingleObject: bad/closed sem handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto* s = reinterpret_cast<ipc::KSemaphore*>(obj);

    const u64 timeout_ms = frame->rsi & 0xFFFFFFFFu;
    if (timeout_ms == kInfiniteMs)
    {
        ipc::KSemaphoreAcquire(s);
        ipc::KObjectRelease(obj);
        frame->rax = kWaitObject0;
        return;
    }
    const u64 ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
    const bool got = ipc::KSemaphoreAcquireTimed(s, ticks);
    ipc::KObjectRelease(obj);
    frame->rax = got ? kWaitObject0 : kWaitTimeout;
}

void DoSemRelease(arch::TrapFrame* frame)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/sem", "NtReleaseSemaphore ENTRY; handle", frame->rdi);
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/sem", "  release_count", frame->rsi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    const i64 release_signed = static_cast<i64>(frame->rsi);
    if (release_signed <= 0 || release_signed > 0xFFFFFFFFLL)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem", "release: bad count; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u32 release_count = static_cast<u32>(release_signed);
    const ipc::Handle ipc_h = Win32HandleToIpc(handle);
    if (ipc_h == ipc::kHandleInvalid)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem", "release: bad handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    // Per-handle rights gate — ReleaseSemaphore posts to the
    // count, signalling waiters == Signal.
    if (!ipc::HandleCheckRight(proc->kobj_handles, ipc_h, ipc::kHandleRightSignal))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem", "release: handle lacks Signal right; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Semaphore);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/sem", "release: bad/closed handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto* s = reinterpret_cast<ipc::KSemaphore*>(obj);
    u32 prev = 0;
    const bool ok = ipc::KSemaphoreTryRelease(s, release_count, &prev);
    ipc::KObjectRelease(obj);
    if (!ok)
    {
        // ERROR_TOO_MANY_POSTS — count would exceed max_count.
        // Win32 contract: count stays at its prior value; no
        // waiter is released.
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = static_cast<u64>(prev);
}

} // namespace duetos::subsystems::win32
