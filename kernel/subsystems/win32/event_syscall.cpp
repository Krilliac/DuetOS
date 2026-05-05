/*
 * SYS_EVENT_* dispatch — backs Win32 CreateEventW / SetEvent /
 * ResetEvent / WaitForSingleObject(event_handle).
 *
 * Routes through the unified `Process::kobj_handles` table + the
 * concrete `KEvent` infrastructure in `kernel/ipc/`. Win32 ABI is
 * preserved at the syscall boundary (kWaitObject0 / kWaitTimeout
 * return values; manual-reset latch; auto-reset consume-on-wake);
 * the per-process `Win32EventHandle` fixed-size array that this
 * surface used to inhabit was removed alongside this slice — the
 * KEvent layer's condvar-backed wait + refcounted handle-table
 * lookup carry the equivalent storage-lifetime guarantees safely.
 */

#include "subsystems/win32/event_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "ipc/handle_table.h"
#include "ipc/kevent.h"
#include "ipc/kobject.h"
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

// Map a Win32 event handle to a kobj_handles slot id, or
// `ipc::kHandleInvalid` if the value is out of range. The
// translation is a flat subtraction of the per-type base so a
// PE that DuplicateHandle'd from another DuetOS process sees the
// same opaque value.
ipc::Handle Win32HandleToIpc(u64 handle)
{
    if (handle < core::Process::kWin32EventBase ||
        handle >= core::Process::kWin32EventBase + core::Process::kWin32EventCap)
    {
        return ipc::kHandleInvalid;
    }
    return static_cast<ipc::Handle>(handle - core::Process::kWin32EventBase);
}
} // namespace

void DoEventCreate(arch::TrapFrame* frame)
{
    // rdi = manual_reset, rsi = initial_state.
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/event", "NtCreateEvent ENTRY; manual_reset", frame->rdi);
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/event", "NtCreateEvent ENTRY; initial_state", frame->rsi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Win32, "win32/event", "NtCreateEvent: no current process");
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const bool manual_reset = (frame->rdi != 0);
    const bool initial_state = (frame->rsi != 0);
    auto create_r = ipc::KEventCreate(manual_reset, initial_state);
    if (!create_r.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event", "create OOM in pid", proc->pid);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KEvent* e = create_r.value();

    auto insert_r = ipc::HandleTableInsert(proc->kobj_handles, &e->base);
    if (!insert_r.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event", "create: kobj_handles full in pid", proc->pid);
        // Drop the create-time reference; KEventDestroy fires.
        ipc::KObjectRelease(&e->base);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const ipc::Handle ipc_h = insert_r.value();
    const u64 handle = core::Process::kWin32EventBase + ipc_h;
    KLOG_INFO_AV(::duetos::core::LogArea::Win32, "win32/event", "NtCreateEvent OK; handle", handle);
    custom::OnHandleAlloc(proc, handle, static_cast<u32>(core::SYS_EVENT_CREATE), frame->rip);
    frame->rax = handle;
}

void DoEventSet(arch::TrapFrame* frame)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/event", "NtSetEvent ENTRY; handle", frame->rdi);
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
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event",
                     "NtSetEvent: bad handle (out of valid event range); handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Event);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event", "NtSetEvent: bad/closed event handle; handle",
                     handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto* e = reinterpret_cast<ipc::KEvent*>(obj);
    ipc::KEventSet(e);
    ipc::KObjectRelease(obj);
    frame->rax = 0;
}

void DoEventReset(arch::TrapFrame* frame)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/event", "NtResetEvent ENTRY; handle", frame->rdi);
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
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event", "NtResetEvent: bad handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Event);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event", "NtResetEvent: bad/closed event handle; handle",
                     handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto* e = reinterpret_cast<ipc::KEvent*>(obj);
    ipc::KEventReset(e);
    ipc::KObjectRelease(obj);
    frame->rax = 0;
}

void DoEventWait(arch::TrapFrame* frame)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/event", "NtWaitForSingleObject(event) ENTRY; handle",
                  frame->rdi);
    KLOG_TRACE_AV(::duetos::core::LogArea::Win32, "win32/event", "  timeout_ms", frame->rsi & 0xFFFFFFFFu);
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
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event", "NtWaitForSingleObject: bad event handle; handle",
                     handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Event);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event",
                     "NtWaitForSingleObject: bad/closed event handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto* e = reinterpret_cast<ipc::KEvent*>(obj);

    const u64 timeout_ms = frame->rsi & 0xFFFFFFFFu;
    if (timeout_ms == kInfiniteMs)
    {
        ipc::KEventWait(e);
        ipc::KObjectRelease(obj);
        frame->rax = kWaitObject0;
        return;
    }
    const u64 ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
    const bool got = ipc::KEventWaitTimed(e, ticks);
    ipc::KObjectRelease(obj);
    frame->rax = got ? kWaitObject0 : kWaitTimeout;
}

} // namespace duetos::subsystems::win32
