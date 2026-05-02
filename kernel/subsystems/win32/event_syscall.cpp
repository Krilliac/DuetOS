#include "subsystems/win32/event_syscall.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "arch/x86_64/traps.h"
#include "proc/process.h"
#include "syscall/syscall.h"
#include "sched/sched.h"
#include "subsystems/win32/custom.h"

namespace duetos::subsystems::win32
{

namespace
{
constexpr u64 kInfiniteMs = 0xFFFFFFFFu;
constexpr u64 kWaitObject0 = 0;
constexpr u64 kWaitTimeout = 0x102;
constexpr u64 kMsPerTick = 10;
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
    u64 slot = core::Process::kWin32EventCap;
    arch::Cli();
    for (u64 i = 0; i < core::Process::kWin32EventCap; ++i)
    {
        if (!proc->win32_events[i].in_use)
        {
            slot = i;
            break;
        }
    }
    if (slot == core::Process::kWin32EventCap)
    {
        arch::Sti();
        ::duetos::core::LogAWithValue(::duetos::core::LogLevel::Warn, ::duetos::core::LogArea::Win32, "win32/event",
                                      "event_create: out of slots in pid", proc->pid);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    core::Process::Win32EventHandle& e = proc->win32_events[slot];
    e.in_use = true;
    e.manual_reset = (frame->rdi != 0);
    e.signaled = (frame->rsi != 0);
    e.waiters.head = nullptr;
    e.waiters.tail = nullptr;
    arch::Sti();
    const u64 handle = core::Process::kWin32EventBase + slot;
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
    if (handle < core::Process::kWin32EventBase ||
        handle >= core::Process::kWin32EventBase + core::Process::kWin32EventCap)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event",
                     "NtSetEvent: bad handle (out of valid event range); handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    core::Process::Win32EventHandle& e = proc->win32_events[handle - core::Process::kWin32EventBase];
    arch::Cli();
    if (!e.in_use)
    {
        arch::Sti();
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event",
                     "NtSetEvent: closed handle (use-after-NtClose); handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    e.signaled = true;
    if (e.manual_reset)
    {
        // Manual: wake ALL waiters; signal stays set.
        (void)sched::WaitQueueWakeAll(&e.waiters);
    }
    else
    {
        // Auto: wake ONE; if woken, auto-clear signal.
        sched::Task* next = sched::WaitQueueWakeOne(&e.waiters);
        if (next != nullptr)
            e.signaled = false;
    }
    arch::Sti();
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
    if (handle < core::Process::kWin32EventBase ||
        handle >= core::Process::kWin32EventBase + core::Process::kWin32EventCap)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event", "NtResetEvent: bad handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    core::Process::Win32EventHandle& e = proc->win32_events[handle - core::Process::kWin32EventBase];
    arch::Cli();
    const bool was_in_use = e.in_use;
    if (was_in_use)
        e.signaled = false;
    arch::Sti();
    if (!was_in_use)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event", "NtResetEvent: closed handle; handle", handle);
    }
    frame->rax = was_in_use ? 0 : static_cast<u64>(-1);
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
    if (handle < core::Process::kWin32EventBase ||
        handle >= core::Process::kWin32EventBase + core::Process::kWin32EventCap)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event", "NtWaitForSingleObject: bad event handle; handle",
                     handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    core::Process::Win32EventHandle& e = proc->win32_events[handle - core::Process::kWin32EventBase];
    arch::Cli();
    if (!e.in_use)
    {
        arch::Sti();
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/event",
                     "NtWaitForSingleObject: closed event handle; handle", handle);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    if (e.signaled)
    {
        // Already signaled. Auto-reset events clear the signal
        // for us; manual-reset events keep it.
        if (!e.manual_reset)
            e.signaled = false;
        arch::Sti();
        frame->rax = kWaitObject0;
        return;
    }
    const u64 timeout_ms = frame->rsi & 0xFFFFFFFFu;
    if (timeout_ms == kInfiniteMs)
    {
        sched::WaitQueueBlock(&e.waiters);
        arch::Sti();
        frame->rax = kWaitObject0;
        return;
    }
    const u64 ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
    const bool got = sched::WaitQueueBlockTimeout(&e.waiters, ticks);
    arch::Sti();
    frame->rax = got ? kWaitObject0 : kWaitTimeout;
}

} // namespace duetos::subsystems::win32
