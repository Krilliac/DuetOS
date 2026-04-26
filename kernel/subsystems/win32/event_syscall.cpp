#include "subsystems/win32/event_syscall.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
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
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
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
    arch::SerialWrite("[sys] event_create ok pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" handle=");
    arch::SerialWriteHex(handle);
    arch::SerialWrite(" manual=");
    arch::SerialWriteHex(e.manual_reset ? 1 : 0);
    arch::SerialWrite(" signaled=");
    arch::SerialWriteHex(e.signaled ? 1 : 0);
    arch::SerialWrite("\n");
    custom::OnHandleAlloc(proc, handle, static_cast<u32>(core::SYS_EVENT_CREATE), frame->rip);
    frame->rax = handle;
}

void DoEventSet(arch::TrapFrame* frame)
{
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
        arch::SerialWrite("[sys] event_set bad_handle pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    core::Process::Win32EventHandle& e = proc->win32_events[handle - core::Process::kWin32EventBase];
    arch::Cli();
    if (!e.in_use)
    {
        arch::Sti();
        arch::SerialWrite("[sys] event_set closed_handle pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
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
        arch::SerialWrite("[sys] event_reset bad_handle pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
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
        arch::SerialWrite("[sys] event_reset closed_handle pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
    }
    frame->rax = was_in_use ? 0 : static_cast<u64>(-1);
}

void DoEventWait(arch::TrapFrame* frame)
{
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
        arch::SerialWrite("[sys] event_wait bad_handle pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    core::Process::Win32EventHandle& e = proc->win32_events[handle - core::Process::kWin32EventBase];
    arch::Cli();
    if (!e.in_use)
    {
        arch::Sti();
        arch::SerialWrite("[sys] event_wait closed_handle pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
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
