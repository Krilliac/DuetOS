#include "mutex_syscall.h"

#include "custom.h"

#include "../../arch/x86_64/cpu.h"
#include "../../core/syscall.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/timer.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/process.h"
#include "../../sched/sched.h"
#include "custom.h"

namespace duetos::arch
{
u64 TimerTicks();
} // namespace duetos::arch

namespace duetos::subsystems::win32
{

namespace
{
constexpr u64 kInfiniteMs = 0xFFFFFFFFu;
constexpr u64 kWaitObject0 = 0;
constexpr u64 kWaitTimeout = 0x102;
constexpr u64 kMsPerTick = 10; // scheduler runs at 100 Hz
} // namespace

void DoMutexCreate(arch::TrapFrame* frame)
{
    // Allocate a mutex slot; record the calling task as the
    // initial owner if rdi == 1 (Win32 bInitialOwner).
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    u64 slot = core::Process::kWin32MutexCap;
    arch::Cli();
    for (u64 i = 0; i < core::Process::kWin32MutexCap; ++i)
    {
        if (!proc->win32_mutexes[i].in_use)
        {
            slot = i;
            break;
        }
    }
    if (slot == core::Process::kWin32MutexCap)
    {
        arch::Sti();
        arch::SerialWrite("[sys] mutex_create out-of-slots pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    core::Process::Win32MutexHandle& m = proc->win32_mutexes[slot];
    m.in_use = true;
    m.waiters.head = nullptr;
    m.waiters.tail = nullptr;
    if (frame->rdi != 0)
    {
        m.owner = sched::CurrentTask();
        m.recursion = 1;
    }
    else
    {
        m.owner = nullptr;
        m.recursion = 0;
    }
    arch::Sti();
    const u64 handle = core::Process::kWin32MutexBase + slot;
    arch::SerialWrite("[sys] mutex_create ok pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" handle=");
    arch::SerialWriteHex(handle);
    arch::SerialWrite(" initial_owner=");
    arch::SerialWriteHex(frame->rdi);
    arch::SerialWrite("\n");
    custom::OnHandleAlloc(proc, handle, static_cast<u32>(core::SYS_MUTEX_CREATE), frame->rip);
    frame->rax = handle;
}

void DoMutexWait(arch::TrapFrame* frame)
{
    // Acquire-or-block-with-timeout. Recursive owner check first;
    // otherwise WaitQueueBlockTimeout. Hand-off in DoMutexRelease
    // sets m.owner = us BEFORE waking so a successful wake means
    // the lock is already ours.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    if (handle < core::Process::kWin32MutexBase ||
        handle >= core::Process::kWin32MutexBase + core::Process::kWin32MutexCap)
    {
        arch::SerialWrite("[sys] mutex_wait bad_handle pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 slot = handle - core::Process::kWin32MutexBase;
    core::Process::Win32MutexHandle& m = proc->win32_mutexes[slot];
    if (!m.in_use)
    {
        arch::SerialWrite("[sys] mutex_wait closed_handle pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 timeout_ms = frame->rsi & 0xFFFFFFFFu;
    sched::Task* me = sched::CurrentTask();
    arch::Cli();
    if (m.owner == nullptr)
    {
        m.owner = me;
        m.recursion = 1;
        arch::Sti();
        custom::OnMutexAcquire(proc, static_cast<u32>(slot));
        frame->rax = kWaitObject0;
        return;
    }
    if (m.owner == me)
    {
        m.recursion += 1;
        arch::Sti();
        custom::OnMutexAcquire(proc, static_cast<u32>(slot));
        frame->rax = kWaitObject0;
        return;
    }
    // Custom-Win32 deadlock detect + contention wait_count bump.
    // The owner task's id (if we have it) becomes the holder edge —
    // helps cycle-detection follow the wait-for graph.
    const u64 holder_tid = (m.owner != nullptr) ? sched::TaskId(m.owner) : 0;
    custom::OnMutexWaitStart(proc, static_cast<u32>(slot), handle, holder_tid, proc->pid);
    const u64 wait_start = arch::TimerTicks();
    if (timeout_ms == kInfiniteMs)
    {
        sched::WaitQueueBlock(&m.waiters);
        arch::Sti();
        const u64 wait_end = arch::TimerTicks();
        custom::OnMutexWaitEnd(proc, static_cast<u32>(slot), wait_end - wait_start);
        frame->rax = kWaitObject0;
        return;
    }
    const u64 ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
    const bool got = sched::WaitQueueBlockTimeout(&m.waiters, ticks);
    arch::Sti();
    const u64 wait_end = arch::TimerTicks();
    custom::OnMutexWaitEnd(proc, static_cast<u32>(slot), wait_end - wait_start);
    frame->rax = got ? kWaitObject0 : kWaitTimeout;
}

void DoMutexRelease(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    if (handle < core::Process::kWin32MutexBase ||
        handle >= core::Process::kWin32MutexBase + core::Process::kWin32MutexCap)
    {
        arch::SerialWrite("[sys] mutex_release bad_handle pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 slot = handle - core::Process::kWin32MutexBase;
    core::Process::Win32MutexHandle& m = proc->win32_mutexes[slot];
    sched::Task* me = sched::CurrentTask();
    arch::Cli();
    const bool was_in_use = m.in_use;
    const bool owns = (m.owner == me);
    if (!was_in_use || !owns)
    {
        arch::Sti();
        arch::SerialWrite("[sys] mutex_release ");
        arch::SerialWrite(!was_in_use ? "closed_handle" : "not_owner");
        arch::SerialWrite(" pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    m.recursion -= 1;
    if (m.recursion > 0)
    {
        arch::Sti();
        frame->rax = 0;
        return;
    }
    // Final release. Hand off to the longest-waiting blocker.
    sched::Task* next = sched::WaitQueueWakeOne(&m.waiters);
    m.owner = next;
    m.recursion = (next != nullptr) ? 1 : 0;
    arch::Sti();
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
