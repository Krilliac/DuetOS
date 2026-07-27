#include "subsystems/win32/tls_syscall.h"

#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

namespace duetos::subsystems::win32
{

// TLS slot allocation is per-process; values are per-thread. A process
// generation per slot prevents a freed/reallocated index from exposing a
// previous lifetime's value in another task.

namespace
{
constexpr u32 kErrorSuccess = 0;
constexpr u32 kErrorInvalidParameter = 87;

u64 AdvanceTlsGeneration(core::Process* process, u32 slot)
{
    u64 next = process->tls_slot_generation[slot] + 1;
    if (next == 0)
    {
        next = 1;
    }
    process->tls_slot_generation[slot] = next;
    return next;
}
} // namespace

void DoTlsAlloc(arch::TrapFrame* frame)
{
    KLOG_TRACE("win32/tls", "DoTlsAlloc: enter");
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        KLOG_WARN("win32/tls", "DoTlsAlloc: no current Process");
        frame->rax = static_cast<u64>(-1);
        return;
    }

    u64 slot = core::Process::kWin32TlsCap;
    u64 generation = 0;
    {
        sync::SpinLockGuard guard(proc->tls_lock);
        for (u64 i = 0; i < core::Process::kWin32TlsCap; ++i)
        {
            if ((proc->tls_slot_in_use & (1ULL << i)) == 0)
            {
                slot = i;
                break;
            }
        }
        if (slot != core::Process::kWin32TlsCap)
        {
            proc->tls_slot_in_use |= (1ULL << slot);
            generation = AdvanceTlsGeneration(proc, static_cast<u32>(slot));
        }
    }
    if (slot == core::Process::kWin32TlsCap)
    {
        KLOG_WARN("win32/tls", "DoTlsAlloc: all slots in use");
        frame->rax = static_cast<u64>(-1);
        return;
    }

    sched::SetCurrentTaskTlsSlotValue(static_cast<u32>(slot), generation, 0);
    KLOG_DEBUG_V("win32/tls", "DoTlsAlloc: granted slot", slot);
    frame->rax = slot;
}

void DoTlsFree(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/tls", "DoTlsFree: idx", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        KLOG_WARN("win32/tls", "DoTlsFree: no current Process");
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        KLOG_TRACE_V("win32/tls", "DoTlsFree: idx out of range", idx);
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    bool was_in_use = false;
    u64 generation = 0;
    {
        sync::SpinLockGuard guard(proc->tls_lock);
        was_in_use = (proc->tls_slot_in_use & (1ULL << idx)) != 0;
        if (was_in_use)
        {
            proc->tls_slot_in_use &= ~(1ULL << idx);
            generation = AdvanceTlsGeneration(proc, static_cast<u32>(idx));
        }
    }
    if (!was_in_use)
    {
        KLOG_WARN_V("win32/tls", "DoTlsFree: slot not in use", idx);
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Other tasks keep their old bytes, but their generation is stale.
    sched::SetCurrentTaskTlsSlotValue(static_cast<u32>(idx), generation, 0);
    KLOG_DEBUG_V("win32/tls", "DoTlsFree: released slot", idx);
    frame->rax = 0;
}

void DoTlsGet(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/tls", "DoTlsGet: idx", frame->rdi);
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        KLOG_WARN_V("win32/tls", "DoTlsGet: idx out of range", idx);
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = 0;
        return;
    }

    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = 0;
        return;
    }

    // Windows permits any in-range index. Snapshot the lifetime
    // generation so a recycled slot cannot reveal stale task data.
    u64 generation = 0;
    {
        sync::SpinLockGuard guard(proc->tls_lock);
        generation = proc->tls_slot_generation[idx];
    }
    frame->rax = sched::CurrentTaskTlsSlotValue(static_cast<u32>(idx), generation);
    sched::SetCurrentTaskWin32LastError(kErrorSuccess);
}

void DoTlsSet(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/tls", "DoTlsSet: idx", frame->rdi);
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        KLOG_WARN_V("win32/tls", "DoTlsSet: idx out of range", idx);
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Allocation liveness is the caller's responsibility. Stamp the
    // task value with the current process slot generation.
    u64 generation = 0;
    {
        sync::SpinLockGuard guard(proc->tls_lock);
        generation = proc->tls_slot_generation[idx];
    }
    sched::SetCurrentTaskTlsSlotValue(static_cast<u32>(idx), generation, frame->rsi);
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
