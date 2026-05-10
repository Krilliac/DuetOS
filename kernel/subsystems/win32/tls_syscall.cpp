#include "subsystems/win32/tls_syscall.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::win32
{

// TLS slot ALLOCATION bitmap: per-process — TlsAlloc returns one
// shared index. TLS slot VALUES: per-thread — read/written through
// `sched::CurrentTaskTlsSlotValue` / `SetCurrentTaskTlsSlotValue`.
// (T6-01 partial: per-thread storage closes the cross-thread bleed
// the v0 single-threaded shim had; full static-TLS template + TLS
// callbacks in the PE loader still defer.)

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
    arch::Cli();
    u64 slot = core::Process::kWin32TlsCap;
    for (u64 i = 0; i < core::Process::kWin32TlsCap; ++i)
    {
        if ((proc->tls_slot_in_use & (1ULL << i)) == 0)
        {
            slot = i;
            break;
        }
    }
    if (slot == core::Process::kWin32TlsCap)
    {
        arch::Sti();
        KLOG_WARN("win32/tls", "DoTlsAlloc: all slots in use");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    proc->tls_slot_in_use |= (1ULL << slot);
    // The PROCESS-level value array (`proc->tls_slot_value`) is now
    // the cross-thread template — left at 0 by ProcessCreate's
    // memset; new threads pick this up in their per-thread copy
    // when their first TlsGetValue runs (currently still 0).
    proc->tls_slot_value[slot] = 0;
    // Reset the calling thread's per-thread value too — TlsAlloc
    // contract is "the caller observes 0 in the freshly-allocated
    // slot regardless of what was there before reuse."
    sched::SetCurrentTaskTlsSlotValue(static_cast<u32>(slot), 0);
    arch::Sti();
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
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        // Out-of-range is a documented Win32 error path (TlsFree
        // returns FALSE). Smoke probes call this deliberately.
        // Trace, not warn.
        KLOG_TRACE_V("win32/tls", "DoTlsFree: idx out of range", idx);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    arch::Cli();
    if ((proc->tls_slot_in_use & (1ULL << idx)) == 0)
    {
        arch::Sti();
        KLOG_WARN_V("win32/tls", "DoTlsFree: slot not in use", idx);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    proc->tls_slot_in_use &= ~(1ULL << idx);
    proc->tls_slot_value[idx] = 0;
    // The other tasks' per-thread copies are not cleared here —
    // they remain "garbage" from the freed-slot's perspective,
    // matching Win32's "TlsFree doesn't reach across threads"
    // contract. A subsequent TlsAlloc that reuses the slot zeroes
    // the calling thread's view; other threads see 0 the next
    // time they TlsGetValue (the new value, not the stale one
    // from before TlsFree).
    sched::SetCurrentTaskTlsSlotValue(static_cast<u32>(idx), 0);
    arch::Sti();
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
        frame->rax = 0;
        return;
    }
    // Win32 TlsGetValue returns 0 for unallocated slots too, so no
    // in-use check; just return the stored per-thread value.
    frame->rax = sched::CurrentTaskTlsSlotValue(static_cast<u32>(idx));
}

void DoTlsSet(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/tls", "DoTlsSet: idx", frame->rdi);
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        KLOG_WARN_V("win32/tls", "DoTlsSet: idx out of range", idx);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    sched::SetCurrentTaskTlsSlotValue(static_cast<u32>(idx), frame->rsi);
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
