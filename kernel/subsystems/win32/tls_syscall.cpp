#include "subsystems/win32/tls_syscall.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "proc/process.h"

namespace duetos::subsystems::win32
{

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
    proc->tls_slot_value[slot] = 0; // TlsAlloc: initial value is NULL
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
        KLOG_WARN_V("win32/tls", "DoTlsFree: idx out of range", idx);
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
    arch::Sti();
    KLOG_DEBUG_V("win32/tls", "DoTlsFree: released slot", idx);
    frame->rax = 0;
}

void DoTlsGet(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/tls", "DoTlsGet: idx", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        KLOG_WARN("win32/tls", "DoTlsGet: no current Process");
        frame->rax = 0;
        return;
    }
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        KLOG_WARN_V("win32/tls", "DoTlsGet: idx out of range", idx);
        frame->rax = 0;
        return;
    }
    // Win32 TlsGetValue returns 0 for unallocated slots too, so no
    // in-use check; just return the stored value.
    frame->rax = proc->tls_slot_value[idx];
}

void DoTlsSet(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/tls", "DoTlsSet: idx", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        KLOG_WARN("win32/tls", "DoTlsSet: no current Process");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        KLOG_WARN_V("win32/tls", "DoTlsSet: idx out of range", idx);
        frame->rax = static_cast<u64>(-1);
        return;
    }
    proc->tls_slot_value[idx] = frame->rsi;
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
