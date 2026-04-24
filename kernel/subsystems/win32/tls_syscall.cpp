#include "tls_syscall.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/process.h"

namespace duetos::subsystems::win32
{

void DoTlsAlloc(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
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
        frame->rax = static_cast<u64>(-1);
        return;
    }
    proc->tls_slot_in_use |= (1ULL << slot);
    proc->tls_slot_value[slot] = 0; // TlsAlloc: initial value is NULL
    arch::Sti();
    frame->rax = slot;
}

void DoTlsFree(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    arch::Cli();
    if ((proc->tls_slot_in_use & (1ULL << idx)) == 0)
    {
        arch::Sti();
        frame->rax = static_cast<u64>(-1);
        return;
    }
    proc->tls_slot_in_use &= ~(1ULL << idx);
    proc->tls_slot_value[idx] = 0;
    arch::Sti();
    frame->rax = 0;
}

void DoTlsGet(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        frame->rax = 0;
        return;
    }
    // Win32 TlsGetValue returns 0 for unallocated slots too, so no
    // in-use check; just return the stored value.
    frame->rax = proc->tls_slot_value[idx];
}

void DoTlsSet(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32TlsCap)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    proc->tls_slot_value[idx] = frame->rsi;
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
