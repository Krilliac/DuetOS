#include "debug/bp_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "proc/process.h"
#include "debug/breakpoints.h"

namespace duetos::debug
{

void DoBpInstall(arch::TrapFrame* frame)
{
    // rdi = va, rsi = BpKind (1=exec, 2=write, 3=read/write),
    // rdx = length (1/2/4/8). Returns bp_id > 0 on success,
    // u64(-1) on any rejection (cap, bad args, no slot).
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr || !core::CapSetHas(proc->caps, core::kCapDebug))
    {
        const u64 pid = (proc != nullptr) ? proc->pid : 0;
        core::RecordSandboxDenial(core::kCapDebug);
        if (proc != nullptr && core::ShouldLogDenial(proc->sandbox_denials))
        {
            arch::SerialWrite("[sys] denied syscall=SYS_BP_INSTALL pid=");
            arch::SerialWriteHex(pid);
            arch::SerialWrite(" cap=");
            arch::SerialWrite(core::CapName(core::kCapDebug));
            arch::SerialWrite("\n");
        }
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 va = frame->rdi;
    const u64 kind_u = frame->rsi;
    const u64 len_u = frame->rdx;
    // High bits of `kind` carry modifier flags. Bit 4 (0x10) =
    // suspend-on-hit.
    const bool suspend_on_hit = (kind_u & 0x10) != 0;
    BpKind kind = BpKind::HwExecute;
    switch (kind_u & 0xF)
    {
    case 1:
        kind = BpKind::HwExecute;
        break;
    case 2:
        kind = BpKind::HwWrite;
        break;
    case 3:
        kind = BpKind::HwReadWrite;
        break;
    default:
        frame->rax = static_cast<u64>(-1);
        return;
    }
    BpLen len = BpLen::One;
    switch (len_u)
    {
    case 1:
        len = BpLen::One;
        break;
    case 2:
        len = BpLen::Two;
        break;
    case 4:
        len = BpLen::Four;
        break;
    case 8:
        len = BpLen::Eight;
        break;
    default:
        frame->rax = static_cast<u64>(-1);
        return;
    }
    BpError err = BpError::None;
    const BreakpointId id = BpInstallHardware(va, kind, len, proc->pid, suspend_on_hit, &err);
    if (err != BpError::None || id.value == 0)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = static_cast<u64>(id.value);
}

void DoBpRemove(arch::TrapFrame* frame)
{
    // rdi = bp_id. Returns 0 on success, u64(-1) on unknown id or
    // cross-owner attempt.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr || !core::CapSetHas(proc->caps, core::kCapDebug))
    {
        const u64 pid = (proc != nullptr) ? proc->pid : 0;
        core::RecordSandboxDenial(core::kCapDebug);
        if (proc != nullptr && core::ShouldLogDenial(proc->sandbox_denials))
        {
            arch::SerialWrite("[sys] denied syscall=SYS_BP_REMOVE pid=");
            arch::SerialWriteHex(pid);
            arch::SerialWrite(" cap=");
            arch::SerialWrite(core::CapName(core::kCapDebug));
            arch::SerialWrite("\n");
        }
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const BreakpointId id = {static_cast<u32>(frame->rdi)};
    const BpError err = BpRemove(id, proc->pid);
    frame->rax = (err == BpError::None) ? 0ULL : static_cast<u64>(-1);
}

} // namespace duetos::debug
