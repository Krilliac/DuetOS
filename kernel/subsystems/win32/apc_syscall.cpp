/*
 * SYS_QUEUE_USER_APC / SYS_DRAIN_USER_APC implementation.
 *
 * The kernel-resident APC queue lives on `core::Process::apc_slots`
 * (16 entries, see process.h). SYS_QUEUE_USER_APC writes into the
 * TARGET task's process queue; SYS_DRAIN_USER_APC pops the first
 * entry whose `target_tid` matches the calling task. The kernel
 * never invokes the user-mode pfn — it only stages the
 * (pfn, NormalContext, SystemArgument1, SystemArgument2) tuple so
 * the caller can call it from ring 3 after returning from
 * SYS_DRAIN_USER_APC. Single-argument PAPCFUNC callers leave the
 * SA1 / SA2 register inputs zeroed and the SA1 / SA2 user-pointer
 * outputs at NULL — the kernel stores and copies-back whatever
 * was passed, so 1-arg and 3-arg shapes share the slot table
 * without an ABI fork.
 *
 * Cross-process delivery is GAP: SYS_QUEUE_USER_APC requires the
 * target task's owning Process to match the caller. NtQueueApcThread
 * with a foreign thread handle returns -1 from ring 0 and the
 * caller is expected to fall through to its synchronous path.
 */

#include "subsystems/win32/apc_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "syscall/syscall.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u64 kBadResult = static_cast<u64>(-1);

// Win32 GetCurrentThread pseudo-handle (-2) and "no thread"
// sentinels collapse to "self".
bool TidIsSelfSentinel(u64 tid)
{
    if (tid == 0)
        return true;
    if (tid == static_cast<u64>(-1))
        return true;
    if (tid == static_cast<u64>(-2))
        return true;
    return false;
}

} // namespace

void DoQueueUserApc(arch::TrapFrame* frame)
{
    using ::duetos::core::CapSetHas;
    using ::duetos::core::kCapSpawnThread;
    using ::duetos::core::Process;

    Process* caller = ::duetos::core::CurrentProcess();
    if (caller == nullptr)
    {
        frame->rax = kBadResult;
        return;
    }
    if (!CapSetHas(caller->caps, kCapSpawnThread))
    {
        ::duetos::core::RecordSandboxDenial(kCapSpawnThread);
        frame->rax = kBadResult;
        return;
    }

    u64 target_tid = frame->rdi;
    const u64 pfn = frame->rsi;
    const u64 data = frame->rdx;
    // Nt-style three-arg APC payload — SystemArgument1 / SystemArgument2.
    // Legacy QueueUserAPC callers leave r10/r8 zeroed (they only
    // pass rdi/rsi/rdx); the kernel stores whatever was passed and
    // hands it back on drain, so single-arg callers remain wire-
    // compatible without code changes.
    const u64 arg1 = frame->r10;
    const u64 arg2 = frame->r8;

    if (pfn == 0)
    {
        frame->rax = kBadResult;
        return;
    }

    if (TidIsSelfSentinel(target_tid))
        target_tid = ::duetos::sched::CurrentTaskId();

    // Resolve the target tid to a live task and verify same-process.
    // Cross-process is GAP — drop with -1 so the caller's fallback
    // path (synchronous polling) runs.
    Process* target_proc = caller;
    if (target_tid != ::duetos::sched::CurrentTaskId())
    {
        ::duetos::sched::Task* t = ::duetos::sched::SchedFindTaskByTid(target_tid);
        if (t == nullptr)
        {
            frame->rax = kBadResult;
            return;
        }
        Process* t_proc = ::duetos::sched::TaskProcess(t);
        if (t_proc == nullptr || t_proc != caller)
        {
            // Cross-process or kernel-only task — refuse.
            frame->rax = kBadResult;
            return;
        }
        target_proc = t_proc;
    }

    // Find a free slot in the target process's queue.
    for (u32 i = 0; i < Process::kApcSlotCap; ++i)
    {
        if (target_proc->apc_slots[i].in_use == 0)
        {
            target_proc->apc_slots[i].target_tid = target_tid;
            target_proc->apc_slots[i].pfn = pfn;
            target_proc->apc_slots[i].data = data;
            target_proc->apc_slots[i].arg1 = arg1;
            target_proc->apc_slots[i].arg2 = arg2;
            target_proc->apc_slots[i].in_use = 1;
            frame->rax = 0;
            return;
        }
    }

    // Queue full. The user-space queue acts as overflow buffer.
    frame->rax = kBadResult;
}

void DoDrainUserApc(arch::TrapFrame* frame)
{
    using ::duetos::core::Process;

    Process* caller = ::duetos::core::CurrentProcess();
    if (caller == nullptr)
    {
        frame->rax = kBadResult;
        return;
    }

    const u64 user_pfn_out = frame->rdi;
    const u64 user_data_out = frame->rsi;
    // SystemArgument1 / SystemArgument2 sinks — optional. NULL
    // means "drop"; the original SYS_DRAIN_USER_APC contract took
    // only pfn + data and we keep that path working by treating
    // the new outs as opt-in. Legacy kernel32!win32_drain_apc_queue
    // callers can ride the same syscall without an ABI fork.
    const u64 user_arg1_out = frame->rdx;
    const u64 user_arg2_out = frame->r10;
    if (user_pfn_out == 0 || user_data_out == 0)
    {
        frame->rax = kBadResult;
        return;
    }

    const u64 self_tid = ::duetos::sched::CurrentTaskId();

    // Drain in registration order.
    for (u32 i = 0; i < Process::kApcSlotCap; ++i)
    {
        if (caller->apc_slots[i].in_use != 0 && caller->apc_slots[i].target_tid == self_tid)
        {
            const u64 pfn = caller->apc_slots[i].pfn;
            const u64 data = caller->apc_slots[i].data;
            const u64 arg1 = caller->apc_slots[i].arg1;
            const u64 arg2 = caller->apc_slots[i].arg2;
            // Free the slot BEFORE copying out so a faulting copy
            // doesn't strand the entry in the queue.
            caller->apc_slots[i].in_use = 0;
            caller->apc_slots[i].pfn = 0;
            caller->apc_slots[i].data = 0;
            caller->apc_slots[i].arg1 = 0;
            caller->apc_slots[i].arg2 = 0;
            caller->apc_slots[i].target_tid = 0;

            if (!::duetos::mm::CopyToUser(reinterpret_cast<void*>(user_pfn_out), &pfn, sizeof(pfn)) ||
                !::duetos::mm::CopyToUser(reinterpret_cast<void*>(user_data_out), &data, sizeof(data)))
            {
                // Bad user pointer — entry is already lost. Surface
                // the failure so the caller doesn't loop forever.
                frame->rax = kBadResult;
                return;
            }
            // SA1 / SA2 are opt-in — only copy if the caller passed
            // a non-NULL sink. A faulting write here mirrors the
            // pfn/data failure semantics: surface kBadResult so the
            // caller doesn't loop forever on a half-delivered APC.
            if (user_arg1_out != 0)
            {
                if (!::duetos::mm::CopyToUser(reinterpret_cast<void*>(user_arg1_out), &arg1, sizeof(arg1)))
                {
                    frame->rax = kBadResult;
                    return;
                }
            }
            if (user_arg2_out != 0)
            {
                if (!::duetos::mm::CopyToUser(reinterpret_cast<void*>(user_arg2_out), &arg2, sizeof(arg2)))
                {
                    frame->rax = kBadResult;
                    return;
                }
            }
            frame->rax = 1;
            return;
        }
    }

    // Empty queue.
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
