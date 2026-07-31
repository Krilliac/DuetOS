#include "subsystems/win32/fiber_syscall.h"

#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

namespace duetos::subsystems::win32
{

// ---------------------------------------------------------------------------
// Fiber syscall handlers
// ---------------------------------------------------------------------------

void DoFiberConvert(arch::TrapFrame* frame)
{
    KLOG_TRACE("win32/fiber", "DoFiberConvert: enter");
    const u64 fiber_data = frame->rdi;

    const u64 result = sched::CurrentTaskFiberConvert(fiber_data);
    if (result == 0)
    {
        KLOG_WARN("win32/fiber", "DoFiberConvert: failed (already fiber or table full)");
    }
    else
    {
        KLOG_DEBUG_V("win32/fiber", "DoFiberConvert: slot", result);
    }
    frame->rax = result;
}

void DoFiberCreate(arch::TrapFrame* frame)
{
    KLOG_TRACE("win32/fiber", "DoFiberCreate: enter");
    const u64 start_address = frame->rdi;
    const u64 fiber_data = frame->rsi;
    u64 stack_size = frame->rdx;

    if (start_address == 0)
    {
        KLOG_WARN("win32/fiber", "DoFiberCreate: null start address");
        frame->rax = 0;
        return;
    }

    if (!sched::CurrentTaskIsFiber())
    {
        KLOG_WARN("win32/fiber", "DoFiberCreate: thread not converted to fiber");
        frame->rax = 0;
        return;
    }

    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }

    // Default stack: 16 pages = 64 KiB.
    constexpr u64 kDefaultFiberStackPages = 16;
    u64 pages = kDefaultFiberStackPages;
    if (stack_size != 0)
    {
        if (stack_size > (~u64(0) - (mm::kPageSize - 1)))
        {
            KLOG_WARN("win32/fiber", "DoFiberCreate: stack-size rounding overflow");
            frame->rax = 0;
            return;
        }
        pages = (stack_size + mm::kPageSize - 1) / mm::kPageSize;
    }
    // Clamp to reasonable bounds.
    if (pages > 64)
    {
        pages = 64; // 256 KiB max per fiber stack
    }

    // Allocate user VA from the process vmap arena.
    if (proc->vmap_pages_used > core::Process::kWin32VmapCapPages ||
        pages > core::Process::kWin32VmapCapPages - proc->vmap_pages_used)
    {
        KLOG_WARN("win32/fiber", "DoFiberCreate: vmap arena full");
        frame->rax = 0;
        return;
    }

    const u64 stack_base = proc->vmap_base + proc->vmap_pages_used * mm::kPageSize;

    // Map physical frames.
    for (u64 i = 0; i < pages; ++i)
    {
        const mm::PhysAddr f = mm::AllocateFrame().value_or(mm::kNullFrame);
        if (f == mm::kNullFrame)
        {
            for (u64 j = 0; j < i; ++j)
                (void)mm::AddressSpaceUnmapUserPage(proc->as, stack_base + j * mm::kPageSize);
            KLOG_WARN("win32/fiber", "DoFiberCreate: OOM allocating stack frames");
            frame->rax = 0;
            return;
        }
        const u64 va = stack_base + i * mm::kPageSize;
        if (!mm::AddressSpaceMapUserPage(proc->as, va, f,
                                         mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute))
        {
            mm::FreeFrame(f);
            for (u64 j = 0; j < i; ++j)
                (void)mm::AddressSpaceUnmapUserPage(proc->as, stack_base + j * mm::kPageSize);
            KLOG_WARN("win32/fiber", "DoFiberCreate: stack map refused");
            frame->rax = 0;
            return;
        }
    }
    proc->vmap_pages_used += pages;

    // Register the fiber in the task's fiber table.
    const u64 result = sched::CurrentTaskFiberCreate(start_address, fiber_data, pages, stack_base);
    if (result == 0)
    {
        KLOG_WARN("win32/fiber", "DoFiberCreate: fiber table full");
        for (u64 i = 0; i < pages; ++i)
            (void)mm::AddressSpaceUnmapUserPage(proc->as, stack_base + i * mm::kPageSize);
        proc->vmap_pages_used -= pages;
        return;
    }
    else
    {
        KLOG_DEBUG_V("win32/fiber", "DoFiberCreate: fiber addr", result);
    }
    frame->rax = result;
}

void DoFiberSwitch(arch::TrapFrame* frame)
{
    const u64 target_addr = frame->rdi;
    KLOG_TRACE_V("win32/fiber", "DoFiberSwitch: target", target_addr);

    if (target_addr == 0 || target_addr > sched::kFiberCap)
    {
        KLOG_WARN_V("win32/fiber", "DoFiberSwitch: bad target addr", target_addr);
        return; // SwitchToFiber is void — no return value
    }

    const u32 target_slot = static_cast<u32>(target_addr - 1);
    if (!sched::CurrentTaskFiberSwitch(target_slot, frame))
    {
        KLOG_WARN_V("win32/fiber", "DoFiberSwitch: switch failed, slot", target_slot);
    }
    // On success, frame->rip/rsp/regs now point to the target fiber's
    // saved context. When the syscall returns via iretq, execution
    // resumes in the target fiber.
}

void DoFiberDelete(arch::TrapFrame* frame)
{
    const u64 target_addr = frame->rdi;
    KLOG_TRACE_V("win32/fiber", "DoFiberDelete: target", target_addr);

    if (target_addr == 0 || target_addr > sched::kFiberCap)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const u32 target_slot = static_cast<u32>(target_addr - 1);

    // Deleting the current fiber terminates the thread.
    if (sched::CurrentTaskFiberIsActive(target_slot))
    {
        KLOG_DEBUG("win32/fiber", "DoFiberDelete: deleting current fiber -> exit");
        sched::SchedExit(); // noreturn
    }

    u64 stack_base = 0;
    u64 stack_pages = 0;
    if (!sched::CurrentTaskFiberDelete(target_slot, &stack_base, &stack_pages))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // GAP: stack frames are not reclaimed (vmap is bump-only in v0) — reclaim when vmap gets a free-list
    (void)stack_base;
    (void)stack_pages;

    frame->rax = 0;
}

// ---------------------------------------------------------------------------
// FLS syscall handlers
// ---------------------------------------------------------------------------

namespace
{
constexpr u32 kErrorSuccess = 0;
constexpr u32 kErrorInvalidParameter = 87;

u64 AdvanceFlsGeneration(core::Process* process, u32 slot)
{
    u64 next = process->fls_slot_generation[slot] + 1;
    if (next == 0)
    {
        next = 1;
    }
    process->fls_slot_generation[slot] = next;
    return next;
}
} // namespace

void DoFlsAlloc(arch::TrapFrame* frame)
{
    KLOG_TRACE("win32/fls", "DoFlsAlloc: enter");
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const u64 cleanup_cb = frame->rdi; // callback VA (0 = none)

    u64 slot = core::Process::kWin32FlsCap;
    u64 generation = 0;
    {
        sync::SpinLockGuard guard(proc->fls_lock);
        for (u64 i = 0; i < core::Process::kWin32FlsCap; ++i)
        {
            if ((proc->fls_slot_in_use & (1u << i)) == 0)
            {
                slot = i;
                break;
            }
        }
        if (slot != core::Process::kWin32FlsCap)
        {
            proc->fls_slot_in_use |= (1u << slot);
            generation = AdvanceFlsGeneration(proc, static_cast<u32>(slot));
            proc->fls_cleanup_callback[slot] = cleanup_cb;
        }
    }
    if (slot == core::Process::kWin32FlsCap)
    {
        KLOG_WARN("win32/fls", "DoFlsAlloc: all slots in use");
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Zero the current fiber's (or thread's) FLS value for this slot.
    u64* fls_vals = sched::CurrentTaskActiveFiberFlsValues();
    u64* fls_gens = sched::CurrentTaskActiveFiberFlsGenerations();
    if (fls_vals != nullptr && slot < sched::kFlsCap)
    {
        fls_vals[slot] = 0;
        fls_gens[slot] = generation;
    }

    KLOG_DEBUG_V("win32/fls", "DoFlsAlloc: granted slot", slot);
    frame->rax = slot;
}

void DoFlsFree(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/fls", "DoFlsFree: idx", frame->rdi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32FlsCap)
    {
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    bool was_in_use = false;
    {
        sync::SpinLockGuard guard(proc->fls_lock);
        was_in_use = (proc->fls_slot_in_use & (1u << idx)) != 0;
        if (was_in_use)
        {
            proc->fls_slot_in_use &= ~(1u << idx);
            AdvanceFlsGeneration(proc, static_cast<u32>(idx));
            proc->fls_cleanup_callback[idx] = 0;
        }
    }
    if (!was_in_use)
    {
        sched::SetCurrentTaskWin32LastError(kErrorInvalidParameter);
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // GAP: cleanup callbacks not invoked on FlsFree — revisit when real CRT needs it
    frame->rax = 0;
}

void DoFlsGet(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/fls", "DoFlsGet: idx", frame->rdi);
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32FlsCap)
    {
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

    // Snapshot the generation under the lock.
    u64 generation = 0;
    {
        sync::SpinLockGuard guard(proc->fls_lock);
        generation = proc->fls_slot_generation[idx];
    }

    // Read from the active fiber's FLS values.
    u64* fls_vals = sched::CurrentTaskActiveFiberFlsValues();
    u64* fls_gens = sched::CurrentTaskActiveFiberFlsGenerations();
    if (fls_vals != nullptr && fls_gens != nullptr)
    {
        if (fls_gens[idx] == generation)
        {
            frame->rax = fls_vals[idx];
        }
        else
        {
            frame->rax = 0; // stale generation
        }
    }
    else
    {
        // Not a fiber — fall back to TLS (same behaviour as before fibers).
        frame->rax = sched::CurrentTaskTlsSlotValue(static_cast<u32>(idx), generation);
    }
    sched::SetCurrentTaskWin32LastError(kErrorSuccess);
}

void DoFlsSet(arch::TrapFrame* frame)
{
    KLOG_TRACE_V("win32/fls", "DoFlsSet: idx", frame->rdi);
    const u64 idx = frame->rdi;
    if (idx >= core::Process::kWin32FlsCap)
    {
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

    u64 generation = 0;
    {
        sync::SpinLockGuard guard(proc->fls_lock);
        generation = proc->fls_slot_generation[idx];
    }

    u64* fls_vals = sched::CurrentTaskActiveFiberFlsValues();
    u64* fls_gens = sched::CurrentTaskActiveFiberFlsGenerations();
    if (fls_vals != nullptr && fls_gens != nullptr)
    {
        fls_vals[idx] = frame->rsi;
        fls_gens[idx] = generation;
    }
    else
    {
        // Not a fiber — fall back to TLS.
        sched::SetCurrentTaskTlsSlotValue(static_cast<u32>(idx), generation, frame->rsi);
    }
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
