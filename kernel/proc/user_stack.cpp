/**
 * @file kernel/proc/user_stack.cpp
 * @brief Demand-grown ring-3 stacks — reservation planning + #PF service.
 *
 * See kernel/proc/user_stack.h for the layout diagram and the
 * growth condition. This TU owns the only code that may move a
 * process's `stack.commit_lo`.
 */

#include "proc/user_stack.h"

#include "debug/probes.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "proc/process.h"

namespace duetos::core
{
namespace
{

constexpr u64 kPageSize = duetos::mm::kPageSize;

u64 AlignDownPage(u64 v)
{
    return v & ~(kPageSize - 1);
}

u64 AlignUpPage(u64 v)
{
    return AlignDownPage(v + kPageSize - 1);
}

/// Commit one page at `page_va` into `as`. Returns false on frame
/// OOM or when the AS's frame budget refuses the mapping — both
/// leave the PTE absent, which the probe below detects.
///
/// AddressSpaceMapUserPage panics on an already-mapped VA, so the
/// present-probe here is load-bearing, not defensive padding: two
/// growth attempts racing on the same page would otherwise take
/// down the kernel.
bool CommitOnePage(mm::AddressSpace* as, u64 page_va)
{
    if ((mm::AddressSpaceProbePteRaw(as, page_va) & mm::kPagePresent) != 0)
    {
        return true; // already committed by a concurrent grow
    }

    auto frame_r = mm::AllocateFrame();
    if (!frame_r)
    {
        KLOG_WARN_V("mm/ustack", "stack grow: frame alloc failed at va", page_va);
        KBP_PROBE_V(::duetos::debug::ProbeId::kPhysAllocFail, page_va);
        return false;
    }

    const mm::PhysAddr frame = frame_r.value();
    if (!mm::AddressSpaceMapUserPage(as, page_va, frame,
                                     mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute))
    {
        KLOG_WARN_V("mm/ustack", "stack grow: MapUserPage refused (budget/OOM) at va", page_va);
        mm::FreeFrame(frame);
        return false;
    }
    return true;
}

} // namespace

const char* UserStackFaultName(UserStackFault f)
{
    switch (f)
    {
    case UserStackFault::NotStack:
        return "NotStack";
    case UserStackFault::Grow:
        return "Grow";
    case UserStackFault::Grew:
        return "Grew";
    case UserStackFault::Guard:
        return "Guard";
    case UserStackFault::Failed:
        return "Failed";
    }
    return "unknown";
}

UserStackFault UserStackServiceFault(u64 fault_va, u64 err_code, u64 rsp)
{
    Process* proc = CurrentProcess();
    if (proc == nullptr || proc->as == nullptr || proc->stack.top == 0)
    {
        return UserStackFault::NotStack;
    }

    const UserStackFault verdict = UserStackClassify(proc->stack, fault_va, err_code, rsp);

    if (verdict == UserStackFault::Guard)
    {
        // Windows commits the guard at the moment it raises
        // STATUS_STACK_OVERFLOW, so the thread's __except handler
        // has somewhere to run. One shot only — this never turns
        // Guard into Grow, so the overflowing recursion still dies;
        // it just dies with a diagnosable exception instead of an
        // unservicable second fault inside the SEH dispatcher.
        //
        // The whole region goes in at once: the dispatcher tower
        // (KiUserExceptionDispatcher -> __C_specific_handler ->
        // RtlUnwindEx) needs several KiB, and committing it lazily
        // would just re-enter here on the dispatcher's own next
        // fault, which classifies NotStack once guard_taken is set.
        if (!proc->stack.guard_taken)
        {
            proc->stack.guard_taken = true;
            for (u64 va = proc->stack.reserve_lo; va > proc->stack.guard_lo; va -= kPageSize)
            {
                const u64 page_va = va - kPageSize;
                if (!CommitOnePage(proc->as, page_va))
                {
                    break;
                }
                proc->stack.commit_lo = page_va;
            }
        }
        return UserStackFault::Guard;
    }
    if (verdict != UserStackFault::Grow)
    {
        return verdict;
    }

    const u64 page_va = AlignDownPage(fault_va);
    if (!CommitOnePage(proc->as, page_va))
    {
        return UserStackFault::Failed;
    }
    proc->stack.commit_lo = page_va;

    KLOG_DEBUG_V("mm/ustack", "stack grew to", page_va);
    return UserStackFault::Grew;
}

bool UserStackCommitRange(u64 lo, u64 hi)
{
    if (hi <= lo)
    {
        return true;
    }

    Process* proc = CurrentProcess();
    if (proc == nullptr || proc->as == nullptr || proc->stack.top == 0)
    {
        return false;
    }

    const u64 lo_page = AlignDownPage(lo);
    const u64 hi_page = AlignUpPage(hi);

    const UserStackRange& s = proc->stack;

    // Wholly inside the committable region. That is the reservation,
    // extended by the guard page once the one-shot guard commit has
    // fired — which is exactly the case that matters here: the SEH
    // records for a STATUS_STACK_OVERFLOW land in the guard page.
    const u64 floor = s.guard_taken ? s.guard_lo : s.reserve_lo;
    if (lo_page < floor || hi_page > s.top)
    {
        return false;
    }
    if (lo_page >= s.commit_lo)
    {
        return true; // already committed
    }
    // Bounded: a caller bug cannot turn one call into a
    // whole-reservation commit.
    if ((s.commit_lo - lo_page) / kPageSize > kUserStackKernelCommitMax)
    {
        KLOG_WARN_V("mm/ustack", "kernel stack pre-commit refused — range too far below commit edge", lo_page);
        return false;
    }

    for (u64 va = s.commit_lo - kPageSize; va >= lo_page; va -= kPageSize)
    {
        if (!CommitOnePage(proc->as, va))
        {
            return false;
        }
        proc->stack.commit_lo = va;
        if (va == lo_page)
        {
            break;
        }
    }
    return true;
}

} // namespace duetos::core
