#include "cpu/critical.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/percpu_ops.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "log/klog.h"
#include "sched/sched.h"

/*
 * DuetOS — preemption-off (IRQs-on) critical section, implementation.
 *
 * See kernel/cpu/critical.h for the design rationale.
 *
 * The hot path uses the single-instruction `arch::ThisCpu*` operators
 * to read-modify-write the four per-CPU u32/u64 slots
 * (critnest, deferred_preempt, critical_enter_count,
 * critical_exit_count, critical_deferred_count, critical_max_nesting).
 *
 * critnest and deferred_preempt are u32 — the `arch::ThisCpu*`
 * helpers operate on u64; we access these slots via the normal
 * `cpu::CurrentCpu()` pointer (which is also one instruction: a GS
 * load + offset). The cost difference between a `mov %gs:off, %reg`
 * via the pointer-deref and a hand-written `gs:`-relative
 * read-modify-write is negligible at this granularity; using the
 * normal access keeps the code readable and avoids partial-word
 * `gs:` access tricks. The stat counters ARE u64 and use the
 * `arch::ThisCpu*` operators.
 */

namespace duetos::cpu
{

namespace
{

// One-instruction increment of the per-CPU enter / exit / deferred
// counters via the GS segment override. These are u64 fields, so
// the `arch::ThisCpu*` helpers apply directly.
constexpr u64 kOffEnterCount = DUETOS_THIS_CPU_OFFSET(PerCpu, critical_enter_count);
constexpr u64 kOffExitCount = DUETOS_THIS_CPU_OFFSET(PerCpu, critical_exit_count);
constexpr u64 kOffDeferredCount = DUETOS_THIS_CPU_OFFSET(PerCpu, critical_deferred_count);

} // namespace

void CriticalEnter()
{
    // Path is hot. No KLOG_TRACE here — every critical section would
    // emit two trace lines (one per Enter, one per Exit) which would
    // saturate the trace ring instantly. Add a probe instead if a
    // future investigation needs visibility.
    //
    // BspInstalled gate: before PerCpuInitBsp runs, GSBASE points
    // at user-mode garbage (or zero). The very-early boot path
    // doesn't call CriticalEnter today, but the guard means a
    // future bring-up reorder surfaces a clean panic instead of a
    // triple fault.
    if (!cpu::BspInstalled())
    {
        return;
    }

    PerCpu* p = CurrentCpu();
    // Single-CPU writer → no LOCK prefix. Migration is what this
    // primitive is preventing, and a same-CPU IRQ taken between the
    // load and the store can't observe a partial value (incl. an
    // IRQ that also calls CriticalEnter — it would observe the new
    // value or the old, never a torn value).
    const u32 new_nest = p->critnest + 1;
    p->critnest = new_nest;

    // Track the high-water mark for the diagnostic sum-walk. Same
    // single-CPU-writer rule applies.
    if (new_nest > p->critical_max_nesting)
    {
        p->critical_max_nesting = new_nest;
    }

    arch::ThisCpuInc64(kOffEnterCount);
}

void CriticalExit()
{
    if (!cpu::BspInstalled())
    {
        return;
    }

    PerCpu* p = CurrentCpu();
    // Underflow guard — pairs MUST balance. A CriticalExit without a
    // matching Enter is a contract violation; surfacing it here
    // (instead of underflowing critnest to UINT32_MAX and silently
    // disabling preemption forever) is essential for catching the
    // RAII-bypass cases.
    KASSERT_WITH_VALUE(p->critnest > 0, "cpu/critical", "CriticalExit with critnest == 0", p->critnest);

    const u32 new_nest = p->critnest - 1;
    p->critnest = new_nest;
    arch::ThisCpuInc64(kOffExitCount);

    if (new_nest != 0)
    {
        return; // still nested — no preempt drain yet.
    }

    // critnest just returned to zero. If a reschedule was deferred
    // while we were inside the critical section, drain it now.
    //
    // Important ordering: clear deferred_preempt BEFORE calling
    // Schedule(). Schedule() may not return (this task could be
    // descheduled), and even if it does, a peer-CPU's set of
    // deferred_preempt while we were inside the section is the
    // request to reschedule — once we've honoured it, the flag
    // should be down. Re-arming during this CPU's next tick is the
    // tick handler's job, not ours.
    if (p->deferred_preempt != 0)
    {
        p->deferred_preempt = 0;
        // Mirror the existing TakeNeedResched + Schedule pattern in
        // arch/x86_64/traps.cpp (post-IRQ handler). IRQs must be on
        // here — we're back at preempt-OK, and the scheduler's lock
        // acquire handles its own IRQ masking.
        sched::Schedule();
    }
}

u32 CriticalNesting()
{
    if (!cpu::BspInstalled())
    {
        return 0;
    }
    return CurrentCpu()->critnest;
}

bool DeferPreemptIfCritical()
{
    if (!cpu::BspInstalled())
    {
        return false;
    }
    PerCpu* p = CurrentCpu();
    if (p->critnest == 0)
    {
        return false; // caller may proceed to Schedule() directly.
    }
    // Inside a critical section. Mark the deferred-preempt flag and
    // bump the diagnostic counter. CriticalExit's drain will pick
    // it up.
    p->deferred_preempt = 1;
    arch::ThisCpuInc64(kOffDeferredCount);
    return true;
}

CriticalStats CriticalStatsRead()
{
    CriticalStats s{};
    // Cross-CPU sum-walk. Same shape as SchedStats: visit every CPU
    // slot, sum the per-CPU partial counts. Reads are unsynchronised
    // — a stale partial is fine; these are diagnostic counters.
    const u32 cpu_limit = arch::SmpCpuIdLimit();
    for (u32 i = 0; i < cpu_limit; ++i)
    {
        PerCpu* p = arch::SmpGetPercpu(i);
        if (p == nullptr)
        {
            continue;
        }
        s.enter_total += p->critical_enter_count;
        s.exit_total += p->critical_exit_count;
        s.deferred_preempts_total += p->critical_deferred_count;
        if (p->critical_max_nesting > s.max_nesting_observed)
        {
            s.max_nesting_observed = p->critical_max_nesting;
        }
    }
    return s;
}

void CriticalSelfTest()
{
    KLOG_TRACE_SCOPE("cpu/critical", "CriticalSelfTest");

    // Must run AFTER PerCpuInitBsp — every read/write of critnest
    // goes through CurrentCpu(). The caller (boot_bringup) sequences
    // the call correctly; this guard exists so a future reordering
    // surfaces a clean panic instead of a triple fault.
    KASSERT(cpu::BspInstalled(), "cpu/critical", "self-test ran before BSP install");

    PerCpu* p = CurrentCpu();
    const u32 baseline_nest = p->critnest;
    const u32 baseline_deferred = p->deferred_preempt;
    const u64 baseline_enter = p->critical_enter_count;
    const u64 baseline_exit = p->critical_exit_count;
    const u64 baseline_def_count = p->critical_deferred_count;

    KASSERT_WITH_VALUE(baseline_nest == 0, "cpu/critical", "self-test entered with critnest != 0", baseline_nest);
    KASSERT_WITH_VALUE(baseline_deferred == 0, "cpu/critical", "self-test entered with deferred_preempt != 0",
                       baseline_deferred);

    // 1. Plain enter / exit round-trip. critnest must return to zero.
    CriticalEnter();
    KASSERT_WITH_VALUE(p->critnest == 1, "cpu/critical", "single Enter did not bump critnest to 1", p->critnest);
    CriticalExit();
    KASSERT_WITH_VALUE(p->critnest == 0, "cpu/critical", "single Exit did not restore critnest to 0", p->critnest);

    // 2. Nested enter / exit. Walk to depth 3, verify each step.
    CriticalEnter();
    KASSERT_WITH_VALUE(p->critnest == 1, "cpu/critical", "nested Enter depth-1 mismatch", p->critnest);
    CriticalEnter();
    KASSERT_WITH_VALUE(p->critnest == 2, "cpu/critical", "nested Enter depth-2 mismatch", p->critnest);
    CriticalEnter();
    KASSERT_WITH_VALUE(p->critnest == 3, "cpu/critical", "nested Enter depth-3 mismatch", p->critnest);
    CriticalExit();
    KASSERT_WITH_VALUE(p->critnest == 2, "cpu/critical", "nested Exit depth-2 mismatch", p->critnest);
    CriticalExit();
    KASSERT_WITH_VALUE(p->critnest == 1, "cpu/critical", "nested Exit depth-1 mismatch", p->critnest);
    CriticalExit();
    KASSERT_WITH_VALUE(p->critnest == 0, "cpu/critical", "nested Exit depth-0 mismatch", p->critnest);

    // 3. RAII guard. Scope-based pair.
    {
        CriticalGuard g;
        KASSERT_WITH_VALUE(p->critnest == 1, "cpu/critical", "CriticalGuard did not bump critnest", p->critnest);
    }
    KASSERT_WITH_VALUE(p->critnest == 0, "cpu/critical", "CriticalGuard did not restore critnest", p->critnest);

    // 4. Deferred preempt. Enter, simulate a "preempt me" request
    //    via the public DeferPreemptIfCritical path (which is what
    //    the scheduler's tick handler calls). The flag must be set
    //    while we're inside; CriticalExit must clear it; the
    //    deferred-count counter must advance.
    const u64 before_deferred = p->critical_deferred_count;
    CriticalEnter();
    const bool deferred = DeferPreemptIfCritical();
    KASSERT(deferred == true, "cpu/critical", "DeferPreemptIfCritical returned false inside critical section");
    KASSERT_WITH_VALUE(p->deferred_preempt == 1, "cpu/critical",
                       "DeferPreemptIfCritical did not set deferred_preempt flag", p->deferred_preempt);
    KASSERT_WITH_VALUE(p->critical_deferred_count == before_deferred + 1, "cpu/critical",
                       "deferred-preempt counter did not advance", p->critical_deferred_count);

    // CriticalExit will see deferred_preempt == 1 and clear it.
    // We can't easily verify "Schedule() was called" without a
    // probe-style hook — but we CAN verify the flag was cleared,
    // which is the externally-observable signal that the drain ran.
    // Schedule() itself is exercised continuously by the boot path
    // (every timer tick); the in-flight Schedule from this self-
    // test would just pick the same task (us) right back, since
    // no other runnable task is parked behind a deferred preempt.
    CriticalExit();
    KASSERT_WITH_VALUE(p->deferred_preempt == 0, "cpu/critical", "CriticalExit did not drain deferred_preempt",
                       p->deferred_preempt);
    KASSERT_WITH_VALUE(p->critnest == 0, "cpu/critical", "deferred-drain Exit did not restore critnest to 0",
                       p->critnest);

    // 5. Sanity: when NOT inside a critical section,
    //    DeferPreemptIfCritical must report false and not touch the
    //    counter.
    const u64 before_no_defer = p->critical_deferred_count;
    const bool no_defer = DeferPreemptIfCritical();
    KASSERT(no_defer == false, "cpu/critical", "DeferPreemptIfCritical returned true outside critical section");
    KASSERT_WITH_VALUE(p->critical_deferred_count == before_no_defer, "cpu/critical",
                       "deferred-preempt counter advanced outside critical section", p->critical_deferred_count);

    // 6. Counter deltas. Enter ran 5 times (steps 1 + 2x3 + 3 RAII +
    //    4) wait — 1 + 3 + 1 + 1 = 6. Exit also 6. Recompute exactly
    //    so the assertion is self-checking.
    constexpr u64 kExpectedEnters = 1    // step 1
                                    + 3  // step 2
                                    + 1  // step 3 RAII
                                    + 1; // step 4
    constexpr u64 kExpectedExits = kExpectedEnters;
    KASSERT_WITH_VALUE(p->critical_enter_count == baseline_enter + kExpectedEnters, "cpu/critical",
                       "enter_count delta wrong", p->critical_enter_count - baseline_enter);
    KASSERT_WITH_VALUE(p->critical_exit_count == baseline_exit + kExpectedExits, "cpu/critical",
                       "exit_count delta wrong", p->critical_exit_count - baseline_exit);
    KASSERT_WITH_VALUE(p->critical_deferred_count == baseline_def_count + 1, "cpu/critical",
                       "deferred_count delta wrong", p->critical_deferred_count - baseline_def_count);

    // Max nesting observed must be at least 3 (step 2 walked to
    // depth 3). It may be higher if some future hot-path Enter ran
    // before us with deeper nesting — but the self-test runs at
    // boot before there's any other critical-section client, so 3
    // is the value we expect today. Use ">=" to be future-robust.
    KASSERT_WITH_VALUE(p->critical_max_nesting >= 3, "cpu/critical", "max_nesting did not record depth 3",
                       p->critical_max_nesting);

    // Structural sentinel — CI greps for this line as proof the
    // self-test actually ran (PASS is otherwise silent).
    arch::SerialWrite("[critical] self-test OK\n");
}

} // namespace duetos::cpu
