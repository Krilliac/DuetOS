#pragma once

#include "../core/types.h"

/*
 * CustomOS — per-CPU data (v0).
 *
 * Each CPU gets its own `PerCpu` struct. The struct pointer lives in
 * the `IA32_GS_BASE` MSR (0xC0000101), so any CPU can read its own
 * per-CPU data via `mov rax, gs:[offset]` with zero synchronization.
 *
 * Today (pre-SMP) only the BSP's struct exists; `PerCpuInitBsp` is
 * called from `kernel_main` before `SchedInit`. When SMP AP bring-up
 * lands, each AP trampoline will allocate its own PerCpu and write
 * GSBASE with its address before jumping into kernel code.
 *
 * Context: kernel. Safe at any interrupt level — accessing GSBASE is
 * a straight MSR read on every CPU that supports long mode.
 */

namespace customos::sched
{
struct Task; // forward decl; defined in kernel/sched/sched.cpp
}

namespace customos::cpu
{

struct PerCpu
{
    u32 cpu_id;                // 0 = BSP; APs number 1..N in bring-up order
    u32 lapic_id;              // APIC ID as read from LAPIC ID register
    sched::Task* current_task; // currently-running Task (was g_current)
    bool need_resched;         // set by TimerHandler / wake paths
    u8 _pad[7];                // keep 8-byte alignment after bool

    // Everything below this line will grow as SMP matures:
    //   - per-CPU runqueue head/tail + spinlock
    //   - per-CPU heap magazine (when the heap grows per-CPU caching)
    //   - TSS pointer
    //   - idle stack pointer
    //   - stats (ticks, context switches, irqs served)
};

/// Install the BSP's PerCpu struct and write its address to GSBASE.
/// Called once from kernel_main before SchedInit so that CurrentCpu()
/// is valid when the scheduler comes up. Also records the BSP's APIC
/// ID (read from the LAPIC register — LapicInit must have run).
void PerCpuInitBsp();

/// Return a pointer to the currently-executing CPU's PerCpu struct.
/// Reads GSBASE — constant-time, no locks. Safe from IRQ context.
PerCpu* CurrentCpu();

/// Convenience wrapper. Returns `CurrentCpu()->cpu_id` if GSBASE is
/// set, or 0 (BSP) if it isn't. Used by very-early code (e.g. the
/// spinlock primitive during BSP bring-up, before PerCpuInitBsp has
/// run) so that lock-owner tracking still produces a meaningful value.
u32 CurrentCpuIdOrBsp();

} // namespace customos::cpu
