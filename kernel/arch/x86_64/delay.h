#pragma once

#include "arch/x86_64/timer.h"
#include "util/types.h"

/*
 * Short busy-wait primitives for the kernel's interrupt-disabled /
 * preempt-sensitive paths (SMP bring-up, LAPIC arming, AP rendezvous).
 *
 * WHY THIS HEADER EXISTS
 *
 *   The naive shape — `while (TimerTicks() - start < N) { pause; }` —
 *   wedges under QEMU TCG with LTO release builds. The emulator
 *   never gets a chance to fire the guest's emulated LAPIC timer
 *   without an observable side effect, so `g_ticks` never advances
 *   and the loop spins forever (or for the bounded iteration cap,
 *   which has to be padded to seconds-of-wallclock to be safe).
 *
 *   Independently of TCG, the `SchedSleepTicks(1)` shape — yielding
 *   to the scheduler for one tick — used to wedge the SMP=8 release
 *   `aps=?` boot because the wake-side `PickClusterPlacement` would
 *   route the BSP boot task to a freshly-allocated AP whose own
 *   PerCpu slot existed but whose CPU wasn't running yet. That's
 *   fixed at the predicate layer (`PerCpu::online`) and the
 *   iteration-key layer (deferred `g_cpu_id_limit` bump), but the
 *   busy-wait still needs to be the right shape for both QEMU
 *   TCG and real hardware.
 *
 * THE RECIPE (Delay10msApproximate)
 *
 *   `sti; hlt` inside a loop checking `TimerTicks()`:
 *     - On real hardware: halts the CPU until the next interrupt
 *       (the LAPIC timer tick fires within 10 ms by design).
 *     - On QEMU TCG: `hlt` is the canonical "yield virtual-time
 *       to the host" instruction, so the guest's emulated clock
 *       advances and `g_ticks` increments. The volatile read in
 *       `TimerTicks()` sees the new value on the next iteration.
 *
 *   Bounded by `kMaxIters` (a defence-in-depth cap so a future
 *   regression that breaks the volatile semantics or masks the
 *   LAPIC timer can't wedge the box forever — retires in <5s of
 *   wallclock even if `g_ticks` is permanently stuck).
 *
 *   The IRQ-exit reschedule check that normally runs after a
 *   timer tick (`traps.cpp:575`) can preempt the calling task off
 *   the CPU; callers that need to keep running on the same CPU
 *   must arrange that themselves (the SmpStartAps fix uses
 *   `PerCpu::online` + the deferred `g_cpu_id_limit` bump so the
 *   preempt-back-to-this-task path can't route to an offline AP).
 *
 *   Context: kernel only. Safe to call from any kernel context
 *   that has IRQs enabled at the time of the call (the loop sets
 *   IF=1 via `sti`).
 *
 * WHEN TO USE
 *
 *   - INIT→SIPI 10ms wait in SmpStartAps (post-2026-05-22).
 *   - Any future "wait a tick or two before polling some hardware
 *     state" sequence that runs before the scheduler is healthy
 *     enough to call `SchedSleepTicks` safely.
 *
 *   Long waits (> 100ms) belong on the scheduler — use
 *   `sched::SchedSleepTicks`, not this header.
 */

namespace duetos::arch
{

/// Bounded busy-wait approximating 10ms (one timer tick at the
/// default 100Hz tick frequency). Yields via `sti; hlt` so QEMU
/// TCG advances virtual-time and real hardware idles efficiently.
/// Returns AFTER the timer-tick count has advanced by at least
/// one OR after a generous iteration cap that retires in <5s of
/// wallclock — whichever fires first.
inline void Delay10msApproximate()
{
    constexpr u64 kMaxIters = 200000000ULL;
    const u64 start = TimerTicks();
    for (u64 i = 0; i < kMaxIters; ++i)
    {
        if (TimerTicks() - start >= 1)
        {
            return;
        }
        asm volatile("sti; hlt" ::: "memory");
    }
}

} // namespace duetos::arch
