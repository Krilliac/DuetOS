#pragma once

#include "util/types.h"

/*
 * LAPIC timer — v0.
 *
 * Periodic kernel tick driven by the per-CPU LAPIC timer, calibrated once
 * at boot using the legacy PIT channel 2. Delivers interrupts at vector
 * 0x20 (IRQ 0 in the remapped IDT layout).
 *
 * Scope limits that will be fixed in later commits:
 *   - BSP only. Per-CPU calibration + per-CPU ticks come with SMP.
 *   - One-shot calibration at boot. No recalibration on CPU frequency
 *     changes (power management). Fine for early bring-up, but any
 *     serious workload will want either TSC-deadline mode or HPET-based
 *     calibration that's aware of turbo/power states.
 *   - Single global tick counter (`g_ticks`). 64-bit wraps in ~6 billion
 *     years at 100 Hz; not a real concern.
 *
 * Context: kernel. Init runs once, after LapicInit. After Init, IRQ 0x20
 * fires at `kTickFrequencyHz` until interrupts are masked.
 */

namespace duetos::arch
{

inline constexpr u8 kTimerVector = 0x20;     // IRQ 0 in remapped layout
inline constexpr u64 kTickFrequencyHz = 100; // 10 ms tick

/// Calibrate the LAPIC timer against the PIT, configure it in periodic
/// mode at `kTickFrequencyHz`, install the tick handler on `kTimerVector`,
/// and start the timer. Interrupts are NOT unmasked here — caller should
/// run `sti` (or enter IdleLoop) when ready to receive ticks.
void TimerInit();

/// Global tick counter, monotonically increasing. Safe to read from any
/// context; incremented by the timer IRQ handler. Read-only snapshot,
/// not a synchronised clock.
u64 TimerTicks();

} // namespace duetos::arch
