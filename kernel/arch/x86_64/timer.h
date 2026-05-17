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

/// Read the x86_64 Time-Stamp Counter as a u64. Single source of truth
/// so subsystems don't open-code `rdtsc` inline asm — keeps the
/// implementation in one place if/when we need to add an `mfence;
/// rdtsc` ordering variant or switch to `rdtscp` for serialised reads.
/// Callers requiring strict ordering w.r.t. surrounding loads/stores
/// should add their own fence; this helper is the unordered fast path.
/// Safe from any context, including NMI.
inline u64 TscRead()
{
    u32 lo;
    u32 hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<u64>(hi) << 32) | lo;
}

/// Calibrate the LAPIC timer against the PIT, configure it in periodic
/// mode at `kTickFrequencyHz`, install the tick handler on `kTimerVector`,
/// and start the timer. Interrupts are NOT unmasked here — caller should
/// run `sti` (or enter IdleLoop) when ready to receive ticks.
void TimerInit();

/// Verify the armed LAPIC timer actually delivers its IRQ, and fall
/// back to an IOAPIC-routed PIT channel-0 periodic tick if it does
/// not. Call this AFTER interrupts are live and the LAPIC timer is
/// armed (i.e. after `TimerInit()` and the scheduler/`sti`), and
/// BEFORE any long-running / CPU-bound ring-3 task is spawned. It
/// watches the tick counter across a short TSC-bounded window; if it
/// never advances (observed under VirtualBox: the LAPIC timer counts
/// but the underflow interrupt is never raised), it masks the LAPIC
/// timer LVT and drives the scheduler tick from PIT ch0 (periodic,
/// mode 3) routed via the IOAPIC as ISA IRQ 0 to `kTimerVector`.
/// No-op on QEMU / real hardware where the LAPIC timer delivers.
void TimerVerifyDeliveryOrFallback();

/// Global tick counter, monotonically increasing. Safe to read from any
/// context; incremented by the timer IRQ handler. Read-only snapshot,
/// not a synchronised clock.
u64 TimerTicks();

/// Arm the LAPIC timer on the calling CPU using the cached calibration
/// from TimerInit. Used by APs in SchedEnterOnAp — TimerInit ran on
/// the BSP and computed g_lapic_ticks_per_period; the AP's LAPIC bus
/// clock is assumed identical (defensible v0 assumption for a
/// homogeneous package). Idempotent — programs the AP's LAPIC timer
/// MMIO registers; doesn't touch the global tick counter or install
/// the IDT handler (already installed BSP-side).
///
/// `// GAP: per-package LAPIC frequency variance — recalibrate per CPU
/// when the workload exposes drift.`
void LapicTimerStartOnCurrent();

/// Inform the init-wedge watchdog that boot init has finished. After
/// this call, steady-state quiet windows (idle loop, compositor naps
/// with no UI activity) stop counting toward the silent-heartbeats
/// threshold. Idempotent; called from `core/main.cpp` at the end of
/// the `Userland` phase.
void MarkInitComplete();

/// Configure the init-wedge watchdog escalation. 0 (default) =
/// warn-only: the watchdog logs an `[init-wedge] WARN` line and
/// fires the `boot.init_wedge` probe but the kernel keeps trying
/// to progress. >0 = panic: after `silent_heartbeats` consecutive
/// 5 s intervals of zero init progress, the watchdog calls
/// `core::Panic` so an attached debugger / CI grep gets a hard
/// failure instead of a stuck box. Parsed from the kernel cmdline
/// arg `init-wedge-panic=<N>` in `core/main.cpp`.
void SetInitWedgePanicThreshold(u32 silent_heartbeats);

} // namespace duetos::arch
