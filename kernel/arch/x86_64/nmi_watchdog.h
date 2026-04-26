#pragma once

#include "util/types.h"

/*
 * DuetOS — NMI watchdog.
 *
 * Detects a wedged kernel — one that's stuck hard enough that the
 * normal scheduler tick (and therefore the health scan) has
 * stopped firing. The health scan catches every slow drift; the
 * watchdog covers the one class of failure where the scan itself
 * is the thing that's not running.
 *
 * Mechanism: architectural Performance Monitoring Unit counter 0
 * counts unhalted core cycles. The counter is preloaded so it
 * overflows every few seconds of real execution; the LAPIC LVT
 * Perfmon entry is configured to deliver NMI on overflow. An NMI
 * is not maskable by RFLAGS.IF, so it fires even when the CPU has
 * been running with CLI for a long time.
 *
 * Pet: the timer IRQ handler increments a `pet_counter` on every
 * tick. Each watchdog-NMI compares the current pet_counter to the
 * one observed at the previous watchdog-NMI. If it didn't advance
 * across `kUnpettedThreshold` consecutive intervals, the kernel
 * is declared wedged and we Panic(). If it did advance (timer IRQ
 * is still firing), we reset the counter and iretq.
 *
 * Gating: CPUID.0Ah.EAX[7:0] (arch perfmon version). QEMU TCG
 * typically reports version=0 so the watchdog silently stays
 * disabled there. KVM + real hardware advertise v2+.
 *
 * Threats it catches:
 *   - Kernel code entered an infinite loop inside a CLI section.
 *   - Spinlock deadlock across CPUs (pet from either CPU's timer
 *     IRQ still advances; only a full wedge stops both).
 *   - A trap handler that looped without iret (rare but real).
 *
 * Threats it doesn't catch (by design):
 *   - User-mode busy loop — the timer IRQ preempts it, pet
 *     counter advances, scan thread sees CPU% and logs runaway.
 *   - A single hung task — same reason, plus the runaway-CPU
 *     detector catches it.
 *
 * Context: kernel. Thread-safe (all state is per-CPU or NMI-only).
 * NmiWatchdogHandleNmi runs in NMI context; NmiWatchdogPet runs
 * in IRQ context. Init runs once at boot after TimerInit.
 */

namespace duetos::arch
{

/// One-time init. Gated on architectural-perfmon support; silently
/// returns (leaving the watchdog disabled) if the PMU isn't
/// available or advertised. Call after LapicInit + TimerInit.
void NmiWatchdogInit();

/// Called from the NMI dispatch path. Returns true if this NMI
/// was a watchdog-PMI and has been consumed (caller should iretq);
/// false if it came from somewhere else (the dispatcher should
/// fall through to its existing NMI handling, e.g., panic halt).
bool NmiWatchdogHandleNmi();

/// Pet the watchdog. Cheap (single increment). Called from the
/// timer IRQ handler on every tick.
void NmiWatchdogPet();

/// Hard-disable the watchdog. Called from the Panic path so the
/// PMU counter doesn't overflow and re-enter the trap dispatcher
/// while the crash dump is being written. Idempotent.
void NmiWatchdogDisable();

} // namespace duetos::arch
