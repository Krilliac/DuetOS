#pragma once

#include "../../core/types.h"

/*
 * SMP AP bring-up.
 *
 * Current scope (as of decision log #023):
 *   - MADT LAPIC enumeration identifies BSP + AP candidates
 *     (`acpi::Lapic(i)`).
 *   - `SmpSendIpi` wraps the LAPIC ICR dance; usable by any future
 *     caller (AP wake-up, TLB shootdown, resched-IPI).
 *   - `SmpStartAps` copies the trampoline image to physical 0x8000,
 *     allocates each AP's stack + `PerCpu`, and drives the full
 *     INIT-SIPI-SIPI sequence. Each AP writes `online_flag` from
 *     `ApEntryFromTrampoline` after installing GSBASE + enabling
 *     its LAPIC; BSP polls with a bounded timeout before moving on.
 *   - AP-side C++ entry halts with interrupts masked — the AP's
 *     LAPIC is live, but the scheduler is not SMP-safe across
 *     context-switch yet (the lock-passing half of
 *     `smp-ap-bringup-scope.md` Commit D is still pending).
 *
 * Deferred (see `docs/knowledge/smp-ap-bringup-scope.md`):
 *   - Lock-passing across `ContextSwitch` so a peer CPU can safely
 *     wake tasks that this CPU is about to switch away from.
 *   - `SchedEnterOnAp` — each AP calls `SchedStartIdle("idle-apN")`,
 *     arms its LAPIC timer, and enters the scheduler loop.
 *   - Per-AP TSS + IST (needed alongside ring 3).
 *   - Broadcast-NMI panic halt for Class-A recovery on SMP.
 *
 * Context: kernel. Run once after SchedInit + IoApicInit +
 * PerCpuInitBsp (BSP's `PerCpu` must be live before APs allocate
 * theirs).
 */

namespace customos::arch
{

/// Copy the trampoline to physical 0x8000, allocate each AP's stack
/// + per-CPU struct, and drive INIT-SIPI-SIPI for every enabled
/// LAPIC in the MADT other than the BSP's. Returns the number of
/// APs that reached `ApEntryFromTrampoline` and flipped their
/// `online_flag` within the bounded polling window.
u64 SmpStartAps();

/// Number of online CPUs (BSP + any APs that successfully entered
/// `ApEntryFromTrampoline`). BSP is always counted; each AP
/// increments this on bring-up.
u64 SmpCpusOnline();

/// Send an arbitrary IPI via the LAPIC Interrupt Command Register.
/// `target_apic_id` is the destination LAPIC ID (bits 24..31 of the
/// ICR high half). `icr_low` carries the delivery mode + vector +
/// level/trigger bits per Intel SDM Vol. 3A "LAPIC Interrupt Command
/// Register." Blocks until the delivery-status bit clears; panics if
/// it stays pending for ~1e6 spin iterations (indicates a broken
/// LAPIC or a CPU that never accepted the IPI).
///
/// Exposed now so future callers (TLB shootdown, resched-IPI, AP
/// wake-up) share the same ICR dance rather than reimplementing it.
void SmpSendIpi(u8 target_apic_id, u32 icr_low);

/// Broadcast an NMI to every CPU except the calling one. Used by
/// the panic path to halt peer CPUs before dumping diagnostics so
/// they can't keep executing against potentially-corrupt shared
/// state while we're writing the crash banner. Uses the "all
/// excluding self" destination shorthand so no per-CPU loop is
/// needed. Safe to call even on single-CPU systems — the shorthand
/// simply matches zero targets.
///
/// Blocks until delivery-status clears, but will not panic on
/// timeout (see PanicBroadcastNmi's own comment): the panic path
/// is already committed to halting; tolerating a stuck IPI is
/// better than recursing into another panic.
void PanicBroadcastNmi();

} // namespace customos::arch
