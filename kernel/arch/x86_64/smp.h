#pragma once

#include "../../core/types.h"

/*
 * SMP AP bring-up — v0 (discovery-only scaffolding).
 *
 * v0 scope: enumerate MADT LAPIC records and log which apic_ids are
 * candidates for AP bring-up. Expose `SmpSendIpi()` so future
 * subsystems (TLB shootdown, IPI-driven reschedule) can already use
 * the LAPIC ICR plumbing.
 *
 * Deferred to a dedicated session (see
 * `docs/knowledge/smp-ap-bringup-scope.md`):
 *   - The real→long mode trampoline assembly.
 *   - The INIT-SIPI-SIPI sequence that wakes each AP.
 *   - Per-AP stack + PerCpu allocation.
 *   - AP-side LAPIC enable + C++ entry + scheduler join.
 *
 * Landing this half first gets the ACPI MADT LAPIC enumeration +
 * IPI-send helper into the tree without blocking on the trampoline
 * assembly, which needs iterative QEMU testing to get right.
 *
 * Context: kernel. Run once after SchedInit + IoApicInit.
 */

namespace customos::arch
{

/// Discover APs and log them. Returns 0 in v0 (no APs actually brought
/// up). Future versions return the number of APs that reached the
/// scheduler.
u64 SmpStartAps();

/// Number of online CPUs. BSP is always 1; APs contribute when they
/// finish bringing themselves up.
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

} // namespace customos::arch
