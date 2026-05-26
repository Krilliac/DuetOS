#pragma once

#include "util/types.h"

/*
 * DuetOS — ACPI System Control Interrupt (SCI) service, v0.
 *
 * The SCI is the single shared interrupt the ACPI hardware raises
 * for power-management events: the power/sleep button (PM1 event
 * block, PWRBTN_STS) and the General Purpose Events (GPE0/GPE1
 * blocks — lid, AC, thermal, EC `_Qxx`). FADT reports its line in
 * SCI_INT and the register blocks in PM1a/b_EVT + GPE0/1; the
 * accessors live in `acpi.h`.
 *
 * This module:
 *   - hands ACPI ownership from firmware SMM to the OS (write
 *     ACPI_ENABLE to SMI_CMD, poll PM1_CNT.SCI_EN) when the
 *     firmware didn't already (QEMU/SeaBIOS does);
 *   - clears + arms PWRBTN_EN in the PM1 enable register;
 *   - installs an IRQ handler on the SCI vector (IOAPIC-routed,
 *     honouring the MADT override like every other ISA IRQ);
 *   - in the handler (IRQ context — no AML, no allocation) reads
 *     and write-1-clears PM1 / GPE status, records what fired, and
 *     wakes a caller-supplied WaitQueue so a process-context
 *     worker (the `env-monitor` task) can react.
 *
 * Status: GPE status is acked (so a firmware-raised GPE can't
 * keep the level-triggered SCI asserted). EC `_Qxx` events are
 * dispatched by the `env-monitor` task, which on any pending
 * GPE drains `AcpiEcDispatchPendingQuery` (acpi/ec.h) in a
 * bounded loop. That picks up lid / AC / battery events routed
 * through the EC. The remaining gap is per-GPE `_Lxx`/`_Exx`
 * dispatch for events whose firmware skips the EC (rare on
 * laptops); a full GPE dispatch worker that consults the
 * namespace is the documented follow-on. Power-button (the one
 * event QEMU can exercise) is fully handled via PM1 status.
 *
 * Context: kernel. `AcpiSciInit` runs once at boot after AcpiInit
 * + IOAPIC are up and the scheduler is online (it needs the
 * wake-target WaitQueue). The handler is IRQ context;
 * `AcpiSciTakePending` is process context.
 */

namespace duetos::sched
{
struct WaitQueue;
}

namespace duetos::acpi
{

/// What the SCI handler observed since the last `AcpiSciTakePending`.
struct SciPending
{
    bool power_button; // PWRBTN_STS fired (power or sleep button)
    u32 gpe0_status;   // OR of GPE0 status bytes that fired (acked)
    u32 gpe1_status;   // OR of GPE1 status bytes that fired (acked)
};

/// Enter ACPI mode if needed, arm the power button, install the
/// SCI IRQ handler, and remember `wake` as the WaitQueue to
/// `WaitQueueWakeOne` from the handler. No-op (logs + returns) if
/// the FADT exposed no PM1 event block. Safe once.
void AcpiSciInit(sched::WaitQueue* wake);

/// True iff the SCI handler is installed and live.
bool AcpiSciActive();

/// Atomically read and clear the pending-event record. Call from
/// process context (the woken worker). Returns an all-false record
/// if nothing fired (e.g. a spurious wake).
SciPending AcpiSciTakePending();

/// Boot self-test: exercises the PM1-status decode predicate on a
/// synthetic status word (no port I/O, never triggers a real
/// shutdown) and asserts the take-pending latch round-trips.
/// Emits one `[acpi/sci-selftest] PASS` line. Panics on regression.
void AcpiSciSelfTest();

} // namespace duetos::acpi
