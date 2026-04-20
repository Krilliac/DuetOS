#pragma once

#include "../../core/types.h"

/*
 * I/O APIC — v0.
 *
 * The IOAPIC is what routes external (chipset / device) interrupts to
 * LAPIC vectors on modern x86. The 8259 PIC is disabled earlier in
 * boot; without the IOAPIC online, the only interrupt source we have
 * is the in-package LAPIC timer. Every peripheral IRQ — keyboard,
 * AHCI, NVMe, NIC, USB, whatever — goes through here.
 *
 * This module:
 *   - consumes the ACPI MADT cache (IOAPIC records + ISA overrides)
 *   - maps each IOAPIC's 4 KiB MMIO window via MapMmio
 *   - reads the VERSION register to determine the redirection-entry
 *     count (commonly 24 on q35)
 *   - masks every redirection entry at init (no stray IRQs while
 *     drivers set up)
 *   - exposes Route / Mask / Unmask for downstream drivers
 *
 * Scope limits that will be fixed in later commits:
 *   - Fixed routing: every IRQ goes to the BSP (APIC ID read from
 *     the LAPIC ID register). SMP bring-up will add affinity + MSI.
 *   - Physical destination mode + fixed delivery only. Lowest-priority
 *     / logical destination come when we actually need them.
 *   - No MSI/MSI-X support (that's per-device, configured via PCIe).
 *     The IOAPIC path is for legacy / chipset interrupts.
 *
 * Context: kernel. Init runs once after LapicInit (needs LAPIC ID)
 * and AcpiInit (needs IOAPIC records + ISA overrides).
 */

namespace customos::arch
{

/// Bring up every IOAPIC the MADT described. Maps MMIO, logs version +
/// entry count, masks every pin. Panics if the MADT advertised zero
/// IOAPICs — every modern x86_64 machine has at least one.
void IoApicInit();

/// Route a Global System Interrupt to `vector` delivered to `lapic_id`.
/// Polarity + trigger mode come from the MADT ISA override for the
/// corresponding ISA IRQ when `isa_irq < 16`; pass `isa_irq = 0xFF` to
/// use bus-default (edge, active high) for non-ISA sources (PCI INTx
/// with _PRT resolved elsewhere, or direct GSI routing).
///
/// After routing, the pin is UNMASKED automatically — the caller
/// having configured it means they want IRQs to start flowing.
///
/// Panics if `gsi` is outside every IOAPIC's [gsi_base, gsi_base +
/// redir_count) window.
void IoApicRoute(u32 gsi, u8 vector, u8 lapic_id, u8 isa_irq);

/// Set / clear the mask bit on the redirection entry for `gsi`. Leaves
/// vector + delivery fields untouched. No-op (silent) for unknown GSIs
/// to make driver teardown tolerant of partially-configured state.
void IoApicMask(u32 gsi);
void IoApicUnmask(u32 gsi);

} // namespace customos::arch
