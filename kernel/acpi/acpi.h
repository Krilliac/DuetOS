#pragma once

#include "../core/types.h"

/*
 * CustomOS — ACPI discovery (v0).
 *
 * Walks the Multiboot2 info to locate the RSDP, validates its checksums,
 * walks the RSDT/XSDT to find the MADT ("APIC" signature), and caches
 * the MADT's IOAPIC + Interrupt-Source-Override entries. The rest of
 * the system then has everything it needs to bring up IOAPICs and route
 * legacy ISA IRQs.
 *
 * Scope limits that will be fixed in later commits:
 *   - Requires the bootloader to provide the RSDP via Multiboot2 tag
 *     14 or 15. No EBDA / low-1MiB fallback scan — GRUB always hands it
 *     over, and anything booted via a loader that doesn't is a config
 *     bug, not a runtime recoverable one.
 *   - Assumes every ACPI table lives in the first 1 GiB of physical
 *     RAM (reachable via the boot direct map). Panics otherwise. The
 *     fix is to MapMmio the out-of-range range; deferred until a real
 *     machine makes us care.
 *   - Only MADT is parsed. FADT, MCFG, HPET, SRAT etc. are untouched.
 *     Add a dispatcher when a consumer needs one.
 *   - No DSDT/SSDT bytecode interpreter. That's a multi-thousand-line
 *     subsystem in its own right (see: ACPICA). When we need
 *     enumeration beyond static tables we'll integrate or write one.
 *
 * Context: kernel. Init runs once, after PagingInit (so PhysToVirt is
 * safe to use) and BEFORE LapicInit (the LAPIC base comes from MADT).
 */

namespace customos::acpi
{

constexpr u64 kMaxIoapics = 4;
constexpr u64 kMaxInterruptOverrides = 16;
constexpr u64 kMaxCpus = 32; // upper bound on MADT LAPIC entries cached

struct IoApicRecord
{
    u8 id;
    u32 address;  // physical base of the IOAPIC's 4 KiB MMIO window
    u32 gsi_base; // first Global System Interrupt this IOAPIC handles
};

struct LapicRecord
{
    u8 processor_uid;    // ACPI processor UID (opaque to us beyond logging)
    u8 apic_id;          // LAPIC ID — the target for IPIs / IOAPIC routes
    bool enabled;        // MADT flag bit 0: 1 = present + usable
    bool online_capable; // MADT flag bit 1: 1 = can be onlined by OS
};

struct InterruptOverride
{
    u8 bus;    // always 0 (ISA) for the entries we care about
    u8 source; // the legacy ISA IRQ number (0..15)
    u32 gsi;   // the Global System Interrupt it now maps to
    u16 flags; // bit 0..1 polarity, bit 2..3 trigger mode (MPS encoding)
};

/// Parse ACPI static tables. Panics on missing RSDP, bad signatures, or
/// bad checksums — ACPI is required to bring up IOAPIC on any modern
/// x86_64 machine, and a corrupt table at boot means the firmware is
/// lying about something critical.
void AcpiInit(uptr multiboot_info_phys);

/// LAPIC base physical address from the MADT header. Typically
/// 0xFEE00000 but firmware can relocate it. Callers should prefer this
/// over the IA32_APIC_BASE MSR when the two disagree — the MADT is
/// authoritative for the firmware-intended layout.
u64 LocalApicAddress();

u64 IoApicCount();
const IoApicRecord& IoApic(u64 index);

/// Number of processor-LAPIC entries the MADT reported. The BSP itself
/// counts; AP bring-up iterates Lapic(0..CpuCount-1) to find its targets.
u64 CpuCount();
const LapicRecord& Lapic(u64 index);

/// Translate a legacy ISA IRQ (0..15) to the Global System Interrupt
/// the IOAPIC should be programmed to trigger on. Returns the input
/// unchanged if the MADT didn't override it (identity mapping is the
/// default for ISA IRQs 0..15 without an override).
u32 IsaIrqToGsi(u8 isa_irq);

/// Flags bitfield returned for an ISA override entry. See MPS 1.4 §4.3.4:
/// polarity in bits 0..1 (00 bus default, 01 high, 11 low), trigger mode
/// in bits 2..3 (00 bus default, 01 edge, 11 level). Callers program the
/// IOAPIC redirection entry accordingly.
u16 IsaIrqFlags(u8 isa_irq);

} // namespace customos::acpi
