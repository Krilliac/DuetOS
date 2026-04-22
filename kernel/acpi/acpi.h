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
 *   - FADT parsing is minimal — only RESET_REG + RESET_VALUE + SCI_INT
 *     are cached. The rest (PM1a/PM1b event/control blocks, PM timer,
 *     GPE blocks, preferred CPU C-state hints) lands when a consumer
 *     exists.
 *   - MCFG (PCIe ECAM), HPET, SRAT are still untouched. Add a
 *     dispatcher when a consumer needs one.
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

/// ACPI System Control Interrupt vector, as reported by the FADT.
/// Returns 9 (the ACPI-spec default ISA IRQ) if the FADT was not
/// found or didn't set a value. The SCI itself is an edge/level-
/// triggered line that fires on power-management events; no handler
/// is installed yet.
u16 SciVector();

/// Issue a firmware-defined reboot via the FADT's RESET_REG. Returns
/// true if the reset register was advertised as supported and the
/// write was issued — on success the CPU does not return, so any
/// code past `if (AcpiReset()) unreachable;` is executed only on
/// failure (no FADT, RESET_REG_SUP flag clear, or unsupported
/// address-space id). Fall back to `Outb(0xCF9, 0x06)` or a triple
/// fault in that case.
bool AcpiReset();

/// HPET event-timer-block physical address from the ACPI HPET
/// table. Returns 0 if no HPET table was present (in which case
/// drivers should fall back to PIT or LAPIC timers only).
u64 HpetAddress();

/// Number of timers implemented in the HPET (1..32). Returns 0
/// if no HPET is present.
u8 HpetTimerCount();

/// HPET main-counter width — 64 if the COUNT_SIZE_CAP bit is set
/// in the HPET capabilities register (from the ACPI table's
/// event-timer-block-id), 32 otherwise. Returns 0 if no HPET.
u8 HpetCounterWidth();

/// MCFG (PCIe Memory-Mapped Configuration Space) base address for
/// segment group 0 (the only segment that exists on every x86_64
/// machine we target). Returns 0 if no MCFG table was present —
/// callers fall back to legacy port-IO config access in that case.
///
/// The region runs from `McfgAddress()` to
/// `McfgAddress() + (McfgEndBus() - McfgStartBus() + 1) * 0x100000`;
/// each bus covers 1 MiB, each device 32 KiB, each function 4 KiB.
u64 McfgAddress();

/// First PCI bus covered by the MCFG region. Usually 0.
u8 McfgStartBus();

/// Last PCI bus covered by the MCFG region (inclusive).
u8 McfgEndBus();

// -------------------------------------------------------------------
// DSDT + SSDT discovery. These are the ACPI tables that contain
// AML bytecode (power-management methods, battery / thermal-zone
// objects, embedded-controller regions, …). Today we only cache
// the physical base + length; a future slice walks the bytecode to
// find specific named objects (BAT0, AC, TZ0 …) or interprets the
// methods via a minimal AML executor.
// -------------------------------------------------------------------

u64 DsdtAddress();
u32 DsdtLength();

/// Number of SSDT tables found (capped at 16 — beyond that, a Warn
/// log at boot records the truncation).
u64 SsdtCount();

/// Physical base of the i-th SSDT. Returns 0 for out-of-range.
u64 SsdtAddress(u64 index);

/// Length (bytes) of the i-th SSDT's full table, header + AML.
/// Returns 0 for out-of-range.
u32 SsdtLength(u64 index);

/// Scan the DSDT + every SSDT's AML bytecode for a 4-byte ASCII
/// name. ACPI identifiers are 4 uppercase ASCII/digit chars stored
/// verbatim in the bytecode, so naive substring search finds them
/// with very low false-positive risk for device-class names like
/// "BAT0" / "BAT1" / "ADP1" / "_TZ_" / "TZ0_".
///
/// `name4` must be exactly 4 bytes (no NUL terminator needed).
/// Returns true iff the pattern appears in any cached AML blob.
///
/// Used by the power driver to decide "SMBIOS says laptop-like
/// AND the DSDT declares BAT0 → battery really is present".
/// Not a substitute for a real AML interpreter — you can't read
/// the battery's current state this way, just its declaration.
bool AmlContainsName(const char* name4);

} // namespace customos::acpi
