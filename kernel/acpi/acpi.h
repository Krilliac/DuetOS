#pragma once

#include "util/types.h"

/*
 * DuetOS — ACPI discovery (v0).
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
 *   - ACPI tables below the 1 GiB direct map (QEMU/OVMF) are read
 *     directly via PhysToVirt; tables the firmware parks higher
 *     (VirtualBox puts the XSDT near the top of 2 GiB RAM) are reached
 *     through a cached MapMmio fallback in AcpiMapPhys(). Mappings are
 *     kept for the kernel lifetime (the DSDT/SSDT scanners reuse them).
 *   - FADT parsing covers RESET_REG/VALUE, SCI_INT, PM1a/b control
 *     + event blocks, GPE0/GPE1 blocks, and the SMI_CMD/ACPI_ENABLE
 *     handshake (consumed by acpi_sci.cpp for the SCI). PM timer +
 *     preferred CPU C-state hints still land when a consumer exists.
 *   - MCFG (PCIe ECAM), HPET, SRAT are still untouched. Add a
 *     dispatcher when a consumer needs one.
 *   - No DSDT/SSDT bytecode interpreter. That's a multi-thousand-line
 *     subsystem in its own right (see: ACPICA). When we need
 *     enumeration beyond static tables we'll integrate or write one.
 *
 * Context: kernel. Init runs once, after PagingInit (so PhysToVirt is
 * safe to use) and BEFORE LapicInit (the LAPIC base comes from MADT).
 */

namespace duetos::acpi
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
    u32 apic_id;         // LAPIC ID — the target for IPIs / IOAPIC routes
                         // (32-bit so x2APIC IDs from MADT type 9 fit; legacy
                         // xAPIC IDs occupy only the low 8 bits)
    bool enabled;        // MADT flag bit 0: 1 = present + usable
    bool online_capable; // MADT flag bit 1: 1 = can be onlined by OS
    bool is_x2apic;      // true if sourced from a MADT type-9 (Local x2APIC)
                         // entry; false for legacy type-0 (Local APIC). Affects
                         // how the AP-bringup code renders the id in boot logs
                         // and lets future code key on the wider ID space.
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

/// Map `len` bytes of an ACPI table's physical memory and return a
/// readable virtual pointer. Uses the kernel direct map when the table
/// is below it, an MMIO mapping (cached, kept for kernel lifetime)
/// otherwise — firmware (VirtualBox, real UEFI) frequently parks ACPI
/// tables above the 1 GiB direct map. Every ACPI TU must resolve table
/// addresses through this, never mm::PhysToVirt directly.
const void* AcpiMapTable(u64 phys, u64 len);

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
/// triggered line that fires on power-management events;
/// `kernel/acpi/acpi_sci.cpp` installs the handler on this vector.
u16 SciVector();

/// Issue a firmware-defined reboot via the FADT's RESET_REG. Returns
/// true if the reset register was advertised as supported and the
/// write was issued — on success the CPU does not return, so any
/// code past `if (AcpiReset()) unreachable;` is executed only on
/// failure (no FADT, RESET_REG_SUP flag clear, or unsupported
/// address-space id). Fall back to `Outb(0xCF9, 0x06)` or a triple
/// fault in that case.
bool AcpiReset();

/// PM1a / PM1b control block I/O port addresses from FADT.
/// Returns 0 when the FADT didn't populate the block. Used by
/// the shutdown path: writing `(SLP_TYP << 10) | SLP_EN` to
/// PM1a — with SLP_TYP taken from AML `\_S5` — triggers ACPI
/// soft-off on compliant hardware + QEMU.
u32 Pm1aControlPort();
u32 Pm1bControlPort();

/// PM1 event block I/O port addresses from FADT (0 when absent).
/// The block is `Pm1EventLen()` bytes: the PM1 *status* register
/// at the base, the PM1 *enable* register at base + len/2. Bit 8
/// of each is the power-button (PWRBTN_STS / PWRBTN_EN). Consumed
/// by `kernel/acpi/acpi_sci.cpp` to arm + service the SCI.
u32 Pm1aEventPort();
u32 Pm1bEventPort();
u8 Pm1EventLen();

/// GPE0 / GPE1 register block I/O ports + lengths from FADT
/// (0 when absent — common on QEMU, which exposes no GPEs). Each
/// block is split half status / half enable like PM1. `Gpe1Base()`
/// is the 0-based GPE index the GPE1 block starts at.
u32 Gpe0Block();
u8 Gpe0BlockLen();
u32 Gpe1Block();
u8 Gpe1BlockLen();
u8 Gpe1Base();

/// SMI command port + the value to write there to hand ACPI
/// ownership from firmware SMM to the OS (FADT SMI_CMD /
/// ACPI_ENABLE). Both 0 ⇒ no firmware handshake needed (already in
/// ACPI mode / hardware-reduced) — the SCI installer skips it.
u32 AcpiSmiCommandPort();
u8 AcpiEnableValue();

/// Trigger ACPI soft-off (S5) by reading SLP_TYP from AML `\_S5`
/// and writing `(SLP_TYP << 10) | SLP_EN` to PM1a (and PM1b if
/// present). On full-ACPI-compliant hardware this powers the
/// machine off; on QEMU it exits the guest cleanly. Returns
/// false on missing `\_S5`, missing PM1 block, or if execution
/// continued past the write (spec-compliant firmware would have
/// honoured it, but the full path requires _PTS / _GTS method
/// execution we don't do yet).
bool AcpiShutdown();

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

/// Locate an arbitrary ACPI table by its 4-byte signature and
/// return its physical base address + length. `sig4` is the 4-byte
/// signature (no NUL needed, e.g. "DMAR", "IVRS"). Returns true on
/// hit; `*out_phys` is the physical base, `*out_len` is the table's
/// `length` field (the whole table including the 36-byte SDT
/// header). Returns false if AcpiInit didn't run, or if the
/// signature was not present in either the XSDT or the RSDT.
///
/// Used by the IOMMU subsystem (DMAR for Intel VT-d, IVRS for
/// AMD-Vi) to fetch the firmware's IOMMU description without
/// having to expose the static table cache directly. Mirrors the
/// MADT / FADT / HPET / MCFG getters but for tables that may be
/// added by future slices.
bool AcpiFindTablePhys(const char* sig4, u64* out_phys, u32* out_len);

/// Boot-time self-test for the parser-underflow guards added when a
/// hostile / malformed firmware ships an ACPI table whose
/// `header.length` is smaller than its struct size. Invoked from
/// `kernel_main` after AcpiInit so the test runs on an already-online
/// table cache; saves and restores the live state so re-running it is
/// idempotent. Panics on guard regression.
void AcpiUnderflowSelfTest();

/// Boot-time self-test for the S5 sleep-prep path. Exercises the
/// exact mechanism `AcpiShutdown` uses — resolve a root method by
/// absolute path, pass the sleep-type as Arg0, evaluate an
/// `If(LEqual(Arg0,5))`-gated body — on synthetic bytecode (so it
/// never powers the test VM off), and reports whether the live
/// firmware declares `\_PTS` / `\_GTS`. Emits one
/// `[acpi/s5] selftest PASS` line. Panics on a wrong result.
void AcpiSleepPrepSelfTest();

/// Boot-time self-test for the MADT Local x2APIC (type 9) parser.
/// Builds a synthetic MADT containing one valid x2APIC entry (wide
/// ID 0x12345678), one with the 0xFFFFFFFF sentinel (must be
/// dropped), and one Local x2APIC NMI entry (type 10; must parse
/// without panicking). Saves and restores the live g_lapics table
/// around the call so re-running it is idempotent. Emits
/// `[acpi/madt-x2apic-selftest] PASS` on success; panics on a
/// wrong field round-trip.
void AcpiMadtX2ApicSelfTest();

} // namespace duetos::acpi
