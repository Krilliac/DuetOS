#pragma once

#include "../../core/types.h"

/*
 * CustomOS — PCI (legacy port-IO) enumeration, v0.
 *
 * Walks the PCI config space via the classic 0xCF8 / 0xCFC port pair:
 *   - 0xCF8 CONFIG_ADDRESS — write (enable|bus|dev|fn|offset) here
 *   - 0xCFC CONFIG_DATA    — then read/write the 32-bit register
 *
 * Works on every x86 machine made in the last 25 years. Not the fastest
 * path — MMCONFIG (ECAM) via the ACPI MCFG table is ~10x faster and
 * doesn't need a locked port pair — but MCFG requires additional ACPI
 * table parsing that's deferred (see usb-xhci-scope-estimate.md
 * "Commit 1"). Once MCFG lands, this module grows a `PciConfigRead*`
 * fast path that prefers ECAM and falls back to legacy.
 *
 * Scope limits that will be fixed in later commits:
 *   - Legacy port-IO only. No MCFG/ECAM yet.
 *   - Bus enumeration is shallow: bus 0..3, device 0..31, function
 *     0..7. Recursive walking into PCI bridges comes when we care
 *     about anything beyond the root bus (q35 hangs everything
 *     interesting on bus 0; bus 1+ is typically empty until we hit
 *     a board with bridges).
 *   - BAR parsing + resource allocation deferred. We read BAR 0..5
 *     raw when a driver asks; auto-assign + size-probe is a separate
 *     commit.
 *   - No interrupt line / INTx routing (needs ACPI _PRT or MSI).
 *   - Non-SMP-safe: two CPUs racing the CONFIG_ADDRESS register would
 *     corrupt each other. Wrapped in a spinlock when SMP runqueue
 *     spinlock lands; single-CPU today.
 *
 * Context: kernel. `PciEnumerate` runs once at boot; accessors are
 * read-only after.
 */

namespace customos::drivers::pci
{

constexpr u64 kMaxDevices = 64;

struct DeviceAddress
{
    u8 bus;
    u8 device;   // 0..31
    u8 function; // 0..7
    u8 _pad;
};

struct Device
{
    DeviceAddress addr;
    u16 vendor_id; // 0xFFFF means no device
    u16 device_id;
    u8 class_code; // high-level group (e.g. 0x01 mass storage)
    u8 subclass;   // subgroup (e.g. 0x06 SATA)
    u8 prog_if;    // programming interface (e.g. 0x01 AHCI)
    u8 revision;
    u8 header_type; // 0x00 endpoint, 0x01 PCI-to-PCI bridge, 0x02 CardBus
};

/// Walk every (bus, device, function) on bus 0..3; cache and log each
/// present device. Safe to call exactly once at boot. Double-init
/// panics via KASSERT.
void PciEnumerate();

/// Number of devices discovered by the most recent `PciEnumerate`.
u64 PciDeviceCount();

/// Accessor for a cached device record. Panics on out-of-range index.
const Device& PciDevice(u64 index);

// -----------------------------------------------------------------
// Raw config-space access. Useful for drivers that need to read
// vendor-specific registers past the standard header fields.
// -----------------------------------------------------------------

u32 PciConfigRead32(DeviceAddress addr, u8 offset);
u16 PciConfigRead16(DeviceAddress addr, u8 offset);
u8 PciConfigRead8(DeviceAddress addr, u8 offset);
void PciConfigWrite32(DeviceAddress addr, u8 offset, u32 value);

// -----------------------------------------------------------------
// BAR (Base Address Register) inspection.
//
// Each header-type-0 endpoint has up to 6 BARs at config offsets
// 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24. Each BAR is either a 32-bit
// MMIO window, a 64-bit MMIO window (consumes the next BAR slot
// too), or a 16-bit I/O port range. The size of each region is
// discovered by writing all 1s and reading back the one-bits mask.
//
// PciReadBar performs that size probe non-destructively (saves +
// restores the BAR value) and returns the decoded result.
//   bar.address      : base MMIO/IO address (already decoded).
//                      For 64-bit BARs, includes the upper half.
//   bar.size         : size in bytes. 0 means the BAR is unused.
//   bar.is_io        : true for I/O port BAR, false for MMIO.
//   bar.is_64bit     : true if BAR consumes this index + index+1.
//   bar.is_prefetchable : MMIO-only; true if the spec allows
//                      prefetching (controller framebuffer etc.).
// -----------------------------------------------------------------

struct Bar
{
    u64 address;
    u64 size;
    bool is_io;
    bool is_64bit;
    bool is_prefetchable;
    bool _pad;
};

/// Read and size BAR `index` (0..5) on a header-type-0 endpoint.
/// Returns Bar{size=0} for empty / invalid BARs. Non-destructive:
/// the original BAR value is restored before returning.
///
/// NOT safe to call on a BAR that a driver has already claimed and
/// is actively using — the size-probe sequence briefly writes
/// all-1s into the BAR which would re-parent any MMIO access during
/// the probe. Call during device bring-up only.
Bar PciReadBar(DeviceAddress addr, u8 index);

// -----------------------------------------------------------------
// PCI capability list iteration. Each capability is at least two
// bytes: {id, next_offset}. next_offset == 0 terminates the list.
// Status register bit 4 (offset 0x06) gates whether a capabilities
// list is present at all.
//
// Common capability IDs:
//   0x01 PM  (power management)
//   0x05 MSI (message-signalled interrupts)
//   0x10 PCIe (express capability)
//   0x11 MSI-X (MSI with separate vector table)
//   0x12 SATA (SATA HBA-specific)
//   0x13 AF  (advanced features)
// -----------------------------------------------------------------

constexpr u8 kPciCapMsi = 0x05;
constexpr u8 kPciCapPcie = 0x10;
constexpr u8 kPciCapMsix = 0x11;

/// Find the first capability with the given ID. Returns the config-
/// space offset where that capability's header lives (always non-
/// zero for the low 16 reserved offsets), or 0 if not found / no
/// capabilities list present.
u8 PciFindCapability(DeviceAddress addr, u8 cap_id);

// -----------------------------------------------------------------
// Class-code string for diagnostic logs. Returns a stable pointer to
// a short label ("mass storage", "network", "display", "bridge", ...)
// or "unknown" for codes we haven't named yet.
// -----------------------------------------------------------------
const char* PciClassName(u8 class_code);

} // namespace customos::drivers::pci
