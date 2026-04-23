#pragma once

#include "../../core/types.h"

/*
 * CustomOS — Network driver shell, v0.
 *
 * Discovery + classification for PCI network controllers, mirroring
 * the `drivers/gpu/` pattern. Walks the `pci::Device` cache after
 * `PciEnumerate`, picks every device with class_code == 0x02
 * (network controller), dispatches to a vendor/device probe, and
 * logs the result. BAR 0 is mapped as MMIO for each NIC so a
 * future driver slice can reach the register file without
 * re-running the size probe.
 *
 * Scope (v0):
 *   - Discovery + classification only. Probes identify the chip
 *     family (e1000e / rtl8169 / virtio-net / ...) and log it.
 *   - BAR 0 mapped into the kernel MMIO arena.
 *   - No packet I/O, no MAC address read, no link-state, no IRQ
 *     wiring. The upper network stack (TCP/IP, ARP, DHCP) is a
 *     later track entirely (kernel/net/).
 *
 * The device tier maps to `docs/knowledge/hardware-target-matrix.md`:
 *   Tier 1: Intel e1000 / e1000e (commodity wired NICs)
 *   Tier 2: Realtek rtl8169, Broadcom bcm57xx
 *   Tier 3: virtio-net (dev only)
 *   Tier 4: Intel iwlwifi, Realtek rtl88xx (Wi-Fi, much later)
 *
 * Context: kernel. `NetInit` runs once at boot after `PciEnumerate`.
 */

namespace customos::drivers::net
{

// Common vendor IDs. A few are duplicated with drivers/gpu — PCI
// vendor IDs are global, not per-class.
inline constexpr u16 kVendorIntel = 0x8086;
inline constexpr u16 kVendorRealtek = 0x10EC;
inline constexpr u16 kVendorBroadcom = 0x14E4;
inline constexpr u16 kVendorMarvell = 0x11AB;
inline constexpr u16 kVendorMellanox = 0x15B3;
inline constexpr u16 kVendorRedHatVirt = 0x1AF4; // virtio-net

// PCI class codes.
inline constexpr u8 kPciClassNetwork = 0x02;
inline constexpr u8 kPciSubclassEthernet = 0x00;
inline constexpr u8 kPciSubclassTokenRing = 0x01;
inline constexpr u8 kPciSubclassOther = 0x80;

inline constexpr u64 kMaxNics = 4;

struct NicInfo
{
    u16 vendor_id;
    u16 device_id;
    u8 bus;
    u8 device;
    u8 function;
    u8 subclass;        // 0x00 Ethernet, 0x80 Other (Wi-Fi)
    const char* vendor; // short string ("Intel", "Realtek", ...)
    const char* family; // chip family ("e1000e-82574", "rtl8169", ...)
    u64 mmio_phys;
    u64 mmio_size;
    void* mmio_virt;
    u8 mac[6]; // all-zero if the vendor probe didn't read it
    bool mac_valid;
    bool link_up; // filled by the vendor probe; false on NICs
                  // whose status register we don't read yet
};

/// Walk the PCI cache, register every network controller, run the
/// vendor-specific probe. Once per boot.
void NetInit();

/// Number of NICs discovered.
u64 NicCount();

/// Accessor for a discovered NIC record.
const NicInfo& Nic(u64 index);

// Vendor probe stubs — classify by device_id and log the family.
// No packet I/O. Replaced by real chip-specific init in a future
// driver slice (e1000 ring setup, rtl8169 MAC config, etc.).

const char* IntelNicTag(u16 device_id);
const char* RealtekNicTag(u16 device_id);
const char* BroadcomNicTag(u16 device_id);
const char* VirtioNetTag(u16 device_id);

} // namespace customos::drivers::net
