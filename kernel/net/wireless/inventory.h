#pragma once

#include "drivers/net/net.h"
#include "util/types.h"

/*
 * DuetOS — wireless hardware inventory.
 *
 * Walks every detected Wi-Fi-capable adapter — PCI NICs collected
 * by `drivers::net::NetInit` plus USB adapters collected by
 * `drivers::net::AthHtcInit` — and emits a single boot-log block
 * that lists exactly what hardware was found, what state each
 * adapter reached, and which firmware basename it needs.
 *
 * Purpose: this is the first thing a real-hardware tester reads
 * on the serial console. Without it, "did my Wi-Fi card get
 * detected?" requires grepping a long boot log for vendor-
 * specific log tags. With it, the answer is one block, deterministic
 * format, machine-readable, copy-pasteable into a bug report.
 *
 * Threading: pure read of the existing NIC + AthHtc tables. No
 * allocation. Safe from any kernel thread after NetInit / AthHtcInit.
 */

namespace duetos::net::wireless
{

enum class WirelessInventoryBus : u8
{
    Pci = 0,
    Usb = 1,
};

enum class WirelessInventoryFwOpenness : u8
{
    None = 0,            // not a wireless adapter / no firmware needed
    OpenSource = 1,      // ath9k_htc (qca/open-ath9k-htc-firmware), b43-openfwwf
    Redistributable = 2, // iwlwifi, rtl88xx, mt76, brcmfmac — closed but redistributable
};

struct WirelessInventoryEntry
{
    WirelessInventoryBus bus;
    // PCI: (pci_bus, pci_device, pci_function). USB: (slot_id, 0, 0).
    u8 addr0;
    u8 addr1;
    u8 addr2;
    u16 vendor_id;
    u16 product_id; // device_id for PCI, USB product id for USB
    const char* family;
    bool driver_online;
    drivers::net::NicInfo::WirelessFwState fw_state;
    const char* expected_basename;  // canonical basename for the loader
    const char* firmware_path_hint; // human-readable directory hint
    WirelessInventoryFwOpenness openness;
};

inline constexpr u32 kWirelessInventoryMax = 8;

/// Number of entries cached after the most recent `Refresh`.
u32 WirelessInventoryCount();

/// Accessor. Asserts on out-of-range.
const WirelessInventoryEntry& WirelessInventoryAt(u32 index);

/// Walk the live NIC and ath9k_htc tables to rebuild the cached
/// entry table. Idempotent.
void WirelessInventoryRefresh();

/// Emit the inventory block to the serial log. Always calls
/// Refresh first so the dump matches current state.
void WirelessInventoryDump();

/// Boot self-test. Synthesises entries via direct table seeding,
/// re-reads them, and verifies the formatter does not crash on
/// the empty / single / max-fill cases.
void WirelessInventorySelfTest();

const char* WirelessInventoryFwStateName(drivers::net::NicInfo::WirelessFwState s);
const char* WirelessInventoryOpennessName(WirelessInventoryFwOpenness o);

} // namespace duetos::net::wireless
