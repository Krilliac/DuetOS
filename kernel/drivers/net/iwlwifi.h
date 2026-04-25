#pragma once

#include "../../core/types.h"
#include "net.h"

/*
 * DuetOS — Intel iwlwifi driver shell, v0.
 *
 * Brings up Intel Wireless adapters (Centrino/Wireless 1000, 4965,
 * 5000, 6000, 7260/3160/3165, 8260, 9000, AX2xx, Be2xx) to the level
 * where the chip is identified by reading CSR_HW_REV (BAR0+0x028)
 * and the device record carries a real chip-revision dword that the
 * shell + GUI can show.
 *
 * Scope (v0):
 *   - PCI ID match table covering the iwlwifi family from 1000-series
 *     through Be2xx. Match logic mirrors the Linux iwlwifi pci_table.
 *   - Soft chip identification: read CSR_HW_REV; reject 0xFFFFFFFF
 *     (BAR mapping failed) or 0 (chip stuck in reset).
 *   - Mark the NIC `driver_online=true`, `firmware_pending=true`. The
 *     iwlwifi family REQUIRES a vendor-signed microcode blob loaded
 *     before any 802.11 association can occur; DuetOS has no
 *     firmware-loader subsystem yet, so the driver shell stops at
 *     chip identification and tells the user honestly.
 *   - Spawn an `iwlwifi-watch` task that periodically re-reads the
 *     status register so the GUI's link indicator picks up an
 *     unexpected reset / removal cleanly.
 *
 * Out of scope (deferred):
 *   - Firmware loading (FW_LOAD_BUFFER + KEEP_WARM allocations,
 *     SECURE_BOOT handshake, microcode sections walk).
 *   - TX/RX queue setup (TFD/RBD ring layouts differ across silicon
 *     revisions; needs the firmware for valid context-info layouts).
 *   - 802.11 management frames, scan, association, key install.
 *   - Power management (D0i3 / D3 hand-off via PMU).
 *
 * Threading: `IwlwifiBringUp` runs on the NetInit task at boot.
 * `IwlwifiWatchEntry` is a polling kernel thread that reads the
 * status register at 100 Hz / 10 ticks (1 s) cadence — well below
 * the rate where stale state would matter.
 */

namespace duetos::drivers::net
{

/// True iff (vendor_id, device_id) matches an iwlwifi PCI ID. Used by
/// `RunVendorProbe` to dispatch wireless bring-up.
bool IwlwifiMatches(u16 vendor_id, u16 device_id);

/// Bring an iwlwifi NIC up to "chip identified, MMIO live, awaiting
/// firmware". Idempotent — second call on the same NIC index returns
/// the cached result. Returns true iff the chip responded with a
/// plausible (non-0/non-all-ones) HW_REV.
bool IwlwifiBringUp(NicInfo& n);

struct IwlwifiStats
{
    u32 adapters_bound;        // total iwlwifi NICs that came online
    u32 watch_polls;           // iwlwifi-watch task wake count
    u32 unexpected_dead_polls; // polls where MMIO went 0xFFFFFFFF
    u32 hw_rev;                // last bound NIC's HW_REV dword
};

IwlwifiStats IwlwifiStatsRead();

} // namespace duetos::drivers::net
