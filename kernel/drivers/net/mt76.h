#pragma once

#include "drivers/net/net.h"
#include "util/types.h"

/*
 * DuetOS — MediaTek mt76 Wi-Fi driver shell, v0.
 *
 * Brings up the MediaTek mt76 PCIe wireless family (MT7615, MT7663,
 * MT7902, MT7915, MT7916, MT7921, MT7922, MT7925) to the level
 * where the chip is identified by a PCI ID match plus an MMIO
 * probe of the hardware-bound register at BAR0+0x0008, and the
 * device record carries a real chip-class dword.
 *
 * This is the biggest gap in the on-board Wi-Fi story today:
 * MediaTek MT7921 / MT7922 / MT7925 ship in the majority of recent
 * AMD Ryzen 6000/7000/8000 laptops, many Intel laptops, all current
 * Chromebooks, and most thin-and-lights from 2022 onward. Without
 * this scaffold those machines silently report "no wireless driver"
 * even though the firmware loader would happily stage the bytes.
 *
 * Scope (v0):
 *   - PCI ID match table for the mt76 PCIe parts; covers the
 *     Linux `mt7921e` / `mt7922e` / `mt7925e` / `mt7915e` /
 *     `mt7615e` driver families.
 *   - Soft chip identification: read MT_HW_BOUND (BAR0+0x0008);
 *     reject 0xFFFFFFFF / 0 (BAR mapping failed or chip stuck).
 *   - Request the per-family firmware blob through the kernel
 *     firmware loader; parse and log the v3 header when present.
 *   - Mark `driver_online=true`, `firmware_pending=true` until the
 *     upload state machine lands.
 *   - NetInit starts an `mt76-watch` task that polls MT_HW_BOUND at
 *     1 Hz so a hot-removed adapter flips `driver_online`.
 *
 * Out of scope (deferred):
 *   - WM (WLAN MCU) firmware ROM-patch download via PCI BAR4 mailbox.
 *   - DMA TX/RX ring setup; per-band hardware queues.
 *   - 802.11 management frames; firmware command channel.
 *   - WED (Wireless Ethernet Dispatcher) offload.
 *
 * Threading: bring-up runs on the NetInit task; watch task is a
 * regular kernel thread.
 */

namespace duetos::drivers::net
{

inline constexpr u16 kVendorMediaTek = 0x14C3;

enum class Mt76Family : u8
{
    Unknown = 0,
    Mt7615 = 1, // Wi-Fi 5 (802.11ac)
    Mt7663 = 2,
    Mt7915 = 3, // Wi-Fi 6 (PCIe AP-grade)
    Mt7916 = 4,
    Mt7921 = 5, // Wi-Fi 6 / 6E — most common consumer chip
    Mt7922 = 6, // Wi-Fi 6E
    Mt7925 = 7, // Wi-Fi 7
};

const char* Mt76FamilyName(Mt76Family f);
Mt76Family Mt76FamilyFromDeviceId(u16 device_id);

/// True iff (vendor_id, device_id) matches a MediaTek mt76 PCI ID.
/// Used by `RunVendorProbe` to dispatch wireless bring-up.
bool Mt76Matches(u16 vendor_id, u16 device_id);

/// Bring an mt76 NIC up to "chip identified, MMIO live, awaiting
/// firmware". Idempotent. Returns true iff MT_HW_BOUND returned a
/// plausible chip-class dword.
bool Mt76BringUp(NicInfo& n);

/// Start the 1 Hz liveness watch after NetInit has copied the NIC
/// record into the stable global NIC table.
void Mt76StartWatch(NicInfo& n);

struct Mt76Stats
{
    u32 adapters_bound;
    u32 watch_polls;
    u32 unexpected_dead_polls;
    u32 hw_bound;      // last bound NIC's MT_HW_BOUND dword
    u32 chip_class;    // bits[31:16] of MT_HW_BOUND
    u32 chip_revision; // bits[15:0]  of MT_HW_BOUND
};

Mt76Stats Mt76StatsRead();

} // namespace duetos::drivers::net
