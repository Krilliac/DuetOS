#pragma once

#include "util/types.h"
#include "drivers/net/net.h"

/*
 * DuetOS — Realtek rtl88xx Wi-Fi driver shell, v0.
 *
 * Brings up the Realtek wireless PCIe family (rtl8723, rtl8812,
 * rtl8813, rtl8814, rtl8821, rtl8822, rtl8852) to the level where
 * the chip is identified by reading the SYS_CFG1 register
 * (BAR0+0x00F4) and the device record carries a real chip-version
 * dword.
 *
 * Scope (v0):
 *   - PCI ID match table covering rtl8723be / rtl8812ae /
 *     rtl8813ae / rtl8814ae / rtl8821ae / rtl8822be / rtl8852ae.
 *   - Soft chip identification via SYS_CFG1; SYS_CFG2 read for
 *     the trim/efuse code so the firmware-loader slice has a
 *     known baseline.
 *   - Mark the NIC `driver_online=true`, `firmware_pending=true`.
 *     rtlwifi cards REQUIRE vendor firmware before the MAC can
 *     associate; without a firmware loader the shell stops at
 *     chip identification.
 *   - Spawn an `rtl88xx-watch` task that polls SYS_CFG1 once a
 *     second so a hot-removed card flips `driver_online` off.
 *
 * Out of scope (deferred):
 *   - 8051 microcode upload (RAM_CODE address window, polling
 *     RSV_CTRL after upload).
 *   - DMA queue setup (BCN, TX_LOW/NORMAL/HIGH, RX_DESC ring).
 *   - 802.11 association / scan / key install.
 *   - Hardware crypto (AES-128/256, TKIP).
 *
 * Threading: bring-up runs on the NetInit task; watch task at
 * 1 Hz on the regular kernel scheduler.
 */

namespace duetos::drivers::net
{

/// True iff (vendor_id, device_id) matches a Realtek wireless PCI
/// ID. Used by `RunVendorProbe` to dispatch wireless bring-up.
bool Rtl88xxMatches(u16 vendor_id, u16 device_id);

/// Bring an rtl88xx NIC up to "chip identified, MMIO live, awaiting
/// firmware". Idempotent. Returns true iff SYS_CFG1 returned a
/// plausible chip-version dword.
bool Rtl88xxBringUp(NicInfo& n);

struct Rtl88xxStats
{
    u32 adapters_bound;
    u32 watch_polls;
    u32 unexpected_dead_polls;
    u32 sys_cfg1; // last bound NIC's SYS_CFG1
    u32 sys_cfg2;
};

Rtl88xxStats Rtl88xxStatsRead();

} // namespace duetos::drivers::net
