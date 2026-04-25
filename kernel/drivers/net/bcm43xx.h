#pragma once

#include "../../core/types.h"
#include "net.h"

/*
 * DuetOS — Broadcom bcm43xx Wi-Fi driver shell, v0.
 *
 * Brings up the Broadcom wireless PCIe family (bcm4313, bcm4318,
 * bcm4322, bcm4331, bcm4350, bcm43602, AirPort/AirPort Extreme
 * silicon used in Apple hardware) to the level where the chip is
 * identified by reading the ChipCommon CORE_INFO register at
 * BAR0+0x000 and the device record carries a real chip-id +
 * revision triplet.
 *
 * Scope (v0):
 *   - PCI ID match table: 0x4300..0x43FF wireless plus the legacy
 *     0x4727 (bcm4313).
 *   - Soft chip identification via ChipCommon (the first core on
 *     the SiliconBackplane, mapped at offset 0 of BAR0).
 *   - Mark the NIC `driver_online=true`, `firmware_pending=true`.
 *     b43/brcmsmac/brcmfmac all need vendor microcode (.fw) before
 *     PHY init runs; without a firmware loader we stop here.
 *   - Spawn a `bcm43xx-watch` task that polls CORE_INFO at 1 Hz so
 *     unexpected disappearance flips `driver_online`.
 *
 * Out of scope (deferred):
 *   - Backplane (BCMA/SSB) core enumeration past ChipCommon.
 *   - PHY/RF init (LP/N/HT/AC PHY all have separate sequencers).
 *   - Microcode upload + ucode-version handshake.
 *   - 802.11 MLME, scan, association.
 *
 * Threading: bring-up runs on the NetInit task; watch task is a
 * regular kernel thread.
 */

namespace duetos::drivers::net
{

/// True iff (vendor_id, device_id) matches a Broadcom wireless
/// PCI ID. Used by `RunVendorProbe`.
bool Bcm43xxMatches(u16 vendor_id, u16 device_id);

/// Bring a bcm43xx NIC up to "chip identified, MMIO live, awaiting
/// firmware". Idempotent. Returns true iff CORE_INFO returned a
/// plausible chip-id dword.
bool Bcm43xxBringUp(NicInfo& n);

struct Bcm43xxStats
{
    u32 adapters_bound;
    u32 watch_polls;
    u32 unexpected_dead_polls;
    u32 chip_info;      // last bound NIC's CORE_INFO
    u16 chip_id_field;  // bits[15:0]
    u16 chip_rev_field; // bits[19:16]
};

Bcm43xxStats Bcm43xxStatsRead();

} // namespace duetos::drivers::net
