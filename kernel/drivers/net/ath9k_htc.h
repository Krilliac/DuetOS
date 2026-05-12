#pragma once

#include "drivers/net/ath9k_htc_fw.h"
#include "drivers/net/ath9k_htc_upload.h"
#include "util/types.h"

/*
 * DuetOS — Qualcomm Atheros `ath9k_htc` USB Wi-Fi adapter driver, v0.
 *
 * Targets AR9271 (USB 802.11n single-chip) and AR7010 (USB→PCIe
 * bridge fronting AR9280/AR9285 PHYs). These adapters ship with
 * source-available firmware in the `qca/open-ath9k-htc-firmware`
 * tree, which makes them the canonical open-firmware Wi-Fi target
 * for DuetOS bring-up. See `wiki/drivers/Wireless-Firmware.md`.
 *
 * Scope (v0):
 *   - USB VID/PID match table (AR9271 family + AR7010 family +
 *     well-known OEM rebrands).
 *   - Discover matching xHCI-addressed slots via the xHCI
 *     `PortRecord` cache.
 *   - For each matched slot: look up open firmware via the
 *     `core::FwLoad` path (prefers `/lib/firmware/duetos/open/`),
 *     validate via `AthHtcFirmwareParse`, build the HTC chunk plan
 *     via `AthHtcBuildUploadPlan`, and drive
 *     `AthHtcUploadDrive` to push the bytes over USB control
 *     transfers.
 *   - Record bring-up metrics for the `WirelessStatus` rollup so
 *     the GUI net flyout can show ath9k_htc adapters.
 *
 * Out of scope (deferred):
 *   - HTC service negotiation (WMI service IDs, endpoint mapping)
 *     after the bootrom hand-off. The firmware exposes a
 *     mailbox/EP1+EP2 protocol that the driver must complete
 *     before scan/auth/assoc.
 *   - 802.11 MLME wire-up. The wdev/MLME layer in
 *     `kernel/net/wireless/` is the eventual consumer.
 *   - Interrupt-driven RX. The probe path uses polled control
 *     transfers.
 *
 * Threading: bring-up runs on the post-xHCI init task; no IRQ
 * context. Idempotent — multiple invocations short-circuit.
 */

namespace duetos::drivers::net
{

inline constexpr u16 kAthVendorAtheros = 0x0CF3;

struct AthHtcUsbId
{
    u16 vendor_id;
    u16 product_id;
    AthHtcTarget target;
    const char* tag; // human-readable name; safe for serial log
};

/// Compile-time USB ID match table. Entries are derived from the
/// upstream `ath9k_htc` Linux driver's USB_DEVICE_ID table; each
/// row is hardware ABI (VID/PID assignments by USB-IF and Atheros).
const AthHtcUsbId* AthHtcMatchUsbId(u16 vendor_id, u16 product_id);

u32 AthHtcUsbIdCount();
const AthHtcUsbId& AthHtcUsbIdAt(u32 i);

struct AthHtcAdapter
{
    bool in_use;
    u8 slot_id;
    u16 vendor_id;
    u16 product_id;
    AthHtcTarget target;
    bool firmware_loaded;   // FwLoad hit on the open-firmware path
    bool firmware_parsed;   // AthHtcFirmwareParse returned valid
    bool firmware_uploaded; // AthHtcUploadDrive returned Ok
    u32 last_chunks_planned;
    u32 last_chunks_sent;
    u32 last_bytes_sent;
    u32 last_load_address;
    u32 firmware_fletcher32;
    const char* tag;
};

struct AthHtcStats
{
    u32 adapters_seen;     // slots that matched the VID/PID table
    u32 firmware_ready;    // valid parsed firmware available
    u32 firmware_missing;  // VFS lookup miss
    u32 firmware_corrupt;  // parse rejected the blob
    u32 uploads_attempted; // Drive() invocations
    u32 uploads_succeeded; // Drive() returned Ok
};

inline constexpr u32 kAthHtcMaxAdapters = 4;

/// Initialise the driver. Walks every xHCI controller's PortRecord
/// table for VID/PID matches and runs bring-up for each match.
/// Idempotent. Safe to call once at boot after `XhciInit`.
void AthHtcInit();

/// Read the per-adapter stats snapshot. `index < AthHtcAdapterCount()`.
AthHtcStats AthHtcStatsRead();
u32 AthHtcAdapterCount();
const AthHtcAdapter& AthHtcAdapterAt(u32 index);

void AthHtcSelfTest();

} // namespace duetos::drivers::net
