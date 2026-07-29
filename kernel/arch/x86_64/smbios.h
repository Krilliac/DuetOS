#pragma once

#include "util/types.h"

/*
 * DuetOS — SMBIOS probe.
 *
 * Finds the SMBIOS entry-point structure, then walks the structure
 * table. Decoded types:
 *
 *   Type 0  — BIOS info (vendor + version)
 *   Type 1  — System info (manufacturer + product + version)
 *   Type 2  — Baseboard / motherboard (manufacturer + product + version)
 *   Type 3  — System enclosure / chassis (chassis type → laptop
 *             vs desktop)
 *   Type 4  — Processor info (manufacturer + version)
 *   Type 17 — Memory Device, one record per DIMM slot (size, speed,
 *             manufacturer, part number, slot locator)
 *
 * Only the short string fields are kept. No bootmem allocation,
 * no heap — everything is cached in static globals.
 *
 * ENTRY-POINT DISCOVERY — two sources, tried in this order:
 *
 *   1. The EFI Configuration Table, looked up by GUID
 *      (SMBIOS3_TABLE_GUID preferred, then SMBIOS_TABLE_GUID) via
 *      `arch::UefiFindConfigTable`. This is the ONLY source that works
 *      on a UEFI boot: pure UEFI firmware does not populate the legacy
 *      BIOS area at all, so the 0xF0000 scan below finds nothing.
 *   2. The legacy BIOS scan window 0xF0000..0xFFFFF, 16-byte aligned,
 *      looking for the "_SM_" / "_SM3_" anchors. This is the path a
 *      SeaBIOS / legacy-BIOS boot takes.
 *
 * Both candidates go through the same Rust anchor validator
 * (signature + checksum + length caps), so a wrong guess fails closed
 * rather than parsing garbage.
 *
 * History: before the EFI path landed, `tools/qemu/run.sh` — which
 * boots OVMF by default — always logged "no SMBIOS entry point", and
 * the gap was mistaken for QEMU not providing SMBIOS at all. It does;
 * we were only looking in the legacy window.
 *
 * Context: kernel — runs after the Multiboot2 snapshot is captured and
 * after PagingInit.
 */

namespace duetos::arch
{

// Chassis type from SMBIOS Type 3 byte 5 (1-indexed in the
// spec). The names below are the human-readable mapping; the
// ones we care most about for "is this a laptop?" are 8..14.
enum ChassisType : u8
{
    kChassisOther = 0x01,
    kChassisUnknown = 0x02,
    kChassisDesktop = 0x03,
    kChassisLowProfileDesktop = 0x04,
    kChassisPizzaBox = 0x05,
    kChassisMiniTower = 0x06,
    kChassisTower = 0x07,
    kChassisPortable = 0x08,
    kChassisLaptop = 0x09,
    kChassisNotebook = 0x0A,
    kChassisHandheld = 0x0B,
    kChassisDockingStation = 0x0C,
    kChassisAllInOne = 0x0D,
    kChassisSubNotebook = 0x0E,
    kChassisSpaceSaving = 0x0F,
    kChassisLunchBox = 0x10,
    kChassisMainServer = 0x11,
    kChassisExpansion = 0x12,
    kChassisServerRack = 0x17,
    kChassisTablet = 0x1E,
    kChassisConvertible = 0x1F,
    kChassisDetachable = 0x20,
};

// Upper bound on Type 17 (Memory Device) records we cache. Consumer
// boards ship 2-4 DIMM slots and HEDT up to 8; 16 covers those with
// headroom. A machine with more slots sets `memory_devices_truncated`
// rather than silently reporting a short list.
inline constexpr u32 kSmbiosMaxMemoryDevices = 16;

// One SMBIOS Type 17 "Memory Device" record — a single DIMM slot.
// A slot that physically exists but has no module fitted is reported
// with `populated == false`; the locator strings are still valid, so a
// UI can render "DIMM_B2 — empty" instead of dropping the row.
struct SmbiosMemoryDevice
{
    bool populated;          // Size field != 0 (an empty slot reports size 0)
    u64 size_bytes;          // module capacity; 0 when the slot is empty
    u32 speed_mts;           // configured speed in MT/s; 0 = firmware said unknown
    u8 memory_type;          // Type 17 offset 0x12 (0x1A = DDR4, 0x22 = DDR5, ...)
    u8 form_factor;          // Type 17 offset 0x0E (0x09 = DIMM, 0x0D = SODIMM)
    char device_locator[32]; // silkscreen slot name, e.g. "DIMM_A1"
    char bank_locator[32];   // channel/bank grouping, e.g. "P0 CHANNEL A"
    char manufacturer[32];
    char part_number[32];
};

struct SmbiosSummary
{
    bool present;
    u16 major_version;
    u16 minor_version;
    // Type 0
    char bios_vendor[64];
    char bios_version[64];
    // Type 1
    char system_manufacturer[64];
    char system_product[64];
    char system_version[64];
    // Type 2 — Baseboard (motherboard)
    char baseboard_manufacturer[64];
    char baseboard_product[64];
    char baseboard_version[64];
    // Type 3
    u8 chassis_type;
    // Type 4 (first CPU only)
    char cpu_manufacturer[64];
    char cpu_version[64];

    // Type 17 — Memory Devices, one entry per DIMM slot.
    //
    // Distinguishing "unavailable" from "zero modules" is the caller's
    // job and both states are representable:
    //   !present                        -> no SMBIOS at all; a UI must
    //                                      render "unavailable", never 0.
    //   present && device_count == 0    -> SMBIOS parsed but the firmware
    //                                      published no Type 17 records.
    //   present && device_count > 0     -> real per-slot data.
    u32 memory_device_count;       // records stored in `memory_devices`
    bool memory_devices_truncated; // machine had > kSmbiosMaxMemoryDevices
    u64 memory_installed_bytes;    // sum of populated modules' sizes
    SmbiosMemoryDevice memory_devices[kSmbiosMaxMemoryDevices];
};

/// Scan the BIOS area for SMBIOS, parse the handful of types we
/// care about, cache the result. Logs a structured summary.
/// Safe single-init: double-call is a KASSERT.
void SmbiosInit();

/// Read-only accessor for the parsed summary.
const SmbiosSummary& SmbiosGet();

/// Convenience: true if the chassis type strongly implies a
/// laptop-shaped system (portable / laptop / notebook /
/// sub-notebook / tablet / convertible / detachable).
bool SmbiosIsLaptopChassis();

/// Human-readable chassis name for logs.
const char* ChassisTypeName(u8 t);

} // namespace duetos::arch
