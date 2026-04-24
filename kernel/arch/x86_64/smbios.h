#pragma once

#include "../../core/types.h"

/*
 * DuetOS — SMBIOS probe, v0.
 *
 * Finds the SMBIOS entry-point structure by scanning the
 * legacy BIOS area (0xF0000..0xFFFFF) for the "_SM_" / "_SM3_"
 * anchors, then walks the structure table. Decoded fields:
 *
 *   Type 0  — BIOS info (vendor + version)
 *   Type 1  — System info (manufacturer + product + serial + UUID)
 *   Type 3  — System enclosure / chassis (chassis type → laptop
 *             vs desktop)
 *   Type 4  — Processor info (manufacturer + voltage + socket)
 *
 * Only the short string fields are kept. No bootmem allocation,
 * no heap — everything is cached in static globals. The SMBIOS
 * entry-point scan happens once at boot after PagingInit (we
 * need the low 1 MiB visible via the direct map, which it is).
 *
 * UEFI note: on UEFI boot the SMBIOS entry point is passed via
 * the system configuration table (GUID
 * SMBIOS_TABLE_GUID / SMBIOS3_TABLE_GUID). Our current boot
 * protocol is Multiboot2, which doesn't propagate that — so we
 * fall back to the legacy scan. A UEFI-first boot path (track 2)
 * will add a `SmbiosInitFromConfigTable(u64 va)` overload.
 *
 * Context: kernel.
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
    // Type 3
    u8 chassis_type;
    // Type 4 (first CPU only)
    char cpu_manufacturer[64];
    char cpu_version[64];
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
