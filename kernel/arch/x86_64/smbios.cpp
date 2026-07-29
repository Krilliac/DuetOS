#include "arch/x86_64/smbios.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/smbios_decode.h"
#include "arch/x86_64/uefi_nvram.h"
#include "core/panic.h"
#include "log/klog.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "smbios_rust.h"

namespace duetos::arch
{

namespace
{

using ::duetos::arch::smbios_rust::duetos_smbios_parse_entry_point;
using ::duetos::arch::smbios_rust::duetos_smbios_parse_structure;
using ::duetos::arch::smbios_rust::duetos_smbios_read_string;
using ::duetos::arch::smbios_rust::DuetosSmbiosEntryPoint;
using ::duetos::arch::smbios_rust::DuetosSmbiosString;
using ::duetos::arch::smbios_rust::DuetosSmbiosStructure;

SmbiosSummary g_summary = {};

// Legacy BIOS scan window: SMBIOS entry point lives 16-byte
// aligned somewhere in 0xF0000..0xFFFFF.
constexpr u64 kScanStart = 0xF0000;
constexpr u64 kScanEnd = 0x100000;

// The 3.x anchor entry-point length is 24 bytes; the 2.x anchor
// is 31. Pass 32 bytes to the Rust validator so either fits.
constexpr u64 kScanProbeBytes = 32;

// SMBIOS string fields are spec-capped at 64 KiB but real strings
// run < 128 bytes. We mirror the kernel-side summary buffer width
// when copying.
constexpr u64 kSummaryFieldCap = 64;

// SMBIOS_TABLE_GUID — EB9D2D31-2D88-11D3-9A16-0090273FC14D.
// Published by UEFI firmware pointing at a 32-bit ("_SM_") entry point.
constexpr EfiGuid kSmbiosTableGuid = {
    0xEB9D2D31u, 0x2D88u, 0x11D3u, {0x9Au, 0x16u, 0x00u, 0x90u, 0x27u, 0x3Fu, 0xC1u, 0x4Du}};

// SMBIOS3_TABLE_GUID — F2FD1544-9794-4A2C-992E-E5BBCF20E394.
// Points at a 64-bit ("_SM3_") entry point, whose structure table may
// legitimately sit above 4 GiB. Preferred when the firmware publishes
// both, since the 3.x anchor is authoritative on a modern box.
constexpr EfiGuid kSmbios3TableGuid = {
    0xF2FD1544u, 0x9794u, 0x4A2Cu, {0x99u, 0x2Eu, 0xE5u, 0xBBu, 0xCFu, 0x20u, 0xE3u, 0x94u}};

/// Resolve the SMBIOS entry-point physical address from the EFI
/// Configuration Table, preferring the 3.x GUID. Returns 0 when the
/// system wasn't UEFI-booted or the firmware publishes neither GUID.
u64 FindEntryPointPhysViaEfi()
{
    const u64 v3 = UefiFindConfigTable(kSmbios3TableGuid);
    if (v3 != 0)
        return v3;
    return UefiFindConfigTable(kSmbiosTableGuid);
}

// Copy a slice of validated SMBIOS bytes into a NUL-terminated
// C string, truncating at `cap - 1`. Used after
// `duetos_smbios_read_string` validates the slice's bounds.
void CopyStringSlice(char* dst, u64 cap, const u8* src, u32 length)
{
    if (cap == 0)
        return;
    u32 copy = length;
    if (static_cast<u64>(copy) + 1 > cap)
        copy = static_cast<u32>(cap - 1);
    for (u32 i = 0; i < copy; ++i)
        dst[i] = static_cast<char>(src[i]);
    dst[copy] = '\0';
}

/// Read a structure's 1-based string index and copy it into a
/// caller-provided buffer. No-op when the index is 0 (SMBIOS "no
/// string" sentinel) or the lookup fails.
void ReadStringIntoBuffer(const u8* table, u64 table_len, const DuetosSmbiosStructure& s, u8 idx, char* dst, u64 cap)
{
    if (idx == 0 || cap == 0)
    {
        if (cap != 0)
            dst[0] = '\0';
        return;
    }
    DuetosSmbiosString out = {};
    const bool ok =
        duetos_smbios_read_string(table, static_cast<usize>(table_len), s.strings_offset, s.end_offset, idx, &out);
    if (!ok)
    {
        dst[0] = '\0';
        return;
    }
    CopyStringSlice(dst, cap, table + out.offset, out.length);
}

/// Decode one Type 17 record into the summary's memory-device array.
void HandleMemoryDevice(const u8* table, u64 table_len, const DuetosSmbiosStructure& s)
{
    namespace dec = ::duetos::arch::smbios_decode;

    const u8* fmt = table + s.formatted_offset;
    const u8 length = s.formatted_length;

    // The locator strings live at 0x10/0x11, so a record that doesn't
    // reach them is a pre-2.1 stub with nothing we can render.
    if (length < dec::kType17OffsetBankLocator + 1)
        return;

    if (g_summary.memory_device_count >= kSmbiosMaxMemoryDevices)
    {
        g_summary.memory_devices_truncated = true;
        return;
    }

    SmbiosMemoryDevice& d = g_summary.memory_devices[g_summary.memory_device_count];
    ++g_summary.memory_device_count;

    d.size_bytes = dec::DecodeMemorySizeBytes(fmt, length);
    d.populated = !dec::MemorySlotIsEmpty(fmt, length) && d.size_bytes > 0;
    d.speed_mts = dec::DecodeMemorySpeedMts(fmt, length);
    d.form_factor = fmt[dec::kType17OffsetFormFactor];
    d.memory_type = (length > dec::kType17OffsetMemoryType) ? fmt[dec::kType17OffsetMemoryType] : 0;

    ReadStringIntoBuffer(table, table_len, s, fmt[dec::kType17OffsetDeviceLocator], d.device_locator,
                         sizeof(d.device_locator));
    ReadStringIntoBuffer(table, table_len, s, fmt[dec::kType17OffsetBankLocator], d.bank_locator,
                         sizeof(d.bank_locator));
    if (length > dec::kType17OffsetManufacturer)
    {
        ReadStringIntoBuffer(table, table_len, s, fmt[dec::kType17OffsetManufacturer], d.manufacturer,
                             sizeof(d.manufacturer));
    }
    if (length > dec::kType17OffsetPartNumber)
    {
        ReadStringIntoBuffer(table, table_len, s, fmt[dec::kType17OffsetPartNumber], d.part_number,
                             sizeof(d.part_number));
    }

    if (d.populated)
        g_summary.memory_installed_bytes += d.size_bytes;
}

void HandleStructure(const u8* table, u64 table_len, const DuetosSmbiosStructure& s)
{
    // The Rust walker has already validated that
    // `formatted_offset .. formatted_offset + formatted_length`
    // is a bounded slice inside `table`. We're free to read
    // fixed-offset bytes within that window with no further
    // bounds check; positions below match SMBIOS §7.
    const u8* fmt = table + s.formatted_offset;
    const u8 length = s.formatted_length;
    switch (s.struct_type)
    {
    case 0: // BIOS Information
        if (length >= 6)
        {
            ReadStringIntoBuffer(table, table_len, s, fmt[4], g_summary.bios_vendor, kSummaryFieldCap);
            ReadStringIntoBuffer(table, table_len, s, fmt[5], g_summary.bios_version, kSummaryFieldCap);
        }
        break;
    case 1: // System Information
        if (length >= 7)
        {
            ReadStringIntoBuffer(table, table_len, s, fmt[4], g_summary.system_manufacturer, kSummaryFieldCap);
            ReadStringIntoBuffer(table, table_len, s, fmt[5], g_summary.system_product, kSummaryFieldCap);
            ReadStringIntoBuffer(table, table_len, s, fmt[6], g_summary.system_version, kSummaryFieldCap);
        }
        break;
    case 2: // Baseboard / Module Information (the motherboard)
        if (length >= 7)
        {
            ReadStringIntoBuffer(table, table_len, s, fmt[4], g_summary.baseboard_manufacturer, kSummaryFieldCap);
            ReadStringIntoBuffer(table, table_len, s, fmt[5], g_summary.baseboard_product, kSummaryFieldCap);
            ReadStringIntoBuffer(table, table_len, s, fmt[6], g_summary.baseboard_version, kSummaryFieldCap);
        }
        break;
    case 3: // System Enclosure / Chassis
        // Chassis type is byte 5 (offset 0x05 from structure
        // start). High bit = chassis lock, bits 6:0 = type.
        if (length >= 6)
            g_summary.chassis_type = fmt[5] & 0x7F;
        break;
    case 4: // Processor Information
        // Only capture the FIRST processor — multi-socket parts
        // would otherwise overwrite earlier slots with the last
        // CPU's info.
        if (g_summary.cpu_manufacturer[0] == '\0' && length >= 0x11)
        {
            ReadStringIntoBuffer(table, table_len, s, fmt[7], g_summary.cpu_manufacturer, kSummaryFieldCap);
            ReadStringIntoBuffer(table, table_len, s, fmt[0x10], g_summary.cpu_version, kSummaryFieldCap);
        }
        break;
    case 17: // Memory Device — one record per DIMM slot
        HandleMemoryDevice(table, table_len, s);
        break;
    default:
        break;
    }
}

} // namespace

void SmbiosInit()
{
    static constinit bool s_done = false;
    KASSERT(!s_done, "arch/smbios", "SmbiosInit called twice");
    s_done = true;

    // 1) Find the entry point. The EFI Configuration Table is tried
    // first because it is the ONLY source that works on a UEFI boot —
    // pure UEFI firmware leaves the legacy BIOS window empty, which is
    // why this probe reported "no SMBIOS entry point" under OVMF for as
    // long as the legacy scan was the only path. The legacy scan
    // remains as the SeaBIOS / legacy-BIOS fallback.
    DuetosSmbiosEntryPoint ep = {};
    bool found = false;
    const char* source = "none";

    const u64 efi_ep_phys = FindEntryPointPhysViaEfi();
    if (efi_ep_phys != 0)
    {
        const auto* p = static_cast<const u8*>(mm::MapMmio(efi_ep_phys, kScanProbeBytes));
        if (p != nullptr && duetos_smbios_parse_entry_point(p, static_cast<usize>(kScanProbeBytes), &ep))
        {
            found = true;
            source = "efi-config-table";
        }
    }

    // 2) Legacy BIOS window, 16-byte aligned. The first candidate the
    // Rust validator accepts wins — it checks the anchor signature and
    // the additive checksum, so a false positive here is not a concern.
    if (!found)
    {
        for (u64 phys = kScanStart; phys + kScanProbeBytes <= kScanEnd; phys += 16)
        {
            const auto* p = static_cast<const u8*>(mm::PhysToVirt(phys));
            if (p == nullptr)
                continue;
            if (duetos_smbios_parse_entry_point(p, static_cast<usize>(kScanProbeBytes), &ep))
            {
                found = true;
                source = "legacy-scan";
                break;
            }
        }
    }

    if (!found)
    {
        core::Log(core::LogLevel::Warn, "arch/smbios",
                  "no SMBIOS entry point (EFI config table + legacy scan) — skipping");
        return;
    }

    arch::SerialWrite("[smbios] entry-point source=");
    arch::SerialWrite(source);
    arch::SerialWrite("\n");

    g_summary.present = true;
    g_summary.major_version = ep.major_version;
    g_summary.minor_version = ep.minor_version;

    // 2) Map the structure table. The anchor parser already capped
    // `table_length` at 1 MiB. Use the fast direct map when the table
    // sits below it; fall back to an MMIO mapping otherwise. An SMBIOS
    // 3.x (64-bit) anchor is explicitly allowed to park its structure
    // table above 4 GiB, and VirtualBox-EFI / real UEFI do exactly
    // that — feeding such an address straight to PhysToVirt would
    // hard-panic ("outside direct map") at boot, the same firmware-
    // shape trap the ACPI parser hit. The MMIO mapping is kept for the
    // kernel's lifetime (this runs once at boot, single table).
    const u64 tbl_span = static_cast<u64>(ep.table_length);
    const u8* tbl_base = nullptr;
    if (ep.table_phys + tbl_span <= mm::kDirectMapBytes)
    {
        tbl_base = static_cast<const u8*>(mm::PhysToVirt(ep.table_phys));
    }
    else
    {
        tbl_base = static_cast<const u8*>(mm::MapMmio(ep.table_phys, tbl_span == 0 ? 1 : tbl_span));
    }
    if (tbl_base == nullptr)
    {
        core::Log(core::LogLevel::Warn, "arch/smbios", "SMBIOS table phys unmappable — skipping");
        return;
    }

    // 3) Walk every structure. Each `parse_structure` call returns
    // the next structure's start in `end_offset` — we stop on the
    // type=127 sentinel, a parse error, or running off the end.
    u64 off = 0;
    while (off < ep.table_length)
    {
        DuetosSmbiosStructure s = {};
        if (!duetos_smbios_parse_structure(tbl_base, static_cast<usize>(ep.table_length), static_cast<usize>(off), &s))
            break;
        HandleStructure(tbl_base, ep.table_length, s);
        if (s.struct_type == 127)
            break;
        off = s.end_offset;
    }

    // 4) Log compact summary.
    arch::SerialWrite("[smbios] v");
    arch::SerialWriteHex(g_summary.major_version);
    arch::SerialWrite(".");
    arch::SerialWriteHex(g_summary.minor_version);
    arch::SerialWrite(" bios=\"");
    arch::SerialWrite(g_summary.bios_vendor);
    arch::SerialWrite(" ");
    arch::SerialWrite(g_summary.bios_version);
    arch::SerialWrite("\"\n");
    arch::SerialWrite("[smbios] system=\"");
    arch::SerialWrite(g_summary.system_manufacturer);
    arch::SerialWrite(" ");
    arch::SerialWrite(g_summary.system_product);
    arch::SerialWrite("\" chassis=");
    arch::SerialWrite(ChassisTypeName(g_summary.chassis_type));
    arch::SerialWrite(g_summary.chassis_type != 0 && SmbiosIsLaptopChassis() ? " (laptop-like)" : "");
    arch::SerialWrite("\n");
    arch::SerialWrite("[smbios] baseboard=\"");
    arch::SerialWrite(g_summary.baseboard_manufacturer);
    arch::SerialWrite(" ");
    arch::SerialWrite(g_summary.baseboard_product);
    arch::SerialWrite("\"\n");

    // Per-DIMM roll-up. Slot rows are DEBUG-gated (a 16-DIMM box would
    // otherwise add 16 lines to every boot); the one-line total is not.
    arch::SerialWrite("[smbios] memory devices=");
    arch::SerialWriteHex(g_summary.memory_device_count);
    arch::SerialWrite(" installed_mib=");
    arch::SerialWriteHex(g_summary.memory_installed_bytes / (1024ULL * 1024ULL));
    arch::SerialWrite(g_summary.memory_devices_truncated ? " (truncated)" : "");
    arch::SerialWrite("\n");
    for (u32 i = 0; i < g_summary.memory_device_count; ++i)
    {
        const SmbiosMemoryDevice& d = g_summary.memory_devices[i];
        KLOG_DEBUG_S("arch/smbios", "dimm", "locator", d.device_locator);
    }
}

const SmbiosSummary& SmbiosGet()
{
    return g_summary;
}

bool SmbiosIsLaptopChassis()
{
    if (!g_summary.present)
        return false;
    switch (g_summary.chassis_type)
    {
    case kChassisPortable:
    case kChassisLaptop:
    case kChassisNotebook:
    case kChassisHandheld:
    case kChassisSubNotebook:
    case kChassisTablet:
    case kChassisConvertible:
    case kChassisDetachable:
        return true;
    default:
        return false;
    }
}

const char* ChassisTypeName(u8 t)
{
    switch (t)
    {
    case kChassisOther:
        return "other";
    case kChassisUnknown:
        return "unknown";
    case kChassisDesktop:
        return "desktop";
    case kChassisLowProfileDesktop:
        return "low-profile-desktop";
    case kChassisPizzaBox:
        return "pizza-box";
    case kChassisMiniTower:
        return "mini-tower";
    case kChassisTower:
        return "tower";
    case kChassisPortable:
        return "portable";
    case kChassisLaptop:
        return "laptop";
    case kChassisNotebook:
        return "notebook";
    case kChassisHandheld:
        return "handheld";
    case kChassisDockingStation:
        return "docking-station";
    case kChassisAllInOne:
        return "all-in-one";
    case kChassisSubNotebook:
        return "sub-notebook";
    case kChassisSpaceSaving:
        return "space-saving";
    case kChassisLunchBox:
        return "lunch-box";
    case kChassisMainServer:
        return "main-server";
    case kChassisExpansion:
        return "expansion";
    case kChassisServerRack:
        return "server-rack";
    case kChassisTablet:
        return "tablet";
    case kChassisConvertible:
        return "convertible";
    case kChassisDetachable:
        return "detachable";
    default:
        return "(none)";
    }
}

} // namespace duetos::arch
