#include "smbios.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/page.h"

namespace duetos::arch
{

namespace
{

SmbiosSummary g_summary = {};

// Legacy BIOS scan window: SMBIOS entry point lives 16-byte
// aligned somewhere in 0xF0000..0xFFFFF.
constexpr u64 kScanStart = 0xF0000;
constexpr u64 kScanEnd = 0x100000;

// "_SM_"  (2.x) and "_SM3_" (3.x) anchors.
constexpr u8 kAnchor2x[4] = {'_', 'S', 'M', '_'};
constexpr u8 kAnchor3x[5] = {'_', 'S', 'M', '3', '_'};

// Copy at most `cap-1` chars + NUL terminator. Caps strings
// pulled from the structure table — those can be up to 64 KiB
// per the SMBIOS spec, way larger than our budgets.
void CopyStringBounded(char* dst, const char* src, u64 cap)
{
    if (cap == 0)
        return;
    if (src == nullptr)
    {
        dst[0] = '\0';
        return;
    }
    u64 i = 0;
    while (i + 1 < cap)
    {
        const char c = src[i];
        if (c == '\0')
            break;
        dst[i] = c;
        ++i;
    }
    dst[i] = '\0';
}

// SMBIOS stores strings immediately after each structure's
// formatted-area bytes, in a u8-indexed list (1-based). The
// unformatted area ends with a double-NUL.
//
// `struct_ptr` points at the start of the formatted area.
// `formatted_len` is the `Length` byte from the header (the
// size of the formatted area, not including the trailing
// strings).
// `index` is the 1-based string index.
const char* SmbiosString(const u8* struct_ptr, u8 formatted_len, u8 index)
{
    if (index == 0)
        return nullptr;
    const char* p = reinterpret_cast<const char*>(struct_ptr + formatted_len);
    u8 cur = 1;
    while (*p != '\0')
    {
        if (cur == index)
            return p;
        while (*p != '\0')
            ++p;
        ++p; // skip the NUL
        ++cur;
    }
    return nullptr;
}

// Return a pointer to the byte AFTER the unformatted strings of
// a structure (i.e. the start of the next structure). Handles
// the case where there are no strings at all (two NULs
// back-to-back immediately after the formatted area).
const u8* NextStructure(const u8* struct_ptr, u8 formatted_len)
{
    const u8* p = struct_ptr + formatted_len;
    // Walk until we find the terminating double-NUL.
    if (*p == '\0' && *(p + 1) == '\0')
        return p + 2; // no strings at all
    while (true)
    {
        while (*p != '\0')
            ++p;
        if (*(p + 1) == '\0')
            return p + 2;
        ++p;
    }
}

void HandleStructure(const u8* hdr, u8 type, u8 length)
{
    switch (type)
    {
    case 0: // BIOS Information
        CopyStringBounded(g_summary.bios_vendor, SmbiosString(hdr, length, hdr[4]), sizeof(g_summary.bios_vendor));
        CopyStringBounded(g_summary.bios_version, SmbiosString(hdr, length, hdr[5]), sizeof(g_summary.bios_version));
        break;
    case 1: // System Information
        CopyStringBounded(g_summary.system_manufacturer, SmbiosString(hdr, length, hdr[4]),
                          sizeof(g_summary.system_manufacturer));
        CopyStringBounded(g_summary.system_product, SmbiosString(hdr, length, hdr[5]),
                          sizeof(g_summary.system_product));
        CopyStringBounded(g_summary.system_version, SmbiosString(hdr, length, hdr[6]),
                          sizeof(g_summary.system_version));
        break;
    case 3: // System Enclosure / Chassis
        // Chassis type is byte 5 (offset 0x05 from structure
        // start). High bit = chassis lock, bits 6:0 = type.
        if (length >= 6)
            g_summary.chassis_type = hdr[5] & 0x7F;
        break;
    case 4: // Processor Information
        if (g_summary.cpu_manufacturer[0] == '\0')
        {
            CopyStringBounded(g_summary.cpu_manufacturer, SmbiosString(hdr, length, hdr[7]),
                              sizeof(g_summary.cpu_manufacturer));
            CopyStringBounded(g_summary.cpu_version, SmbiosString(hdr, length, hdr[0x10]),
                              sizeof(g_summary.cpu_version));
        }
        break;
    default:
        break;
    }
}

bool TryAnchor2x(const u8* p, u64* out_table_phys, u16* out_table_len, u16* out_major, u16* out_minor)
{
    // SMBIOS 2.x entry point is 31 bytes: "_SM_" + checksum +
    // entry-length + major + minor + max_struct_size + ...
    // "_DMI_" anchor at offset 16, table addr at 24, length at 22.
    for (u64 i = 0; i < 4; ++i)
    {
        if (p[i] != kAnchor2x[i])
            return false;
    }
    if (p[16] != '_' || p[17] != 'D' || p[18] != 'M' || p[19] != 'I' || p[20] != '_')
        return false;
    *out_major = p[6];
    *out_minor = p[7];
    *out_table_len = u16(p[22]) | (u16(p[23]) << 8);
    *out_table_phys = u32(p[24]) | (u32(p[25]) << 8) | (u32(p[26]) << 16) | (u32(p[27]) << 24);
    return true;
}

bool TryAnchor3x(const u8* p, u64* out_table_phys, u16* out_table_len, u16* out_major, u16* out_minor)
{
    // SMBIOS 3.x entry point: "_SM3_" anchor, 24-byte struct,
    // major at 7, minor at 8, table len at 12 (u32), table
    // phys at 16 (u64).
    for (u64 i = 0; i < 5; ++i)
    {
        if (p[i] != kAnchor3x[i])
            return false;
    }
    *out_major = p[7];
    *out_minor = p[8];
    *out_table_len = u16(p[12]) | (u16(p[13]) << 8);
    u64 phys = 0;
    for (u64 i = 0; i < 8; ++i)
        phys |= u64(p[16 + i]) << (i * 8);
    *out_table_phys = phys;
    return true;
}

} // namespace

void SmbiosInit()
{
    static constinit bool s_done = false;
    KASSERT(!s_done, "arch/smbios", "SmbiosInit called twice");
    s_done = true;

    // Direct-map view of the BIOS scan window.
    u64 table_phys = 0;
    u16 table_len = 0;
    u16 major = 0;
    u16 minor = 0;
    bool found = false;
    for (u64 phys = kScanStart; phys + 32 < kScanEnd; phys += 16)
    {
        const auto* p = static_cast<const u8*>(mm::PhysToVirt(phys));
        if (p == nullptr)
            continue;
        // Prefer 3.x if both are present; more detail.
        if (TryAnchor3x(p, &table_phys, &table_len, &major, &minor))
        {
            found = true;
            break;
        }
        if (TryAnchor2x(p, &table_phys, &table_len, &major, &minor))
        {
            found = true;
            break;
        }
    }

    if (!found)
    {
        core::Log(core::LogLevel::Warn, "arch/smbios", "no SMBIOS entry point — skipping");
        return;
    }

    g_summary.present = true;
    g_summary.major_version = major;
    g_summary.minor_version = minor;

    // Walk the structure table. Each structure starts with a
    // 4-byte header: type, length, handle (u16).
    const auto* tbl_base = static_cast<const u8*>(mm::PhysToVirt(table_phys));
    if (tbl_base == nullptr)
    {
        core::Log(core::LogLevel::Warn, "arch/smbios", "SMBIOS table phys not in direct map");
        return;
    }
    const u8* p = tbl_base;
    const u8* end = tbl_base + table_len;
    while (p + 4 < end)
    {
        const u8 type = p[0];
        const u8 length = p[1];
        if (length < 4)
            break;
        if (p + length >= end)
            break;
        HandleStructure(p, type, length);
        // End-of-table marker.
        if (type == 127)
            break;
        p = NextStructure(p, length);
        if (p == nullptr || p >= end)
            break;
    }

    // Log compact summary.
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
