#pragma once

#include "drivers/net/net.h"
#include "util/types.h"

/*
 * MediaTek Wi-Fi inventory shell.
 *
 * Exact candidates are classified without treating BAR0+8 as a universal
 * mt76 identity register. Mt76Matches returns false and the legacy dormant
 * implementation cannot access MMIO, load firmware, publish driver_online,
 * or start a watcher. MT7921 contract validation lives separately in
 * mt7921_contract.h and stops before hardware bring-up.
 */

namespace duetos::drivers::net
{

inline constexpr u16 kVendorMediaTek = 0x14C3;
inline constexpr u16 kVendorIttim = 0x0B48;

enum class Mt76Family : u8
{
    Unknown = 0,
    Mt7615 = 1, // Wi-Fi 5 (802.11ac)
    Mt7663 = 2,
    Mt7915 = 3, // Wi-Fi 6 (PCIe AP-grade)
    Mt7916 = 4,
    Mt7902 = 8,
    Mt7920 = 9,
    Mt7927 = 10,
    HifCompanion = 11,
    Mt7921 = 5, // Wi-Fi 6 / 6E — most common consumer chip
    Mt7922 = 6, // Wi-Fi 6E
    Mt7925 = 7, // Wi-Fi 7
};

constexpr const char* Mt76FamilyName(Mt76Family family)
{
    switch (family)
    {
    case Mt76Family::Mt7615:
        return "mt7615";
    case Mt76Family::Mt7663:
        return "mt7663";
    case Mt76Family::Mt7915:
        return "mt7915";
    case Mt76Family::Mt7916:
        return "mt7916";
    case Mt76Family::Mt7921:
        return "mt7921";
    case Mt76Family::Mt7922:
        return "mt7922";
    case Mt76Family::Mt7925:
        return "mt7925";
    case Mt76Family::Mt7902:
        return "mt7902";
    case Mt76Family::Mt7920:
        return "mt7920";
    case Mt76Family::Mt7927:
        return "mt7927";
    case Mt76Family::HifCompanion:
        return "mt7915-hif-companion";
    case Mt76Family::Unknown:
    default:
        return "mt76";
    }
}

/// Classify exact product IDs from the current upstream PCI tables.
/// MT7916/790A are secondary HIF functions and must not become independent
/// NIC records. Distinct firmware/layout variants stay distinct even when
/// they share an upstream transport implementation.
constexpr Mt76Family Mt76FamilyFromDeviceId(u16 device_id)
{
    switch (device_id)
    {
    case 0x7615:
    case 0x7611:
        return Mt76Family::Mt7615;
    case 0x7663:
        return Mt76Family::Mt7663;
    case 0x7915:
        return Mt76Family::Mt7915;
    case 0x7906:
        return Mt76Family::Mt7916;
    case 0x7916:
    case 0x790A:
        return Mt76Family::HifCompanion;
    case 0x7961:
    case 0x0608:
        return Mt76Family::Mt7921;
    case 0x7922:
    case 0x0616:
        return Mt76Family::Mt7922;
    case 0x7920:
        return Mt76Family::Mt7920;
    case 0x7902:
        return Mt76Family::Mt7902;
    case 0x7925:
    case 0x0717:
        return Mt76Family::Mt7925;
    case 0x7927:
    case 0x6639:
    case 0x0738:
        return Mt76Family::Mt7927;
    default:
        return Mt76Family::Unknown;
    }
}

/// ITTIM is accepted only for its upstream-listed 0B48:7922 rebadge.
constexpr Mt76Family Mt76FamilyFromIdentity(u16 vendor_id, u16 device_id)
{
    if (vendor_id == kVendorIttim)
        return device_id == 0x7922 ? Mt76Family::Mt7922 : Mt76Family::Unknown;
    return vendor_id == kVendorMediaTek ? Mt76FamilyFromDeviceId(device_id) : Mt76Family::Unknown;
}

constexpr bool Mt76FamilyIsPrimaryAdapter(Mt76Family family)
{
    return family != Mt76Family::Unknown && family != Mt76Family::HifCompanion;
}

/// Returning nullptr for companion/unknown rows prevents a secondary HIF
/// function from being published as a standalone network interface.
constexpr const char* Mt76InventoryTag(Mt76Family family)
{
    switch (family)
    {
    case Mt76Family::Mt7615:
        return "mt7615-wifi";
    case Mt76Family::Mt7663:
        return "mt7663-wifi";
    case Mt76Family::Mt7915:
        return "mt7915-wifi";
    case Mt76Family::Mt7916:
        return "mt7916-wifi";
    case Mt76Family::Mt7921:
        return "mt7921-wifi";
    case Mt76Family::Mt7922:
        return "mt7922-wifi";
    case Mt76Family::Mt7925:
        return "mt7925-wifi";
    case Mt76Family::Mt7902:
        return "mt7902-wifi";
    case Mt76Family::Mt7920:
        return "mt7920-wifi";
    case Mt76Family::Mt7927:
        return "mt7927-wifi";
    case Mt76Family::HifCompanion:
    case Mt76Family::Unknown:
    default:
        return nullptr;
    }
}

/// Functional admission gate. Currently false for every candidate.
bool Mt76Matches(u16 vendor_id, u16 device_id);

/// Dormant implementation entry; fails closed while no safe profile exists.
bool Mt76BringUp(NicInfo& n);

/// Compatibility no-op; no wireless worker is launched.
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
