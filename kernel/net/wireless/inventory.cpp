#include "net/wireless/inventory.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/net/ath9k_htc.h"
#include "drivers/net/bcm43xx.h"
#include "drivers/net/iwlwifi.h"
#include "drivers/net/mt76.h"
#include "drivers/net/mt76_fw.h"
#include "drivers/net/rtl88xx.h"

namespace duetos::net::wireless
{

namespace
{

constinit WirelessInventoryEntry g_entries[kWirelessInventoryMax] = {};
constinit u32 g_entry_count = 0;

const char* IwlBasenameForDeviceId(u16 device_id)
{
    // Pick the canonical basename per generation. The runtime
    // driver picks via HW_REV, but for a one-line inventory hint
    // the device_id is enough to identify the family the operator
    // needs to stage. Mirrors the linux-firmware naming.
    if (device_id == 0x2723 || device_id == 0x2725 || device_id == 0xA0F0 || device_id == 0x43F0)
        return "iwlwifi-cc-a0-46.ucode"; // AX200 / AX201
    if (device_id == 0x7AF0 || device_id == 0x7E40)
        return "iwlwifi-ty-a0-gf-a0-46.ucode"; // AX210
    if (device_id == 0x272B || device_id == 0x51F0 || device_id == 0x51F1 || device_id == 0xD2F0 || device_id == 0xE2F0)
        return "iwlwifi-gl-c0-fm-c0-83.ucode"; // BE200 (Wi-Fi 7)
    if (device_id == 0x24F3 || device_id == 0x24F4 || device_id == 0x24F5 || device_id == 0x24FD)
        return "iwlwifi-8000C-46.ucode"; // 8260
    if (device_id == 0x2526 || device_id == 0x271B || device_id == 0x271C || device_id == 0x9DF0 || device_id == 0xA370)
        return "iwlwifi-9000-pu-b0-jf-b0-46.ucode"; // 9000 family
    return "iwlwifi-<generation>.ucode";
}

const char* RtlBasenameForDeviceId(u16 device_id)
{
    switch (device_id)
    {
    case 0x8723:
    case 0xB723:
        return "rtlwifi/rtl8723befw.bin";
    case 0x8812:
    case 0xB812:
        return "rtlwifi/rtl8812aefw.bin";
    case 0x8814:
    case 0xB814:
        return "rtlwifi/rtl8814aefw.bin";
    case 0x8821:
    case 0xC820:
    case 0xC821:
    case 0xC822:
        return "rtlwifi/rtl8821aefw.bin";
    case 0x8822:
    case 0xB822:
        return "rtlwifi/rtl8822befw.bin";
    case 0x8852:
    case 0xB852:
        return "rtw89/rtw8852a_fw.bin";
    default:
        return "rtlwifi/rtl<chip>fw.bin";
    }
}

const char* BcmBasenameForDeviceId(u16 device_id)
{
    // brcmfmac uses chip-specific `brcmfmac<chip>-pcie.bin`; the
    // exact suffix depends on board revision so we leave it
    // generic in the hint.
    (void)device_id;
    return "brcm/brcmfmac<chip>-pcie.bin";
}

void WriteAddr(const WirelessInventoryEntry& e)
{
    if (e.bus == WirelessInventoryBus::Pci)
    {
        arch::SerialWrite("[pci ");
        arch::SerialWriteHex(e.addr0);
        arch::SerialWrite(":");
        arch::SerialWriteHex(e.addr1);
        arch::SerialWrite(".");
        arch::SerialWriteHex(e.addr2);
        arch::SerialWrite("] ");
    }
    else
    {
        arch::SerialWrite("[usb slot=");
        arch::SerialWriteHex(e.addr0);
        arch::SerialWrite("]   ");
    }
}

void DumpEntry(const WirelessInventoryEntry& e)
{
    arch::SerialWrite("  ");
    WriteAddr(e);
    arch::SerialWrite("vid=");
    arch::SerialWriteHex(e.vendor_id);
    arch::SerialWrite(" ");
    arch::SerialWrite(e.bus == WirelessInventoryBus::Pci ? "did=" : "pid=");
    arch::SerialWriteHex(e.product_id);
    arch::SerialWrite(" family=");
    arch::SerialWrite(e.family != nullptr ? e.family : "?");
    arch::SerialWrite(" driver=");
    arch::SerialWrite(e.driver_online ? "ON" : "off");
    arch::SerialWrite(" fw=");
    arch::SerialWrite(WirelessInventoryFwStateName(e.fw_state));
    arch::SerialWrite(" (");
    arch::SerialWrite(WirelessInventoryOpennessName(e.openness));
    arch::SerialWrite(")\n");

    if (e.expected_basename != nullptr)
    {
        arch::SerialWrite("    firmware basename : ");
        arch::SerialWrite(e.expected_basename);
        arch::SerialWrite("\n");
    }
    if (e.firmware_path_hint != nullptr && e.fw_state != drivers::net::NicInfo::WirelessFwState::Ready)
    {
        arch::SerialWrite("    stage under       : ");
        arch::SerialWrite(e.firmware_path_hint);
        arch::SerialWrite("\n");
    }
}

bool AppendEntry(const WirelessInventoryEntry& e)
{
    if (g_entry_count >= kWirelessInventoryMax)
        return false;
    g_entries[g_entry_count++] = e;
    return true;
}

void IngestNic(const drivers::net::NicInfo& n, u64 /*nic_index*/)
{
    // Skip wired Ethernet — easy heuristic: drivers::net::NicIsWireless
    // looks at subclass + family string. We mirror its logic here
    // (without taking a dependency on the private predicate) by
    // checking which wireless matcher claims the device.
    const bool is_wireless = drivers::net::IwlwifiMatches(n.vendor_id, n.device_id) ||
                             drivers::net::Rtl88xxMatches(n.vendor_id, n.device_id) ||
                             drivers::net::Bcm43xxMatches(n.vendor_id, n.device_id) ||
                             drivers::net::Mt76Matches(n.vendor_id, n.device_id);
    if (!is_wireless)
        return;

    WirelessInventoryEntry e{};
    e.bus = WirelessInventoryBus::Pci;
    e.addr0 = n.bus;
    e.addr1 = n.device;
    e.addr2 = n.function;
    e.vendor_id = n.vendor_id;
    e.product_id = n.device_id;
    e.family = n.family;
    e.driver_online = n.driver_online;
    e.fw_state = n.wireless_fw_state;

    if (drivers::net::IwlwifiMatches(n.vendor_id, n.device_id))
    {
        e.expected_basename = IwlBasenameForDeviceId(n.device_id);
        e.firmware_path_hint = "/lib/firmware/intel-iwlwifi/";
        e.openness = WirelessInventoryFwOpenness::Redistributable;
    }
    else if (drivers::net::Rtl88xxMatches(n.vendor_id, n.device_id))
    {
        e.expected_basename = RtlBasenameForDeviceId(n.device_id);
        e.firmware_path_hint = "/lib/firmware/realtek-rtl88xx/";
        e.openness = WirelessInventoryFwOpenness::Redistributable;
    }
    else if (drivers::net::Bcm43xxMatches(n.vendor_id, n.device_id))
    {
        e.expected_basename = BcmBasenameForDeviceId(n.device_id);
        e.firmware_path_hint = "/lib/firmware/broadcom-bcm43xx/  (b43-openfwwf for legacy chips)";
        // Older bcm43xx revisions can use OpenFWWF — flag the
        // possibility for the operator. Newer brcmfmac chips
        // can't.
        e.openness = (n.device_id <= 0x4329) ? WirelessInventoryFwOpenness::OpenSource
                                             : WirelessInventoryFwOpenness::Redistributable;
    }
    else if (drivers::net::Mt76Matches(n.vendor_id, n.device_id))
    {
        const drivers::net::Mt76Family fam = drivers::net::Mt76FamilyFromDeviceId(n.device_id);
        e.expected_basename = drivers::net::Mt76FirmwareBasenameForFamily(fam);
        e.firmware_path_hint = "/lib/firmware/mediatek-mt76/";
        e.openness = WirelessInventoryFwOpenness::Redistributable;
    }
    AppendEntry(e);
}

void IngestAthHtc(const drivers::net::AthHtcAdapter& a)
{
    if (!a.in_use)
        return;
    WirelessInventoryEntry e{};
    e.bus = WirelessInventoryBus::Usb;
    e.addr0 = a.slot_id;
    e.vendor_id = a.vendor_id;
    e.product_id = a.product_id;
    e.family = a.tag;
    e.driver_online = true;
    // ath9k_htc state isn't a NicInfo::WirelessFwState; map the
    // captured upload booleans into the same enum so the dump
    // surface is uniform with PCI entries.
    if (a.firmware_uploaded)
        e.fw_state = drivers::net::NicInfo::WirelessFwState::Ready;
    else if (a.firmware_parsed)
        e.fw_state = drivers::net::NicInfo::WirelessFwState::UploadFailed;
    else if (a.firmware_loaded)
        e.fw_state = drivers::net::NicInfo::WirelessFwState::Incompatible;
    else
        e.fw_state = drivers::net::NicInfo::WirelessFwState::Missing;
    e.expected_basename = (a.target == drivers::net::AthHtcTarget::Ar9271)   ? "htc_9271.fw"
                          : (a.target == drivers::net::AthHtcTarget::Ar7010) ? "htc_7010.fw"
                                                                             : nullptr;
    e.firmware_path_hint = "/lib/firmware/duetos/open/ath9k-htc/";
    e.openness = WirelessInventoryFwOpenness::OpenSource;
    AppendEntry(e);
}

} // namespace

const char* WirelessInventoryFwStateName(drivers::net::NicInfo::WirelessFwState s)
{
    using S = drivers::net::NicInfo::WirelessFwState;
    switch (s)
    {
    case S::NotApplicable:
        return "n/a";
    case S::Ready:
        return "ready";
    case S::Missing:
        return "missing";
    case S::Incompatible:
        return "incompatible";
    case S::LoadError:
        return "load-error";
    case S::UploadFailed:
        return "upload-failed";
    }
    return "?";
}

const char* WirelessInventoryOpennessName(WirelessInventoryFwOpenness o)
{
    switch (o)
    {
    case WirelessInventoryFwOpenness::None:
        return "none";
    case WirelessInventoryFwOpenness::OpenSource:
        return "open-firmware";
    case WirelessInventoryFwOpenness::Redistributable:
        return "closed-redistributable";
    }
    return "?";
}

u32 WirelessInventoryCount()
{
    return g_entry_count;
}

const WirelessInventoryEntry& WirelessInventoryAt(u32 index)
{
    KASSERT_WITH_VALUE(index < g_entry_count, "net/wireless/inventory", "WirelessInventoryAt index out of range",
                       index);
    return g_entries[index];
}

void WirelessInventoryRefresh()
{
    g_entry_count = 0;
    for (u32 i = 0; i < kWirelessInventoryMax; ++i)
        g_entries[i] = {};
    const u64 nic_count = drivers::net::NicCount();
    for (u64 i = 0; i < nic_count; ++i)
        IngestNic(drivers::net::Nic(i), i);
    const u32 ath_count = drivers::net::AthHtcAdapterCount();
    for (u32 i = 0; i < ath_count; ++i)
        IngestAthHtc(drivers::net::AthHtcAdapterAt(i));
}

void WirelessInventoryDump()
{
    WirelessInventoryRefresh();
    arch::SerialWrite("\n=== WIRELESS HARDWARE INVENTORY ===\n");
    if (g_entry_count == 0)
    {
        arch::SerialWrite("  (no wireless adapters detected)\n");
        arch::SerialWrite("=== END WIRELESS INVENTORY (0 adapters) ===\n\n");
        return;
    }
    u32 fw_ready = 0;
    for (u32 i = 0; i < g_entry_count; ++i)
    {
        DumpEntry(g_entries[i]);
        if (g_entries[i].fw_state == drivers::net::NicInfo::WirelessFwState::Ready)
            ++fw_ready;
    }
    arch::SerialWrite("=== END WIRELESS INVENTORY (");
    arch::SerialWriteHex(g_entry_count);
    arch::SerialWrite(" adapters, ");
    arch::SerialWriteHex(fw_ready);
    arch::SerialWrite(" firmware-ready) ===\n\n");
}

void WirelessInventorySelfTest()
{
    // The self-test runs before NetInit / AthHtcInit so both
    // upstream tables are empty. Refresh should produce zero
    // entries and Dump must not crash on the empty case.
    WirelessInventoryRefresh();
    KASSERT(WirelessInventoryCount() <= kWirelessInventoryMax, "net/wireless/inventory",
            "refresh produced too many entries");
    // Dumping the empty inventory must be safe.
    WirelessInventoryDump();
    // The name helpers must return non-null for every enum value
    // that the dumper might receive.
    KASSERT(WirelessInventoryFwStateName(drivers::net::NicInfo::WirelessFwState::Ready) != nullptr,
            "net/wireless/inventory", "Ready name null");
    KASSERT(WirelessInventoryFwStateName(drivers::net::NicInfo::WirelessFwState::Missing) != nullptr,
            "net/wireless/inventory", "Missing name null");
    KASSERT(WirelessInventoryOpennessName(WirelessInventoryFwOpenness::OpenSource) != nullptr, "net/wireless/inventory",
            "OpenSource name null");
    KASSERT(WirelessInventoryOpennessName(WirelessInventoryFwOpenness::Redistributable) != nullptr,
            "net/wireless/inventory", "Redistributable name null");
    arch::SerialWrite("[wireless-inventory] selftest pass\n");
}

} // namespace duetos::net::wireless
