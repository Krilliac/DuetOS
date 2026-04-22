#include "net.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/paging.h"
#include "../pci/pci.h"

namespace customos::drivers::net
{

namespace
{

NicInfo g_nics[kMaxNics] = {};
u64 g_nic_count = 0;

struct VendorEntry
{
    u16 vendor_id;
    const char* short_name;
};

constexpr VendorEntry kVendors[] = {
    {kVendorIntel, "Intel"},     {kVendorRealtek, "Realtek"},   {kVendorBroadcom, "Broadcom"},
    {kVendorMarvell, "Marvell"}, {kVendorMellanox, "Mellanox"}, {kVendorRedHatVirt, "virtio-net"},
};

const char* VendorShort(u16 vid)
{
    for (const VendorEntry& v : kVendors)
    {
        if (v.vendor_id == vid)
            return v.short_name;
    }
    return "unknown";
}

const char* SubclassName(u8 subclass)
{
    switch (subclass)
    {
    case kPciSubclassEthernet:
        return "ethernet";
    case kPciSubclassTokenRing:
        return "token-ring";
    case kPciSubclassOther:
        return "other/wifi";
    default:
        return "?";
    }
}

void RunVendorProbe(NicInfo& n)
{
    const char* family = nullptr;
    switch (n.vendor_id)
    {
    case kVendorIntel:
        family = IntelNicTag(n.device_id);
        break;
    case kVendorRealtek:
        family = RealtekNicTag(n.device_id);
        break;
    case kVendorBroadcom:
        family = BroadcomNicTag(n.device_id);
        break;
    case kVendorRedHatVirt:
        family = VirtioNetTag(n.device_id);
        break;
    default:
        return;
    }
    n.family = family;
    arch::SerialWrite("[net-probe] vid=");
    arch::SerialWriteHex(n.vendor_id);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(n.device_id);
    arch::SerialWrite(" family=");
    arch::SerialWrite(family);
    arch::SerialWrite("  (stub OK — no packet I/O yet)\n");
}

void LogNic(const NicInfo& n)
{
    arch::SerialWrite("  nic ");
    arch::SerialWriteHex(n.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(n.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(n.function);
    arch::SerialWrite("  vid=");
    arch::SerialWriteHex(n.vendor_id);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(n.device_id);
    arch::SerialWrite(" vendor=\"");
    arch::SerialWrite(n.vendor);
    arch::SerialWrite("\" sub=");
    arch::SerialWrite(SubclassName(n.subclass));
    if (n.mmio_size != 0)
    {
        arch::SerialWrite(" bar0=");
        arch::SerialWriteHex(n.mmio_phys);
        arch::SerialWrite("/");
        arch::SerialWriteHex(n.mmio_size);
        if (n.mmio_virt != nullptr)
        {
            arch::SerialWrite(" -> ");
            arch::SerialWriteHex(reinterpret_cast<u64>(n.mmio_virt));
        }
    }
    arch::SerialWrite("\n");
}

} // namespace

void NetInit()
{
    KLOG_TRACE_SCOPE("drivers/net", "NetInit");
    static constinit bool s_done = false;
    KASSERT(!s_done, "drivers/net", "NetInit called twice");
    s_done = true;

    const u64 n = pci::PciDeviceCount();
    for (u64 i = 0; i < n && g_nic_count < kMaxNics; ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.class_code != kPciClassNetwork)
            continue;

        NicInfo nic = {};
        nic.vendor_id = d.vendor_id;
        nic.device_id = d.device_id;
        nic.bus = d.addr.bus;
        nic.device = d.addr.device;
        nic.function = d.addr.function;
        nic.subclass = d.subclass;
        nic.vendor = VendorShort(d.vendor_id);

        const pci::Bar bar0 = pci::PciReadBar(d.addr, 0);
        if (bar0.size != 0 && !bar0.is_io)
        {
            nic.mmio_phys = bar0.address;
            nic.mmio_size = bar0.size;
            // Cap at 2 MiB — NIC register files are tiny (<256 KiB);
            // bigger BARs on HPC NICs are for RDMA doorbells which
            // no v0 driver touches.
            constexpr u64 kMmioCap = 2ULL * 1024 * 1024;
            const u64 map_bytes = (bar0.size > kMmioCap) ? kMmioCap : bar0.size;
            nic.mmio_virt = mm::MapMmio(bar0.address, map_bytes);
        }

        RunVendorProbe(nic);
        g_nics[g_nic_count++] = nic;
    }

    core::LogWithValue(core::LogLevel::Info, "drivers/net", "discovered NICs", g_nic_count);
    for (u64 i = 0; i < g_nic_count; ++i)
    {
        LogNic(g_nics[i]);
    }
    if (g_nic_count == 0)
    {
        core::Log(core::LogLevel::Warn, "drivers/net", "no PCI network controllers found");
    }
}

u64 NicCount()
{
    return g_nic_count;
}

const NicInfo& Nic(u64 index)
{
    KASSERT_WITH_VALUE(index < g_nic_count, "drivers/net", "Nic index out of range", index);
    return g_nics[index];
}

// -------------------------------------------------------------------
// Vendor classifiers. Coarse ranges; unknown IDs land on "unknown".
// Source: Linux kernel driver pci_device_id tables.
// -------------------------------------------------------------------

const char* IntelNicTag(u16 device_id)
{
    // e1000 (82540..82547) → gigabit legacy. Every "82..." in the
    // 0x1000..0x107F range is e1000 family.
    if (device_id >= 0x1000 && device_id <= 0x107F)
        return "e1000-82540em";
    // e1000e (82571..82579) — PCIe variants. Many device IDs.
    if (device_id >= 0x10A0 && device_id <= 0x10FB)
        return "e1000e-82574";
    if (device_id >= 0x1501 && device_id <= 0x15FF)
        return "e1000e-82579/i210/i217";
    // ixgbe (82598..82599 + X540/X550/X710) — 10/25/40 Gbps.
    if (device_id >= 0x10B6 && device_id <= 0x10FB)
        return "ixgbe-82598";
    if (device_id >= 0x1528 && device_id <= 0x1560)
        return "ixgbe-x540/x550";
    // i40e (X710/XL710) — 40 Gbps.
    if (device_id >= 0x1572 && device_id <= 0x158B)
        return "i40e-x710";
    // Wi-Fi: iwlwifi 7xxx/8xxx/9xxx/AX2xx ranges.
    if (device_id >= 0x24F3 && device_id <= 0x7AF0)
        return "iwlwifi";
    return "intel-nic-unknown";
}

const char* RealtekNicTag(u16 device_id)
{
    switch (device_id)
    {
    case 0x8139:
        return "rtl8139";
    case 0x8168:
    case 0x8169:
        return "rtl8169";
    case 0x8136:
        return "rtl8101e";
    case 0x8125:
        return "rtl8125-2.5g";
    case 0xC821:
    case 0xC822:
        return "rtl8821ae-wifi";
    default:
        return "realtek-unknown";
    }
}

const char* BroadcomNicTag(u16 device_id)
{
    // bcm57xx family range (rough).
    if (device_id >= 0x1600 && device_id <= 0x16FF)
        return "bcm57xx-tg3";
    if (device_id >= 0x43A0 && device_id <= 0x43FF)
        return "bcm4331-wifi";
    return "broadcom-unknown";
}

const char* VirtioNetTag(u16 device_id)
{
    // virtio-net uses the "transitional" PCI ID 0x1000 or the
    // modern PCI ID 0x1041.
    if (device_id == 0x1000 || device_id == 0x1041)
        return "virtio-net";
    return "virtio-unknown-class";
}

} // namespace customos::drivers::net
