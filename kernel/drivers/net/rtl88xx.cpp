#include "rtl88xx.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/firmware_loader.h"
#include "../../core/klog.h"
#include "../../sched/sched.h"

namespace duetos::drivers::net
{

namespace
{

// Realtek MAC register offsets, BAR0-relative. The rtlwifi driver
// in Linux defines these as REG_SYS_CFG1 / REG_SYS_CFG2 — they
// expose the chip's silicon revision + trim configuration and are
// stable across the rtl8723..rtl8852 generations.
constexpr u32 kRegSysCfg1 = 0x00F0; // chip version + IC type + cut version
constexpr u32 kRegSysCfg2 = 0x00FC; // trim / efuse code
constexpr u32 kRegMacIdSetting = 0x0610;

// SYS_CFG1 layout (rtlwifi rtl_phycfg.h):
//   bits[3:0]   IC version (cut)
//   bits[7:4]   IC type code
//   bits[15:8]  RF type
//   bit 16      VENDOR_UMC
//   bit 17      TRP_BT_EN
//   bit 18      BD_MAC2/BD_HCI_SEL
//   bit 19      SPS_SEL (regulator)
//   bits[23:20] CHIP_VER (00 = test, 01 = A-cut, 02 = B-cut, ...)
//   bits[31:24] reserved

const char* CutVersionString(u32 cfg1)
{
    const u32 cut = (cfg1 >> 20) & 0x0F;
    switch (cut)
    {
    case 0:
        return "test";
    case 1:
        return "A-cut";
    case 2:
        return "B-cut";
    case 3:
        return "C-cut";
    case 4:
        return "D-cut";
    case 5:
        return "E-cut";
    case 6:
        return "F-cut";
    default:
        return "?-cut";
    }
}

const char* IcTypeString(u32 cfg1)
{
    const u32 ic = (cfg1 >> 4) & 0x0F;
    switch (ic)
    {
    case 0x0:
        return "8723/8821";
    case 0x1:
        return "8812";
    case 0x2:
        return "8814";
    case 0x3:
        return "8822";
    case 0x4:
        return "8852";
    case 0x5:
        return "8813";
    default:
        return "rtl-wifi-unknown";
    }
}

constinit Rtl88xxStats g_stats = {};

u32 Mmio32Read(const NicInfo& n, u64 off)
{
    if (n.mmio_virt == nullptr)
        return 0xFFFFFFFFu;
    return *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off);
}

void Rtl88xxWatchEntry(void* arg)
{
    auto* n = static_cast<NicInfo*>(arg);
    if (n == nullptr)
        return;
    for (;;)
    {
        ++g_stats.watch_polls;
        const u32 cfg1 = Mmio32Read(*n, kRegSysCfg1);
        if (cfg1 == 0xFFFFFFFFu)
        {
            ++g_stats.unexpected_dead_polls;
            n->driver_online = false;
            n->link_up = false;
        }
        duetos::sched::SchedSleepTicks(100);
    }
}

} // namespace

bool Rtl88xxMatches(u16 vendor_id, u16 device_id)
{
    if (vendor_id != kVendorRealtek)
        return false;

    // The rtl88xx wireless device IDs cluster around 0x88xx, 0xB8xx,
    // and 0xC8xx. Match the IDs the rtlwifi pci_table covers.
    switch (device_id)
    {
    case 0x8723: // rtl8723be
    case 0xB723:
    case 0x8812: // rtl8812ae
    case 0xB812:
    case 0x8813: // rtl8813ae
    case 0xB813:
    case 0x8814: // rtl8814ae
    case 0xB814:
    case 0x8821: // rtl8821ae
    case 0xC821:
    case 0xC822:
    case 0xC820:
    case 0x8822: // rtl8822be / 8822ce
    case 0xB822:
    case 0x8852: // rtl8852ae (Wi-Fi 6E)
    case 0xB852:
        return true;
    default:
        return false;
    }
}

bool Rtl88xxBringUp(NicInfo& n)
{
    KLOG_TRACE_SCOPE("drivers/net/rtl88xx", "BringUp");
    if (n.mmio_virt == nullptr)
    {
        arch::SerialWrite("[rtl88xx] no MMIO BAR — skipping\n");
        return false;
    }
    if (n.driver_online)
        return true;

    const u32 cfg1 = Mmio32Read(n, kRegSysCfg1);
    if (cfg1 == 0xFFFFFFFFu || cfg1 == 0)
    {
        arch::SerialWrite("[rtl88xx] chip not responsive (sys_cfg1=");
        arch::SerialWriteHex(cfg1);
        arch::SerialWrite(") — leaving in probe-only state\n");
        return false;
    }

    const u32 cfg2 = Mmio32Read(n, kRegSysCfg2);
    const u32 mac_id = Mmio32Read(n, kRegMacIdSetting);

    n.chip_id = cfg1;
    n.driver_online = true;
    n.link_up = false;

    // Probe firmware loader. rtl88xx vendor blob naming follows
    // `rtlwifi/rtl<chip>fw.bin`; pick by IC nibble.
    duetos::core::FwLoadRequest req{};
    req.vendor = "realtek-rtl88xx";
    const u32 ic = (cfg1 >> 4) & 0x0F;
    switch (ic)
    {
    case 0x0:
        req.basename = "rtlwifi/rtl8723befw.bin";
        break;
    case 0x1:
        req.basename = "rtlwifi/rtl8812aefw.bin";
        break;
    case 0x2:
        req.basename = "rtlwifi/rtl8814aefw.bin";
        break;
    case 0x3:
        req.basename = "rtlwifi/rtl8822befw.bin";
        break;
    case 0x4:
        req.basename = "rtw89/rtw8852a_fw.bin";
        break;
    default:
        req.basename = "rtlwifi/rtl8821aefw.bin";
        break;
    }
    auto fw = duetos::core::FwLoad(req);
    if (fw.has_value())
    {
        duetos::core::FwRelease(fw.value());
        n.firmware_pending = false;
    }
    else
    {
        n.firmware_pending = true;
    }

    g_stats.sys_cfg1 = cfg1;
    g_stats.sys_cfg2 = cfg2;
    ++g_stats.adapters_bound;

    arch::SerialWrite("[rtl88xx] online pci=");
    arch::SerialWriteHex(n.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(n.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(n.function);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(n.device_id);
    arch::SerialWrite(" sys_cfg1=");
    arch::SerialWriteHex(cfg1);
    arch::SerialWrite(" cfg2=");
    arch::SerialWriteHex(cfg2);
    arch::SerialWrite(" mac_id=");
    arch::SerialWriteHex(mac_id);
    arch::SerialWrite(" ic=");
    arch::SerialWrite(IcTypeString(cfg1));
    arch::SerialWrite(" cut=");
    arch::SerialWrite(CutVersionString(cfg1));
    arch::SerialWrite(" status=fw-pending\n");

    duetos::sched::SchedCreate(Rtl88xxWatchEntry, &n, "rtl88xx-watch");
    return true;
}

Rtl88xxStats Rtl88xxStatsRead()
{
    return g_stats;
}

} // namespace duetos::drivers::net
