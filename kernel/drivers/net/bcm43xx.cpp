#include "bcm43xx.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../sched/sched.h"

namespace duetos::drivers::net
{

namespace
{

// Broadcom SiliconBackplane ChipCommon core registers, BAR0-relative
// (ChipCommon is always the first core on the backplane and maps to
// the start of BAR0 on PCIe wireless cards).
//
// CORE_INFO layout (Broadcom backplane spec):
//   bits[15:0]  ChipID    (e.g. 0x4331, 0x4350, 0x43A0)
//   bits[19:16] ChipRev   (silicon revision)
//   bits[27:20] PackageOpt
//   bits[31:28] CC_REV    (ChipCommon core revision)
constexpr u32 kRegChipInfo = 0x000;
constexpr u32 kRegCapabilities = 0x004;
constexpr u32 kRegCoreCtl = 0x008;
constexpr u32 kRegStrapOpt = 0x010;

constinit Bcm43xxStats g_stats = {};

u32 Mmio32Read(const NicInfo& n, u64 off)
{
    if (n.mmio_virt == nullptr)
        return 0xFFFFFFFFu;
    return *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off);
}

const char* ChipFamilyString(u16 chip_id)
{
    // Common known IDs — pulled from b43 / brcmsmac / brcmfmac
    // chip_info_t tables. Falls back to a generic "bcm43xx".
    switch (chip_id)
    {
    case 0x4301:
        return "bcm4301";
    case 0x4306:
        return "bcm4306";
    case 0x4311:
    case 0x4312:
    case 0x4313:
        return "bcm4311";
    case 0x4315:
        return "bcm4315";
    case 0x4318:
    case 0x4319:
        return "bcm4318";
    case 0x4322:
        return "bcm4322";
    case 0x4324:
        return "bcm4324";
    case 0x4329:
        return "bcm4329";
    case 0x4331:
        return "bcm4331";
    case 0x4350:
        return "bcm4350";
    case 0x4356:
    case 0x4357:
    case 0x4358:
        return "bcm4356";
    case 0x4359:
        return "bcm4359";
    case 0x43A0:
    case 0x43A1:
    case 0x43A2:
    case 0x43A3:
        return "bcm43602";
    case 0x43A9:
    case 0x43AA:
        return "bcm4358";
    case 0x43B1:
        return "bcm4352";
    default:
        return "bcm43xx";
    }
}

void Bcm43xxWatchEntry(void* arg)
{
    auto* n = static_cast<NicInfo*>(arg);
    if (n == nullptr)
        return;
    for (;;)
    {
        ++g_stats.watch_polls;
        const u32 info = Mmio32Read(*n, kRegChipInfo);
        if (info == 0xFFFFFFFFu)
        {
            ++g_stats.unexpected_dead_polls;
            n->driver_online = false;
            n->link_up = false;
        }
        duetos::sched::SchedSleepTicks(100);
    }
}

} // namespace

bool Bcm43xxMatches(u16 vendor_id, u16 device_id)
{
    if (vendor_id != kVendorBroadcom)
        return false;

    // Wireless range: every bcm43xx PCIe card lives in 0x4300..0x43FF.
    // bcm4313 is the well-known outlier at 0x4727.
    if (device_id >= 0x4300 && device_id <= 0x43FF)
        return true;
    if (device_id == 0x4727)
        return true;
    return false;
}

bool Bcm43xxBringUp(NicInfo& n)
{
    KLOG_TRACE_SCOPE("drivers/net/bcm43xx", "BringUp");
    if (n.mmio_virt == nullptr)
    {
        arch::SerialWrite("[bcm43xx] no MMIO BAR — skipping\n");
        return false;
    }
    if (n.driver_online)
        return true;

    const u32 info = Mmio32Read(n, kRegChipInfo);
    if (info == 0xFFFFFFFFu || info == 0)
    {
        arch::SerialWrite("[bcm43xx] chip not responsive (chip_info=");
        arch::SerialWriteHex(info);
        arch::SerialWrite(") — leaving in probe-only state\n");
        return false;
    }

    const u16 chip_id_field = u16(info & 0xFFFFu);
    const u16 chip_rev_field = u16((info >> 16) & 0x000Fu);
    const u32 caps = Mmio32Read(n, kRegCapabilities);
    const u32 strap = Mmio32Read(n, kRegStrapOpt);
    const u32 corectl = Mmio32Read(n, kRegCoreCtl);

    n.chip_id = info;
    n.driver_online = true;
    n.firmware_pending = true;
    n.link_up = false;

    g_stats.chip_info = info;
    g_stats.chip_id_field = chip_id_field;
    g_stats.chip_rev_field = chip_rev_field;
    ++g_stats.adapters_bound;

    arch::SerialWrite("[bcm43xx] online pci=");
    arch::SerialWriteHex(n.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(n.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(n.function);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(n.device_id);
    arch::SerialWrite(" chip_info=");
    arch::SerialWriteHex(info);
    arch::SerialWrite(" id=");
    arch::SerialWriteHex(chip_id_field);
    arch::SerialWrite(" rev=");
    arch::SerialWriteHex(chip_rev_field);
    arch::SerialWrite(" caps=");
    arch::SerialWriteHex(caps);
    arch::SerialWrite(" strap=");
    arch::SerialWriteHex(strap);
    arch::SerialWrite(" core_ctl=");
    arch::SerialWriteHex(corectl);
    arch::SerialWrite(" silicon=");
    arch::SerialWrite(ChipFamilyString(chip_id_field));
    arch::SerialWrite(" status=fw-pending\n");

    duetos::sched::SchedCreate(Bcm43xxWatchEntry, &n, "bcm43xx-watch");
    return true;
}

Bcm43xxStats Bcm43xxStatsRead()
{
    return g_stats;
}

} // namespace duetos::drivers::net
