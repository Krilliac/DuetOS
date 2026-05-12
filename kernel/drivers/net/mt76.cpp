#include "drivers/net/mt76.h"

#include "arch/x86_64/serial.h"
#include "drivers/net/mt76_fw.h"
#include "loader/firmware_loader.h"
#include "log/klog.h"
#include "sched/sched.h"

namespace duetos::drivers::net
{

namespace
{

// MT_HW_BOUND register. Reading BAR0+0x0008 returns the
// concatenation (chip-class << 16) | chip-revision on every MT76xx
// chip family we care about. Reference: Linux
// `drivers/net/wireless/mediatek/mt76/mt7921/regs.h::MT_HW_BOUND`.
// The exact bit layout shifted across silicon revisions but the
// "0xFFFFFFFF means BAR is unmapped" / "0 means stuck in reset"
// rejection bands hold for every variant.
constexpr u32 kRegHwBound = 0x0008;

constinit Mt76Stats g_stats = {};

u32 Mmio32Read(const NicInfo& n, u64 off)
{
    if (n.mmio_virt == nullptr)
        return 0xFFFFFFFFu;
    return *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off);
}

void Mt76WatchEntry(void* arg)
{
    auto* n = static_cast<NicInfo*>(arg);
    if (n == nullptr)
        return;
    for (;;)
    {
        ++g_stats.watch_polls;
        const u32 v = Mmio32Read(*n, kRegHwBound);
        if (v == 0xFFFFFFFFu)
        {
            ++g_stats.unexpected_dead_polls;
            n->driver_online = false;
            n->link_up = false;
        }
        duetos::sched::SchedSleepTicks(100);
    }
}

} // namespace

const char* Mt76FamilyName(Mt76Family f)
{
    switch (f)
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
    case Mt76Family::Unknown:
    default:
        return "mt76";
    }
}

Mt76Family Mt76FamilyFromDeviceId(u16 device_id)
{
    switch (device_id)
    {
    case 0x7615:
    case 0x7611:
        return Mt76Family::Mt7615;
    case 0x7663:
        return Mt76Family::Mt7663;
    case 0x7915:
    case 0x7906:
    case 0x7902:
        return Mt76Family::Mt7915;
    case 0x7916:
        return Mt76Family::Mt7916;
    case 0x7961: // MT7921 — most common consumer chip
    case 0x0608: // MT7921 alt product code
    case 0x7920:
        return Mt76Family::Mt7921;
    case 0x0616: // MT7922
        return Mt76Family::Mt7922;
    case 0x0717: // MT7925
    case 0x7925:
        return Mt76Family::Mt7925;
    default:
        return Mt76Family::Unknown;
    }
}

bool Mt76Matches(u16 vendor_id, u16 device_id)
{
    if (vendor_id != kVendorMediaTek)
        return false;
    return Mt76FamilyFromDeviceId(device_id) != Mt76Family::Unknown;
}

bool Mt76BringUp(NicInfo& n)
{
    KLOG_TRACE_SCOPE("drivers/net/mt76", "BringUp");
    if (n.mmio_virt == nullptr)
    {
        arch::SerialWrite("[mt76] no MMIO BAR — skipping\n");
        return false;
    }
    if (n.driver_online)
        return true;

    const u32 hw_bound = Mmio32Read(n, kRegHwBound);
    if (hw_bound == 0xFFFFFFFFu || hw_bound == 0)
    {
        arch::SerialWrite("[mt76] chip not responsive (hw_bound=");
        arch::SerialWriteHex(hw_bound);
        arch::SerialWrite(") — leaving in probe-only state\n");
        return false;
    }

    const Mt76Family family = Mt76FamilyFromDeviceId(n.device_id);
    const u16 chip_class = u16((hw_bound >> 16) & 0xFFFFu);
    const u16 chip_revision = u16(hw_bound & 0xFFFFu);

    n.chip_id = hw_bound;
    n.driver_online = true;
    n.link_up = false;
    n.wireless_fw_state = NicInfo::WirelessFwState::Missing;

    duetos::core::FwLoadRequest req{};
    req.vendor = "mediatek-mt76";
    req.basename = Mt76FirmwareBasenameForFamily(family);
    req.min_bytes = kMt76FwMinBytes;
    req.max_bytes = kMt76FwMaxBytes;

    if (req.basename != nullptr)
    {
        auto fw = duetos::core::FwLoad(req);
        if (fw.has_value())
        {
            Mt76FirmwareParsed parsed{};
            auto p = Mt76FirmwareParse(fw.value().data, fw.value().size, &parsed);
            if (p.has_value() && parsed.valid)
            {
                Mt76FirmwareLog(parsed);
                n.firmware_pending = false;
                n.wireless_fw_state = NicInfo::WirelessFwState::Ready;
            }
            else
            {
                arch::SerialWrite("[mt76] firmware blob found but parse rejected — marking Incompatible\n");
                n.firmware_pending = true;
                n.wireless_fw_state = NicInfo::WirelessFwState::Incompatible;
            }
            duetos::core::FwRelease(fw.value());
        }
        else
        {
            n.firmware_pending = true;
            switch (fw.error())
            {
            case duetos::core::ErrorCode::NotFound:
                n.wireless_fw_state = NicInfo::WirelessFwState::Missing;
                break;
            case duetos::core::ErrorCode::Corrupt:
                n.wireless_fw_state = NicInfo::WirelessFwState::Incompatible;
                break;
            default:
                n.wireless_fw_state = NicInfo::WirelessFwState::LoadError;
                break;
            }
        }
    }
    else
    {
        // Family known by PCI ID but firmware basename not yet mapped.
        // Don't try to load: a missing basename is a code gap, not a
        // runtime miss, and the trace would lie about coverage.
        n.firmware_pending = true;
    }

    g_stats.hw_bound = hw_bound;
    g_stats.chip_class = chip_class;
    g_stats.chip_revision = chip_revision;
    ++g_stats.adapters_bound;

    arch::SerialWrite("[mt76] online pci=");
    arch::SerialWriteHex(n.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(n.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(n.function);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(n.device_id);
    arch::SerialWrite(" family=");
    arch::SerialWrite(Mt76FamilyName(family));
    arch::SerialWrite(" hw_bound=");
    arch::SerialWriteHex(hw_bound);
    arch::SerialWrite(" class=");
    arch::SerialWriteHex(chip_class);
    arch::SerialWrite(" rev=");
    arch::SerialWriteHex(chip_revision);
    arch::SerialWrite(" status=fw-pending\n");

    return true;
}

void Mt76StartWatch(NicInfo& n)
{
    if (!n.driver_online || n.mmio_virt == nullptr)
        return;
    duetos::sched::SchedCreate(Mt76WatchEntry, &n, "mt76-watch");
}

Mt76Stats Mt76StatsRead()
{
    return g_stats;
}

} // namespace duetos::drivers::net
