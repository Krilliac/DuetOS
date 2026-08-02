#include "drivers/net/mt76.h"

#include "arch/x86_64/serial.h"
#include "drivers/net/mt76_fw.h"
#include "loader/firmware_loader.h"
#include "log/klog.h"

namespace duetos::drivers::net
{

namespace
{

// Retained experimental MediaTek shell. MT76 PCIe generations require
// family-specific power ownership and L1 register mapping before register
// reads; BAR0+8 is not a universal safe identification probe. Mt76Matches
// fails closed, and BringUp repeats that gate before this dormant read.
constexpr u32 kRegHwBound = 0x0008;

constinit Mt76Stats g_stats = {};

u32 Mmio32Read(const NicInfo& n, u64 off)
{
    if (n.mmio_virt == nullptr)
        return 0xFFFFFFFFu;
    return *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off);
}


} // namespace

bool Mt76Matches(u16 vendor_id, u16 device_id)
{
    // Inventory recognizes exact upstream candidates, but the retired shell
    // treated BAR0+8 as a universal MT_HW_BOUND register. Current mt76 PCIe
    // transports require family-specific power ownership and L1 register
    // mapping before those reads. Fail closed until that backend exists.
    (void)Mt76FamilyFromIdentity(vendor_id, device_id);
    return false;
}

bool Mt76BringUp(NicInfo& n)
{
    KLOG_TRACE_SCOPE("drivers/net/mt76", "BringUp");
    if (!Mt76Matches(n.vendor_id, n.device_id))
        return false;
    if (n.mmio_virt == nullptr)
    {
        KLOG_WARN("drivers/net/mt76", "no MMIO BAR — skipping");
        return false;
    }
    if (n.driver_online)
        return true;

    const u32 hw_bound = Mmio32Read(n, kRegHwBound);
    if (hw_bound == 0xFFFFFFFFu || hw_bound == 0)
    {
        // Same dead-chip shape as iwlwifi: all-ones / all-zeros on
        // the first register read means BAR mapping is broken or the
        // chip is wedged. Route through klog so the ring captures it.
        KLOG_ERROR_V("drivers/net/mt76", "chip not responsive — leaving in probe-only state", hw_bound);
        return false;
    }

    const Mt76Family family = Mt76FamilyFromIdentity(n.vendor_id, n.device_id);
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
    (void)n;
}

Mt76Stats Mt76StatsRead()
{
    return g_stats;
}

} // namespace duetos::drivers::net
