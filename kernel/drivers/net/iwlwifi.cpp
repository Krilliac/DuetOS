#include "drivers/net/iwlwifi.h"

#include "arch/x86_64/serial.h"
#include "loader/firmware_loader.h"
#include "log/klog.h"
#include "sched/sched.h"

namespace duetos::drivers::net
{

namespace
{

// CSR (Control + Status Register) block, BAR0-relative. Layout is
// stable across iwlwifi silicon from 1000-series through AX/Be —
// only the *meaning* of fields varies, not the offsets. We touch
// the register file read-only here; writing would require knowing
// the exact silicon family, which means walking HW_REV first
// anyway.
constexpr u32 kCsrHwRev = 0x028;   // u32 — silicon stepping + dash + sku
constexpr u32 kCsrGpCntrl = 0x024; // u32 — power / sleep state
constexpr u32 kCsrIntCoalescing = 0x004;
[[maybe_unused]] constexpr u32 kCsrInt = 0x008;

// HW_REV layout (Intel CSR programming guide):
//   bits[31:24] SiSku, [23:16] Step, [15:8] Dash, [7:4] Type, [3:0] Rev.
// The full dword is what we expose; ChipIdShortString below gives a
// human label for the most common steppings without pulling in a
// 100-entry table that would rot the moment Intel ships new silicon.

const char* ChipIdShortString(u32 hw_rev)
{
    if (hw_rev == 0 || hw_rev == 0xFFFFFFFF)
        return "stuck";
    const u8 type = u8((hw_rev >> 4) & 0x0F);
    switch (type)
    {
    case 0x0:
        return "1000/4965";
    case 0x1:
        return "5000/6000";
    case 0x2:
        return "7260/3160";
    case 0x3:
        return "7265/3165";
    case 0x4:
        return "8260/3168";
    case 0x5:
        return "9000-Th/Cy";
    case 0x6:
        return "AX200/AX201";
    case 0x7:
        return "AX210";
    case 0x8:
        return "AX411/Be";
    case 0x9:
        return "Be200/Be201";
    default:
        return "intel-wifi-unknown";
    }
}

constinit IwlwifiStats g_stats = {};

u32 Mmio32Read(const NicInfo& n, u64 off)
{
    if (n.mmio_virt == nullptr)
        return 0xFFFFFFFFu;
    return *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off);
}

// Periodic watch loop — re-reads HW_REV every 1 s. Catches the case
// where the card was hot-removed or the firmware loader (when it
// arrives) puts the chip in a state that returns all-ones.
void IwlwifiWatchEntry(void* arg)
{
    auto* n = static_cast<NicInfo*>(arg);
    if (n == nullptr)
        return;
    for (;;)
    {
        ++g_stats.watch_polls;
        const u32 rev = Mmio32Read(*n, kCsrHwRev);
        if (rev == 0xFFFFFFFFu)
        {
            ++g_stats.unexpected_dead_polls;
            // Mark the NIC offline so the GUI flips the indicator.
            // Don't tear MMIO down — a future firmware loader may
            // bring it back.
            n->driver_online = false;
            n->link_up = false;
        }
        // Sleep ~1 s on a 100 Hz tick.
        duetos::sched::SchedSleepTicks(100);
    }
}

} // namespace

bool IwlwifiMatches(u16 vendor_id, u16 device_id)
{
    if (vendor_id != kVendorIntel)
        return false;

    // 1000 series.
    if (device_id == 0x0083 || device_id == 0x0084 || device_id == 0x0085 || device_id == 0x0087 ||
        device_id == 0x0089 || device_id == 0x008A || device_id == 0x008B)
        return true;

    // 6000 series — overlaps with 1000 in the dense 0x008x area, plus
    // its own dense range 0x0082..0x0091.
    if (device_id >= 0x0082 && device_id <= 0x0091)
        return true;
    if (device_id == 0x008D || device_id == 0x008E)
        return true;

    // 4965AGN.
    if (device_id == 0x4229 || device_id == 0x4230)
        return true;

    // 5000 series + 5150.
    if (device_id >= 0x4232 && device_id <= 0x423D)
        return true;

    // 7260/3160 family.
    if (device_id >= 0x08B1 && device_id <= 0x08B4)
        return true;

    // 7265/3165/3168.
    if (device_id == 0x095A || device_id == 0x095B)
        return true;

    // 8260/3168.
    if (device_id == 0x24F3 || device_id == 0x24F4 || device_id == 0x24F5 || device_id == 0x24FD)
        return true;

    // 9000 family (Wireless-AC 9260, Killer 1550, JfP).
    if (device_id == 0x2526 || device_id == 0x271B || device_id == 0x271C || device_id == 0x30DC ||
        device_id == 0x31DC || device_id == 0x9DF0 || device_id == 0xA370)
        return true;

    // AX2xx (AX200, AX201, AX210/AX211).
    if (device_id == 0x2723 || device_id == 0x2725 || device_id == 0x7AF0 || device_id == 0x7E40 ||
        device_id == 0xA0F0 || device_id == 0x43F0)
        return true;

    // Be2xx (Wi-Fi 7).
    if (device_id == 0x272B || device_id == 0x51F0 || device_id == 0x51F1 || device_id == 0xD2F0 || device_id == 0xE2F0)
        return true;

    return false;
}

bool IwlwifiBringUp(NicInfo& n)
{
    KLOG_TRACE_SCOPE("drivers/net/iwlwifi", "BringUp");
    if (n.mmio_virt == nullptr)
    {
        arch::SerialWrite("[iwlwifi] no MMIO BAR — skipping\n");
        return false;
    }
    if (n.driver_online)
    {
        // Re-probe is a no-op; iwlwifi state lives in the NIC table.
        return true;
    }

    // Chip ID read. 0xFFFFFFFF means BAR mapping is broken or the
    // chip is in deep sleep without a wake handshake — we don't have
    // firmware to do that handshake, so log and bail.
    const u32 hw_rev = Mmio32Read(n, kCsrHwRev);
    if (hw_rev == 0xFFFFFFFFu || hw_rev == 0)
    {
        arch::SerialWrite("[iwlwifi] chip not responsive (hw_rev=");
        arch::SerialWriteHex(hw_rev);
        arch::SerialWrite(") — leaving in probe-only state\n");
        return false;
    }

    // Read the GP_CNTRL register too — it carries the MAC_ACCESS_REQ
    // / MAC_CLOCK_READY bits that a firmware loader will eventually
    // need to drive. Logging it now gives the firmware-loader slice
    // a known baseline.
    const u32 gp_cntrl = Mmio32Read(n, kCsrGpCntrl);
    const u32 int_coal = Mmio32Read(n, kCsrIntCoalescing);

    n.chip_id = hw_rev;
    n.driver_online = true;
    // Wireless link is UP only after association — which needs FW.
    n.link_up = false;
    n.wireless_fw_state = NicInfo::WirelessFwState::Missing;

    // Probe the firmware loader for vendor microcode. v0 backend
    // always misses; the driver records `firmware_pending=true`
    // and the watch task continues. When a real backend lands
    // (VFS-mounted /lib/firmware), this branch starts seeing
    // hits and the next slice's loader can chain into PHY/RF
    // init.
    duetos::core::FwLoadRequest req{};
    req.vendor = "intel-iwlwifi";
    // Firmware basename is silicon-family-dependent. Pick a
    // canonical name per HW_REV Type nibble; the real iwlwifi
    // table is much larger but this is enough to exercise the
    // loader path.
    const u8 type = u8((hw_rev >> 4) & 0x0F);
    switch (type)
    {
    case 0x6:
        req.basename = "iwlwifi-cc-a0-46.ucode"; // AX200/AX201
        break;
    case 0x7:
        req.basename = "iwlwifi-ty-a0-gf-a0-46.ucode"; // AX210
        break;
    case 0x4:
        req.basename = "iwlwifi-8000C-46.ucode"; // 8260
        break;
    default:
        req.basename = "iwlwifi-9000-pu-b0-jf-b0-46.ucode";
        break;
    }
    auto fw = duetos::core::FwLoad(req);
    if (fw.has_value())
    {
        // Real fw — cannot happen in v0; reserved for the loader
        // slice. Drop the blob (we don't yet know how to use it).
        duetos::core::FwRelease(fw.value());
        n.firmware_pending = false;
        n.wireless_fw_state = NicInfo::WirelessFwState::Ready;
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

    g_stats.hw_rev = hw_rev;
    ++g_stats.adapters_bound;

    arch::SerialWrite("[iwlwifi] online pci=");
    arch::SerialWriteHex(n.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(n.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(n.function);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(n.device_id);
    arch::SerialWrite(" hw_rev=");
    arch::SerialWriteHex(hw_rev);
    arch::SerialWrite(" gp_cntrl=");
    arch::SerialWriteHex(gp_cntrl);
    arch::SerialWrite(" int_coal=");
    arch::SerialWriteHex(int_coal);
    arch::SerialWrite(" silicon=");
    arch::SerialWrite(ChipIdShortString(hw_rev));
    arch::SerialWrite(" status=fw-pending\n");

    duetos::sched::SchedCreate(IwlwifiWatchEntry, &n, "iwlwifi-watch");
    return true;
}

IwlwifiStats IwlwifiStatsRead()
{
    return g_stats;
}

} // namespace duetos::drivers::net
