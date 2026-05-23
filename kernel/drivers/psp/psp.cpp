#include "drivers/psp/psp.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "security/me_psp_guard.h"

namespace duetos::drivers::psp
{

namespace
{

constinit PspDeviceInfo g_devices[kMaxPspDevices] = {};
constinit u32 g_count = 0;
constinit bool g_init_done = false;

// AMD PSP / CCP and SMU mailbox device-ID classification.
// Sourced from the AMD-published driver tables for ccp / sev /
// smu across Zen 1 → Zen 4. We deliberately list each generation
// explicitly rather than matching a class code, because the PSP's
// PCI class (0x10 encryption controller) collides with unrelated
// crypto accelerators on third-party cards.
struct Entry
{
    u16 device_id;
    PspRole role;
};

constexpr Entry kKnownDevices[] = {
    // ---- PSP / CCP (Cryptographic Co-Processor + PSP mailbox) ----
    {0x1456, PspRole::Ccp}, // Zen 1 / Zen+ Ryzen (Naples / Pinnacle)
    {0x1468, PspRole::Ccp}, // Zen 2 APU (Renoir / Lucienne)
    {0x1486, PspRole::Ccp}, // Zen 2 Ryzen (Matisse / Castle Peak)
    {0x14CA, PspRole::Ccp}, // Zen 4 Ryzen / EPYC
    {0x15DF, PspRole::Ccp}, // Zen / Zen+ APU (Raven Ridge)
    {0x1649, PspRole::Ccp}, // Zen 3 (Cezanne)
    // ---- SMU mailbox (where exposed) ----
    {0x1537, PspRole::Smu}, // EPYC SMU
};

PspRole ClassifyDeviceId(u16 device_id)
{
    for (const Entry& e : kKnownDevices)
    {
        if (e.device_id == device_id)
            return e.role;
    }
    return PspRole::Unknown;
}

void Eq(u64 actual, u64 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[psp] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("drivers/psp", "PSP self-test mismatch", actual);
}

duetos::security::CoProcessor RoleToCoProc(PspRole r)
{
    switch (r)
    {
    case PspRole::Smu:
        return duetos::security::CoProcessor::AmdSmu;
    case PspRole::Ccp:
    case PspRole::Unknown:
    default:
        return duetos::security::CoProcessor::AmdPspCcp;
    }
}

} // namespace

const char* PspRoleTag(PspRole r)
{
    switch (r)
    {
    case PspRole::Unknown:
        return "?";
    case PspRole::Ccp:
        return "psp-ccp";
    case PspRole::Smu:
        return "amd-smu";
    }
    return "?";
}

PspRole PspClassifyDeviceId(u16 device_id)
{
    return ClassifyDeviceId(device_id);
}

void PspInit()
{
    if (g_init_done)
        return;
    g_init_done = true;

    const u64 n = duetos::drivers::pci::PciDeviceCount();
    for (u64 i = 0; i < n && g_count < kMaxPspDevices; ++i)
    {
        const auto& d = duetos::drivers::pci::PciDevice(i);
        if (d.vendor_id != kVendorAmd)
            continue;
        const PspRole role = ClassifyDeviceId(d.device_id);
        if (role == PspRole::Unknown)
            continue;

        PspDeviceInfo info{};
        info.live = true;
        info.vendor_id = d.vendor_id;
        info.device_id = d.device_id;
        info.bus = d.addr.bus;
        info.device = d.addr.device;
        info.function = d.addr.function;
        info.role = role;
        info.role_tag = PspRoleTag(role);

        const auto bar0 = duetos::drivers::pci::PciReadBar(d.addr, 0);
        if (bar0.size != 0 && !bar0.is_io)
        {
            // PSP / SMU register files are small. Map a single
            // page so the existence of the BAR is observed; the
            // guard will refuse every subsequent mapping attempt.
            constexpr u64 kMmioCap = 4096;
            const u64 map_bytes = (bar0.size > kMmioCap) ? kMmioCap : bar0.size;
            info.mmio_phys = bar0.address;
            info.mmio_size = bar0.size;
            info.mmio_virt = duetos::mm::MapMmio(bar0.address, map_bytes);
        }

        // Clear Bus Master Enable on the device's PCI Command
        // register BEFORE registering with the guard — once
        // registered, config writes are denied. This closes the
        // standard PCIe DMA initiator path on this BDF; AMD's
        // private PSP-mailbox DMA paths still go through the
        // chipset until IOMMU lands and remaps them.
        constexpr u8 kCfgCmdSts = 0x04;
        constexpr u32 kCmdBusMasterEnable = 1u << 2;
        const u32 cmdsts = duetos::drivers::pci::PciConfigRead32(d.addr, kCfgCmdSts);
        const u32 cmd_only = cmdsts & 0xFFFFu;
        const u32 cmd_no_bme = cmd_only & ~kCmdBusMasterEnable;
        bool bme_cleared = true;
        if (cmd_only != cmd_no_bme)
        {
            duetos::drivers::pci::PciConfigWrite32(d.addr, kCfgCmdSts, cmd_no_bme);
            const u32 readback = duetos::drivers::pci::PciConfigRead32(d.addr, kCfgCmdSts);
            bme_cleared = ((readback & kCmdBusMasterEnable) == 0);
        }

        arch::SerialWrite("[psp] device=");
        arch::SerialWriteHex(info.device_id);
        arch::SerialWrite(" role=");
        arch::SerialWrite(info.role_tag);
        arch::SerialWrite(" bus=");
        arch::SerialWriteHex(info.bus);
        arch::SerialWrite(" mmio_phys=");
        arch::SerialWriteHex(info.mmio_phys);
        arch::SerialWrite(" mmio_size=");
        arch::SerialWriteHex(info.mmio_size);
        arch::SerialWrite(" bme_cleared=");
        arch::SerialWriteHex(bme_cleared ? 1u : 0u);
        arch::SerialWrite("\n");

        KLOG_WARN("drivers/psp",
                  "AMD PSP / SMU host interface detected — fenced (DMA-capable coprocessor with vendor firmware)");

        // Register with the central guard. The fence becomes
        // active immediately — any subsequent MapMmio that
        // overlaps this BAR returns nullptr.
        duetos::security::FencedDevice fenced{};
        fenced.kind = RoleToCoProc(role);
        fenced.vendor_id = info.vendor_id;
        fenced.device_id = info.device_id;
        fenced.bus = info.bus;
        fenced.device = info.device;
        fenced.function = info.function;
        fenced.mmio_phys = info.mmio_phys;
        fenced.mmio_size = info.mmio_size;
        duetos::security::MePspGuardRegister(fenced);

        g_devices[g_count++] = info;
    }

    if (g_count == 0)
    {
        KLOG_INFO("drivers/psp", "no AMD PSP / SMU device present");
    }
    else
    {
        KLOG_INFO("drivers/psp", "online — devices probed and fenced");
    }
}

u32 PspDeviceCount()
{
    return g_count;
}

const PspDeviceInfo& PspDevice(u32 index)
{
    KASSERT(index < g_count, "drivers/psp", "PspDevice index out of range");
    return g_devices[index];
}

void PspSelfTest()
{
    // Classification table coverage. One device-ID per generation.
    Eq(static_cast<u64>(PspClassifyDeviceId(0x1456)), static_cast<u64>(PspRole::Ccp), "Zen 1 Ryzen");
    Eq(static_cast<u64>(PspClassifyDeviceId(0x1486)), static_cast<u64>(PspRole::Ccp), "Zen 2 Ryzen");
    Eq(static_cast<u64>(PspClassifyDeviceId(0x1649)), static_cast<u64>(PspRole::Ccp), "Zen 3 Cezanne");
    Eq(static_cast<u64>(PspClassifyDeviceId(0x14CA)), static_cast<u64>(PspRole::Ccp), "Zen 4 Ryzen");
    Eq(static_cast<u64>(PspClassifyDeviceId(0x1537)), static_cast<u64>(PspRole::Smu), "EPYC SMU");
    Eq(static_cast<u64>(PspClassifyDeviceId(0xFFFF)), static_cast<u64>(PspRole::Unknown), "unknown rejected");
    Eq(static_cast<u64>(PspClassifyDeviceId(0x0000)), static_cast<u64>(PspRole::Unknown), "vendor-zero rejected");

    // Tag round-trip.
    Eq(u64(PspRoleTag(PspRole::Ccp)[0]), u64('p'), "tag psp-ccp[0]");
    Eq(u64(PspRoleTag(PspRole::Smu)[0]), u64('a'), "tag amd-smu[0]");

    arch::SerialWrite("[psp] selftest pass\n");
}

} // namespace duetos::drivers::psp
