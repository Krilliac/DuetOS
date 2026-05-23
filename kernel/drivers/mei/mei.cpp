#include "drivers/mei/mei.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "security/me_psp_guard.h"

namespace duetos::drivers::mei
{

namespace
{

constinit MeiDeviceInfo g_devices[kMaxMeiDevices] = {};
constinit u32 g_count = 0;
constinit bool g_init_done = false;

// Intel MEI device-ID classification. The published MEI device IDs
// fall into a small number of well-known families:
//
//   0x2974 / 0x2984 / 0x2994 / 0x29A4 / 0x29B4 / 0x29C4 / 0x29D4 /
//   0x29E4 / 0x2A04 / 0x2A14 / 0x2A24 / 0x2A34 / 0x9C3A / 0x9CBA /
//   0x9D3A / 0x9D3B / 0xA13A / 0xA13B / 0xA1BA / 0xA2BA / 0xA303 /
//   0xA360 / 0xA3BA / 0xA3DA / 0x4DE0 / 0x7AE8 / 0x51E0 / 0x7E40 /
//   0x7DE0 / 0x7E70 / 0xA70A / 0xAD9A    — chipset CSME
//
//   0x4F87 / 0x4F88 / 0x4FB1               — DG2 / Arc GSC
//   0x5DBC / 0x5DBE                         — Battlemage GSC
//
//   0x0F18 / 0x2298 / 0x22D8 / 0x22DE      — Atom Trusted Execution Engine
//
//   0x2360 / 0x2363 / 0x2380 / 0x2388       — Server platform services (SPS)
//
// We don't enumerate every chipset variant — there are ~80 — but we
// pin the discrete-GPU GSC IDs because that's the family the GSC
// firmware-image parser pairs with. Anything that doesn't match
// the GSC / TXE / SPS bands is reported as CSME by default, which
// is the correct guess for any consumer Intel chipset.
MeiRole ClassifyByDeviceId(u16 device_id)
{
    switch (device_id)
    {
    case 0x4F87:
    case 0x4F88:
    case 0x4FB1:
    case 0x5DBC:
    case 0x5DBE:
        return MeiRole::Gsc;
    case 0x0F18:
    case 0x2298:
    case 0x22D8:
    case 0x22DE:
        return MeiRole::Txe;
    case 0x2360:
    case 0x2363:
    case 0x2380:
    case 0x2388:
        return MeiRole::Sps;
    default:
        return MeiRole::Csme;
    }
}

void Eq(u64 actual, u64 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[mei] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("drivers/mei", "MEI self-test mismatch", actual);
}

} // namespace

const char* MeiRoleTag(MeiRole r)
{
    switch (r)
    {
    case MeiRole::Unknown:
        return "?";
    case MeiRole::Csme:
        return "csme";
    case MeiRole::Gsc:
        return "gsc";
    case MeiRole::Txe:
        return "txe";
    case MeiRole::Sps:
        return "sps";
    }
    return "?";
}

MeiRole MeiClassifyDeviceId(u16 device_id)
{
    return ClassifyByDeviceId(device_id);
}

void MeiInit()
{
    if (g_init_done)
        return;
    g_init_done = true;

    const u64 n = duetos::drivers::pci::PciDeviceCount();
    for (u64 i = 0; i < n && g_count < kMaxMeiDevices; ++i)
    {
        const auto& d = duetos::drivers::pci::PciDevice(i);
        if (d.vendor_id != kVendorIntel)
            continue;
        if (d.class_code != kPciClassCommunications)
            continue;
        if (d.subclass != kPciSubclassMeiOther)
            continue;

        MeiDeviceInfo info{};
        info.live = true;
        info.vendor_id = d.vendor_id;
        info.device_id = d.device_id;
        info.bus = d.addr.bus;
        info.device = d.addr.device;
        info.function = d.addr.function;
        info.role = ClassifyByDeviceId(d.device_id);
        info.role_tag = MeiRoleTag(info.role);

        const auto bar0 = duetos::drivers::pci::PciReadBar(d.addr, 0);
        if (bar0.size != 0 && !bar0.is_io)
        {
            // The MEI register file is small — under 4 KiB on every
            // chipset. Map a single page; size_probe just confirms
            // the BAR exists.
            constexpr u64 kMmioCap = 4096;
            const u64 map_bytes = (bar0.size > kMmioCap) ? kMmioCap : bar0.size;
            info.mmio_phys = bar0.address;
            info.mmio_size = bar0.size;
            info.mmio_virt = duetos::mm::MapMmio(bar0.address, map_bytes);
        }

        arch::SerialWrite("[mei] device=");
        arch::SerialWriteHex(info.device_id);
        arch::SerialWrite(" role=");
        arch::SerialWrite(info.role_tag);
        arch::SerialWrite(" bus=");
        arch::SerialWriteHex(info.bus);
        arch::SerialWrite(" mmio_phys=");
        arch::SerialWriteHex(info.mmio_phys);
        arch::SerialWrite(" mmio_size=");
        arch::SerialWriteHex(info.mmio_size);
        arch::SerialWrite("\n");

        // Hand the BAR + BDF to the central ME/PSP fence. From
        // this point on, any further `MapMmio` of this physical
        // range — from any driver, subsystem, or diagnostic
        // path — is refused. The probe-time map above succeeded
        // because the guard hadn't been told yet; that single
        // mapping is the only kernel-side window into this
        // device's register file.
        duetos::security::FencedDevice fenced{};
        switch (info.role)
        {
        case MeiRole::Gsc:
            fenced.kind = duetos::security::CoProcessor::IntelMeGsc;
            break;
        case MeiRole::Txe:
            fenced.kind = duetos::security::CoProcessor::IntelMeTxe;
            break;
        case MeiRole::Sps:
            fenced.kind = duetos::security::CoProcessor::IntelMeSps;
            break;
        case MeiRole::Csme:
        case MeiRole::Unknown:
        default:
            fenced.kind = duetos::security::CoProcessor::IntelMeCsme;
            break;
        }
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
        KLOG_INFO("drivers/mei", "no Intel MEI/HECI device present");
    }
    else
    {
        KLOG_INFO("drivers/mei", "online — devices probed");
    }
}

u32 MeiDeviceCount()
{
    return g_count;
}

const MeiDeviceInfo& MeiDevice(u32 index)
{
    KASSERT(index < g_count, "drivers/mei", "MeiDevice index out of range");
    return g_devices[index];
}

void MeiSelfTest()
{
    // Classification table coverage. These are public Intel device
    // IDs — choosing one each from the GSC, TXE, SPS, and a
    // representative consumer CSME family.
    Eq(static_cast<u64>(MeiClassifyDeviceId(0x4F87)), static_cast<u64>(MeiRole::Gsc), "DG2 GSC");
    Eq(static_cast<u64>(MeiClassifyDeviceId(0x5DBC)), static_cast<u64>(MeiRole::Gsc), "Battlemage GSC");
    Eq(static_cast<u64>(MeiClassifyDeviceId(0x22D8)), static_cast<u64>(MeiRole::Txe), "Atom TXE");
    Eq(static_cast<u64>(MeiClassifyDeviceId(0x2360)), static_cast<u64>(MeiRole::Sps), "Xeon SPS");
    Eq(static_cast<u64>(MeiClassifyDeviceId(0xA13A)), static_cast<u64>(MeiRole::Csme), "consumer CSME");
    Eq(static_cast<u64>(MeiClassifyDeviceId(0xFFFF)), static_cast<u64>(MeiRole::Csme), "default = CSME");

    // Tag round-trip on the entries operators see.
    Eq(u64(MeiRoleTag(MeiRole::Gsc)[0]), u64('g'), "tag gsc[0]");
    Eq(u64(MeiRoleTag(MeiRole::Csme)[0]), u64('c'), "tag csme[0]");
    Eq(u64(MeiRoleTag(MeiRole::Txe)[0]), u64('t'), "tag txe[0]");
    Eq(u64(MeiRoleTag(MeiRole::Sps)[0]), u64('s'), "tag sps[0]");

    arch::SerialWrite("[mei] selftest pass\n");
}

} // namespace duetos::drivers::mei
