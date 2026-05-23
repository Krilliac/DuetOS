#include "drivers/npu/npu.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "diag/fix_journal.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "mm/paging.h"

namespace duetos::drivers::npu
{

namespace
{

constinit NpuDeviceInfo g_devices[kMaxNpuDevices] = {};
constinit u32 g_count = 0;
constinit bool g_init_done = false;

// Known NPU/AI-accelerator endpoints. Public IDs from the in-tree
// Linux drivers (intel ivpu, amdxdna):
//
//   Intel  0x7D1D  NPU 3720  Meteor Lake
//   Intel  0xAD1D  NPU 3720  Arrow Lake
//   Intel  0x643E  NPU 4000  Lunar Lake
//   AMD    0x1502  AIE-ML    Phoenix / Hawk Point (XDNA1)
//   AMD    0x17F0  AIE-ML v2 Strix Point (XDNA2)
//
// GAP: per-SKU device-ID list — new SoCs (Panther Lake, future
// Ryzen AI) ship IDs not in this table. AMD parts still match via
// the standards class gate; an unrecognised Intel part will be
// missed until its ID is added here. Revisit when a target board
// with a newer NPU is in the test matrix. The classifier returning
// Unknown is the deliberate honest fallback (no mis-labelled gen).
NpuKind ClassifyByVendorDevice(u16 vendor_id, u16 device_id)
{
    if (vendor_id == kVendorIntel)
    {
        switch (device_id)
        {
        case 0x7D1D:
        case 0xAD1D:
            return NpuKind::IntelNpu37;
        case 0x643E:
            return NpuKind::IntelNpu40;
        default:
            // Unrecognised Intel NPU SKU — the per-SKU table above
            // needs updating. Record the (vendor, device) so a
            // boot on new silicon surfaces in the journal.
            FIX_NOTE_GAP("drivers/npu/npu.cpp:ClassifyByVendorDevice",
                         "unknown Intel NPU device-id; extend per-SKU table");
            KLOG_ONCE_WARN("drivers/npu", "fix-journal hot: unknown Intel NPU device-id; extend per");
            return NpuKind::Unknown;
        }
    }
    if (vendor_id == kVendorAmd)
    {
        switch (device_id)
        {
        case 0x1502:
            return NpuKind::AmdXdna1;
        case 0x17F0:
            return NpuKind::AmdXdna2;
        default:
            // Unrecognised AMD XDNA SKU — same shape as Intel arm.
            FIX_NOTE_GAP("drivers/npu/npu.cpp:ClassifyByVendorDevice",
                         "unknown AMD XDNA device-id; extend per-SKU table");
            return NpuKind::Unknown;
        }
    }
    return NpuKind::Unknown;
}

void Eq(u64 actual, u64 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[npu] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("drivers/npu", "NPU self-test mismatch", actual);
}

} // namespace

const char* NpuKindTag(NpuKind k)
{
    switch (k)
    {
    case NpuKind::Unknown:
        return "?";
    case NpuKind::IntelNpu37:
        return "intel-npu37";
    case NpuKind::IntelNpu40:
        return "intel-npu40";
    case NpuKind::AmdXdna1:
        return "amd-xdna1";
    case NpuKind::AmdXdna2:
        return "amd-xdna2";
    }
    return "?";
}

NpuKind NpuClassifyDevice(u16 vendor_id, u16 device_id)
{
    return ClassifyByVendorDevice(vendor_id, device_id);
}

bool NpuIsIntelNpuDeviceId(u16 device_id)
{
    switch (device_id)
    {
    case 0x7D1D:
    case 0xAD1D:
    case 0x643E:
        return true;
    default:
        return false;
    }
}

void NpuInit()
{
    if (g_init_done)
        return;
    g_init_done = true;

    const u64 n = duetos::drivers::pci::PciDeviceCount();
    for (u64 i = 0; i < n && g_count < kMaxNpuDevices; ++i)
    {
        const auto& d = duetos::drivers::pci::PciDevice(i);

        // Property-first gate: the standards-defined Processing
        // Accelerators class catches AMD XDNA and any spec-
        // compliant NPU regardless of vendor. Intel's NPU mis-
        // reports as a Multimedia controller, so a documented
        // device-ID secondary gate covers it. Keying the primary
        // path on the class (not a per-vendor whitelist) avoids
        // the whitelist-incompleteness failure class.
        const bool is_accel_class = (d.class_code == kPciClassProcessingAccel);
        const bool is_intel_npu = (d.vendor_id == kVendorIntel && NpuIsIntelNpuDeviceId(d.device_id));
        if (!is_accel_class && !is_intel_npu)
            continue;

        NpuDeviceInfo info{};
        info.live = true;
        info.vendor_id = d.vendor_id;
        info.device_id = d.device_id;
        info.bus = d.addr.bus;
        info.device = d.addr.device;
        info.function = d.addr.function;
        info.kind = ClassifyByVendorDevice(d.vendor_id, d.device_id);
        info.kind_tag = NpuKindTag(info.kind);

        const auto bar0 = duetos::drivers::pci::PciReadBar(d.addr, 0);
        if (bar0.size != 0 && !bar0.is_io)
        {
            // The NPU's BAR0 is large (MiBs of register + doorbell
            // aperture). v0 only needs the boot register file at
            // the base; cap the mapping so the probe doesn't eat
            // the MMIO arena. GAP: full aperture (command ring,
            // doorbell page) is mapped by the firmware/submit
            // slice, not here.
            constexpr u64 kMmioCap = 0x10000; // 64 KiB
            const u64 map_bytes = (bar0.size > kMmioCap) ? kMmioCap : bar0.size;
            info.mmio_phys = bar0.address;
            info.mmio_size = bar0.size;
            info.mmio_virt = duetos::mm::MapMmio(bar0.address, map_bytes);
        }

        arch::SerialWrite("[npu] device=");
        arch::SerialWriteHex(info.device_id);
        arch::SerialWrite(" vendor=");
        arch::SerialWriteHex(info.vendor_id);
        arch::SerialWrite(" kind=");
        arch::SerialWrite(info.kind_tag);
        arch::SerialWrite(" bus=");
        arch::SerialWriteHex(info.bus);
        arch::SerialWrite(" mmio_phys=");
        arch::SerialWriteHex(info.mmio_phys);
        arch::SerialWrite(" mmio_size=");
        arch::SerialWriteHex(info.mmio_size);
        arch::SerialWrite("\n");

        g_devices[g_count++] = info;
    }

    if (g_count == 0)
    {
        KLOG_INFO("drivers/npu", "no NPU / AI-accelerator device present");
    }
    else
    {
        KLOG_INFO("drivers/npu", "online — devices probed");
    }
}

u32 NpuDeviceCount()
{
    return g_count;
}

const NpuDeviceInfo& NpuDevice(u32 index)
{
    KASSERT(index < g_count, "drivers/npu", "NpuDevice index out of range");
    return g_devices[index];
}

void NpuSelfTest()
{
    // Classifier coverage — one per generation, plus the honest
    // Unknown fallbacks (wrong-vendor and unrecognised-ID).
    Eq(static_cast<u64>(NpuClassifyDevice(kVendorIntel, 0x7D1D)), static_cast<u64>(NpuKind::IntelNpu37), "MTL NPU37");
    Eq(static_cast<u64>(NpuClassifyDevice(kVendorIntel, 0xAD1D)), static_cast<u64>(NpuKind::IntelNpu37), "ARL NPU37");
    Eq(static_cast<u64>(NpuClassifyDevice(kVendorIntel, 0x643E)), static_cast<u64>(NpuKind::IntelNpu40), "LNL NPU40");
    Eq(static_cast<u64>(NpuClassifyDevice(kVendorAmd, 0x1502)), static_cast<u64>(NpuKind::AmdXdna1), "Phoenix XDNA1");
    Eq(static_cast<u64>(NpuClassifyDevice(kVendorAmd, 0x17F0)), static_cast<u64>(NpuKind::AmdXdna2), "Strix XDNA2");
    Eq(static_cast<u64>(NpuClassifyDevice(kVendorIntel, 0xFFFF)), static_cast<u64>(NpuKind::Unknown),
       "unknown Intel ID");
    Eq(static_cast<u64>(NpuClassifyDevice(0x1234, 0x7D1D)), static_cast<u64>(NpuKind::Unknown), "wrong vendor");

    // Intel device-ID secondary gate — true for the NPU family,
    // false for an arbitrary non-NPU Intel ID.
    Eq(u64(NpuIsIntelNpuDeviceId(0x7D1D)), 1u, "intel gate MTL");
    Eq(u64(NpuIsIntelNpuDeviceId(0x643E)), 1u, "intel gate LNL");
    Eq(u64(NpuIsIntelNpuDeviceId(0x0000)), 0u, "intel gate negative");

    // Tag round-trip on the entries operators see.
    Eq(u64(NpuKindTag(NpuKind::IntelNpu37)[0]), u64('i'), "tag intel[0]");
    Eq(u64(NpuKindTag(NpuKind::AmdXdna2)[0]), u64('a'), "tag amd[0]");
    Eq(u64(NpuKindTag(NpuKind::Unknown)[0]), u64('?'), "tag unknown[0]");

    arch::SerialWrite("[npu] selftest pass\n");
}

} // namespace duetos::drivers::npu
