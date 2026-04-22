#include "gpu.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/paging.h"
#include "../pci/pci.h"

namespace customos::drivers::gpu
{

namespace
{

// Cache of discovered GPUs. A modest cap; anything beyond that is
// extremely rare in hardware we'd boot and would need the PCI layer
// to grow too.
GpuInfo g_gpus[kMaxGpus] = {};
u64 g_gpu_count = 0;

struct VendorEntry
{
    u16 vendor_id;
    const char* short_name;
    const char* tier;
};

// Tier mapping — matches docs/knowledge/hardware-target-matrix.md.
// Unknown vendors fall through to the default-case "unknown" tier
// and are still recorded + logged so the gap is visible.
constexpr VendorEntry kVendors[] = {
    {kVendorIntel, "Intel", "tier1-intel-igpu"},   {kVendorAmd, "AMD", "tier1-amd-radeon"},
    {kVendorNvidia, "NVIDIA", "tier1-nvidia"},     {kVendorVmware, "VMware-SVGA", "tier3-vm"},
    {kVendorQemuBochs, "QEMU-Bochs", "tier3-dev"}, {kVendorRedHatVirt, "virtio-gpu", "tier3-dev"},
};

const VendorEntry* FindVendor(u16 vid)
{
    for (const VendorEntry& v : kVendors)
    {
        if (v.vendor_id == vid)
            return &v;
    }
    return nullptr;
}

// Pretty subclass name. Purely for logs.
const char* SubclassName(u8 subclass)
{
    switch (subclass)
    {
    case 0x00:
        return "VGA";
    case 0x01:
        return "XGA";
    case 0x02:
        return "3D";
    case 0x80:
        return "other";
    default:
        return "?";
    }
}

void LogGpu(const GpuInfo& g)
{
    arch::SerialWrite("  gpu ");
    arch::SerialWriteHex(g.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(g.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(g.function);
    arch::SerialWrite("  vid=");
    arch::SerialWriteHex(g.vendor_id);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(g.device_id);
    arch::SerialWrite(" vendor=\"");
    arch::SerialWrite(g.vendor);
    arch::SerialWrite("\" tier=");
    arch::SerialWrite(g.tier);
    arch::SerialWrite(" sub=");
    arch::SerialWrite(SubclassName(g.subclass));
    if (g.mmio_size != 0)
    {
        arch::SerialWrite(" bar0=");
        arch::SerialWriteHex(g.mmio_phys);
        arch::SerialWrite("/");
        arch::SerialWriteHex(g.mmio_size);
        if (g.mmio_virt != nullptr)
        {
            arch::SerialWrite(" -> ");
            arch::SerialWriteHex(reinterpret_cast<u64>(g.mmio_virt));
        }
        else
        {
            arch::SerialWrite(" (map failed)");
        }
    }
    else
    {
        arch::SerialWrite(" bar0=<none>");
    }
    arch::SerialWrite("\n");
}

} // namespace

void GpuInit()
{
    KLOG_TRACE_SCOPE("drivers/gpu", "GpuInit");
    static constinit bool s_done = false;
    KASSERT(!s_done, "drivers/gpu", "GpuInit called twice");
    s_done = true;

    const u64 n = pci::PciDeviceCount();
    for (u64 i = 0; i < n && g_gpu_count < kMaxGpus; ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.class_code != kPciClassDisplay)
            continue;

        GpuInfo g = {};
        g.vendor_id = d.vendor_id;
        g.device_id = d.device_id;
        g.bus = d.addr.bus;
        g.device = d.addr.device;
        g.function = d.addr.function;
        g.subclass = d.subclass;

        const VendorEntry* v = FindVendor(d.vendor_id);
        g.vendor = (v != nullptr) ? v->short_name : "unknown";
        g.tier = (v != nullptr) ? v->tier : "unknown";

        // BAR 0 is the primary MMIO aperture on every display
        // controller we target today. Intel/AMD use BAR 0 for the
        // register file; QEMU Bochs uses BAR 0 for its framebuffer.
        // A future vendor-specific driver slice can probe more BARs
        // (Intel's GMADR at BAR 2, AMD's doorbell aperture at BAR 5).
        const pci::Bar bar0 = pci::PciReadBar(d.addr, 0);
        if (bar0.size != 0 && !bar0.is_io)
        {
            g.mmio_phys = bar0.address;
            g.mmio_size = bar0.size;
            // Cap the map at 16 MiB for v0. Modern Intel/AMD GPUs
            // advertise multi-hundred-MiB BARs; claiming the whole
            // aperture up-front burns MMIO arena for no v0 value.
            // The register file itself sits in the first couple of
            // MiB; 16 MiB covers every known vendor + QEMU Bochs
            // full framebuffer.
            constexpr u64 kMmioCap = 16ULL * 1024 * 1024;
            const u64 map_bytes = (bar0.size > kMmioCap) ? kMmioCap : bar0.size;
            g.mmio_virt = mm::MapMmio(bar0.address, map_bytes);
        }

        g_gpus[g_gpu_count++] = g;
    }

    core::LogWithValue(core::LogLevel::Info, "drivers/gpu", "discovered GPUs", g_gpu_count);
    for (u64 i = 0; i < g_gpu_count; ++i)
    {
        LogGpu(g_gpus[i]);
    }
    if (g_gpu_count == 0)
    {
        core::Log(core::LogLevel::Warn, "drivers/gpu",
                  "no PCI display controllers found (headless or unsupported board)");
    }
}

u64 GpuCount()
{
    return g_gpu_count;
}

const GpuInfo& Gpu(u64 index)
{
    KASSERT_WITH_VALUE(index < g_gpu_count, "drivers/gpu", "Gpu index out of range", index);
    return g_gpus[index];
}

} // namespace customos::drivers::gpu
