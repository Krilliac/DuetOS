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

// QEMU Bochs VGA registers at BAR 0. Memory-mapped on modern
// QEMU (the legacy I/O ports 0x01CE/0x01CF still work too).
// VBE index register at offset 0x500 (little-endian u16).
u16 Mmio16(const GpuInfo& g, u64 offset)
{
    if (g.mmio_virt == nullptr)
        return 0;
    auto* p = reinterpret_cast<volatile u16*>(static_cast<u8*>(g.mmio_virt) + offset);
    return *p;
}

void DecodeBochsVbe(const GpuInfo& g)
{
    if (g.mmio_virt == nullptr)
        return;
    // VBE_DISPI_INDEX_ID: reading it with the VBE aperture
    // enabled returns 0xB0C0 | version; on QEMU's stdvga with
    // the default framebuffer, bar0 + 0x500 is the VBE register
    // bank (qemu-project.org, hw/display/bochs_display.c).
    constexpr u64 kVbeIndexIdReg = 0x500;
    const u16 id = Mmio16(g, kVbeIndexIdReg);
    arch::SerialWrite("[bochs] vbe_id_reg=");
    arch::SerialWriteHex(id);
    if ((id & 0xFF00) == 0xB000)
    {
        arch::SerialWrite("  (VBE 0xB0Cx family; version nibble=");
        arch::SerialWriteHex(id & 0xFF);
        arch::SerialWrite(")\n");
    }
    else
    {
        arch::SerialWrite("  (register aperture not decoded this way on this BAR layout)\n");
    }
}

// Run the vendor probe for a device. No-op for unknown vendors.
// Each probe is a pure classifier today — it writes `family` into
// the GpuInfo and emits a `[gpu-probe]` log line with the family
// tag. A future vendor-driver slice replaces the body of each
// probe with real engine init.
void RunVendorProbe(GpuInfo& g)
{
    const char* family = nullptr;
    switch (g.vendor_id)
    {
    case kVendorIntel:
        family = IntelGenTag(g.device_id);
        break;
    case kVendorAmd:
        family = AmdGenTag(g.device_id);
        break;
    case kVendorNvidia:
        family = NvidiaGenTag(g.device_id);
        break;
    case kVendorQemuBochs:
        family = "qemu-bochs-vga";
        break;
    case kVendorRedHatVirt:
        family = "virtio-gpu";
        break;
    case kVendorVmware:
        family = "vmware-svga-ii";
        break;
    default:
        return; // no probe for unknown vendors
    }
    g.family = family;
    arch::SerialWrite("[gpu-probe] vid=");
    arch::SerialWriteHex(g.vendor_id);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(g.device_id);
    arch::SerialWrite(" family=");
    arch::SerialWrite(family);
    arch::SerialWrite("  (stub OK — no engine init yet)\n");
    if (g.vendor_id == kVendorQemuBochs)
        DecodeBochsVbe(g);
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

        RunVendorProbe(g);
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

// -------------------------------------------------------------------
// Vendor device-id classifiers. Each walks a compact table and
// returns a family tag. Tables are intentionally coarse — they
// identify the GPU generation + codename, not the exact SKU.
// A full driver slice would refine this via revision / subsystem
// IDs and per-SKU feature bits.
//
// Ranges rather than explicit IDs because modern GPU families
// ship with dozens of device IDs (retail, mobile, workstation,
// server). The ranges come from the vendor Linux kernel drivers
// (i915, amdgpu, nouveau/nvidia-open) as of 2025.
// -------------------------------------------------------------------

const char* IntelGenTag(u16 device_id)
{
    // Major Intel iGPU generations on PCI 0x8086. Integer ranges
    // picked from i915 pci-id tables; not exhaustive — unknown IDs
    // land on "intel-unknown".
    if ((device_id >= 0x1900 && device_id <= 0x193B) || // Skylake
        (device_id >= 0x5900 && device_id <= 0x593B))   // Kaby Lake
        return "gen9-skylake/kabylake";
    if (device_id >= 0x3E90 && device_id <= 0x3EA7)
        return "gen9.5-coffeelake";
    if ((device_id >= 0x8A50 && device_id <= 0x8A7C) || // Ice Lake
        (device_id >= 0x9A40 && device_id <= 0x9A7F))   // Tiger Lake
        return "gen11-12-icelake/tigerlake";
    if (device_id >= 0x4680 && device_id <= 0x46AB)
        return "gen13-alderlake";
    if (device_id >= 0x5690 && device_id <= 0x56C1)
        return "gen12.7-dg2-arc";
    return "intel-unknown";
}

const char* AmdGenTag(u16 device_id)
{
    // AMDGPU generations on PCI 0x1002. GFX9 = Vega, GFX10 = RDNA1/2,
    // GFX11 = RDNA3. Pre-GFX9 (GCN 1..4) are out of scope for the
    // tier-1 roadmap; they report as "amd-pre-gfx9".
    if (device_id >= 0x15DD && device_id <= 0x15DE)
        return "gfx9-raven";
    if (device_id >= 0x6860 && device_id <= 0x687F)
        return "gfx9-vega";
    if (device_id >= 0x7310 && device_id <= 0x7347)
        return "gfx10-navi1x";
    if (device_id >= 0x73A0 && device_id <= 0x73FF)
        return "gfx10.3-navi2x";
    if (device_id >= 0x7440 && device_id <= 0x747F)
        return "gfx11-navi3x";
    return "amd-pre-gfx9-or-unknown";
}

const char* NvidiaGenTag(u16 device_id)
{
    // NVIDIA generations on PCI 0x10DE. Classification is
    // necessarily coarse — NVIDIA recycles device-id ranges across
    // product lines. The modern-open-source window we target is
    // Turing+ (TU10x, 0x1E..0x20 range).
    if (device_id >= 0x1E00 && device_id <= 0x1F99)
        return "turing-rtx-2000";
    if (device_id >= 0x2180 && device_id <= 0x22BB)
        return "ampere-rtx-3000";
    if (device_id >= 0x2484 && device_id <= 0x25AF)
        return "ampere-ga10x";
    if (device_id >= 0x2680 && device_id <= 0x28E1)
        return "ada-rtx-4000";
    return "nvidia-pre-turing-or-unknown";
}

} // namespace customos::drivers::gpu
