/*
 * DuetOS — GPU discovery + driver dispatch: implementation.
 *
 * Companion to gpu.h — see there for the device record, BAR
 * layout, and the unified compositor surface API.
 *
 * WHAT
 *   Walks the PCI device list for class 0x03 (display) and
 *   matches each device against the per-vendor probe chain
 *   (Intel iGPU, AMD Radeon, NVIDIA GeForce, virtio-gpu, Bochs
 *   VBE). The first matching vendor probe takes ownership;
 *   non-matching devices stay unattached.
 *
 * HOW
 *   Common BAR-map / framebuffer-discovery helpers live here;
 *   per-vendor command-stream + DMA fences live in their own
 *   TUs (virtio_gpu.cpp, bochs_vbe.cpp, etc.).
 */

#include "drivers/gpu/gpu.h"

#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"
#include "drivers/video/framebuffer.h"
#include "mm/paging.h"
#include "drivers/pci/pci.h"
#include "drivers/gpu/bochs_vbe.h"
#include "drivers/gpu/virtio_gpu.h"

namespace duetos::drivers::gpu
{

namespace
{

// Cache of discovered GPUs. A modest cap; anything beyond that is
// extremely rare in hardware we'd boot and would need the PCI layer
// to grow too.
GpuInfo g_gpus[kMaxGpus] = {};
u64 g_gpu_count = 0;

// Module-scope so `GpuShutdown` can clear it and the next
// `GpuInit` re-walks PCI.
constinit bool g_init_done = false;

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

u32 Mmio32(const GpuInfo& g, u64 offset)
{
    if (g.mmio_virt == nullptr || offset + 4 > g.mmio_size)
        return 0xFFFFFFFFu;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(g.mmio_virt) + offset);
    return *p;
}

// NVIDIA PMC_BOOT_0 is at BAR0 + 0x000000, 4 bytes, on every
// NVIDIA GPU since NV4 (1998). Format (from open-gpu-kernel-modules
// and nouveau's nvkm/engine/device/base.c):
//   bits 27:20 = chipset / architecture id
//   bits 19:16 = implementation
//   bits 15:8  = reserved
//   bits  7:0  = revision (major:minor nibbles)
//
// We map the architecture nibble to a short name for boot-log
// readability; unknown values land on nullptr so the log shows the
// raw value instead.
const char* NvidiaArchName(u8 arch)
{
    switch (arch)
    {
    case 0x40:
        return "NV40-curie";
    case 0x50:
        return "NV50-tesla";
    case 0xC0:
        return "GF100-fermi";
    case 0xE0:
        return "GK-kepler";
    case 0x10:
        return "GM10x-maxwell";
    case 0x11:
        return "GM20x-maxwell";
    case 0x12:
        return "GP10x-pascal";
    case 0x13:
        return "GV10x-volta";
    case 0x14:
        return "TU10x-turing";
    case 0x15:
        return "GA10x-ampere";
    case 0x16:
        return "GH10x-hopper";
    case 0x17:
        return "AD10x-ada";
    case 0x18:
        return "GB10x-blackwell";
    default:
        return nullptr;
    }
}

void ProbeNvidiaRegisters(GpuInfo& g)
{
    constexpr u64 kPmcBoot0 = 0x000000;
    const u32 boot0 = Mmio32(g, kPmcBoot0);
    g.probe_reg = boot0;
    g.mmio_live = (boot0 != 0xFFFFFFFFu);
    if (!g.mmio_live)
    {
        arch::SerialWrite("[gpu-probe] nvidia: BAR0 read returned 0xFFFFFFFF (MMIO decode failed)\n");
        return;
    }
    const u8 arch_nib = static_cast<u8>((boot0 >> 20) & 0xFF);
    const u8 impl = static_cast<u8>((boot0 >> 16) & 0xF);
    const u8 rev = static_cast<u8>(boot0 & 0xFF);
    g.arch = NvidiaArchName(arch_nib);
    arch::SerialWrite("[gpu-probe] nvidia: PMC_BOOT_0=");
    arch::SerialWriteHex(boot0);
    arch::SerialWrite(" arch=");
    arch::SerialWriteHex(arch_nib);
    if (g.arch != nullptr)
    {
        arch::SerialWrite(" (");
        arch::SerialWrite(g.arch);
        arch::SerialWrite(")");
    }
    arch::SerialWrite(" impl=");
    arch::SerialWriteHex(impl);
    arch::SerialWrite(" rev=");
    arch::SerialWriteHex(rev);
    arch::SerialWrite("\n");
}

// Intel iGPU: BAR0 is the MMIO register aperture on every Gen we
// target (Gen9+). There isn't a single "chip id" register that
// works across every Gen — the canonical GT revision register moves
// between 0x0 (GEN_INFO) and 0x9130 (GT_CAPABILITY) depending on
// generation. For v0, we only perform a liveness read and log the
// first dword. A full-driver slice will decode per-Gen registers.
void ProbeIntelRegisters(GpuInfo& g)
{
    const u32 dword0 = Mmio32(g, 0);
    g.probe_reg = dword0;
    g.mmio_live = (dword0 != 0xFFFFFFFFu);
    arch::SerialWrite("[gpu-probe] intel: BAR0[0]=");
    arch::SerialWriteHex(dword0);
    arch::SerialWrite(g.mmio_live ? " (MMIO live)\n" : " (MMIO decode failed)\n");
}

// AMD Radeon GFX9+: BAR0 is VRAM framebuffer, BAR2 is doorbell, and
// BAR5 is the MMIO register aperture. We only map BAR0 in GpuInit
// today, so we cannot reach AMD register ids. A full AMD slice will
// probe and map BAR5, then read e.g. mmGRBM_STATUS (0x8010).
void ProbeAmdRegisters(GpuInfo& g)
{
    (void)g;
    arch::SerialWrite("[gpu-probe] amd: no register read — registers at BAR5, not mapped in v0\n");
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

// Classify a virtio device by modern device_id. Modern virtio-over-
// PCI uses 0x1040 + device_type. virtio-gpu is type 0x10, so
// modern device_id = 0x1050. QEMU's -vga virtio exposes exactly
// that. Pre-modern ("transitional") virtio-gpu did not exist.
const char* VirtioGpuTag(u16 device_id)
{
    if (device_id == 0x1050)
        return "virtio-gpu";
    return "virtio-other-display";
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
        family = VirtioGpuTag(g.device_id);
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
    arch::SerialWrite("\n");

    // Vendor-specific register reads from the mapped BAR0. Each
    // probe is non-destructive (reads only) and populates
    // `probe_reg`, `mmio_live`, and optionally `arch` on the
    // GpuInfo. These are the first reads that actually talk to
    // the hardware past PCI config-space — a failing read here
    // means the BAR map is broken or the controller is dead.
    if (g.mmio_virt != nullptr)
    {
        switch (g.vendor_id)
        {
        case kVendorNvidia:
            ProbeNvidiaRegisters(g);
            break;
        case kVendorIntel:
            ProbeIntelRegisters(g);
            break;
        case kVendorAmd:
            ProbeAmdRegisters(g);
            break;
        default:
            break;
        }
    }

    // Bochs VBE aperture is a QEMU-only detail — probing it on bare
    // metal would be addressing a device that doesn't exist. The
    // vendor-id 0x1234 gate already covers the QEMU-std-VGA path,
    // but the HV check makes the emulator-specific nature of this
    // register peek explicit and paves the way for real-hardware
    // vendor probes (Intel/AMD/NVIDIA) to land alongside it.
    if (g.vendor_id == kVendorQemuBochs && ::duetos::arch::IsEmulator())
    {
        DecodeBochsVbe(g);
        // Real driver-level query — talks to the device via the
        // legacy port pair (works regardless of BAR mapping). The
        // MMIO-bank decode above is QEMU-specific + BAR-layout
        // dependent; VbeSelfTest is the canonical entry point.
        VbeSelfTest();
    }
    if (g.vendor_id == kVendorRedHatVirt && g.device_id == 0x1050)
    {
        VirtioGpuProbe(g.bus, g.device, g.function);
        // v1: complete the ACK→DRIVER→FEATURES_OK→DRIVER_OK
        // handshake, set up controlq, issue GET_DISPLAY_INFO. All
        // three steps are independently guarded; a failure in
        // bring-up leaves us with the probe data still visible.
        if (VirtioGpuBringUp())
        {
            const auto& info = VirtioGpuGetDisplayInfo();
            // v2: if at least one scanout is active, allocate a 2D
            // resource backed by a guest-owned contiguous buffer,
            // attach it, bind it to scanout 0, paint a boot test
            // pattern (diagonal gradient + corner swatches), and
            // flush. If the host is QEMU with -vga virtio the
            // pattern lands on the display; this is the first real
            // bring-up proof that our 2D command pipeline works.
            //
            // Cap dimensions to avoid an outsized contiguous
            // allocation: 1024x768x4 = 3 MiB = 768 frames, well
            // within what the frame allocator can satisfy at boot.
            if (info.valid && info.active_scanouts != 0)
            {
                u32 w = info.rects[0].width;
                u32 h = info.rects[0].height;
                if (w == 0 || h == 0)
                {
                    w = 640;
                    h = 480;
                }
                constexpr u32 kScanoutMaxW = 1024;
                constexpr u32 kScanoutMaxH = 768;
                if (w > kScanoutMaxW)
                    w = kScanoutMaxW;
                if (h > kScanoutMaxH)
                    h = kScanoutMaxH;

                if (VirtioGpuSetupScanout(w, h))
                {
                    const auto& sc = VirtioGpuScanoutInfo();
                    // Rebind the kernel framebuffer to the virtio-gpu
                    // backing. BGRA8888 is compatible with the video
                    // driver's 32-bpp pixel format (little-endian
                    // layout puts B,G,R,A in memory, which the host
                    // interprets correctly). Register a present hook
                    // so the compositor's end-of-compose step pushes
                    // the new pixels to the host via TRANSFER_TO_HOST_2D
                    // + RESOURCE_FLUSH. On QEMU `-vga virtio` this
                    // turns the virtio-gpu into our primary display.
                    ::duetos::drivers::video::FramebufferRebindExternal(sc.backing_va, sc.backing_phys, sc.width,
                                                                        sc.height, sc.pitch, 32);
                    ::duetos::drivers::video::FramebufferSetPresentHook(
                        []() {
                            (void)VirtioGpuFlushScanout(0, 0, VirtioGpuScanoutInfo().width,
                                                        VirtioGpuScanoutInfo().height);
                        });
                    // Paint a boot-proof test pattern straight into
                    // the backing (now also the kernel framebuffer)
                    // and flush once so the host sees something
                    // before the first DesktopCompose runs.
                    auto* px = static_cast<u32*>(sc.backing_va);
                    for (u32 yy = 0; yy < sc.height; ++yy)
                    {
                        for (u32 xx = 0; xx < sc.width; ++xx)
                        {
                            const u8 r = static_cast<u8>((xx * 255) / sc.width);
                            const u8 g_ = static_cast<u8>((yy * 255) / sc.height);
                            const u8 b = static_cast<u8>(((xx + yy) * 255) / (sc.width + sc.height));
                            px[yy * sc.width + xx] = (u32(0xFF) << 24) | (u32(r) << 16) | (u32(g_) << 8) | u32(b);
                        }
                    }
                    constexpr u32 kSw = 16;
                    auto fill_box = [&](u32 x0, u32 y0, u32 rgb)
                    {
                        for (u32 yy = y0; yy < y0 + kSw && yy < sc.height; ++yy)
                            for (u32 xx = x0; xx < x0 + kSw && xx < sc.width; ++xx)
                                px[yy * sc.width + xx] = rgb;
                    };
                    fill_box(0, 0, 0xFFFF0000);                            // top-left red
                    fill_box(sc.width - kSw, 0, 0xFF00FF00);               // top-right green
                    fill_box(0, sc.height - kSw, 0xFF0000FF);              // bottom-left blue
                    fill_box(sc.width - kSw, sc.height - kSw, 0xFFFFFFFF); // bottom-right white
                    (void)VirtioGpuFlushScanout(0, 0, sc.width, sc.height);
                }
            }
        }
    }
}

// Read and log every populated BAR on a GPU. Useful diagnostic
// for real-hardware bring-up: Intel BAR0 = regs (~2 MiB),
// BAR2 = GMADR / GTT aperture (128 MiB–1 GiB); AMD BAR0 = VRAM
// framebuffer (up to many GiB), BAR2 = doorbell, BAR5 = regs;
// NVIDIA BAR0 = regs (16 MiB), BAR1 = framebuffer (256 MiB–16 GiB).
// Size-probing is non-destructive. We only map BAR 0 in GpuInit;
// this scan reads and logs the rest without mapping them, so the
// MMIO arena stays intact.
void LogBarLayout(const GpuInfo& g)
{
    pci::DeviceAddress addr = {};
    addr.bus = g.bus;
    addr.device = g.device;
    addr.function = g.function;
    for (u8 i = 0; i < 6; ++i)
    {
        const pci::Bar b = pci::PciReadBar(addr, i);
        if (b.size == 0)
            continue;
        arch::SerialWrite("[gpu]   bar");
        arch::SerialWriteHex(i);
        arch::SerialWrite(b.is_io ? " io=" : " mmio=");
        arch::SerialWriteHex(b.address);
        arch::SerialWrite("/");
        arch::SerialWriteHex(b.size);
        if (b.is_64bit)
            arch::SerialWrite(" 64b");
        if (b.is_prefetchable)
            arch::SerialWrite(" pf");
        arch::SerialWrite("\n");
        // 64-bit BAR consumes the next slot; skip it.
        if (b.is_64bit)
            ++i;
    }
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
    if (g_init_done)
        return;
    g_init_done = true;

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
        LogBarLayout(g_gpus[i]);
    }
    if (g_gpu_count == 0)
    {
        core::Log(core::LogLevel::Warn, "drivers/gpu",
                  "no PCI display controllers found (headless or unsupported board)");
    }
}

::duetos::core::Result<void> GpuShutdown()
{
    KLOG_TRACE_SCOPE("drivers/gpu", "GpuShutdown");
    const u64 dropped = g_gpu_count;
    g_gpu_count = 0;
    g_init_done = false;
    arch::SerialWrite("[drivers/gpu] shutdown: dropped ");
    arch::SerialWriteHex(dropped);
    arch::SerialWrite(" GPU records (MMIO mappings retained)\n");
    return {};
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

} // namespace duetos::drivers::gpu
