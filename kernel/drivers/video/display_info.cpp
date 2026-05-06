/*
 * DuetOS — display info aggregator: implementation.
 *
 * Companion to `display_info.h`. Stitches the framebuffer, GPU
 * discovery, and virtio-gpu scanout-state into one struct so a
 * caller (shell, ICD enumeration) doesn't have to know which
 * upstream module to ask first.
 */

#include "drivers/video/display_info.h"

#include "drivers/gpu/gpu.h"
#include "drivers/gpu/virtio_gpu.h"
#include "drivers/video/framebuffer.h"

namespace duetos::drivers::video
{

DisplayInfo Query()
{
    DisplayInfo info{};

    if (FramebufferAvailable())
    {
        const FramebufferInfo fb = FramebufferGet();
        info.available = true;
        info.width = fb.width;
        info.height = fb.height;
        info.pitch = fb.pitch;
        info.bpp = fb.bpp;
        info.fb_phys = fb.phys;
        info.fb_virt = reinterpret_cast<u64>(fb.virt);
    }

    info.gpu_count = ::duetos::drivers::gpu::GpuCount();
    if (info.gpu_count > 0)
    {
        // First display-class device. Multi-GPU boots will need a
        // "which GPU owns which scanout" map once mode-set lands;
        // for now the first device is the implicit primary.
        const ::duetos::drivers::gpu::GpuInfo& g = ::duetos::drivers::gpu::Gpu(0);
        info.gpu_present = true;
        info.gpu_vendor = g.vendor;
        info.gpu_family = g.family;
        info.gpu_tier = g.tier;
        info.gpu_arch = g.arch;
        info.gpu_mmio_phys = g.mmio_phys;
        info.gpu_mmio_size = g.mmio_size;
    }

    // Present-backend classification. A live virtio-gpu scanout
    // wins — it owns the framebuffer backing in that case
    // (`FramebufferRebindExternal` was called from `gpu.cpp`'s
    // bring-up). Otherwise an available framebuffer means the
    // backend is firmware passthrough or Bochs VBE — both of
    // which appear "direct" to the compositor (writes to the
    // framebuffer VA show on screen with no flush).
    const auto& sc = ::duetos::drivers::gpu::VirtioGpuScanoutInfo();
    if (sc.ready)
    {
        info.backend = PresentBackend::VirtioGpu;
    }
    else if (info.available)
    {
        info.backend = PresentBackend::Direct;
    }
    else
    {
        info.backend = PresentBackend::None;
    }

    info.compose_active = FramebufferComposeActive();
    return info;
}

const char* PresentBackendName(PresentBackend b)
{
    switch (b)
    {
    case PresentBackend::None:
        return "none";
    case PresentBackend::Direct:
        return "direct";
    case PresentBackend::VirtioGpu:
        return "virtio-gpu";
    case PresentBackend::Unknown:
        return "unknown";
    }
    return "unknown";
}

} // namespace duetos::drivers::video
