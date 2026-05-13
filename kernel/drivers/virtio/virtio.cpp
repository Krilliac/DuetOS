#include "drivers/virtio/virtio.h"

#include "drivers/pci/pci.h"
#include "log/klog.h"

namespace duetos::drivers::virtio
{

namespace
{
VirtioStats g_stats = {};
} // namespace

VirtioStats GetStats()
{
    return g_stats;
}

void VirtioInit()
{
    if (g_stats.init_done)
        return;
    g_stats.init_done = true;

    const u64 n = pci::PciDeviceCount();
    for (u64 i = 0; i < n; ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.vendor_id != kVirtioVendorId)
            continue;
        // Modern devices only: 0x1040..0x107F. Transitional devices
        // (0x1000..0x103F) need a different cap layout that v0
        // doesn't implement; log and skip.
        if (d.device_id < kVirtioDeviceIdBase)
        {
            KLOG_INFO_V("drivers/virtio", "skipping transitional device (modern transport only)",
                        static_cast<u64>(d.device_id));
            continue;
        }

        ++g_stats.probed_total;
        VirtioPciLayout L = VirtioPciProbe(d.addr);
        if (!L.present)
            continue;

        const u16 cls_idx = static_cast<u16>(L.cls);
        if (cls_idx < 16)
            ++g_stats.by_class[cls_idx];

        bool attached = false;
        switch (L.cls)
        {
        case VirtioClass::kEntropy:
            attached = VirtioRngProbe(L);
            break;
        case VirtioClass::kBlock:
            attached = VirtioBlkProbe(L);
            break;
        case VirtioClass::kNetwork:
            attached = VirtioNetProbe(L);
            break;
        case VirtioClass::kGpu:
            // virtio-gpu has its own dedicated probe path under
            // kernel/drivers/gpu/virtio_gpu.cpp — the fabric only
            // notes the find here so the boot summary is honest.
            KLOG_INFO("drivers/virtio", "gpu class detected (handled by drivers/gpu/virtio_gpu)");
            attached = true;
            break;
        case VirtioClass::kConsole:
            attached = VirtioConsoleProbe(L);
            break;
        case VirtioClass::kBalloon:
        case VirtioClass::kScsi:
        case VirtioClass::kInput:
        case VirtioClass::kSocket:
            // STUB: per-class probes for these aren't in tree yet.
            // They surface in the stats and the shell so a future
            // slice can pick the highest-leverage one and land it
            // against the shared transport.
            KLOG_INFO_V("drivers/virtio", "class present but no driver yet", static_cast<u64>(cls_idx));
            break;
        case VirtioClass::kInvalid:
        default:
            KLOG_WARN_V("drivers/virtio", "unknown modern device-id class", static_cast<u64>(d.device_id));
            break;
        }
        if (attached)
            ++g_stats.attached;
    }

    KLOG_INFO_2V("drivers/virtio", "init complete", "probed", static_cast<u64>(g_stats.probed_total), "attached",
                 static_cast<u64>(g_stats.attached));
}

} // namespace duetos::drivers::virtio
