#include "drivers/virtio/virtio_pci.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/paging.h"

namespace duetos::drivers::virtio
{

namespace
{

// PCI capability IDs + virtio cfg-types (virtio 1.0 §4.1.4).
constexpr u8 kPciCapVirtio = 0x09;
constexpr u8 kCfgCommon = 1;
constexpr u8 kCfgNotify = 2;
constexpr u8 kCfgIsr = 3;
constexpr u8 kCfgDevice = 4;

// Common-config register offsets (virtio 1.0 §4.1.4.3). Only the
// ones v0 actually reads / writes are listed — extend as queue
// setup lands.
constexpr u64 kCcDeviceFeatureSelect = 0x00;
constexpr u64 kCcDeviceFeature = 0x04;
constexpr u64 kCcDriverFeatureSelect = 0x08;
constexpr u64 kCcDriverFeature = 0x0C;
constexpr u64 kCcNumQueues = 0x12;
constexpr u64 kCcDeviceStatus = 0x14;

// PCI command-register bits (offset 0x04). Same values as the
// NVMe driver's EnablePciBusMaster — memory-space decode + bus
// mastering.
constexpr u16 kPciCmdMmio = 1U << 1;
constexpr u16 kPciCmdBusMaster = 1U << 2;

volatile u8* MapCapRegion(pci::DeviceAddress addr, u8 bir, u32 offset, u32 length, u64* out_phys)
{
    const pci::Bar bar = pci::PciReadBar(addr, bir);
    if (bar.size == 0 || bar.is_io || u64(offset) + u64(length) > bar.size)
        return nullptr;
    const u64 region_phys = bar.address + offset;
    *out_phys = region_phys;
    // MapMmio's alignment is page-granular; pad on both sides
    // and return the offset pointer.
    constexpr u64 kPageMask = 0xFFFu;
    const u64 base_phys = region_phys & ~kPageMask;
    const u64 leading = region_phys - base_phys;
    const u64 bytes = (leading + length + kPageMask) & ~kPageMask;
    void* virt = mm::MapMmio(base_phys, bytes);
    if (virt == nullptr)
        return nullptr;
    return static_cast<volatile u8*>(virt) + leading;
}

u8 RdStatus(const VirtioPciLayout* L)
{
    return *reinterpret_cast<volatile u8*>(L->common_cfg + kCcDeviceStatus);
}

void WrStatus(VirtioPciLayout* L, u8 v)
{
    *reinterpret_cast<volatile u8*>(L->common_cfg + kCcDeviceStatus) = v;
}

} // namespace

VirtioClass VirtioClassFromDeviceId(u16 device_id)
{
    if (device_id < kVirtioDeviceIdBase || device_id >= kVirtioDeviceIdBase + 64)
        return VirtioClass::kInvalid;
    const u16 sub = static_cast<u16>(device_id - kVirtioDeviceIdBase);
    switch (sub)
    {
    case 1:
        return VirtioClass::kNetwork;
    case 2:
        return VirtioClass::kBlock;
    case 3:
        return VirtioClass::kConsole;
    case 4:
        return VirtioClass::kEntropy;
    case 5:
        return VirtioClass::kBalloon;
    case 8:
        return VirtioClass::kScsi;
    case 16:
        return VirtioClass::kGpu;
    case 18:
        return VirtioClass::kInput;
    case 19:
        return VirtioClass::kSocket;
    default:
        return VirtioClass::kInvalid;
    }
}

const char* VirtioClassName(VirtioClass c)
{
    switch (c)
    {
    case VirtioClass::kNetwork:
        return "net";
    case VirtioClass::kBlock:
        return "blk";
    case VirtioClass::kConsole:
        return "console";
    case VirtioClass::kEntropy:
        return "rng";
    case VirtioClass::kBalloon:
        return "balloon";
    case VirtioClass::kScsi:
        return "scsi";
    case VirtioClass::kGpu:
        return "gpu";
    case VirtioClass::kInput:
        return "input";
    case VirtioClass::kSocket:
        return "vsock";
    case VirtioClass::kInvalid:
    default:
        return "unknown";
    }
}

VirtioPciLayout VirtioPciProbe(pci::DeviceAddress addr)
{
    VirtioPciLayout L = {};
    L.addr = addr;
    L.cls = VirtioClassFromDeviceId(pci::PciConfigRead16(addr, 0x02));

    // Capabilities-list present? PCI Status reg bit 4.
    const u16 status = pci::PciConfigRead16(addr, 0x06);
    if ((status & (1U << 4)) == 0)
        return L;
    u8 cursor = pci::PciConfigRead8(addr, 0x34) & 0xFC;
    for (int hops = 0; hops < 48 && cursor != 0; ++hops)
    {
        const u8 id = pci::PciConfigRead8(addr, cursor);
        const u8 next = pci::PciConfigRead8(addr, static_cast<u8>(cursor + 1)) & 0xFC;
        if (id == kPciCapVirtio)
        {
            const u8 cap_len = pci::PciConfigRead8(addr, static_cast<u8>(cursor + 2));
            const u8 cfg_type = pci::PciConfigRead8(addr, static_cast<u8>(cursor + 3));
            const u8 bir = pci::PciConfigRead8(addr, static_cast<u8>(cursor + 4));
            const u32 offset = pci::PciConfigRead32(addr, static_cast<u8>(cursor + 8));
            const u32 length = pci::PciConfigRead32(addr, static_cast<u8>(cursor + 12));
            u64 phys = 0;
            volatile u8* mapped = MapCapRegion(addr, bir, offset, length, &phys);
            if (mapped != nullptr)
            {
                switch (cfg_type)
                {
                case kCfgCommon:
                    L.common_cfg = mapped;
                    L.common_cfg_phys = phys;
                    break;
                case kCfgNotify:
                    L.notify = mapped;
                    L.notify_phys = phys;
                    if (cap_len >= 20)
                        L.notify_off_multiplier = pci::PciConfigRead32(addr, static_cast<u8>(cursor + 16));
                    break;
                case kCfgIsr:
                    L.isr = mapped;
                    L.isr_phys = phys;
                    break;
                case kCfgDevice:
                    L.device_cfg = mapped;
                    L.device_cfg_phys = phys;
                    break;
                default:
                    break;
                }
            }
        }
        if (next == cursor)
            break;
        cursor = next;
    }

    if (L.common_cfg == nullptr)
    {
        KLOG_WARN("drivers/virtio", "common_cfg capability not found; device skipped");
        return L;
    }

    // Enable memory-space decode + bus mastering before driving
    // the device. MSI-X messages are inbound memory writes FROM
    // the device — QEMU (and real silicon) will not deliver them
    // while Bus Master Enable is clear, and BAR MMIO needs the
    // decode bit. Same shape as nvme.cpp's EnablePciBusMaster:
    // read the 32-bit command/status word, OR the command bits,
    // write the word back.
    {
        const u32 cmd_status = pci::PciConfigRead32(addr, 0x04);
        const u16 status16 = static_cast<u16>(cmd_status >> 16);
        u16 cmd = static_cast<u16>(cmd_status & 0xFFFF);
        cmd |= (kPciCmdMmio | kPciCmdBusMaster);
        const u32 updated = static_cast<u32>(cmd) | (static_cast<u32>(status16) << 16);
        pci::PciConfigWrite32(addr, 0x04, updated);
    }

    // Reset → wait for status to clear → ACK + DRIVER.
    WrStatus(&L, 0);
    for (u32 i = 0; i < 1000; ++i)
    {
        if (RdStatus(&L) == 0)
            break;
        asm volatile("pause" ::: "memory");
    }
    L.device_status_after_reset = RdStatus(&L);
    WrStatus(&L, kStatusAck);
    WrStatus(&L, kStatusAck | kStatusDriver);

    L.num_queues = *reinterpret_cast<volatile u16*>(L.common_cfg + kCcNumQueues);

    // Snapshot device_features (low + high u32).
    *reinterpret_cast<volatile u32*>(L.common_cfg + kCcDeviceFeatureSelect) = 0;
    L.device_features_lo = *reinterpret_cast<volatile u32*>(L.common_cfg + kCcDeviceFeature);
    *reinterpret_cast<volatile u32*>(L.common_cfg + kCcDeviceFeatureSelect) = 1;
    L.device_features_hi = *reinterpret_cast<volatile u32*>(L.common_cfg + kCcDeviceFeature);

    L.present = true;
    KLOG_INFO_2V("drivers/virtio", "device probed", "device-id", static_cast<u64>(pci::PciConfigRead16(addr, 0x02)),
                 "num-queues", static_cast<u64>(L.num_queues));
    return L;
}

bool VirtioNegotiate(VirtioPciLayout* L, u64 driver_features)
{
    if (L == nullptr || !L->present)
        return false;

    // Tell the device which features we accept (must be a subset
    // of what it offered). Includes VIRTIO_F_VERSION_1 — we are a
    // modern driver only.
    const u32 driver_lo = static_cast<u32>(driver_features & 0xFFFFFFFFULL);
    const u32 driver_hi = static_cast<u32>((driver_features >> 32) & 0xFFFFFFFFULL);
    *reinterpret_cast<volatile u32*>(L->common_cfg + kCcDriverFeatureSelect) = 0;
    *reinterpret_cast<volatile u32*>(L->common_cfg + kCcDriverFeature) = driver_lo;
    *reinterpret_cast<volatile u32*>(L->common_cfg + kCcDriverFeatureSelect) = 1;
    *reinterpret_cast<volatile u32*>(L->common_cfg + kCcDriverFeature) = driver_hi;

    // Set FEATURES_OK and read back — device clears the bit if it
    // doesn't accept our subset.
    const u8 cur = RdStatus(L);
    WrStatus(L, static_cast<u8>(cur | kStatusFeaturesOk));
    const u8 reread = RdStatus(L);
    if ((reread & kStatusFeaturesOk) == 0)
    {
        WrStatus(L, kStatusFailed);
        KLOG_WARN("drivers/virtio", "device rejected driver feature subset");
        return false;
    }
    // Negotiation ends at FEATURES_OK. DRIVER_OK is deliberately
    // NOT set here: spec §3.1.1 requires virtqueue configuration
    // (step 7) to complete BEFORE the DRIVER_OK transition (step
    // 8). Each per-device probe owns its queue setup and calls
    // `VirtioMarkDriverOk` once its rings are up.
    return true;
}

} // namespace duetos::drivers::virtio
