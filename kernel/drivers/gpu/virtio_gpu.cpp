#include "virtio_gpu.h"

#include "../../arch/x86_64/serial.h"
#include "../../mm/paging.h"
#include "../pci/pci.h"

namespace customos::drivers::gpu
{

namespace
{

// virtio-pci capability (virtio 1.0 §4.1.4):
//   cap + 0  : standard PCI cap header (id=0x09, next)
//   cap + 2  : cap_len (at least 16)
//   cap + 3  : cfg_type (1=common, 2=notify, 3=isr, 4=device, 5=access)
//   cap + 4  : bar (0..5)
//   cap + 5  : id (allows multiple caps of same type)
//   cap + 6  : padding
//   cap + 8  : offset (u32 LE) — byte offset into the BAR
//   cap + 12 : length (u32 LE) — bytes
// For cfg_type == 2 (notify), a trailing u32 at cap + 16 carries
// `notify_off_multiplier`.
constexpr u8 kVirtioCapId = 0x09;
constexpr u8 kVirtioCfgCommon = 1;
constexpr u8 kVirtioCfgNotify = 2;
constexpr u8 kVirtioCfgIsr = 3;
constexpr u8 kVirtioCfgDevice = 4;

// Common config register offsets (virtio 1.0 §4.1.4.3).
constexpr u64 kCcDeviceFeatureSelect = 0x00;
constexpr u64 kCcDeviceFeature = 0x04;
constexpr u64 kCcDeviceStatus = 0x14;
constexpr u64 kCcNumQueues = 0x12;

// Device status bits (virtio 1.0 §2.1).
[[maybe_unused]] constexpr u8 kStatusAck = 0x01;
[[maybe_unused]] constexpr u8 kStatusDriver = 0x02;
[[maybe_unused]] constexpr u8 kStatusDriverOk = 0x04;
[[maybe_unused]] constexpr u8 kStatusFeaturesOk = 0x08;

constinit VirtioGpuLayout g_last = {};

u8 CapRead8(pci::DeviceAddress a, u8 off)
{
    return pci::PciConfigRead8(a, off);
}
u16 CapRead16(pci::DeviceAddress a, u8 off)
{
    return pci::PciConfigRead16(a, off);
}
u32 CapRead32(pci::DeviceAddress a, u8 off)
{
    return pci::PciConfigRead32(a, off);
}

volatile u8* MapCapRegion(pci::DeviceAddress a, u8 bir, u32 offset, u32 length, u64* out_phys)
{
    const pci::Bar bar = pci::PciReadBar(a, bir);
    if (bar.size == 0 || bar.is_io || offset + length > bar.size)
        return nullptr;
    const u64 region_phys = bar.address + offset;
    *out_phys = region_phys;
    // Page-align the map so MapMmio's alignment-granular bounds
    // are respected; return a pointer into the leading-padded
    // region.
    constexpr u64 kPageMask = 0xFFFu;
    const u64 base_phys = region_phys & ~kPageMask;
    const u64 leading = region_phys - base_phys;
    const u64 bytes = (leading + length + kPageMask) & ~kPageMask;
    void* virt = mm::MapMmio(base_phys, bytes);
    if (virt == nullptr)
        return nullptr;
    return static_cast<volatile u8*>(virt) + leading;
}

} // namespace

VirtioGpuLayout VirtioGpuProbe(u8 bus, u8 device, u8 function)
{
    VirtioGpuLayout L = {};
    pci::DeviceAddress addr = {};
    addr.bus = bus;
    addr.device = device;
    addr.function = function;

    // Capabilities list present bit.
    const u16 status = CapRead16(addr, 0x06);
    if ((status & (1U << 4)) == 0)
        return L;
    u8 cursor = CapRead8(addr, 0x34) & 0xFC;
    for (int hops = 0; hops < 48 && cursor != 0; ++hops)
    {
        const u8 id = CapRead8(addr, cursor);
        const u8 next = CapRead8(addr, static_cast<u8>(cursor + 1)) & 0xFC;
        if (id == kVirtioCapId)
        {
            const u8 cap_len = CapRead8(addr, static_cast<u8>(cursor + 2));
            const u8 cfg_type = CapRead8(addr, static_cast<u8>(cursor + 3));
            const u8 bir = CapRead8(addr, static_cast<u8>(cursor + 4));
            const u32 offset = CapRead32(addr, static_cast<u8>(cursor + 8));
            const u32 length = CapRead32(addr, static_cast<u8>(cursor + 12));
            u64 phys = 0;
            volatile u8* mapped = MapCapRegion(addr, bir, offset, length, &phys);
            if (mapped == nullptr)
            {
                arch::SerialWrite("[virtio-gpu] cap cfg_type=");
                arch::SerialWriteHex(cfg_type);
                arch::SerialWrite(" map failed (bar ");
                arch::SerialWriteHex(bir);
                arch::SerialWrite(")\n");
            }
            else
            {
                switch (cfg_type)
                {
                case kVirtioCfgCommon:
                    L.common_cfg = mapped;
                    L.common_cfg_phys = phys;
                    break;
                case kVirtioCfgNotify:
                    L.notify = mapped;
                    L.notify_phys = phys;
                    if (cap_len >= 20)
                    {
                        L.notify_off_multiplier = CapRead32(addr, static_cast<u8>(cursor + 16));
                    }
                    break;
                case kVirtioCfgIsr:
                    L.isr = mapped;
                    L.isr_phys = phys;
                    break;
                case kVirtioCfgDevice:
                    L.device_cfg = mapped;
                    L.device_cfg_phys = phys;
                    break;
                default:
                    break; // ignore pci-access + unknown
                }
            }
        }
        if (next == cursor)
            break;
        cursor = next;
    }

    if (L.common_cfg != nullptr)
    {
        // Reset: write 0 to device_status, read back until 0 to
        // confirm the controller saw it. virtio 1.0 §3.1.1.
        *reinterpret_cast<volatile u8*>(L.common_cfg + kCcDeviceStatus) = 0;
        for (u32 i = 0; i < 1000; ++i)
        {
            if (*reinterpret_cast<volatile u8*>(L.common_cfg + kCcDeviceStatus) == 0)
                break;
            asm volatile("pause" ::: "memory");
        }
        L.device_status_after_reset = *reinterpret_cast<volatile u8*>(L.common_cfg + kCcDeviceStatus);
        L.num_queues = *reinterpret_cast<volatile u16*>(L.common_cfg + kCcNumQueues);
        // Snapshot low-32 of device features.
        *reinterpret_cast<volatile u32*>(L.common_cfg + kCcDeviceFeatureSelect) = 0;
        L.device_features_lo = *reinterpret_cast<volatile u32*>(L.common_cfg + kCcDeviceFeature);
        L.present = true;

        arch::SerialWrite("[virtio-gpu] common_cfg phys=");
        arch::SerialWriteHex(L.common_cfg_phys);
        arch::SerialWrite(" num_queues=");
        arch::SerialWriteHex(L.num_queues);
        arch::SerialWrite(" device_features_lo=");
        arch::SerialWriteHex(L.device_features_lo);
        arch::SerialWrite(" status_after_reset=");
        arch::SerialWriteHex(L.device_status_after_reset);
        arch::SerialWrite("\n");
    }
    else
    {
        arch::SerialWrite("[virtio-gpu] common_cfg capability not found — probe aborted\n");
    }

    g_last = L;
    return L;
}

VirtioGpuLayout VirtioGpuLastLayout()
{
    return g_last;
}

} // namespace customos::drivers::gpu
