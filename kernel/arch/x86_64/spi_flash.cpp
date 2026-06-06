#include "arch/x86_64/spi_flash.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/pci/pci.h"
#include "mm/paging.h"

namespace duetos::arch
{

namespace
{
constexpr u16 kVendorIntel = 0x8086;
constexpr u8 kClassSerialBus = 0x0C;
constexpr u8 kSubclassSpi = 0x80; // "other serial bus" — PCH SPI lives here
constexpr u8 kClassBridge = 0x06;
constexpr u8 kSubclassIsa = 0x01; // LPC / ISA bridge
constexpr u64 kHsfsCtlOffset = 0x04;
constexpr u32 kHsfsFdvBit = 1u << 14;
constexpr u32 kHsfsFlockdnBit = 1u << 15;
} // namespace

void SpiHsfsDecode(u32 hsfs, bool* out_fdv, bool* out_flockdn)
{
    if (out_fdv != nullptr)
        *out_fdv = (hsfs & kHsfsFdvBit) != 0;
    if (out_flockdn != nullptr)
        *out_flockdn = (hsfs & kHsfsFlockdnBit) != 0;
}

SpiFlashReading SpiFlashRead()
{
    namespace pci = duetos::drivers::pci;
    SpiFlashReading r = {};

    const u64 n = pci::PciDeviceCount();
    const pci::Device* spi = nullptr;
    const pci::Device* lpc = nullptr;
    for (u64 i = 0; i < n; ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.vendor_id != kVendorIntel)
            continue;
        if (d.class_code == kClassSerialBus && d.subclass == kSubclassSpi && spi == nullptr)
            spi = &d;
        else if (d.class_code == kClassBridge && d.subclass == kSubclassIsa && lpc == nullptr)
            lpc = &d;
    }

    if (spi == nullptr && lpc == nullptr)
        return r; // no Intel PCH SPI/LPC — not an Intel platform we read

    r.valid = true;
    const pci::Device* match = (spi != nullptr) ? spi : lpc;
    r.spi_controller = (spi != nullptr);
    r.lpc_present = (lpc != nullptr);
    r.vendor_id = match->vendor_id;
    r.device_id = match->device_id;
    r.bus = match->addr.bus;
    r.dev = match->addr.device;
    r.func = match->addr.function;

    // Modern path only: BAR0 of the 0:1f.5 SPI function is the SPIBAR.
    if (spi != nullptr)
    {
        const pci::Bar bar0 = pci::PciReadBar(spi->addr, 0);
        if (!bar0.is_io && bar0.address != 0 && bar0.size >= 0x40)
        {
            r.spibar_phys = bar0.address;
            void* spibar = mm::MapMmio(bar0.address, 0x1000);
            if (spibar != nullptr)
            {
                const u32 hsfs = *reinterpret_cast<volatile u32*>(static_cast<u8*>(spibar) + kHsfsCtlOffset);
                r.hsfs_read = true;
                r.hsfs_raw = hsfs;
                SpiHsfsDecode(hsfs, &r.fdv, &r.flockdn);
                // GAP: the SPIBAR mapping is intentionally not unmapped —
                // it's one page and the MMIO arena is a bump allocator
                // (same trade-off as the framebuffer / NIC BAR mappings).
            }
        }
    }
    return r;
}

void SpiFlashProbe()
{
    using arch::SerialWrite;
    const SpiFlashReading r = SpiFlashRead();
    if (!r.valid)
    {
        SerialWrite("[spi] no Intel PCH SPI/LPC controller found\n");
        return;
    }
    SerialWrite("[spi] ");
    SerialWrite(r.spi_controller ? "SPI-controller(1f.5)" : "LPC-bridge(1f.0)");
    SerialWrite(" did=");
    arch::SerialWriteHex(r.device_id);
    if (r.hsfs_read)
    {
        SerialWrite(" hsfs=");
        arch::SerialWriteHex(r.hsfs_raw);
        SerialWrite(r.fdv ? " descriptor=valid" : " descriptor=invalid");
        SerialWrite(r.flockdn ? " flash-config=LOCKED" : " flash-config=unlocked");
    }
    else
    {
        // GAP: legacy RCBA SPIBAR decode (ICH9 / QEMU q35) not implemented.
        SerialWrite(" hsfs=unavailable(legacy-RCBA-path-GAP)");
    }
    SerialWrite("\n");
}

void SpiFlashSelfTest()
{
    using core::PanicWithValue;
    bool fdv = false, flockdn = false;

    SpiHsfsDecode(0x0000u, &fdv, &flockdn);
    if (fdv || flockdn)
        PanicWithValue("arch/spi", "zero HSFS decoded as set", 0);

    SpiHsfsDecode(kHsfsFlockdnBit, &fdv, &flockdn);
    if (!flockdn || fdv)
        PanicWithValue("arch/spi", "FLOCKDN bit15 decode wrong", 1);

    SpiHsfsDecode(kHsfsFdvBit, &fdv, &flockdn);
    if (!fdv || flockdn)
        PanicWithValue("arch/spi", "FDV bit14 decode wrong", 2);

    SpiHsfsDecode(kHsfsFdvBit | kHsfsFlockdnBit, &fdv, &flockdn);
    if (!fdv || !flockdn)
        PanicWithValue("arch/spi", "FDV+FLOCKDN decode wrong", 3);

    // Adjacent bits 13 and 16 must not bleed into FDV/FLOCKDN.
    SpiHsfsDecode((1u << 13) | (1u << 16), &fdv, &flockdn);
    if (fdv || flockdn)
        PanicWithValue("arch/spi", "adjacent bits leaked", 4);

    arch::SerialWrite("[spi-flash-selftest] PASS (HSFSTS FDV/FLOCKDN decode)\n");
}

} // namespace duetos::arch
