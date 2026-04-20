#include "pci.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/panic.h"

namespace customos::drivers::pci
{

namespace
{

// Configuration Mechanism #1 (the only one anyone implements on
// modern hardware). Write a 32-bit address to 0xCF8, then read/write
// the matching 32-bit word at 0xCFC.
constexpr u16 kConfigAddressPort = 0xCF8;
constexpr u16 kConfigDataPort = 0xCFC;
constexpr u32 kConfigEnable = 1U << 31;

constinit Device g_devices[kMaxDevices] = {};
constinit u64 g_device_count = 0;

inline u32 MakeAddress(DeviceAddress addr, u8 offset)
{
    // offset must be 4-byte aligned for legacy port IO — the low 2 bits
    // of the address register are reserved.
    return kConfigEnable | (static_cast<u32>(addr.bus) << 16) | (static_cast<u32>(addr.device & 0x1F) << 11) |
           (static_cast<u32>(addr.function & 0x07) << 8) | (static_cast<u32>(offset & 0xFC));
}

} // namespace

u32 PciConfigRead32(DeviceAddress addr, u8 offset)
{
    const u32 address = MakeAddress(addr, offset);
    asm volatile("outl %0, %w1" : : "a"(address), "Nd"(kConfigAddressPort));
    u32 value;
    asm volatile("inl %w1, %0" : "=a"(value) : "Nd"(kConfigDataPort));
    return value;
}

u16 PciConfigRead16(DeviceAddress addr, u8 offset)
{
    const u32 word = PciConfigRead32(addr, offset & 0xFC);
    const u32 shift = (offset & 0x02) * 8;
    return static_cast<u16>((word >> shift) & 0xFFFF);
}

u8 PciConfigRead8(DeviceAddress addr, u8 offset)
{
    const u32 word = PciConfigRead32(addr, offset & 0xFC);
    const u32 shift = (offset & 0x03) * 8;
    return static_cast<u8>((word >> shift) & 0xFF);
}

void PciConfigWrite32(DeviceAddress addr, u8 offset, u32 value)
{
    u32 address = MakeAddress(addr, offset);
    asm volatile("outl %0, %w1" : : "a"(address), "Nd"(kConfigAddressPort));
    asm volatile("outl %0, %w1" : : "a"(value), "Nd"(kConfigDataPort));
}

Bar PciReadBar(DeviceAddress addr, u8 index)
{
    // Only header-type-0 endpoints have 6 BARs at 0x10..0x24; header-
    // type-1 bridges have 2 BARs + secondary-bus fields. Callers are
    // expected to check header_type before calling. v0 doesn't police
    // it — returning size=0 for bridge "BARs" beyond index 1 is
    // reasonable since they read back as bridge-specific registers.
    if (index >= 6)
    {
        return Bar{};
    }

    const u8 offset = static_cast<u8>(0x10 + index * 4);
    const u32 original = PciConfigRead32(addr, offset);

    // Empty BAR slot reads back all zeros.
    if (original == 0)
    {
        return Bar{};
    }

    // Size-probe: write all 1s, read back. Low bits are fixed by the
    // device to indicate type (bit 0 = I/O, bits 1..2 = memory type).
    // Restore the original value before returning so we don't leave
    // the device pointing at 0xFFFFFFFF.
    PciConfigWrite32(addr, offset, 0xFFFFFFFFu);
    const u32 probe = PciConfigRead32(addr, offset);
    PciConfigWrite32(addr, offset, original);

    Bar bar{};
    bar.is_io = (original & 0x1) != 0;

    if (bar.is_io)
    {
        // I/O BAR: address in bits 2..31, size from inverted probe-mask.
        bar.address = original & 0xFFFFFFFCu;
        const u32 mask = probe & 0xFFFFFFFCu;
        bar.size = mask == 0 ? 0 : (~static_cast<u64>(mask) + 1) & 0xFFFFFFFFu;
        return bar;
    }

    // MMIO BAR. Bits 1..2 are the type field:
    //   00 = 32-bit MMIO
    //   10 = 64-bit MMIO (consumes this + next BAR)
    //   others reserved
    const u32 type = (original >> 1) & 0x3;
    bar.is_prefetchable = (original & 0x8) != 0;
    bar.is_64bit = (type == 0x2);

    u64 low_mask = static_cast<u64>(probe & 0xFFFFFFF0u);
    bar.address = static_cast<u64>(original & 0xFFFFFFF0u);

    if (bar.is_64bit)
    {
        // Read + probe the upper 32 bits from BAR[index+1].
        if (index + 1 >= 6)
        {
            // Malformed: a 64-bit BAR MUST have a successor slot.
            return Bar{};
        }
        const u8 hi_offset = static_cast<u8>(offset + 4);
        const u32 hi_orig = PciConfigRead32(addr, hi_offset);
        PciConfigWrite32(addr, hi_offset, 0xFFFFFFFFu);
        const u32 hi_probe = PciConfigRead32(addr, hi_offset);
        PciConfigWrite32(addr, hi_offset, hi_orig);

        bar.address |= static_cast<u64>(hi_orig) << 32;
        const u64 full_mask = low_mask | (static_cast<u64>(hi_probe) << 32);
        bar.size = full_mask == 0 ? 0 : (~full_mask + 1);
    }
    else
    {
        bar.size = low_mask == 0 ? 0 : (~low_mask + 1) & 0xFFFFFFFFu;
    }

    return bar;
}

u8 PciFindCapability(DeviceAddress addr, u8 cap_id)
{
    // Status register bit 4 at offset 0x06 == "Capabilities List present".
    const u16 status = PciConfigRead16(addr, 0x06);
    if ((status & (1U << 4)) == 0)
    {
        return 0;
    }

    // First capability pointer lives at 0x34 (header-0) or 0x14 for
    // CardBus bridges. We only handle header-0 devices today — caller
    // should not pass bridges with type != 0. Low two bits of the
    // pointer are reserved and must be masked off.
    u8 cursor = PciConfigRead8(addr, 0x34) & 0xFC;

    // Bounded walk: a malformed device could produce a cycle;
    // terminate after 48 hops (any real device has fewer than that).
    for (int i = 0; i < 48 && cursor != 0; ++i)
    {
        const u8 id = PciConfigRead8(addr, cursor);
        if (id == cap_id)
        {
            return cursor;
        }
        const u8 next = PciConfigRead8(addr, static_cast<u8>(cursor + 1)) & 0xFC;
        if (next == cursor)
        {
            break; // self-loop; give up silently
        }
        cursor = next;
    }
    return 0;
}

u64 PciDeviceCount()
{
    return g_device_count;
}

const Device& PciDevice(u64 index)
{
    KASSERT_WITH_VALUE(index < g_device_count, "drivers/pci", "PciDevice index out of range", index);
    return g_devices[index];
}

const char* PciClassName(u8 class_code)
{
    // Subset of the PCI SIG base-class codes. Extend as we grow drivers
    // that care.
    switch (class_code)
    {
    case 0x00:
        return "legacy";
    case 0x01:
        return "mass storage";
    case 0x02:
        return "network";
    case 0x03:
        return "display";
    case 0x04:
        return "multimedia";
    case 0x05:
        return "memory";
    case 0x06:
        return "bridge";
    case 0x07:
        return "comm";
    case 0x08:
        return "system";
    case 0x09:
        return "input";
    case 0x0A:
        return "docking";
    case 0x0B:
        return "processor";
    case 0x0C:
        return "serial bus";
    case 0x0D:
        return "wireless";
    case 0x0E:
        return "intelligent";
    case 0x0F:
        return "satellite";
    case 0x10:
        return "crypto";
    case 0x11:
        return "signal proc";
    case 0xFF:
        return "unassigned";
    default:
        return "unknown";
    }
}

namespace
{

void CacheDevice(DeviceAddress addr, u32 vendor_device, u32 class_reg, u32 header_reg)
{
    if (g_device_count >= kMaxDevices)
    {
        core::Log(core::LogLevel::Warn, "drivers/pci", "device table full; further devices ignored");
        return;
    }
    Device& d = g_devices[g_device_count++];
    d.addr = addr;
    d.vendor_id = static_cast<u16>(vendor_device & 0xFFFF);
    d.device_id = static_cast<u16>((vendor_device >> 16) & 0xFFFF);
    d.revision = static_cast<u8>(class_reg & 0xFF);
    d.prog_if = static_cast<u8>((class_reg >> 8) & 0xFF);
    d.subclass = static_cast<u8>((class_reg >> 16) & 0xFF);
    d.class_code = static_cast<u8>((class_reg >> 24) & 0xFF);
    d.header_type = static_cast<u8>((header_reg >> 16) & 0xFF);
}

// Probe a single (bus, device, function). Returns true if a device was
// present + cached; false if the slot is empty.
bool Probe(u8 bus, u8 dev, u8 fn)
{
    const DeviceAddress addr{.bus = bus, .device = dev, .function = fn, ._pad = 0};
    const u32 vd = PciConfigRead32(addr, 0x00);
    if ((vd & 0xFFFF) == 0xFFFF)
    {
        return false;
    }
    const u32 cls = PciConfigRead32(addr, 0x08);
    const u32 hdr = PciConfigRead32(addr, 0x0C);
    CacheDevice(addr, vd, cls, hdr);
    return true;
}

} // namespace

void PciEnumerate()
{
    static constinit bool s_done = false;
    KASSERT(!s_done, "drivers/pci", "PciEnumerate called twice");
    s_done = true;

    // v0: bus 0..3 is plenty for QEMU q35 + any other board we'd realistically
    // boot today. Recursive bridge walking lands when we actually meet a
    // board whose interesting devices are behind a bridge (not q35).
    for (u32 bus = 0; bus < 4; ++bus)
    {
        for (u8 dev = 0; dev < 32; ++dev)
        {
            const DeviceAddress fn0{.bus = static_cast<u8>(bus), .device = dev, .function = 0, ._pad = 0};
            const u32 vendor_device = PciConfigRead32(fn0, 0x00);
            if ((vendor_device & 0xFFFF) == 0xFFFF)
            {
                continue; // no device at this slot
            }

            // Function 0 always exists; cache it. Then check the multi-function
            // bit (header_type bit 7) to decide if we need to scan functions
            // 1..7.
            Probe(static_cast<u8>(bus), dev, 0);
            const u8 header = PciConfigRead8(fn0, 0x0E);
            if ((header & 0x80) != 0)
            {
                for (u8 fn = 1; fn < 8; ++fn)
                {
                    Probe(static_cast<u8>(bus), dev, fn);
                }
            }
        }
    }

    core::LogWithValue(core::LogLevel::Info, "drivers/pci", "enumerated devices", g_device_count);
    for (u64 i = 0; i < g_device_count; ++i)
    {
        const Device& d = g_devices[i];
        // Structured one-liner per device, plus a "caps:" tail listing
        // which interesting capabilities were found. Drivers auditing
        // the boot log can confirm at a glance that (say) the xHCI
        // controller exposes MSI-X before trying to use it.
        arch::SerialWrite("  pci ");
        arch::SerialWriteHex(d.addr.bus);
        arch::SerialWrite(":");
        arch::SerialWriteHex(d.addr.device);
        arch::SerialWrite(".");
        arch::SerialWriteHex(d.addr.function);
        arch::SerialWrite("  vid=");
        arch::SerialWriteHex(d.vendor_id);
        arch::SerialWrite(" did=");
        arch::SerialWriteHex(d.device_id);
        arch::SerialWrite(" class=");
        arch::SerialWriteHex(d.class_code);
        arch::SerialWrite("/");
        arch::SerialWriteHex(d.subclass);
        arch::SerialWrite("/");
        arch::SerialWriteHex(d.prog_if);
        arch::SerialWrite(" (");
        arch::SerialWrite(PciClassName(d.class_code));
        arch::SerialWrite(")");

        // BAR0 — the "main" MMIO window for most endpoints. Header-type-1
        // bridges have different layout (only 2 BARs, then secondary-bus
        // fields); skip them to avoid printing bogus "BARs" decoded from
        // bridge-control registers.
        if ((d.header_type & 0x7F) == 0x00)
        {
            const Bar bar0 = PciReadBar(d.addr, 0);
            if (bar0.size != 0)
            {
                arch::SerialWrite(" bar0=");
                arch::SerialWriteHex(bar0.address);
                arch::SerialWrite("/");
                arch::SerialWriteHex(bar0.size);
                arch::SerialWrite(bar0.is_io ? "(io)" : bar0.is_64bit ? "(m64)" : "(m32)");
            }

            // Short capability summary: print IDs we recognise.
            if (PciFindCapability(d.addr, kPciCapMsi) != 0)
            {
                arch::SerialWrite(" msi");
            }
            if (PciFindCapability(d.addr, kPciCapMsix) != 0)
            {
                arch::SerialWrite(" msix");
            }
            if (PciFindCapability(d.addr, kPciCapPcie) != 0)
            {
                arch::SerialWrite(" pcie");
            }
        }
        arch::SerialWrite("\n");
    }
}

} // namespace customos::drivers::pci
