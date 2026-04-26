/*
 * DuetOS — PCI / PCIe enumeration: implementation.
 *
 * Companion to pci.h — see there for the device record shape,
 * config-space accessors, and the public API
 * (`PciInit`, `PciFind`, `PciForEach`).
 *
 * WHAT
 *   Walks every (bus, device, function) tuple, reads vendor +
 *   device + class + BAR config-space, and stashes a `PciDev`
 *   record per non-empty function. Drivers query the table at
 *   probe time via class / vendor / device matching.
 *
 * HOW
 *   ECAM (Enhanced Configuration Access Mechanism) is preferred
 *   when ACPI provides an MCFG entry — it's a flat MMIO
 *   window; legacy 0xCF8/0xCFC port pair is the fallback for
 *   pre-PCIe systems. Both paths funnel through `PciCfgRead*`
 *   so callers never branch.
 *
 *   Class-code dispatch lives here too: GPUs (class 0x03) get
 *   forwarded to the GPU-driver probe chain, NVMe (0x01/0x08)
 *   to nvme.cpp, AHCI (0x01/0x06) to ahci.cpp, etc. The probe
 *   chain is per-class, not per-vendor — first matching
 *   driver wins, then enumeration moves on.
 *
 * WHY THIS FILE IS LARGE
 *   Every probe path lives here (one per class we drive). Each
 *   is short but the count adds up. The shell `pci` command's
 *   pretty-printer also lives here so it can read the same
 *   class-code lookup tables without exporting them.
 */

#include "drivers/pci/pci.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "diag/log_names.h"
#include "core/panic.h"
#include "mm/paging.h"
#include "sync/spinlock.h"

namespace duetos::drivers::pci
{

namespace
{

// Configuration Mechanism #1 — legacy port-IO fallback. Write a
// 32-bit address to 0xCF8, then read/write the matching 32-bit word
// at 0xCFC.
//
// The address-then-data dance is NOT atomic — between the outl to
// 0xCF8 and the outl/inl to 0xCFC, a peer CPU could write its own
// address and race us to the data port. On SMP the global spinlock
// below serialises every config-space access; on single CPU the
// spinlock's CLI save/restore is the only overhead.
constexpr u16 kConfigAddressPort = 0xCF8;
constexpr u16 kConfigDataPort = 0xCFC;
constexpr u32 kConfigEnable = 1U << 31;

constinit sync::SpinLock g_pci_config_lock{};

constinit Device g_devices[kMaxDevices] = {};
constinit u64 g_device_count = 0;

// MCFG / ECAM state. Populated by PciEnumerateInit() if the ACPI
// MCFG table was found. When non-null, every PciConfigRead*/Write
// routes through the MMIO region instead of 0xCF8/0xCFC; this is
// the only way to see devices on bus numbers >= 1 on real PCIe
// hardware (legacy port IO supports bus 0 only on many boards, and
// even on q35 the port-IO path races the config-address register
// on SMP while ECAM is per-function addressable).
//
// Bounds: we map McfgEndBus() - McfgStartBus() + 1 buses × 256
// devices × 8 functions × 4 KiB = (end-start+1) × 1 MiB.
constinit u64 g_ecam_mmio_phys = 0;
constinit volatile u8* g_ecam_mmio_virt = nullptr;
constinit u8 g_ecam_start_bus = 0;
constinit u8 g_ecam_end_bus = 0;

inline u32 MakeAddress(DeviceAddress addr, u8 offset)
{
    // offset must be 4-byte aligned for legacy port IO — the low 2 bits
    // of the address register are reserved.
    return kConfigEnable | (static_cast<u32>(addr.bus) << 16) | (static_cast<u32>(addr.device & 0x1F) << 11) |
           (static_cast<u32>(addr.function & 0x07) << 8) | (static_cast<u32>(offset & 0xFC));
}

// ECAM offset within the mapped MMIO aperture. PCIe spec §7.2.2:
// per-bus (relative to start_bus) stride 1 MiB, per-device 32 KiB,
// per-function 4 KiB, per-register byte-addressable up to 4 KiB.
inline u64 EcamOffset(DeviceAddress addr, u16 offset)
{
    const u32 rel_bus = u32(addr.bus) - u32(g_ecam_start_bus);
    return (u64(rel_bus) << 20) | (u64(addr.device & 0x1F) << 15) | (u64(addr.function & 0x07) << 12) |
           u64(offset & 0xFFF);
}

inline bool EcamCovers(DeviceAddress addr)
{
    return g_ecam_mmio_virt != nullptr && addr.bus >= g_ecam_start_bus && addr.bus <= g_ecam_end_bus;
}

} // namespace

u32 PciConfigRead32(DeviceAddress addr, u8 offset)
{
    if (EcamCovers(addr))
    {
        // ECAM is MMIO — the spec guarantees naturally-aligned 32-bit
        // accesses are atomic per-function, so no lock needed.
        const u64 off = EcamOffset(addr, u16(offset) & 0xFFCu);
        return *reinterpret_cast<const volatile u32*>(g_ecam_mmio_virt + off);
    }
    const u32 address = MakeAddress(addr, offset);
    sync::SpinLockGuard guard(g_pci_config_lock);
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
    if (EcamCovers(addr))
    {
        const u64 off = EcamOffset(addr, u16(offset) & 0xFFCu);
        *reinterpret_cast<volatile u32*>(g_ecam_mmio_virt + off) = value;
        return;
    }
    u32 address = MakeAddress(addr, offset);
    sync::SpinLockGuard guard(g_pci_config_lock);
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

bool PciMsixFind(DeviceAddress addr, MsixInfo* info)
{
    KASSERT(info != nullptr, "drivers/pci", "PciMsixFind null info");

    const u8 cap = PciFindCapability(addr, kPciCapMsix);
    if (cap == 0)
    {
        return false;
    }

    // MSI-X capability layout:
    //   cap + 0  : {id (u8), next (u8)}
    //   cap + 2  : message_control (u16)
    //   cap + 4  : table offset/BIR (u32)
    //   cap + 8  : pba   offset/BIR (u32)
    //
    // Table size lives in message_control bits 10..0 minus 1 (so read
    // and add 1). BIR lives in bits 2..0 of table_offset/BIR; the offset
    // is bits 31..3 shifted (the low 3 bits are always zero because the
    // table is 8-byte aligned within the BAR).
    const u16 msg_ctrl = PciConfigRead16(addr, static_cast<u8>(cap + 2));
    const u32 table_reg = PciConfigRead32(addr, static_cast<u8>(cap + 4));
    const u32 pba_reg = PciConfigRead32(addr, static_cast<u8>(cap + 8));

    info->cap_offset = cap;
    info->table_size = static_cast<u16>((msg_ctrl & 0x7FF) + 1);
    info->table_bir = static_cast<u8>(table_reg & 0x7);
    info->table_offset = table_reg & ~0x7u;
    info->pba_bir = static_cast<u8>(pba_reg & 0x7);
    info->pba_offset = pba_reg & ~0x7u;
    info->_pad = 0;
    info->_pad2 = 0;
    return true;
}

void PciMsixSetEntry(volatile void* table_base, u16 table_size, u16 index, u8 lapic_id, u8 vector)
{
    KASSERT(table_base != nullptr, "drivers/pci", "PciMsixSetEntry null table");
    // Index must be inside the capability-reported table_size. The
    // MSI-X table is mapped with MapMmio(table_size * sizeof(MsixEntry))
    // by the caller, so `table[index]` past table_size walks into
    // whatever happens to sit after the mapping — adjacent MMIO
    // registers, another device, or unmapped memory. A malicious or
    // buggy device reporting a short table_size plus a driver that
    // trusts its own index arithmetic is the exact combination that
    // turns a capability into an arbitrary-write primitive.
    if (index >= table_size)
    {
        core::Panic("drivers/pci", "PciMsixSetEntry: index past table_size");
    }

    auto* table = static_cast<volatile MsixEntry*>(table_base);
    volatile MsixEntry& entry = table[index];

    // Message address: 0xFEE_xxxxx encodes "deliver to LAPIC"; high 20 bits
    // fixed, bits 19..12 carry the destination APIC ID when redirection
    // hint (RH) and destination mode (DM) are both zero (physical
    // destination to the specified APIC ID). Bits 11..4 are reserved/0.
    const u32 addr_lo = 0xFEE00000u | (static_cast<u32>(lapic_id) << 12);

    // Message data: low 8 bits = vector, bits 10..8 = delivery mode
    // (000 = fixed), bit 14 = level (1 = assert), bit 15 = trigger
    // (0 = edge). For v0 we always emit {fixed, edge, assert}.
    const u32 data = static_cast<u32>(vector);

    // Mask the entry before rewriting address/data so no stale
    // half-update ever delivers. Writing vector_control with bit 0=1
    // sets mask.
    entry.vector_control = 1;
    entry.addr_lo = addr_lo;
    entry.addr_hi = 0;
    entry.data = data;
    // Leave the entry masked; caller unmasks when they're ready. This
    // matches the mask-at-init pattern already in use for IOAPIC.
}

void PciMsixMaskEntry(volatile void* table_base, u16 table_size, u16 index)
{
    if (index >= table_size)
    {
        core::Panic("drivers/pci", "PciMsixMaskEntry: index past table_size");
    }
    auto* table = static_cast<volatile MsixEntry*>(table_base);
    table[index].vector_control = 1;
}

void PciMsixUnmaskEntry(volatile void* table_base, u16 table_size, u16 index)
{
    if (index >= table_size)
    {
        core::Panic("drivers/pci", "PciMsixUnmaskEntry: index past table_size");
    }
    auto* table = static_cast<volatile MsixEntry*>(table_base);
    table[index].vector_control = 0;
}

void PciMsixEnable(DeviceAddress addr)
{
    const u8 cap = PciFindCapability(addr, kPciCapMsix);
    if (cap == 0)
    {
        core::Panic("drivers/pci", "PciMsixEnable on device without MSI-X");
    }
    // Read-modify-write message_control: set bit 15 = Enable, clear
    // bit 14 = Function Mask (leave per-entry mask bits as-is).
    u16 msg_ctrl = PciConfigRead16(addr, static_cast<u8>(cap + 2));
    msg_ctrl |= (1U << 15);
    msg_ctrl &= ~(1U << 14);
    // Write via PciConfigWrite32 on the 32-bit word; the other 16 bits
    // contain capability id + next_pointer which are read-only.
    const u32 word = PciConfigRead32(addr, static_cast<u8>(cap + 0));
    const u32 updated = (word & 0x0000FFFFu) | (static_cast<u32>(msg_ctrl) << 16);
    PciConfigWrite32(addr, static_cast<u8>(cap + 0), updated);
}

void PciMsixFunctionMask(DeviceAddress addr)
{
    const u8 cap = PciFindCapability(addr, kPciCapMsix);
    if (cap == 0)
    {
        return;
    }
    const u32 word = PciConfigRead32(addr, static_cast<u8>(cap + 0));
    u16 msg_ctrl = static_cast<u16>(word >> 16);
    msg_ctrl |= (1U << 14);
    PciConfigWrite32(addr, static_cast<u8>(cap + 0), (word & 0x0000FFFFu) | (static_cast<u32>(msg_ctrl) << 16));
}

void PciMsixFunctionUnmask(DeviceAddress addr)
{
    const u8 cap = PciFindCapability(addr, kPciCapMsix);
    if (cap == 0)
    {
        return;
    }
    const u32 word = PciConfigRead32(addr, static_cast<u8>(cap + 0));
    u16 msg_ctrl = static_cast<u16>(word >> 16);
    msg_ctrl &= ~(1U << 14);
    PciConfigWrite32(addr, static_cast<u8>(cap + 0), (word & 0x0000FFFFu) | (static_cast<u32>(msg_ctrl) << 16));
}

::duetos::core::Result<u8> PciMsixBindSimple(DeviceAddress addr, u16 entry_index, ::duetos::arch::IrqHandler handler,
                                             MsixRoute* out_route)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (handler == nullptr)
        return Err{ErrorCode::InvalidArgument};

    const u8 vector = ::duetos::arch::IrqAllocVector();
    if (vector == 0)
        return Err{ErrorCode::OutOfMemory};

    // BSP LAPIC ID = LAPIC register 0x20 bits 24..31 (APIC-ID field).
    const u32 apic_id_reg = ::duetos::arch::LapicRead(0x20);
    const u8 lapic_id = static_cast<u8>((apic_id_reg >> 24) & 0xFF);

    // Register the C handler BEFORE enabling the MSI-X entry so a
    // fast-arriving interrupt finds a real callback instead of the
    // dispatcher's "unhandled vector" log path.
    ::duetos::arch::IrqInstall(vector, handler);

    auto r = PciMsixRouteSimple(addr, entry_index, lapic_id, vector);
    if (!r.has_value())
    {
        ::duetos::arch::IrqInstall(vector, nullptr);
        return Err{r.error()};
    }
    if (out_route != nullptr)
        *out_route = r.value();
    return vector;
}

::duetos::core::Result<MsixRoute> PciMsixRouteSimple(DeviceAddress addr, u16 entry_index, u8 lapic_id, u8 vector)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;

    MsixRoute out{};
    out.entry_index = entry_index;

    if (!PciMsixFind(addr, &out.info))
        return Err{ErrorCode::Unsupported};
    if (entry_index >= out.info.table_size)
        return Err{ErrorCode::InvalidArgument};

    const Bar bar = PciReadBar(addr, out.info.table_bir);
    if (bar.size == 0 || bar.is_io)
        return Err{ErrorCode::IoError};

    // We only need the table region itself, not the whole BAR. Map
    // exactly table_size × 16-byte entries from (bar.address +
    // table_offset). Pad up to a 4 KiB page so MapMmio is happy
    // (its alignment guard rounds to page granularity anyway).
    constexpr u64 kPageMask = 0xFFFu;
    const u64 region_phys = bar.address + out.info.table_offset;
    u64 region_bytes = u64(out.info.table_size) * sizeof(MsixEntry);
    const u64 region_phys_aligned = region_phys & ~kPageMask;
    const u64 leading_pad = region_phys - region_phys_aligned;
    region_bytes = (region_bytes + leading_pad + kPageMask) & ~kPageMask;
    void* virt = mm::MapMmio(region_phys_aligned, region_bytes);
    if (virt == nullptr)
        return Err{ErrorCode::OutOfMemory};
    auto* table = reinterpret_cast<volatile u8*>(virt) + leading_pad;
    out.table_base = table;
    out.table_phys = region_phys;
    out.table_size = out.info.table_size;

    PciMsixSetEntry(out.table_base, out.table_size, entry_index, lapic_id, vector);
    PciMsixUnmaskEntry(out.table_base, out.table_size, entry_index);
    PciMsixEnable(addr);
    return out;
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

const char* PciSubclassDetail(u8 class_code, u8 subclass, u8 prog_if)
{
    // Pinpoint names for the subclass/prog_if triples we actually
    // care about — anything more specific than the bare class name
    // helps a reader spot "ah, that's the NVMe drive" or "the xHCI
    // controller" without cross-referencing the PCI SIG database.
    switch (class_code)
    {
    case 0x01: // mass storage
        switch (subclass)
        {
        case 0x01:
            return "IDE";
        case 0x06:
            return (prog_if == 0x01) ? "SATA AHCI" : "SATA";
        case 0x07:
            return "SAS";
        case 0x08:
            return (prog_if == 0x02) ? "NVMe" : "NVM";
        }
        break;
    case 0x02: // network
        switch (subclass)
        {
        case 0x00:
            return "Ethernet";
        case 0x80:
            return "wireless/other";
        }
        break;
    case 0x03: // display
        switch (subclass)
        {
        case 0x00:
            return "VGA";
        case 0x01:
            return "XGA";
        case 0x02:
            return "3D";
        }
        break;
    case 0x06: // bridge
        switch (subclass)
        {
        case 0x00:
            return "host bridge";
        case 0x01:
            return "ISA bridge";
        case 0x04:
            return "PCI-PCI bridge";
        }
        break;
    case 0x0C: // serial bus
        switch (subclass)
        {
        case 0x03: // USB
            switch (prog_if)
            {
            case 0x00:
                return "USB UHCI";
            case 0x10:
                return "USB OHCI";
            case 0x20:
                return "USB EHCI";
            case 0x30:
                return "USB xHCI";
            case 0x40:
                return "USB4";
            default:
                return "USB";
            }
        case 0x05:
            return "SMBus";
        case 0x07:
            return "IPMI";
        }
        break;
    case 0x0D: // wireless
        switch (subclass)
        {
        case 0x10:
            return "802.11a";
        case 0x11:
            return "802.11b";
        case 0x20:
            return "802.11";
        }
        break;
    }
    return "";
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

// Forward-declare for recursive bus descent through PCI-to-PCI
// bridges: a type-1 header exposes primary/secondary/subordinate
// bus numbers and all buses in [secondary, subordinate] live behind
// that bridge. We probe those buses immediately so single-pass
// enumeration covers the full tree regardless of declaration order.
void EnumerateBus(u8 bus, u8& highest_bus_seen);

void EnumerateFunction(u8 bus, u8 dev, u8 fn, u8& highest_bus_seen)
{
    const DeviceAddress addr{.bus = bus, .device = dev, .function = fn, ._pad = 0};
    if (!Probe(bus, dev, fn))
        return;
    const u32 cls_word = PciConfigRead32(addr, 0x08);
    const u8 base_class = u8(cls_word >> 24);
    const u8 sub_class = u8(cls_word >> 16);
    const u8 header = PciConfigRead8(addr, 0x0E) & 0x7F;

    // Type-1 header + class 0x06/0x04 = PCI-to-PCI bridge. Read the
    // secondary-bus field (offset 0x19) and descend if it's non-zero
    // and we haven't already visited it. BIOS/UEFI sets up the bus
    // numbers before boot — we trust them on a first pass. A real
    // driver would ALSO be prepared to rewrite them if
    // primary==secondary==0 (unconfigured), but that's a later slice.
    if (header == 0x01 && base_class == 0x06 && sub_class == 0x04)
    {
        const u8 secondary = PciConfigRead8(addr, 0x19);
        if (secondary != 0 && secondary != bus)
        {
            arch::SerialWrite("  pci: descending P2P bridge ");
            arch::SerialWriteHex(bus);
            arch::SerialWrite(":");
            arch::SerialWriteHex(dev);
            arch::SerialWrite(".");
            arch::SerialWriteHex(fn);
            arch::SerialWrite(" -> secondary bus ");
            arch::SerialWriteHex(secondary);
            arch::SerialWrite("\n");
            EnumerateBus(secondary, highest_bus_seen);
        }
    }
}

void EnumerateBus(u8 bus, u8& highest_bus_seen)
{
    if (g_device_count >= kMaxDevices)
        return;
    if (bus > highest_bus_seen)
        highest_bus_seen = bus;
    for (u8 dev = 0; dev < 32; ++dev)
    {
        const DeviceAddress fn0{.bus = bus, .device = dev, .function = 0, ._pad = 0};
        const u32 vd = PciConfigRead32(fn0, 0x00);
        if ((vd & 0xFFFF) == 0xFFFF)
            continue;
        EnumerateFunction(bus, dev, 0, highest_bus_seen);
        const u8 hdr = PciConfigRead8(fn0, 0x0E);
        if ((hdr & 0x80) != 0)
        {
            for (u8 fn = 1; fn < 8; ++fn)
                EnumerateFunction(bus, dev, fn, highest_bus_seen);
        }
        if (g_device_count >= kMaxDevices)
            break;
    }
}

} // namespace

void PciEnumerate()
{
    KLOG_TRACE_SCOPE("drivers/pci", "PciEnumerate");
    static constinit bool s_done = false;
    KASSERT(!s_done, "drivers/pci", "PciEnumerate called twice");
    s_done = true;

    // If ACPI parsed an MCFG table, map the ECAM aperture into the
    // kernel MMIO arena. ECAM covers (end_bus - start_bus + 1) MiB
    // of physical space; cap the mapping at the MMIO arena budget
    // so a firmware reporting 256 MiB doesn't burn the entire
    // arena on a bus range we'll never fully populate.
    const u64 mcfg_base = ::duetos::acpi::McfgAddress();
    const u8 mcfg_start = ::duetos::acpi::McfgStartBus();
    const u8 mcfg_end = ::duetos::acpi::McfgEndBus();
    if (mcfg_base != 0 && mcfg_end >= mcfg_start)
    {
        const u64 bus_count = u64(mcfg_end - mcfg_start) + 1;
        constexpr u64 kMaxEcamBytes = 16ULL * 1024 * 1024; // 16 MiB = 16 buses
        u64 wanted = bus_count << 20;                      // 1 MiB per bus
        if (wanted > kMaxEcamBytes)
            wanted = kMaxEcamBytes;
        void* virt = mm::MapMmio(mcfg_base, wanted);
        if (virt != nullptr)
        {
            g_ecam_mmio_phys = mcfg_base;
            g_ecam_mmio_virt = static_cast<volatile u8*>(virt);
            g_ecam_start_bus = mcfg_start;
            // Recompute end_bus if the aperture was clamped; we
            // can only reach (wanted / 1 MiB) buses from start_bus.
            const u64 mapped_buses = wanted >> 20;
            g_ecam_end_bus = u8(mcfg_start + mapped_buses - 1);
            arch::SerialWrite("[pci] ECAM online base=");
            arch::SerialWriteHex(mcfg_base);
            arch::SerialWrite(" buses=");
            arch::SerialWriteHex(u32(g_ecam_start_bus));
            arch::SerialWrite("..");
            arch::SerialWriteHex(u32(g_ecam_end_bus));
            arch::SerialWrite(" virt=");
            arch::SerialWriteHex(reinterpret_cast<u64>(virt));
            arch::SerialWrite("\n");
        }
        else
        {
            arch::SerialWrite("[pci] MCFG present but MapMmio failed, falling back to port-IO\n");
        }
    }
    else
    {
        arch::SerialWrite("[pci] no MCFG — using legacy port-IO (bus 0 only)\n");
    }

    // Walk bus 0 first; recursive bridge descent picks up the rest
    // of the tree. When ECAM is online we cap at its end_bus; with
    // port-IO only, stick to bus 0 (the actual reachable range).
    u8 highest = 0;
    EnumerateBus(0, highest);
    // Some firmwares publish devices on buses reachable via MCFG
    // that aren't behind a bridge we can find (multi-root, NUMA
    // hot-add, buggy ACPI). If ECAM is live, sweep every declared
    // bus as a safety net — empty slots return 0xFFFF instantly so
    // the cost is (end_bus - start_bus + 1) × 32 MMIO reads.
    if (g_ecam_mmio_virt != nullptr)
    {
        for (u32 bus = u32(g_ecam_start_bus); bus <= u32(g_ecam_end_bus); ++bus)
        {
            if (bus == 0)
                continue; // already walked
            u8 stub = 0;
            EnumerateBus(u8(bus), stub);
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
        arch::SerialWrite("(");
        arch::SerialWrite(::duetos::core::PciVendorName(d.vendor_id));
        arch::SerialWrite(") did=");
        arch::SerialWriteHex(d.device_id);
        arch::SerialWrite(" class=");
        arch::SerialWriteHex(d.class_code);
        arch::SerialWrite("/");
        arch::SerialWriteHex(d.subclass);
        arch::SerialWrite("/");
        arch::SerialWriteHex(d.prog_if);
        arch::SerialWrite(" (");
        arch::SerialWrite(PciClassName(d.class_code));
        const char* detail = PciSubclassDetail(d.class_code, d.subclass, d.prog_if);
        if (detail[0] != 0)
        {
            arch::SerialWrite(" / ");
            arch::SerialWrite(detail);
        }
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

} // namespace duetos::drivers::pci
