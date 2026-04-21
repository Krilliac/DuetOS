#include "ioapic.h"

#include "cpu.h"
#include "lapic.h"
#include "serial.h"

#include "../../acpi/acpi.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/paging.h"

namespace customos::arch
{

namespace
{

// IOAPIC has exactly two MMIO registers visible:
//   +0x00   IOREGSEL — write the index of the internal register to access
//   +0x10   IOWIN    — read/write the data of the selected register
constexpr u64 kIoApicRegSelOffset = 0x00;
constexpr u64 kIoApicRegWinOffset = 0x10;

// Indirect (IOREGSEL-addressed) registers.
constexpr u32 kIoApicRegVersion = 0x01;
constexpr u32 kIoApicRegRedirBase = 0x10;

// Redirection entry layout (64 bits, accessed as two 32-bit registers).
constexpr u32 kRedirLowMask = 1U << 16;      // bit 16 = mask pin
constexpr u32 kRedirLowLevel = 1U << 15;     // bit 15 = level-triggered
constexpr u32 kRedirLowActiveLow = 1U << 13; // bit 13 = active-low polarity

// MPS-style flag decode for MADT Interrupt Source Override entries.
// bits 0..1 polarity: 00 conforms, 01 active-high, 11 active-low.
// bits 2..3 trigger : 00 conforms, 01 edge,         11 level.
constexpr u16 kMpsPolarityMask = 0x3;
constexpr u16 kMpsPolarityActiveLow = 0x3;
constexpr u16 kMpsTriggerShift = 2;
constexpr u16 kMpsTriggerMask = 0x3;
constexpr u16 kMpsTriggerLevel = 0x3;

struct IoApic
{
    volatile u32* mmio; // base virtual address of the 4 KiB window
    u32 gsi_base;       // first GSI this IOAPIC handles
    u32 redir_count;    // MaxRedirEntry + 1 (typically 24 on q35)
    u8 id;
};

constinit IoApic g_ioapics[acpi::kMaxIoapics]{};
constinit u64 g_ioapic_count = 0;

[[noreturn]] void PanicIoApic(const char* message)
{
    core::Panic("arch/ioapic", message);
}

u32 IoApicRead(const IoApic& io, u32 reg)
{
    io.mmio[kIoApicRegSelOffset / sizeof(u32)] = reg;
    return io.mmio[kIoApicRegWinOffset / sizeof(u32)];
}

void IoApicWrite(IoApic& io, u32 reg, u32 value)
{
    io.mmio[kIoApicRegSelOffset / sizeof(u32)] = reg;
    io.mmio[kIoApicRegWinOffset / sizeof(u32)] = value;
}

IoApic* FindForGsi(u32 gsi)
{
    for (u64 i = 0; i < g_ioapic_count; ++i)
    {
        IoApic& io = g_ioapics[i];
        if (gsi >= io.gsi_base && gsi < io.gsi_base + io.redir_count)
        {
            return &io;
        }
    }
    return nullptr;
}

void WriteRedir(IoApic& io, u32 entry, u64 value)
{
    // Write the high half first so the low half (which carries the mask
    // bit) is the last thing touched — avoids a race window where the
    // pin is "live" pointing at a stale destination.
    const u32 reg_lo = kIoApicRegRedirBase + entry * 2;
    const u32 reg_hi = reg_lo + 1;
    IoApicWrite(io, reg_hi, static_cast<u32>(value >> 32));
    IoApicWrite(io, reg_lo, static_cast<u32>(value & 0xFFFFFFFFu));
}

u64 ReadRedir(const IoApic& io, u32 entry)
{
    const u32 reg_lo = kIoApicRegRedirBase + entry * 2;
    const u32 reg_hi = reg_lo + 1;
    const u64 lo = IoApicRead(io, reg_lo);
    const u64 hi = IoApicRead(io, reg_hi);
    return (hi << 32) | lo;
}

} // namespace

void IoApicInit()
{
    const u64 count = acpi::IoApicCount();
    if (count == 0)
    {
        PanicIoApic("ACPI MADT reported zero IOAPICs");
    }
    if (count > acpi::kMaxIoapics)
    {
        PanicIoApic("more IOAPICs than we can track");
    }

    for (u64 i = 0; i < count; ++i)
    {
        const acpi::IoApicRecord& rec = acpi::IoApic(i);

        void* mmio = customos::mm::MapMmio(rec.address, 0x1000);
        if (mmio == nullptr)
        {
            PanicIoApic("MapMmio failed for IOAPIC window");
        }

        IoApic& io = g_ioapics[i];
        io.mmio = static_cast<volatile u32*>(mmio);
        io.gsi_base = rec.gsi_base;
        io.id = rec.id;

        const u32 version_reg = IoApicRead(io, kIoApicRegVersion);
        io.redir_count = ((version_reg >> 16) & 0xFF) + 1;

        // Mask every redirection entry so stray IRQs can't surprise us
        // while drivers are still wiring up their handlers. Vector bits
        // are left zero; the first Unmask call will supply a real one.
        for (u32 e = 0; e < io.redir_count; ++e)
        {
            WriteRedir(io, e, static_cast<u64>(kRedirLowMask));
        }

        core::LogWith2Values(core::LogLevel::Info, "arch/ioapic", "mapped", "id", io.id, "mmio",
                             reinterpret_cast<u64>(io.mmio));
        core::LogWith2Values(core::LogLevel::Info, "arch/ioapic", "  config", "version", version_reg & 0xFF, "entries",
                             io.redir_count);
        core::LogWithValue(core::LogLevel::Info, "arch/ioapic", "  gsi_base", io.gsi_base);
    }
    g_ioapic_count = count;

    // Lightweight self-test: write a distinctive value to the first
    // entry of IOAPIC 0 with the mask bit set, read it back, then
    // re-mask. Verifies the IOREGSEL / IOWIN indirection is wired up
    // correctly. Any bit lost on round-trip means the MMIO mapping
    // landed with the wrong caching (PCD not set) or a bad physaddr.
    IoApic& io0 = g_ioapics[0];
    constexpr u64 kProbe = static_cast<u64>(kRedirLowMask) | 0x5A;
    WriteRedir(io0, 0, kProbe);
    const u64 got = ReadRedir(io0, 0);
    if ((got & 0xFFFF) != (kProbe & 0xFFFF))
    {
        PanicIoApic("IOAPIC redirection register round-trip failed");
    }
    WriteRedir(io0, 0, static_cast<u64>(kRedirLowMask));

    core::LogWithValue(core::LogLevel::Info, "arch/ioapic", "init OK, controllers online (all pins masked)",
                       g_ioapic_count);
}

void IoApicRoute(u32 gsi, u8 vector, u8 lapic_id, u8 isa_irq)
{
    IoApic* io = FindForGsi(gsi);
    if (io == nullptr)
    {
        PanicIoApic("IoApicRoute: GSI outside any IOAPIC window");
    }

    // Decode MPS-style polarity/trigger flags from the MADT override.
    // For non-ISA callers (isa_irq = 0xFF) we default to edge-triggered
    // active-high, matching the PCI-less bus-default convention that
    // every legacy ISA IRQ uses.
    u32 low = static_cast<u32>(vector);
    if (isa_irq < 16)
    {
        const u16 mps = acpi::IsaIrqFlags(isa_irq);
        if ((mps & kMpsPolarityMask) == kMpsPolarityActiveLow)
        {
            low |= kRedirLowActiveLow;
        }
        if (((mps >> kMpsTriggerShift) & kMpsTriggerMask) == kMpsTriggerLevel)
        {
            low |= kRedirLowLevel;
        }
    }
    const u32 high = static_cast<u32>(lapic_id) << 24;
    const u64 value = (static_cast<u64>(high) << 32) | low;

    // Mask briefly while rewriting to ensure no IRQ is delivered with
    // a half-updated destination.
    const u32 entry = gsi - io->gsi_base;
    WriteRedir(*io, entry, static_cast<u64>(kRedirLowMask));
    WriteRedir(*io, entry, value);
}

void IoApicMask(u32 gsi)
{
    IoApic* io = FindForGsi(gsi);
    if (io == nullptr)
    {
        return; // silent no-op — teardown paths may call after partial init
    }
    const u32 entry = gsi - io->gsi_base;
    u64 v = ReadRedir(*io, entry);
    v |= static_cast<u64>(kRedirLowMask);
    WriteRedir(*io, entry, v);
}

void IoApicUnmask(u32 gsi)
{
    IoApic* io = FindForGsi(gsi);
    if (io == nullptr)
    {
        return;
    }
    const u32 entry = gsi - io->gsi_base;
    u64 v = ReadRedir(*io, entry);
    v &= ~static_cast<u64>(kRedirLowMask);
    WriteRedir(*io, entry, v);
}

} // namespace customos::arch
