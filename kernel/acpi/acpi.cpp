#include "acpi.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../core/panic.h"
#include "../mm/multiboot2.h"
#include "../mm/page.h"

namespace customos::acpi
{

namespace
{

using arch::Halt;
using arch::SerialWrite;
using arch::SerialWriteHex;

// ---------------------------------------------------------------------------
// ACPI table layouts — only the fields we actually touch. All ACPI structs
// are little-endian on x86 so no swapping; all are byte-packed per spec.
// ---------------------------------------------------------------------------

struct [[gnu::packed]] Rsdp
{
    char signature[8]; // "RSD PTR "
    u8 checksum;       // sum of first 20 bytes == 0 (v1 checksum)
    char oem_id[6];
    u8 revision; // 0 = ACPI 1.0 (RSDT), 2+ = ACPI 2.0+ (XSDT available)
    u32 rsdt_address;
    // v2+ fields below; only valid when revision >= 2
    u32 length;
    u64 xsdt_address;
    u8 extended_checksum; // sum of first `length` bytes == 0
    u8 reserved[3];
};

struct [[gnu::packed]] SdtHeader
{
    char signature[4]; // e.g. "XSDT", "RSDT", "APIC", "FACP"
    u32 length;        // total bytes including this header
    u8 revision;
    u8 checksum; // sum of all `length` bytes == 0
    char oem_id[6];
    char oem_table_id[8];
    u32 oem_revision;
    u32 creator_id;
    u32 creator_revision;
};

struct [[gnu::packed]] Madt
{
    SdtHeader header;
    u32 local_apic_addr;
    u32 flags;
    // Variable-length entries follow, each starting with MadtEntryHeader.
};

struct [[gnu::packed]] MadtEntryHeader
{
    u8 type;
    u8 length;
};

constexpr u8 kMadtEntryLapic = 0;
constexpr u8 kMadtEntryIoApic = 1;
constexpr u8 kMadtEntryIntSourceOverride = 2;
constexpr u8 kMadtEntryLapicAddrOverride = 5;

// MADT LAPIC entry flags (Intel-defined, since ACPI 5.0).
constexpr u32 kLapicFlagEnabled = 1U << 0;
constexpr u32 kLapicFlagOnlineCapable = 1U << 1;

struct [[gnu::packed]] MadtIoApic
{
    MadtEntryHeader header;
    u8 id;
    u8 reserved;
    u32 address;
    u32 gsi_base;
};

struct [[gnu::packed]] MadtIntSourceOverride
{
    MadtEntryHeader header;
    u8 bus;
    u8 source;
    u32 gsi;
    u16 flags;
};

struct [[gnu::packed]] MadtLapicAddrOverride
{
    MadtEntryHeader header;
    u16 reserved;
    u64 address;
};

// Multiboot2 ACPI tag headers are identical in layout — an 8-byte tag
// header followed by the actual RSDP bytes.
struct [[gnu::packed]] MbAcpiTag
{
    u32 type; // kMultibootTagAcpiOld (14) or kMultibootTagAcpiNew (15)
    u32 size;
    // Rsdp bytes follow (20 bytes for v1, 36 for v2).
};

// ---------------------------------------------------------------------------
// Cache. Populated once by AcpiInit; read-only after.
// ---------------------------------------------------------------------------
constinit u64 g_lapic_address = 0;
constinit IoApicRecord g_ioapics[kMaxIoapics]{};
constinit u64 g_ioapic_count = 0;
constinit InterruptOverride g_overrides[kMaxInterruptOverrides]{};
constinit u64 g_override_count = 0;
constinit LapicRecord g_lapics[kMaxCpus]{};
constinit u64 g_lapic_count = 0;

[[noreturn]] void PanicAcpi(const char* message)
{
    core::Panic("acpi", message);
}

bool BytesEqual(const char* a, const char* b, u64 n)
{
    for (u64 i = 0; i < n; ++i)
    {
        if (a[i] != b[i])
        {
            return false;
        }
    }
    return true;
}

bool ChecksumOk(const void* p, u32 length)
{
    u8 sum = 0;
    const auto* bytes = static_cast<const u8*>(p);
    for (u32 i = 0; i < length; ++i)
    {
        sum = static_cast<u8>(sum + bytes[i]);
    }
    return sum == 0;
}

// Tag walker that doesn't require any other helpers. We can't reuse the
// one in frame_allocator because it's file-local there; and duplicating a
// 15-line loop is cleaner than plumbing a shared iterator.
//
// Preference: take the "new" (v2+) ACPI tag over the "old" (v1) tag if
// both are present. GRUB provides both for compatibility, and an in-
// order first-match loop would pick whichever appeared first. Since the
// v1 RSDP reports revision = 0 and only the 32-bit RSDT address, using
// it on a v2+ machine means we walk the legacy RSDT instead of the
// authoritative XSDT — still works, but loses the 64-bit entry pointers
// the XSDT gives us.
const Rsdp* FindRsdpInMultiboot(uptr info_phys)
{
    const auto* info = reinterpret_cast<const mm::MultibootInfoHeader*>(info_phys);
    uptr cursor = info_phys + sizeof(mm::MultibootInfoHeader);
    const uptr end = info_phys + info->total_size;

    const Rsdp* old_rsdp = nullptr;
    const Rsdp* new_rsdp = nullptr;

    while (cursor < end)
    {
        const auto* tag = reinterpret_cast<const mm::MultibootTagHeader*>(cursor);
        if (tag->type == mm::kMultibootTagEnd)
        {
            break;
        }
        if (tag->type == mm::kMultibootTagAcpiNew && new_rsdp == nullptr)
        {
            new_rsdp = reinterpret_cast<const Rsdp*>(cursor + sizeof(MbAcpiTag));
        }
        else if (tag->type == mm::kMultibootTagAcpiOld && old_rsdp == nullptr)
        {
            old_rsdp = reinterpret_cast<const Rsdp*>(cursor + sizeof(MbAcpiTag));
        }
        cursor += (tag->size + 7u) & ~uptr{7};
    }
    return new_rsdp != nullptr ? new_rsdp : old_rsdp;
}

const SdtHeader* PhysToHeader(u64 phys)
{
    // All ACPI tables live below 1 GiB on the machines we target today
    // (see scope note in acpi.h). PhysToVirt panics if that assumption
    // breaks, which is the diagnostic we want — silent corruption is
    // worse than a clear "ACPI table out of direct-map range".
    return static_cast<const SdtHeader*>(mm::PhysToVirt(phys));
}

const SdtHeader* FindTable(const Rsdp& rsdp, const char* sig4)
{
    // Prefer XSDT (64-bit entry pointers) on ACPI 2.0+ firmware. Fall back
    // to RSDT (32-bit pointers) on ACPI 1.0 or when no XSDT is present.
    if (rsdp.revision >= 2 && rsdp.xsdt_address != 0)
    {
        const auto* xsdt = PhysToHeader(rsdp.xsdt_address);
        if (!BytesEqual(xsdt->signature, "XSDT", 4))
        {
            PanicAcpi("XSDT has bad signature");
        }
        if (!ChecksumOk(xsdt, xsdt->length))
        {
            PanicAcpi("XSDT checksum failed");
        }

        const u64 count = (xsdt->length - sizeof(SdtHeader)) / sizeof(u64);
        const auto* entries = reinterpret_cast<const u64*>(reinterpret_cast<uptr>(xsdt) + sizeof(SdtHeader));
        for (u64 i = 0; i < count; ++i)
        {
            const auto* h = PhysToHeader(entries[i]);
            if (BytesEqual(h->signature, sig4, 4))
            {
                return h;
            }
        }
        return nullptr;
    }

    const auto* rsdt = PhysToHeader(rsdp.rsdt_address);
    if (!BytesEqual(rsdt->signature, "RSDT", 4))
    {
        PanicAcpi("RSDT has bad signature");
    }
    if (!ChecksumOk(rsdt, rsdt->length))
    {
        PanicAcpi("RSDT checksum failed");
    }

    const u64 count = (rsdt->length - sizeof(SdtHeader)) / sizeof(u32);
    const auto* entries = reinterpret_cast<const u32*>(reinterpret_cast<uptr>(rsdt) + sizeof(SdtHeader));
    for (u64 i = 0; i < count; ++i)
    {
        const auto* h = PhysToHeader(entries[i]);
        if (BytesEqual(h->signature, sig4, 4))
        {
            return h;
        }
    }
    return nullptr;
}

void ParseMadt(const Madt& madt)
{
    g_lapic_address = madt.local_apic_addr;

    uptr cursor = reinterpret_cast<uptr>(&madt) + sizeof(Madt);
    const uptr end = reinterpret_cast<uptr>(&madt) + madt.header.length;

    while (cursor + sizeof(MadtEntryHeader) <= end)
    {
        const auto* h = reinterpret_cast<const MadtEntryHeader*>(cursor);
        if (h->length < sizeof(MadtEntryHeader))
        {
            PanicAcpi("MADT entry has zero length — malformed table");
        }

        switch (h->type)
        {
        case kMadtEntryLapic:
        {
            // Processor Local APIC (ACPI 1.0+). 8-byte body: processor
            // uid (u8), apic id (u8), flags (u32).
            struct [[gnu::packed]] Body
            {
                MadtEntryHeader header;
                u8 processor_uid;
                u8 apic_id;
                u32 flags;
            };
            const auto* e = reinterpret_cast<const Body*>(h);
            if (g_lapic_count >= kMaxCpus)
            {
                PanicAcpi("MADT lists more LAPICs than kMaxCpus");
            }
            g_lapics[g_lapic_count++] = LapicRecord{
                .processor_uid = e->processor_uid,
                .apic_id = e->apic_id,
                .enabled = (e->flags & kLapicFlagEnabled) != 0,
                .online_capable = (e->flags & kLapicFlagOnlineCapable) != 0,
            };
            break;
        }
        case kMadtEntryIoApic:
        {
            const auto* e = reinterpret_cast<const MadtIoApic*>(h);
            if (g_ioapic_count >= kMaxIoapics)
            {
                PanicAcpi("MADT lists more IOAPICs than kMaxIoapics");
            }
            g_ioapics[g_ioapic_count++] = IoApicRecord{
                .id = e->id,
                .address = e->address,
                .gsi_base = e->gsi_base,
            };
            break;
        }
        case kMadtEntryIntSourceOverride:
        {
            const auto* e = reinterpret_cast<const MadtIntSourceOverride*>(h);
            if (g_override_count >= kMaxInterruptOverrides)
            {
                PanicAcpi("MADT lists more overrides than kMaxInterruptOverrides");
            }
            g_overrides[g_override_count++] = InterruptOverride{
                .bus = e->bus,
                .source = e->source,
                .gsi = e->gsi,
                .flags = e->flags,
            };
            break;
        }
        case kMadtEntryLapicAddrOverride:
        {
            const auto* e = reinterpret_cast<const MadtLapicAddrOverride*>(h);
            g_lapic_address = e->address;
            break;
        }
        default:
            // Type 0 (LAPIC) and 4 (LAPIC NMI) etc. are logged by
            // counting alone — we don't cache per-CPU info until
            // SMP AP bring-up needs it.
            break;
        }

        cursor += h->length;
    }
}

} // namespace

void AcpiInit(uptr multiboot_info_phys)
{
    KASSERT(multiboot_info_phys != 0, "acpi", "AcpiInit null multiboot info");

    const Rsdp* rsdp = FindRsdpInMultiboot(multiboot_info_phys);
    if (rsdp == nullptr)
    {
        PanicAcpi("no ACPI RSDP tag in Multiboot2 info");
    }
    if (!BytesEqual(rsdp->signature, "RSD PTR ", 8))
    {
        PanicAcpi("RSDP has bad signature");
    }
    // v1 checksum covers the first 20 bytes and is always required.
    if (!ChecksumOk(rsdp, 20))
    {
        PanicAcpi("RSDP v1 checksum failed");
    }
    // v2+ adds an extended checksum over the whole `length` bytes.
    if (rsdp->revision >= 2 && !ChecksumOk(rsdp, rsdp->length))
    {
        PanicAcpi("RSDP v2 extended checksum failed");
    }

    const SdtHeader* madt_hdr = FindTable(*rsdp, "APIC");
    if (madt_hdr == nullptr)
    {
        PanicAcpi("MADT (APIC signature) not found in RSDT/XSDT");
    }
    if (!ChecksumOk(madt_hdr, madt_hdr->length))
    {
        PanicAcpi("MADT checksum failed");
    }
    ParseMadt(*reinterpret_cast<const Madt*>(madt_hdr));

    SerialWrite("[acpi] rsdp rev=");
    SerialWriteHex(rsdp->revision);
    SerialWrite(" lapic=");
    SerialWriteHex(g_lapic_address);
    SerialWrite(" ioapics=");
    SerialWriteHex(g_ioapic_count);
    SerialWrite(" overrides=");
    SerialWriteHex(g_override_count);
    SerialWrite(" cpus=");
    SerialWriteHex(g_lapic_count);
    SerialWrite("\n");

    for (u64 i = 0; i < g_lapic_count; ++i)
    {
        SerialWrite("  lapic[");
        SerialWriteHex(i);
        SerialWrite("] uid=");
        SerialWriteHex(g_lapics[i].processor_uid);
        SerialWrite(" apic_id=");
        SerialWriteHex(g_lapics[i].apic_id);
        SerialWrite(" enabled=");
        SerialWriteHex(g_lapics[i].enabled ? 1 : 0);
        SerialWrite("\n");
    }

    for (u64 i = 0; i < g_ioapic_count; ++i)
    {
        SerialWrite("  ioapic[");
        SerialWriteHex(i);
        SerialWrite("] id=");
        SerialWriteHex(g_ioapics[i].id);
        SerialWrite(" addr=");
        SerialWriteHex(g_ioapics[i].address);
        SerialWrite(" gsi_base=");
        SerialWriteHex(g_ioapics[i].gsi_base);
        SerialWrite("\n");
    }
    for (u64 i = 0; i < g_override_count; ++i)
    {
        SerialWrite("  override[");
        SerialWriteHex(i);
        SerialWrite("] isa=");
        SerialWriteHex(g_overrides[i].source);
        SerialWrite(" gsi=");
        SerialWriteHex(g_overrides[i].gsi);
        SerialWrite(" flags=");
        SerialWriteHex(g_overrides[i].flags);
        SerialWrite("\n");
    }
}

u64 LocalApicAddress()
{
    return g_lapic_address;
}

u64 IoApicCount()
{
    return g_ioapic_count;
}

const IoApicRecord& IoApic(u64 index)
{
    if (index >= g_ioapic_count)
    {
        PanicAcpi("IoApic(index) out of range");
    }
    return g_ioapics[index];
}

u32 IsaIrqToGsi(u8 isa_irq)
{
    for (u64 i = 0; i < g_override_count; ++i)
    {
        if (g_overrides[i].bus == 0 && g_overrides[i].source == isa_irq)
        {
            return g_overrides[i].gsi;
        }
    }
    return isa_irq; // ISA IRQ N → GSI N when unoverridden
}

u64 CpuCount()
{
    return g_lapic_count;
}

const LapicRecord& Lapic(u64 index)
{
    if (index >= g_lapic_count)
    {
        PanicAcpi("Lapic(index) out of range");
    }
    return g_lapics[index];
}

u16 IsaIrqFlags(u8 isa_irq)
{
    for (u64 i = 0; i < g_override_count; ++i)
    {
        if (g_overrides[i].bus == 0 && g_overrides[i].source == isa_irq)
        {
            return g_overrides[i].flags;
        }
    }
    return 0; // bus-default polarity + trigger
}

} // namespace customos::acpi
