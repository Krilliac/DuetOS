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

// ACPI GenericAddress — the 12-byte descriptor FADT uses for the
// reset register, PM1 event/control blocks, etc. AddressSpaceID
// selects the namespace of `address`: 0 = system memory (MMIO),
// 1 = system I/O (port), 2 = PCI config, 3 = EC, 4 = SMBus, etc.
struct [[gnu::packed]] GenericAddress
{
    u8 address_space_id;
    u8 bit_width;
    u8 bit_offset;
    u8 access_size;
    u64 address;
};

constexpr u8 kGenericAddrSpaceMemory = 0;
constexpr u8 kGenericAddrSpaceIo = 1;

// FADT — Fixed ACPI Description Table. Only fields up through the
// reset register block are declared; later fields (X_* 64-bit
// addresses, SLEEP_CONTROL_REG, HypervisorVendorID) come in when a
// consumer needs them.
struct [[gnu::packed]] Fadt
{
    SdtHeader header;
    u32 firmware_ctrl;
    u32 dsdt;
    u8 reserved;
    u8 preferred_pm_profile;
    u16 sci_int;
    u32 smi_cmd;
    u8 acpi_enable;
    u8 acpi_disable;
    u8 s4bios_req;
    u8 pstate_cnt;
    u32 pm1a_evt_blk;
    u32 pm1b_evt_blk;
    u32 pm1a_cnt_blk;
    u32 pm1b_cnt_blk;
    u32 pm2_cnt_blk;
    u32 pm_tmr_blk;
    u32 gpe0_blk;
    u32 gpe1_blk;
    u8 pm1_evt_len;
    u8 pm1_cnt_len;
    u8 pm2_cnt_len;
    u8 pm_tmr_len;
    u8 gpe0_blk_len;
    u8 gpe1_blk_len;
    u8 gpe1_base;
    u8 cst_cnt;
    u16 p_lvl2_lat;
    u16 p_lvl3_lat;
    u16 flush_size;
    u16 flush_stride;
    u8 duty_offset;
    u8 duty_width;
    u8 day_alrm;
    u8 mon_alrm;
    u8 century;
    u16 iapc_boot_arch;
    u8 reserved2;
    u32 flags;
    GenericAddress reset_reg;
    u8 reset_value;
    // Trailing fields (arm_boot_arch, fadt_minor_version, X_* 64-bit
    // blocks, SLEEP_CONTROL_REG, SLEEP_STATUS_REG, HypervisorVendorID)
    // are unused today and intentionally omitted.
};

// FADT flags bit 10 — RESET_REG_SUP. When set, the RESET_REG +
// RESET_VALUE fields are meaningful. ACPI spec 4.1.3.
constexpr u32 kFadtFlagResetRegSup = 1U << 10;

// HPET description table (ACPI 6.4 §5.2.28). Only fields we use are
// declared — AML-creator metadata and OEM attributes are skipped.
struct [[gnu::packed]] HpetTable
{
    SdtHeader header;
    // Event-timer-block ID: rev + num_tim + count_size + leg_route +
    // vendor — same layout as the low 32 bits of the runtime
    // capabilities register, so drivers can reuse the decoder.
    u32 event_timer_block_id;
    GenericAddress base_address;
    u8 hpet_number;
    u16 main_counter_minimum;
    u8 page_protection_oem;
};

// Bit layout of `event_timer_block_id` (matches CAP[31:0]).
constexpr u32 kHpetBlockIdNumTimMask = 0x1F00;
constexpr u32 kHpetBlockIdNumTimShift = 8;
constexpr u32 kHpetBlockIdCountSize64 = 1U << 13;

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

// FADT-derived cache. Populated by ParseFadt if the FADT is
// present; left at defaults (reset unsupported, SCI on ISA IRQ 9)
// otherwise. The SCI default is the ACPI-spec fallback (ISA IRQ
// 9, level, active-low).
constinit u16 g_sci_vector = 9;
constinit bool g_reset_supported = false;
constinit GenericAddress g_reset_reg{};
constinit u8 g_reset_value = 0;

// HPET-derived cache. All zero if no HPET table was present — the
// HPET driver treats that as "no HPET, fall back to PIT/LAPIC."
constinit u64 g_hpet_address = 0;
constinit u8 g_hpet_timer_count = 0;
constinit u8 g_hpet_counter_width = 0;

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

void ParseFadt(const Fadt& fadt)
{
    g_sci_vector = fadt.sci_int;
    if ((fadt.flags & kFadtFlagResetRegSup) != 0)
    {
        g_reset_supported = true;
        g_reset_reg = fadt.reset_reg;
        g_reset_value = fadt.reset_value;
    }
}

void ParseHpet(const HpetTable& hpet)
{
    // BaseAddress.address is the physical base of the 1 KiB HPET
    // MMIO block. We only honour system-memory space (the spec
    // allows I/O space but no hardware ships that way).
    if (hpet.base_address.address_space_id != kGenericAddrSpaceMemory)
    {
        return;
    }

    g_hpet_address = hpet.base_address.address;
    const u32 num = (hpet.event_timer_block_id & kHpetBlockIdNumTimMask) >> kHpetBlockIdNumTimShift;
    g_hpet_timer_count = static_cast<u8>(num + 1);
    g_hpet_counter_width = (hpet.event_timer_block_id & kHpetBlockIdCountSize64) != 0 ? 64 : 32;
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

    // FADT is optional — a missing one leaves reset unsupported and
    // the SCI vector at the ACPI default (9). Every PC firmware we
    // target ships it, but we don't panic on absence the way MADT
    // does: nothing else in the kernel requires FADT today.
    const SdtHeader* fadt_hdr = FindTable(*rsdp, "FACP");
    if (fadt_hdr != nullptr)
    {
        if (fadt_hdr->length < sizeof(Fadt))
        {
            PanicAcpi("FADT shorter than the fields we read");
        }
        if (!ChecksumOk(fadt_hdr, fadt_hdr->length))
        {
            PanicAcpi("FADT checksum failed");
        }
        ParseFadt(*reinterpret_cast<const Fadt*>(fadt_hdr));
    }

    // HPET is optional — QEMU q35 provides it, older boards may
    // not. Missing is fine; present-but-malformed panics so we
    // don't silently drift past a firmware bug.
    const SdtHeader* hpet_hdr = FindTable(*rsdp, "HPET");
    if (hpet_hdr != nullptr)
    {
        if (hpet_hdr->length < sizeof(HpetTable))
        {
            PanicAcpi("HPET table shorter than the fields we read");
        }
        if (!ChecksumOk(hpet_hdr, hpet_hdr->length))
        {
            PanicAcpi("HPET table checksum failed");
        }
        ParseHpet(*reinterpret_cast<const HpetTable*>(hpet_hdr));
    }

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

    SerialWrite("[acpi] sci_int=");
    SerialWriteHex(g_sci_vector);
    SerialWrite(" reset_reg=");
    if (g_reset_supported)
    {
        SerialWriteHex(g_reset_reg.address_space_id);
        SerialWrite(":");
        SerialWriteHex(g_reset_reg.address);
        SerialWrite(" val=");
        SerialWriteHex(g_reset_value);
    }
    else
    {
        SerialWrite("unsupported");
    }
    SerialWrite("\n");

    SerialWrite("[acpi] hpet=");
    if (g_hpet_address != 0)
    {
        SerialWriteHex(g_hpet_address);
        SerialWrite(" timers=");
        SerialWriteHex(g_hpet_timer_count);
        SerialWrite(" width=");
        SerialWriteHex(g_hpet_counter_width);
    }
    else
    {
        SerialWrite("absent");
    }
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

u16 SciVector()
{
    return g_sci_vector;
}

u64 HpetAddress()
{
    return g_hpet_address;
}

u8 HpetTimerCount()
{
    return g_hpet_timer_count;
}

u8 HpetCounterWidth()
{
    return g_hpet_counter_width;
}

bool AcpiReset()
{
    if (!g_reset_supported)
    {
        return false;
    }

    // Most PC firmware points RESET_REG at I/O port 0xCF9 with value
    // 0x06 (full reset, including chipset). QEMU q35 follows suit.
    // Memory-mapped reset is legal in the spec but unused in the
    // wild on x86 — add MapMmio when a real machine demands it.
    switch (g_reset_reg.address_space_id)
    {
    case kGenericAddrSpaceIo:
        arch::Outb(static_cast<u16>(g_reset_reg.address), g_reset_value);
        return true;
    case kGenericAddrSpaceMemory:
        // Intentional no-op pending an MMIO-reset host to test against.
        return false;
    default:
        return false;
    }
}

} // namespace customos::acpi
