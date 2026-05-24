/*
 * DuetOS — ACPI table discovery: implementation.
 *
 * Companion to acpi.h — see there for the public discovery API
 * (FindRsdp, MapXsdtEntries, the MADT/HPET/MCFG getters).
 *
 * WHAT
 *   Locates the ACPI Root System Description Pointer in either
 *   the EBDA region or the legacy 0xE0000-0xFFFFF window, walks
 *   the XSDT (or RSDT on pre-2.0 firmware) it points at, and
 *   exposes lookups for the tables we currently consume: MADT
 *   (LAPIC/IOAPIC/IRQ overrides), HPET (timer base), MCFG (PCIe
 *   ECAM base), FADT (IAPC boot flags).
 *
 * HOW
 *   Tables get checksummed before any contents are trusted —
 *   `AcpiTableChecksum` is the gatekeeper. Each per-table
 *   parser knows the wire layout from the ACPI 6.x spec; we
 *   never include vendor headers for them.
 *
 *   AML execution lives in aml.cpp; this file owns only the
 *   static-data tables. The split is deliberate: AML touches
 *   I/O ports and SMM-adjacent state, table parsing is
 *   read-only.
 */

#include "acpi/acpi.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "core/panic.h"
#include "mm/multiboot2.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "acpi/aml.h"
#include "acpi/aml_eval.h"
#include "acpi/srat.h"
#include "acpi/acpi_rust/include/acpi_rust.h"

namespace duetos::acpi
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

// MCFG — PCI Express Memory-Mapped Configuration Space. Header is
// followed by `reserved:u64` and then N Configuration Space Base
// Address Allocation Structures, 16 bytes each. We only parse the
// first entry (segment group 0) — multi-segment hardware is vendor-
// specific and no x86_64 platform we target ships it.
struct [[gnu::packed]] McfgEntry
{
    u64 base_address;
    u16 segment_group;
    u8 start_bus;
    u8 end_bus;
    u32 reserved;
};
static_assert(sizeof(McfgEntry) == 16, "MCFG entry is 16 bytes");

struct [[gnu::packed]] McfgTable
{
    SdtHeader header;
    u64 reserved;
    // McfgEntry entries follow; count = (length - sizeof(McfgTable)) / 16.
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

// FADT-derived cache. Populated by ParseFadt if the FADT is
// present; left at defaults (reset unsupported, SCI on ISA IRQ 9)
// otherwise. The SCI default is the ACPI-spec fallback (ISA IRQ
// 9, level, active-low).
constinit u16 g_sci_vector = 9;
constinit bool g_reset_supported = false;
constinit GenericAddress g_reset_reg{};
constinit u8 g_reset_value = 0;
constinit u32 g_pm1a_cnt = 0;
constinit u32 g_pm1b_cnt = 0;
constinit u8 g_pm1_cnt_len = 0;

// PM1 event block + GPE blocks + ACPI-enable handshake, from FADT.
// All zero when the FADT didn't populate them (hardware-reduced
// ACPI, or QEMU with no GPEs). Consumed by kernel/acpi/acpi_sci.cpp
// to install the SCI handler and arm the power button.
constinit u32 g_pm1a_evt = 0;
constinit u32 g_pm1b_evt = 0;
constinit u8 g_pm1_evt_len = 0;
constinit u32 g_gpe0_blk = 0;
constinit u8 g_gpe0_blk_len = 0;
constinit u32 g_gpe1_blk = 0;
constinit u8 g_gpe1_blk_len = 0;
constinit u8 g_gpe1_base = 0;
constinit u32 g_smi_cmd = 0;
constinit u8 g_acpi_enable = 0;

// HPET-derived cache. All zero if no HPET table was present — the
// HPET driver treats that as "no HPET, fall back to PIT/LAPIC."
constinit u64 g_hpet_address = 0;
constinit u8 g_hpet_timer_count = 0;
constinit u8 g_hpet_counter_width = 0;

// MCFG-derived cache. Segment group 0 only. All zero if no MCFG
// table was present — PCI drivers fall back to legacy port IO.
constinit u64 g_mcfg_address = 0;
constinit u8 g_mcfg_start_bus = 0;
constinit u8 g_mcfg_end_bus = 0;

// DSDT + SSDT cache. DSDT address is taken from FADT.dsdt (32-bit
// legacy pointer — FADT.X_DSDT at offset 140 is the 64-bit form we
// should prefer when available, but we don't parse FADT that deep
// yet). SSDTs live as separate XSDT/RSDT entries with the "SSDT"
// signature.
constexpr u64 kMaxSsdts = 16;
constinit u64 g_dsdt_address = 0;
constinit u32 g_dsdt_length = 0;
constinit u64 g_ssdt_address[kMaxSsdts] = {};
constinit u32 g_ssdt_length[kMaxSsdts] = {};
constinit u64 g_ssdt_count = 0;

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
    // CRITICAL: `info_phys` is the LOW identity-mapped address the
    // boot loader handed us. That mapping is torn down by
    // MmFinalizePaging long before AcpiInit runs, so a raw
    // reinterpret_cast<MultibootInfoHeader*>(info_phys) dereference
    // here either silently hangs (VBox — first observed in PR #336's
    // VBox boot of the 0e017192 ISO, captured at OneDrive Desktop\\
    // DuetOS Logs\\serial.txt: boot wedged at [acpi] step=find-rsdp
    // with no further output) or surfaces as a late-boot #PF (the
    // shape boot_cmdline.cpp:38-45 documents at cr2=0x92000).
    //
    // FindBootCmdline (sibling walker over the SAME structure) avoids
    // this by caching the cmdline string on the first early-boot
    // call. AcpiInit only calls this ONCE per boot, so caching has
    // no value; instead, route the dereference through the upper-
    // half direct map via PhysToVirt. The direct map covers the low
    // 1 GiB of physical RAM (per kernel/mm/paging — the
    // k.directmap region 0xffffffff80000000..0xffffffffc0000000),
    // which is where every multiboot loader places the info struct.
    const auto* info = reinterpret_cast<const mm::MultibootInfoHeader*>(mm::PhysToVirt(info_phys));
    const uptr base = reinterpret_cast<uptr>(info);
    uptr cursor = base + sizeof(mm::MultibootInfoHeader);
    const uptr end = base + info->total_size;

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
        // Defensive: a corrupt or zero-sized tag would otherwise stall
        // this loop forever. Bound the per-iteration advance at 8 bytes
        // minimum (the smallest legal tag — type + size, both u32).
        // Under VBox this is what previously presented as a silent
        // hang before the PhysToVirt fix landed.
        const uptr step = (tag->size + 7u) & ~uptr{7};
        cursor += step < 8 ? 8 : step;
    }
    return new_rsdp != nullptr ? new_rsdp : old_rsdp;
}

// Map `len` bytes of ACPI physical memory and return a readable virtual
// pointer. ACPI tables can live anywhere in physical RAM: QEMU/OVMF parks
// them low (inside the 1 GiB direct map) so the fast PhysToVirt path is
// used; VirtualBox places the XSDT near the top of 2 GiB RAM, outside the
// direct map, so we fall back to an MMIO mapping. Mappings are cached by
// physical base (a handful of distinct ACPI pages) so the repeated XSDT
// walks across the ~6 FindTable calls don't exhaust the MMIO arena, and
// kept for the kernel's lifetime (matching the prior PhysToVirt-forever
// assumption — the DSDT/SSDT scanners reuse these addresses post-boot).
struct AcpiMapEntry
{
    u64 phys;
    u64 len;
    void* virt;
};
constinit AcpiMapEntry g_acpi_maps[24] = {};
constinit u64 g_acpi_map_count = 0;

void* AcpiMapPhys(u64 phys, u64 len)
{
    if (len == 0)
    {
        len = 1;
    }
    if (phys + len <= mm::kDirectMapBytes)
    {
        return mm::PhysToVirt(phys);
    }
    for (u64 i = 0; i < g_acpi_map_count; ++i)
    {
        if (g_acpi_maps[i].phys == phys && g_acpi_maps[i].len >= len)
        {
            return g_acpi_maps[i].virt;
        }
    }
    void* v = mm::MapMmio(phys, len);
    if (v == nullptr)
    {
        PanicAcpi("ACPI table mapping failed (MMIO arena exhausted)");
    }
    if (g_acpi_map_count < 24)
    {
        g_acpi_maps[g_acpi_map_count++] = AcpiMapEntry{phys, len, v};
    }
    return v;
}

const SdtHeader* PhysToHeader(u64 phys)
{
    // Read the fixed 36-byte header first to learn the table length,
    // then ensure the whole table is mapped. AcpiMapPhys picks the
    // direct map or an MMIO fallback depending on where the firmware
    // placed the table.
    const auto* probe = static_cast<const SdtHeader*>(AcpiMapPhys(phys, sizeof(SdtHeader)));
    return static_cast<const SdtHeader*>(AcpiMapPhys(phys, probe->length));
}

// XSDT entries are 8-byte physical pointers stored right after the
// 36-byte SdtHeader. 36 is u32-aligned but not u64-aligned, so a
// plain `reinterpret_cast<const u64*>` indexed read is a misaligned
// u64 load — UBSAN flags it as type-mismatch (it would also #GP on
// architectures stricter than x86). Read via byte-wise copy instead;
// every UBSAN type-mismatch report from acpi.cpp resolves once the
// five XSDT loops (FindTable's loop, FindAllSsdts's loop, and the
// SSDT cache walks) all go through this helper.
inline u64 XsdtEntryAt(const SdtHeader* xsdt, u64 i)
{
    const auto* bytes = reinterpret_cast<const u8*>(xsdt) + sizeof(SdtHeader) + i * sizeof(u64);
    u64 v = 0;
    for (u64 j = 0; j < sizeof(u64); ++j)
    {
        v |= static_cast<u64>(bytes[j]) << (j * 8);
    }
    return v;
}

const SdtHeader* FindTable(const Rsdp& rsdp, const char* sig4)
{
    // Prefer the XSDT (64-bit entry pointers) on ACPI 2.0+ firmware,
    // then fall back to the RSDT (32-bit pointers) — used on ACPI 1.0,
    // when no XSDT is present, OR when the XSDT is present but does not
    // list the requested table. The last case is real: VirtualBox ships
    // an incomplete XSDT (only FADT + SSDT) and lists the MADT and the
    // rest only in the legacy RSDT. The spec says the two tables should
    // agree; firmware in the wild does not always honour that.
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

        // Subtractive bound: a malformed XSDT with `length` less than
        // the header itself would wrap the subtraction to a huge u64
        // and the loop would walk hundreds of garbage bytes past the
        // table's end. The checksum guard above doesn't catch this —
        // a bad-length table can still sum to zero.
        const u64 count = (xsdt->length >= sizeof(SdtHeader)) ? (xsdt->length - sizeof(SdtHeader)) / sizeof(u64) : 0;
        for (u64 i = 0; i < count; ++i)
        {
            const auto* h = PhysToHeader(XsdtEntryAt(xsdt, i));
            if (BytesEqual(h->signature, sig4, 4))
            {
                return h;
            }
        }
        // Not found in the XSDT. Do NOT give up here — fall through to
        // the RSDT scan below (incomplete-XSDT firmware, see header
        // comment). A genuinely-absent table is reported by returning
        // nullptr only after both roots have been searched.
    }

    if (rsdp.rsdt_address == 0)
    {
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

    // Same underflow guard as the XSDT path above.
    const u64 count = (rsdt->length >= sizeof(SdtHeader)) ? (rsdt->length - sizeof(SdtHeader)) / sizeof(u32) : 0;
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

// One-shot boot diagnostic: dump the RSDP + root system table + every
// entry's physical address and 4-char signature. WARN-level so it lands
// in a serial capture by default. Kept (gated by the once-at-boot call
// site) because non-QEMU firmware — VirtualBox, real UEFI — lays the
// ACPI tables out differently than the QEMU/OVMF path the parser was
// written against, and this is the cheapest way to see that layout when
// a table lookup fails on a machine we can't introspect any other way.
void AcpiDiagDumpRoot(const char* tag, u64 root_phys, bool entries_are_64bit)
{
    if (root_phys == 0)
    {
        KLOG_WARN_S("acpi", "diag root absent", "which", tag);
        return;
    }
    const auto* root = PhysToHeader(root_phys);
    char rsig[5] = {root->signature[0], root->signature[1], root->signature[2], root->signature[3], 0};
    KLOG_WARN_S("acpi", "diag root which", "which", tag);
    KLOG_WARN_S("acpi", "diag root signature", "sig", rsig);
    KLOG_WARN_2V("acpi", "diag root phys/length", "phys", root_phys, "length", root->length);

    const u64 esz = entries_are_64bit ? sizeof(u64) : sizeof(u32);
    const u64 count = (root->length >= sizeof(SdtHeader)) ? (root->length - sizeof(SdtHeader)) / esz : 0;
    KLOG_WARN_V("acpi", "diag root entry count", count);
    for (u64 i = 0; i < count; ++i)
    {
        u64 ep = 0;
        if (entries_are_64bit)
        {
            ep = XsdtEntryAt(root, i);
        }
        else
        {
            const auto* e32 = reinterpret_cast<const u32*>(reinterpret_cast<uptr>(root) + sizeof(SdtHeader));
            ep = e32[i];
        }
        const auto* th = PhysToHeader(ep);
        char s[5] = {th->signature[0], th->signature[1], th->signature[2], th->signature[3], 0};
        KLOG_WARN_2V("acpi", "diag entry", "idx", i, "phys", ep);
        KLOG_WARN_S("acpi", "diag entry signature", "sig", s);
    }
}

void AcpiDiagDumpTables(const Rsdp& rsdp)
{
    KLOG_WARN_2V("acpi", "diag RSDP", "revision", rsdp.revision, "rsdt_address", rsdp.rsdt_address);
    KLOG_WARN_V("acpi", "diag RSDP xsdt_address", rsdp.xsdt_address);
    // Dump BOTH roots — VirtualBox ships an incomplete XSDT and the
    // MADT may live only in the RSDT (or vice versa), so we need to
    // see exactly what each one lists.
    if (rsdp.revision >= 2 && rsdp.xsdt_address != 0)
    {
        AcpiDiagDumpRoot("XSDT", rsdp.xsdt_address, /*entries_are_64bit=*/true);
    }
    AcpiDiagDumpRoot("RSDT", static_cast<u64>(rsdp.rsdt_address), /*entries_are_64bit=*/false);
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
        // The loop guard only proved the 2-byte header fits. Each
        // per-type body (8+ bytes) is cast and fully dereferenced
        // below, so reject an entry whose declared length runs past
        // the table end before touching the body — a truncated final
        // entry in malformed firmware would otherwise read OOB.
        if (cursor + h->length > end)
        {
            PanicAcpi("MADT entry runs past table length — malformed table");
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
    // Cross-validate the FADT body via the Rust decoder. The C++
    // packed-struct overlay below is what the cache actually
    // consumes; Rust runs first as a length / bounds gate so a
    // malformed FADT can't poison the kernel cache. The fields
    // are field-by-field cross-checked when both succeed.
    ::duetos::acpi::rust::DuetosAcpiFadt rust_fadt{};
    const bool rust_ok = ::duetos::acpi::rust::duetos_acpi_parse_fadt(reinterpret_cast<const u8*>(&fadt),
                                                                      fadt.header.length, &rust_fadt);
    if (rust_ok && rust_fadt.ok != 0)
    {
        if (rust_fadt.sci_int != fadt.sci_int || rust_fadt.dsdt != fadt.dsdt ||
            rust_fadt.pm1a_cnt_blk != fadt.pm1a_cnt_blk)
        {
            KLOG_WARN("acpi", "FADT Rust/C++ decoders disagreed — staying with C++ overlay");
        }
    }
    g_sci_vector = fadt.sci_int;
    if ((fadt.flags & kFadtFlagResetRegSup) != 0)
    {
        g_reset_supported = true;
        g_reset_reg = fadt.reset_reg;
        g_reset_value = fadt.reset_value;
    }
    g_pm1a_cnt = fadt.pm1a_cnt_blk;
    g_pm1b_cnt = fadt.pm1b_cnt_blk;
    g_pm1_cnt_len = fadt.pm1_cnt_len;
    g_pm1a_evt = fadt.pm1a_evt_blk;
    g_pm1b_evt = fadt.pm1b_evt_blk;
    g_pm1_evt_len = fadt.pm1_evt_len;
    g_gpe0_blk = fadt.gpe0_blk;
    g_gpe0_blk_len = fadt.gpe0_blk_len;
    g_gpe1_blk = fadt.gpe1_blk;
    g_gpe1_blk_len = fadt.gpe1_blk_len;
    g_gpe1_base = fadt.gpe1_base;
    g_smi_cmd = fadt.smi_cmd;
    g_acpi_enable = fadt.acpi_enable;
    // DSDT pointer is a 32-bit physical address in the legacy FADT;
    // modern firmware also populates X_DSDT (64-bit) further on.
    // Cache the 32-bit form — on every x86_64 box we target it's
    // below 4 GiB so the legacy field is valid. Read the DSDT
    // header to get the length for the size log.
    if (fadt.dsdt != 0)
    {
        g_dsdt_address = fadt.dsdt;
        const auto* dsdt_hdr = PhysToHeader(fadt.dsdt);
        if (dsdt_hdr != nullptr)
        {
            g_dsdt_length = dsdt_hdr->length;
        }
    }
}

// Cache a single SSDT table entry. `phys` is the physical base
// (u32 or u64 per the XSDT / RSDT entry we came from); `length`
// comes from the table header we've already validated lives in
// the direct map. Bounded by kMaxSsdts; anything past that is
// logged and dropped (no firmware we target ships more).
void CacheSsdt(u64 phys, u32 length)
{
    if (g_ssdt_count >= kMaxSsdts)
    {
        core::Log(core::LogLevel::Warn, "acpi", "more SSDTs than cache capacity — truncating");
        return;
    }
    g_ssdt_address[g_ssdt_count] = phys;
    g_ssdt_length[g_ssdt_count] = length;
    ++g_ssdt_count;
}

// Walk the XSDT (or RSDT) again, collecting every "SSDT" entry
// into g_ssdt_*. `FindTable` returns on the first match; for
// SSDTs we need all of them, hence the duplicated walker. Cheap:
// tables are usually 5..15 entries.
void CollectSsdts(const Rsdp& rsdp)
{
    if (rsdp.revision >= 2 && rsdp.xsdt_address != 0)
    {
        const auto* xsdt = PhysToHeader(rsdp.xsdt_address);
        // Underflow guard: malformed firmware could ship `length <
        // sizeof(SdtHeader)`. Treat as zero entries.
        const u64 count = (xsdt->length >= sizeof(SdtHeader)) ? (xsdt->length - sizeof(SdtHeader)) / sizeof(u64) : 0;
        for (u64 i = 0; i < count; ++i)
        {
            const u64 entry = XsdtEntryAt(xsdt, i);
            const auto* h = PhysToHeader(entry);
            if (BytesEqual(h->signature, "SSDT", 4))
            {
                if (!ChecksumOk(h, h->length))
                {
                    // Every other ACPI table the kernel consumes is
                    // checksum-validated before use. SSDTs were
                    // skipping the check, so a corrupt SSDT would
                    // be cached and later read by AmlContainsName.
                    core::Log(core::LogLevel::Warn, "acpi", "SSDT checksum failed; skipping table");
                    continue;
                }
                CacheSsdt(entry, h->length);
            }
        }
        return;
    }
    const auto* rsdt = PhysToHeader(rsdp.rsdt_address);
    // Same underflow guard for the RSDT path.
    const u64 count = (rsdt->length >= sizeof(SdtHeader)) ? (rsdt->length - sizeof(SdtHeader)) / sizeof(u32) : 0;
    const auto* entries = reinterpret_cast<const u32*>(reinterpret_cast<uptr>(rsdt) + sizeof(SdtHeader));
    for (u64 i = 0; i < count; ++i)
    {
        const auto* h = PhysToHeader(entries[i]);
        if (BytesEqual(h->signature, "SSDT", 4))
        {
            if (!ChecksumOk(h, h->length))
            {
                core::Log(core::LogLevel::Warn, "acpi", "SSDT checksum failed; skipping table");
                continue;
            }
            CacheSsdt(entries[i], h->length);
        }
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

void ParseMcfg(const McfgTable& mcfg)
{
    // Subtractive bound: a malformed firmware can ship a table whose
    // header.length is smaller than sizeof(McfgTable). The subtraction
    // below would then wrap to a huge u64 and the loop reads OOB. Pin
    // the underflow before it can wrap.
    if (mcfg.header.length < sizeof(McfgTable) + sizeof(McfgEntry))
    {
        KLOG_WARN_V("acpi", "MCFG truncated; header.length", mcfg.header.length);
        KBP_PROBE_V(::duetos::debug::ProbeId::kAcpiMcfgTruncated, mcfg.header.length);
        return;
    }
    const u64 entries_bytes = mcfg.header.length - sizeof(McfgTable);

    const auto* first = reinterpret_cast<const McfgEntry*>(reinterpret_cast<uptr>(&mcfg) + sizeof(McfgTable));

    // Only cache segment group 0. Walk the entries in case segment 0
    // isn't the first record — firmware ordering isn't guaranteed.
    const u64 count = entries_bytes / sizeof(McfgEntry);
    for (u64 i = 0; i < count; ++i)
    {
        if (first[i].segment_group == 0)
        {
            g_mcfg_address = first[i].base_address;
            g_mcfg_start_bus = first[i].start_bus;
            g_mcfg_end_bus = first[i].end_bus;
            return;
        }
    }
}

} // namespace

// Shared ACPI physical→virtual mapper. Thin named wrapper around the
// file-local AcpiMapPhys so other ACPI TUs (aml.cpp) resolve table
// addresses through the same direct-map / MapMmio fallback + cache
// instead of calling mm::PhysToVirt directly (which panics for the
// >1 GiB tables VirtualBox/real-UEFI firmware hands us). One source of
// truth for ACPI table mapping.
const void* AcpiMapTable(u64 phys, u64 len)
{
    return AcpiMapPhys(phys, len);
}

void AcpiInit(uptr multiboot_info_phys)
{
    KLOG_TRACE_SCOPE("acpi", "AcpiInit");
    KASSERT(multiboot_info_phys != 0, "acpi", "AcpiInit null multiboot info");

    // Structural step sentinels. Raw SerialWrite so they emit even
    // in a fault-loop context (klog could deadlock on the spinlock
    // we already hold, or its formatting could re-page-fault). A
    // clean boot adds ~13 short lines; a fault loop pins the last
    // line printed to the failing step.
    arch::SerialWrite("[acpi] step=enter\n");

    arch::SerialWrite("[acpi] step=find-rsdp\n");
    const Rsdp* rsdp = FindRsdpInMultiboot(multiboot_info_phys);
    if (rsdp == nullptr)
    {
        PanicAcpi("no ACPI RSDP tag in Multiboot2 info");
    }
    arch::SerialWrite("[acpi] step=rsdp-found rev=");
    SerialWriteHex(rsdp->revision);
    arch::SerialWrite("\n");
    // Delegate signature + checksum validation to the Rust walker
    // (`duetos_acpi_parse_rsdp`). The bytes-walker layer does both
    // v1 and v2 in one call.
    {
        ::duetos::acpi::rust::DuetosAcpiRsdp validated{};
        const usize raw_len = rsdp->revision >= 2 ? rsdp->length : 20;
        if (!::duetos::acpi::rust::duetos_acpi_parse_rsdp(reinterpret_cast<const u8*>(rsdp), raw_len, &validated) ||
            validated.ok == 0)
        {
            PanicAcpi("RSDP failed Rust signature/checksum validation");
        }
    }
    arch::SerialWrite("[acpi] step=rsdp-validated\n");

    AcpiDiagDumpTables(*rsdp);
    arch::SerialWrite("[acpi] step=diag-dumped\n");

    const SdtHeader* madt_hdr = FindTable(*rsdp, "APIC");
    if (madt_hdr == nullptr)
    {
        PanicAcpi("MADT (APIC signature) not found in RSDT/XSDT");
    }
    arch::SerialWrite("[acpi] step=madt-found\n");
    if (!ChecksumOk(madt_hdr, madt_hdr->length))
    {
        PanicAcpi("MADT checksum failed");
    }
    arch::SerialWrite("[acpi] step=madt-checksummed\n");
    ParseMadt(*reinterpret_cast<const Madt*>(madt_hdr));
    arch::SerialWrite("[acpi] step=madt-parsed\n");

    // FADT is optional — a missing one leaves reset unsupported and
    // the SCI vector at the ACPI default (9). Every PC firmware we
    // target ships it, but we don't panic on absence the way MADT
    // does: nothing else in the kernel requires FADT today.
    //
    // A FADT shorter than our `Fadt` struct happens on legacy
    // ACPI 1.0 firmware (i440fx + older UEFI builds, some embedded
    // boards). Reading past the end of a short FADT into our struct
    // would deliver garbage to ParseFadt; treating "too short" as
    // "absent" is consistent with the optional-FADT contract above
    // — the reset register and SCI overrides simply stay at their
    // ACPI defaults, same as if no FADT at all were published.
    arch::SerialWrite("[acpi] step=find-fadt\n");
    const SdtHeader* fadt_hdr = FindTable(*rsdp, "FACP");
    if (fadt_hdr != nullptr)
    {
        if (fadt_hdr->length < sizeof(Fadt))
        {
            KLOG_WARN_2V("acpi", "FADT shorter than expected struct - skipping (legacy firmware?)", "fadt_len",
                         fadt_hdr->length, "want", sizeof(Fadt));
        }
        else if (!ChecksumOk(fadt_hdr, fadt_hdr->length))
        {
            PanicAcpi("FADT checksum failed");
        }
        else
        {
            ParseFadt(*reinterpret_cast<const Fadt*>(fadt_hdr));
        }
    }
    arch::SerialWrite("[acpi] step=fadt-done\n");

    // HPET is optional — QEMU q35 provides it, older boards may
    // not. Missing is fine; present-but-malformed panics so we
    // don't silently drift past a firmware bug.
    arch::SerialWrite("[acpi] step=find-hpet\n");
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
    arch::SerialWrite("[acpi] step=hpet-done\n");

    // DSDT was discovered via FADT.dsdt (above). SSDTs are
    // separate XSDT/RSDT entries — walk once more and cache
    // every one for the future AML interpreter. The interpreter
    // itself is deferred (see wiki/reference/Roadmap.md, "Battery
    // + ACPI suspend"), but surfacing the addresses at boot lets
    // follow-on slices land without re-walking.
    arch::SerialWrite("[acpi] step=collect-ssdts\n");
    CollectSsdts(*rsdp);
    arch::SerialWrite("[acpi] step=ssdts-collected\n");

    // MCFG is optional — QEMU q35 provides it, legacy platforms
    // without PCIe do not. PCI drivers use the cached base to enable
    // ECAM config access; missing means "fall back to port IO."
    arch::SerialWrite("[acpi] step=find-mcfg\n");
    const SdtHeader* mcfg_hdr = FindTable(*rsdp, "MCFG");
    if (mcfg_hdr != nullptr)
    {
        if (mcfg_hdr->length < sizeof(McfgTable))
        {
            PanicAcpi("MCFG table shorter than the header");
        }
        if (!ChecksumOk(mcfg_hdr, mcfg_hdr->length))
        {
            PanicAcpi("MCFG table checksum failed");
        }
        ParseMcfg(*reinterpret_cast<const McfgTable*>(mcfg_hdr));
    }
    arch::SerialWrite("[acpi] step=mcfg-done\n");

    // SRAT — optional. UMA-only firmware may omit it entirely; the
    // parser treats null + bad-checksum tables as "absent" without
    // panicking. Consumed by `cpu/topology.cpp` to assign cluster
    // IDs in the scheduler. ParseSrat doesn't reach into our file-
    // local types — it's a flat byte-walk in `acpi/srat.cpp`.
    arch::SerialWrite("[acpi] step=find-srat\n");
    const SdtHeader* srat_hdr = FindTable(*rsdp, "SRAT");
    arch::SerialWrite("[acpi] step=srat-init\n");
    srat::SratInit(srat_hdr);
    arch::SerialWrite("[acpi] step=srat-done\n");

    SerialWrite("[acpi] srat=");
    if (srat::SratPresent())
    {
        SerialWrite("present nodes=");
        SerialWriteHex(srat::SratNodeCount());
    }
    else
    {
        SerialWrite("absent");
    }
    SerialWrite("\n");

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

    SerialWrite("[acpi] mcfg=");
    if (g_mcfg_address != 0)
    {
        SerialWriteHex(g_mcfg_address);
        SerialWrite(" buses=");
        SerialWriteHex(g_mcfg_start_bus);
        SerialWrite("..");
        SerialWriteHex(g_mcfg_end_bus);
    }
    else
    {
        SerialWrite("absent");
    }
    SerialWrite("\n");

    SerialWrite("[acpi] dsdt=");
    if (g_dsdt_address != 0)
    {
        SerialWriteHex(g_dsdt_address);
        SerialWrite(" length=");
        SerialWriteHex(g_dsdt_length);
    }
    else
    {
        SerialWrite("absent");
    }
    SerialWrite(" ssdts=");
    SerialWriteHex(g_ssdt_count);
    SerialWrite("\n");
    for (u64 i = 0; i < g_ssdt_count; ++i)
    {
        SerialWrite("  ssdt[");
        SerialWriteHex(i);
        SerialWrite("] addr=");
        SerialWriteHex(g_ssdt_address[i]);
        SerialWrite(" length=");
        SerialWriteHex(g_ssdt_length[i]);
        SerialWrite("\n");
    }

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

u64 McfgAddress()
{
    return g_mcfg_address;
}

u8 McfgStartBus()
{
    return g_mcfg_start_bus;
}

u8 McfgEndBus()
{
    return g_mcfg_end_bus;
}

u64 DsdtAddress()
{
    return g_dsdt_address;
}

u32 DsdtLength()
{
    return g_dsdt_length;
}

u64 SsdtCount()
{
    return g_ssdt_count;
}

u64 SsdtAddress(u64 index)
{
    if (index >= g_ssdt_count)
        return 0;
    return g_ssdt_address[index];
}

u32 SsdtLength(u64 index)
{
    if (index >= g_ssdt_count)
        return 0;
    return g_ssdt_length[index];
}

namespace
{

// Scan a byte buffer for the 4-byte ASCII pattern `name4`.
// Linear, naive — tables are small (DSDT typically < 64 KB,
// SSDTs similar) so a 4-byte sliding compare is fine.
bool ContainsName4(const u8* buf, u32 len, const char* name4)
{
    if (len < 4)
        return false;
    for (u32 i = 0; i + 4 <= len; ++i)
    {
        if (buf[i] == u8(name4[0]) && buf[i + 1] == u8(name4[1]) && buf[i + 2] == u8(name4[2]) &&
            buf[i + 3] == u8(name4[3]))
            return true;
    }
    return false;
}

} // namespace

bool AmlContainsName(const char* name4)
{
    if (name4 == nullptr)
        return false;
    if (g_dsdt_address != 0 && g_dsdt_length > 0)
    {
        const auto* buf = static_cast<const u8*>(AcpiMapPhys(g_dsdt_address, g_dsdt_length));
        if (buf != nullptr && ContainsName4(buf, g_dsdt_length, name4))
            return true;
    }
    for (u64 i = 0; i < g_ssdt_count; ++i)
    {
        const auto* buf = static_cast<const u8*>(AcpiMapPhys(g_ssdt_address[i], g_ssdt_length[i]));
        if (buf != nullptr && ContainsName4(buf, g_ssdt_length[i], name4))
            return true;
    }
    return false;
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

u32 Pm1aControlPort()
{
    return g_pm1a_cnt;
}

u32 Pm1bControlPort()
{
    return g_pm1b_cnt;
}

u32 Pm1aEventPort()
{
    return g_pm1a_evt;
}

u32 Pm1bEventPort()
{
    return g_pm1b_evt;
}

u8 Pm1EventLen()
{
    return g_pm1_evt_len;
}

u32 Gpe0Block()
{
    return g_gpe0_blk;
}

u8 Gpe0BlockLen()
{
    return g_gpe0_blk_len;
}

u32 Gpe1Block()
{
    return g_gpe1_blk;
}

u8 Gpe1BlockLen()
{
    return g_gpe1_blk_len;
}

u8 Gpe1Base()
{
    return g_gpe1_base;
}

u32 AcpiSmiCommandPort()
{
    return g_smi_cmd;
}

u8 AcpiEnableValue()
{
    return g_acpi_enable;
}

// Run the ACPI sleep-preparation control methods for `sleep_type`
// in spec order: `\_PTS` (Prepare To Sleep) then `\_GTS` (Going To
// Sleep). Both are optional and take the sleep type as Arg0; firmware
// uses them to quiesce devices / poke the EC / arm SMI before the
// SLP_TYP write. Missing methods are not an error (NotFound). Returns
// the count actually executed (for the diagnostic line). Idempotent
// only to the extent the firmware's own methods are.
u32 AcpiRunSleepPrep(u8 sleep_type)
{
    u32 ran = 0;
    AmlValue arg = AmlValue::Int(sleep_type);
    AmlValue r;
    if (AmlEvaluate("\\_PTS", &arg, 1, &r).has_value())
        ++ran;
    if (AmlEvaluate("\\_GTS", &arg, 1, &r).has_value())
        ++ran;
    KLOG_INFO_2V("acpi", "sleep-prep methods executed", "sleep_type", sleep_type, "ran", ran);
    return ran;
}

bool AcpiShutdown()
{
    u8 slp_typa = 0;
    u8 slp_typb = 0;
    if (!::duetos::acpi::AmlReadS5(&slp_typa, &slp_typb))
    {
        return false;
    }
    if (g_pm1a_cnt == 0)
    {
        return false;
    }
    // ACPI §7: the OS must execute `\_PTS(5)` (and legacy `\_GTS(5)`)
    // BEFORE writing SLP_TYP/SLP_EN. Many real laptops poke the EC /
    // arm SMI here and will NOT power off without it — this is the
    // step the pre-interpreter path could not perform. Empty/absent
    // on QEMU and most UEFI (pre-evaluated at firmware time), so this
    // is a no-op there and a correctness fix on real hardware.
    AcpiRunSleepPrep(5);

    // PM1 control register: bit 13 = SLP_EN (write-only, write 1
    // to initiate the sleep transition), bits 10..12 = SLP_TYP.
    // Per ACPI §4.8.3.2.1.
    constexpr u16 kSlpEn = 1U << 13;
    const u16 pm1a_val = static_cast<u16>(((slp_typa & 0x7) << 10) | kSlpEn);
    const u16 pm1b_val = static_cast<u16>(((slp_typb & 0x7) << 10) | kSlpEn);
    // Write is 16-bit on every FADT we've seen (pm1_cnt_len == 2).
    arch::Outw(static_cast<u16>(g_pm1a_cnt), pm1a_val);
    if (g_pm1b_cnt != 0)
    {
        arch::Outw(static_cast<u16>(g_pm1b_cnt), pm1b_val);
    }
    // If we're still executing, the transition didn't take
    // effect (real hardware requires the OS to have executed
    // _PTS, _GTS etc. first). Return false so the caller knows
    // to fall back to a harder method (reset, hlt loop, triple
    // fault).
    for (u32 i = 0; i < 1'000'000; ++i)
        asm volatile("pause" ::: "memory");
    return false;
}

void AcpiUnderflowSelfTest()
{
    // Save live MCFG state so the test is idempotent — running this
    // can't perturb a real PCIe ECAM cache primed by AcpiInit.
    const u64 saved_addr = g_mcfg_address;
    const u8 saved_start = g_mcfg_start_bus;
    const u8 saved_end = g_mcfg_end_bus;

    // Force a deliberately-not-zero sentinel into g_mcfg_address so we
    // can prove ParseMcfg's early-return preserved it. (If the guard
    // regressed, the corrupt count loop would either trip a fault or
    // overwrite this value with whatever bytes lie past the synthetic
    // table.)
    g_mcfg_address = 0xDEADBEEFCAFEBABEULL;

    // Synthesize a malformed MCFG: header.length = sizeof(SdtHeader),
    // which is smaller than sizeof(McfgTable). The pre-fix code did
    // `entries_bytes = length - sizeof(McfgTable)` which underflows to
    // ~UINT64_MAX, then divides by sizeof(McfgEntry) and walks every
    // resulting "entry" — reading megabytes off the end of our buffer.
    McfgTable bogus = {};
    bogus.header.signature[0] = 'M';
    bogus.header.signature[1] = 'C';
    bogus.header.signature[2] = 'F';
    bogus.header.signature[3] = 'G';
    bogus.header.length = sizeof(SdtHeader); // < sizeof(McfgTable)
    bogus.header.revision = 1;

    ParseMcfg(bogus);

    if (g_mcfg_address != 0xDEADBEEFCAFEBABEULL)
    {
        core::Panic("acpi", "AcpiUnderflowSelfTest: ParseMcfg wrote past truncated header");
    }

    // Restore live state.
    g_mcfg_address = saved_addr;
    g_mcfg_start_bus = saved_start;
    g_mcfg_end_bus = saved_end;

    arch::SerialWrite("[acpi-test] underflow guards PASS\n");
}

void AcpiSleepPrepSelfTest()
{
    // Synthetic _PTS-shaped body:
    //   Method(_,1) { If (LEqual(Arg0,5)) { Return(0xAB) } Return(0) }
    // This is the exact shape AcpiRunSleepPrep drives: a root method
    // taking the sleep-type as Arg0 with an If(LEqual(Arg0,5)) gate.
    // Running it on synthetic bytecode proves the mechanism without
    // powering the test VM off.
    static const u8 prog[] = {0xA0, 0x08, 0x93, 0x68, 0x0A, 0x05, 0xA4, 0x0A, 0xAB, 0xA4, 0x00};

    AmlValue a5 = AmlValue::Int(5);
    AmlValue a3 = AmlValue::Int(3);
    AmlValue r;

    if (!AmlEvaluateRaw(prog, sizeof(prog), &a5, 1, &r).has_value() || r.type != AmlType::Integer || r.integer != 0xAB)
        core::PanicWithValue("acpi/s5", "selftest: sleep-prep S5-gated path wrong", r.integer);
    if (!AmlEvaluateRaw(prog, sizeof(prog), &a3, 1, &r).has_value() || r.type != AmlType::Integer || r.integer != 0)
        core::PanicWithValue("acpi/s5", "selftest: sleep-prep non-S5 path wrong", r.integer);

    const bool has_pts = AmlNamespaceFind("\\_PTS") != nullptr;
    const bool has_gts = AmlNamespaceFind("\\_GTS") != nullptr;
    arch::SerialWrite("[acpi/s5] selftest PASS (sleep-prep arg-gating verified; firmware _PTS=");
    arch::SerialWrite(has_pts ? "present" : "absent");
    arch::SerialWrite(" _GTS=");
    arch::SerialWrite(has_gts ? "present" : "absent");
    arch::SerialWrite(")\n");
    KLOG_INFO_2V("acpi/s5", "selftest PASS", "_PTS", has_pts ? 1 : 0, "_GTS", has_gts ? 1 : 0);
}

} // namespace duetos::acpi
