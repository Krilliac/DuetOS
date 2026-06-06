/*
 * DuetOS — AML interpreter (v0): implementation.
 *
 * Companion to aml.h — see there for the supported opcode
 * subset and the integration points (the shell `acpi` command,
 * device-power transitions).
 *
 * WHAT
 *   A minimal walker over AML byte streams from the DSDT/SSDT.
 *   v0 covers the opcodes we actually need to read battery /
 *   thermal / device-power state and to evaluate simple `_STA`
 *   methods. Anything outside that subset returns "not
 *   supported" so the caller falls back to a default.
 *
 * HOW
 *   The interpreter is a pure-software walker — no JIT, no
 *   intermediate IR. State lives in a small struct that
 *   tracks the current cursor, scope chain, and named-object
 *   table. Each opcode handler decodes operands, executes,
 *   and either advances or pushes a new scope.
 *
 * WHY THIS FILE IS LARGE
 *   AML has ~80 opcodes in the v0 subset. Each handler is
 *   short but they accumulate. A switch over the leading
 *   byte (with two-byte ExtOp prefix handled in a nested
 *   switch) compiles to a tight jump table.
 */

#include "acpi/aml.h"

#include "arch/x86_64/serial.h"
#include "diag/fix_journal.h"
#include "log/klog.h"
#include "core/panic.h"
#include "mm/page.h"
#include "acpi/acpi.h"
#include "acpi/aml_rust/include/aml_rust.h"

namespace duetos::acpi
{

namespace
{

constinit AmlNamespaceEntry g_entries[kMaxAmlNsEntries] = {};
constinit u32 g_entry_count = 0;

// OperationRegion + FieldUnit index. Populated alongside the
// namespace walk; consumed by the AML method interpreter
// (aml_eval.cpp) to back FieldUnit reads/writes.
inline constexpr u32 kMaxAmlRegions = 64;
inline constexpr u32 kMaxAmlFields = 256;
constinit AmlRegionInfo g_regions[kMaxAmlRegions] = {};
constinit u32 g_region_count = 0;
constinit AmlFieldInfo g_fields[kMaxAmlFields] = {};
constinit u32 g_field_count = 0;

// Module-scope so `AmlNamespaceShutdown` can clear it and a
// subsequent `AmlNamespaceBuild` re-runs the walk. Was a
// function-local `static constinit` while this subsystem was
// init-once; lifted out for the fault-domain restart path.
constinit bool g_built = false;


inline bool IsLeadNameChar(u8 c)
{
    return c == '_' || (c >= 'A' && c <= 'Z');
}
inline bool IsNameChar(u8 c)
{
    return IsLeadNameChar(c) || (c >= '0' && c <= '9');
}

// Decode a PkgLength field. ACPI 6.x §20.2.4. Returns the encoded
// length in `*out_len` and the byte count consumed in `*out_consumed`.
// On malformed input returns false (caller stops the walk).
bool ReadPkgLength(const u8* p, u64 remaining, u32* out_len, u32* out_consumed)
{
    if (remaining < 1)
        return false;
    const u8 lead = p[0];
    const u32 follow = (lead >> 6) & 0x3;
    if (remaining < u64(1 + follow))
        return false;
    if (follow == 0)
    {
        *out_len = lead & 0x3F;
        *out_consumed = 1;
        return true;
    }
    u32 len = lead & 0x0F;
    for (u32 i = 0; i < follow; ++i)
        len |= u32(p[1 + i]) << (4 + i * 8);
    *out_len = len;
    *out_consumed = 1 + follow;
    return true;
}

// Parse a NameString (ACPI 6.x §20.2.2) into a flat C-string.
// Forms:
//   '\\' (root) followed by NamePath
//   ('^')+      followed by NamePath
//   NamePath
//
// NamePath:
//   NameSeg            (4 chars: lead + 3 name chars)
//   DualNamePath       0x2E NameSeg NameSeg
//   MultiNamePath      0x2F SegCount NameSeg{SegCount}
//   NullName           0x00
//
// We emit "\seg.seg.seg" or "^^seg.seg" or just "seg.seg" (no
// leading separator). out_buf is at least 64 bytes.
struct NameStringInfo
{
    char text[64];    // NUL-terminated
    u32 prefix_caret; // count of leading '^' chars (parent-scope hops)
    bool absolute;    // true iff started with '\\'
    bool null_name;   // true iff the entire name was 0x00 (NullName)
};

bool ReadNameString(const u8* p, u64 remaining, NameStringInfo* out, u32* out_consumed)
{
    *out = NameStringInfo{};
    u32 pos = 0;

    // Prefix: at most one of '\\' or many '^'.
    if (pos < remaining && p[pos] == '\\')
    {
        out->absolute = true;
        ++pos;
    }
    else
    {
        while (pos < remaining && p[pos] == '^')
        {
            ++out->prefix_caret;
            ++pos;
        }
    }

    if (pos >= remaining)
        return false;

    // NullName.
    if (p[pos] == 0x00)
    {
        out->null_name = true;
        out->text[0] = '\0';
        *out_consumed = pos + 1;
        return true;
    }

    u8 seg_count = 1;
    if (p[pos] == 0x2E) // DualNamePrefix
    {
        seg_count = 2;
        ++pos;
    }
    else if (p[pos] == 0x2F) // MultiNamePrefix
    {
        ++pos;
        if (pos >= remaining)
            return false;
        seg_count = p[pos];
        ++pos;
        if (seg_count == 0)
            return false;
    }

    if (pos + u64(seg_count) * 4 > remaining)
        return false;

    u32 write = 0;
    for (u8 s = 0; s < seg_count; ++s)
    {
        if (s != 0)
        {
            if (write + 1 >= sizeof(out->text))
                return false;
            out->text[write++] = '.';
        }
        for (u8 i = 0; i < 4; ++i)
        {
            const u8 c = p[pos + i];
            if (i == 0 ? !IsLeadNameChar(c) : !IsNameChar(c))
                return false;
            if (write + 1 >= sizeof(out->text))
                return false;
            out->text[write++] = char(c);
        }
        pos += 4;
    }
    out->text[write] = '\0';
    *out_consumed = pos;
    return true;
}

// The recursive AML TermList walker now lives in the memory-safe
// no_std `duetos_aml` Rust crate (kernel/acpi/aml_rust/). The C++
// side keeps only the namespace-table storage + accessors and the
// small offset-based slicers (AmlMethodBody / AmlNameValue /
// AmlReadS5) the evaluator drives. The walker writes named-object
// records straight into the global tables, so the kernel structs
// must stay layout-compatible with the crate's FFI mirrors — a
// drift here is a build break, not a silent runtime corruption.
static_assert(sizeof(AmlNamespaceEntry) == sizeof(rust::DuetosAmlEntry), "AmlNamespaceEntry / DuetosAmlEntry layout");
static_assert(sizeof(AmlRegionInfo) == sizeof(rust::DuetosAmlRegion), "AmlRegionInfo / DuetosAmlRegion layout");
static_assert(sizeof(AmlFieldInfo) == sizeof(rust::DuetosAmlField), "AmlFieldInfo / DuetosAmlField layout");
static_assert(__builtin_offsetof(AmlNamespaceEntry, aml_offset) == __builtin_offsetof(rust::DuetosAmlEntry, aml_offset),
              "AmlNamespaceEntry::aml_offset offset");
static_assert(__builtin_offsetof(AmlRegionInfo, base) == __builtin_offsetof(rust::DuetosAmlRegion, base),
              "AmlRegionInfo::base offset");
static_assert(__builtin_offsetof(AmlFieldInfo, region) == __builtin_offsetof(rust::DuetosAmlField, region),
              "AmlFieldInfo::region offset");

// Walk one cached table's AML body via the Rust crate, appending
// into the global namespace / region / field tables (running counts
// carried across the DSDT + every SSDT, exactly as the former C++
// per-table walk did).
void WalkTable(const u8* sdt, u32 total_len, u8 source_idx)
{
    rust::duetos_aml_walk_table(sdt, total_len, source_idx, reinterpret_cast<rust::DuetosAmlEntry*>(g_entries),
                                kMaxAmlNsEntries, &g_entry_count, reinterpret_cast<rust::DuetosAmlRegion*>(g_regions),
                                kMaxAmlRegions, &g_region_count, reinterpret_cast<rust::DuetosAmlField*>(g_fields),
                                kMaxAmlFields, &g_field_count);
}

} // namespace

const char* AmlObjectKindName(AmlObjectKind k)
{
    switch (k)
    {
    case AmlObjectKind::Scope:
        return "Scope";
    case AmlObjectKind::Device:
        return "Device";
    case AmlObjectKind::Method:
        return "Method";
    case AmlObjectKind::Name:
        return "Name";
    case AmlObjectKind::OpRegion:
        return "OpRegion";
    case AmlObjectKind::Mutex:
        return "Mutex";
    case AmlObjectKind::Event:
        return "Event";
    case AmlObjectKind::Alias:
        return "Alias";
    case AmlObjectKind::External:
        return "External";
    case AmlObjectKind::Processor:
        return "Processor";
    case AmlObjectKind::ThermalZone:
        return "ThermalZone";
    case AmlObjectKind::PowerResource:
        return "PowerResource";
    case AmlObjectKind::Field:
        return "Field";
    default:
        return "?";
    }
}

void AmlNamespaceBuild()
{
    KLOG_TRACE_SCOPE("acpi/aml", "AmlNamespaceBuild");
    if (g_built)
        return;
    g_built = true;

    const u64 dsdt_phys = DsdtAddress();
    const u32 dsdt_len = DsdtLength();
    if (dsdt_phys != 0 && dsdt_len >= 36)
    {
        const auto* sdt = static_cast<const u8*>(AcpiMapTable(dsdt_phys, dsdt_len));
        if (sdt != nullptr)
            WalkTable(sdt, dsdt_len, /*source_idx=*/0);
    }
    const u64 ssdt_n = SsdtCount();
    for (u64 i = 0; i < ssdt_n; ++i)
    {
        const u64 phys = SsdtAddress(i);
        const u32 len = SsdtLength(i);
        if (phys == 0 || len < 36)
            continue;
        const auto* sdt = static_cast<const u8*>(AcpiMapTable(phys, len));
        if (sdt != nullptr)
            WalkTable(sdt, len, u8(i + 1));
    }

    // Klog-side summary mirrors the rich serial dump below: gives
    // dmesg a single high-signal line ("namespace built — N
    // entries") plus emits the original detailed hex on serial for
    // anyone watching at boot. KLOG_INFO_2V pins the count + cap
    // so saturation against kMaxAmlNsEntries is grep-able from a
    // post-mortem.
    KLOG_INFO_2V("acpi/aml", "namespace built", "entries", g_entry_count, "cap", kMaxAmlNsEntries);
    arch::SerialWrite("[acpi/aml] namespace: ");
    arch::SerialWriteHex(g_entry_count);
    arch::SerialWrite(" entries (cap ");
    arch::SerialWriteHex(kMaxAmlNsEntries);
    arch::SerialWrite("): scopes=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::Scope));
    arch::SerialWrite(" devices=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::Device));
    arch::SerialWrite(" methods=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::Method));
    arch::SerialWrite(" opregions=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::OpRegion));
    arch::SerialWrite(" thermal=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::ThermalZone));
    arch::SerialWrite(" power=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::PowerResource));
    arch::SerialWrite(" cpus=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::Processor));
    arch::SerialWrite("\n");
}

::duetos::core::Result<void> AmlNamespaceShutdown()
{
    KLOG_TRACE_SCOPE("acpi/aml", "AmlNamespaceShutdown");
    const u32 dropped = g_entry_count;
    g_entry_count = 0;
    g_region_count = 0;
    g_field_count = 0;
    g_built = false;
    KLOG_INFO_V("acpi/aml", "namespace shutdown — dropped entries", dropped);
    arch::SerialWrite("[acpi/aml] shutdown: dropped ");
    arch::SerialWriteHex(dropped);
    arch::SerialWrite(" namespace entries\n");
    return {};
}

u32 AmlNamespaceCount()
{
    return g_entry_count;
}

const AmlNamespaceEntry* AmlNamespaceEntryAt(u32 i)
{
    if (i >= g_entry_count)
        return nullptr;
    return &g_entries[i];
}

const AmlNamespaceEntry* AmlNamespaceFind(const char* path)
{
    if (path == nullptr)
        return nullptr;
    for (u32 i = 0; i < g_entry_count; ++i)
    {
        const char* a = g_entries[i].path;
        const char* b = path;
        while (*a != '\0' && *a == *b)
        {
            ++a;
            ++b;
        }
        if (*a == '\0' && *b == '\0')
            return &g_entries[i];
    }
    return nullptr;
}

u32 AmlNamespaceCountByKind(AmlObjectKind k)
{
    u32 n = 0;
    for (u32 i = 0; i < g_entry_count; ++i)
    {
        if (g_entries[i].kind == k)
            ++n;
    }
    return n;
}

// Read the two-byte SLP_TYP values encoded in `\_S5` /  `\_S5_`.
// Two firmware shapes are recognised:
//
//   1. Name(_S5_, Package(4) { SLP_TYPa, SLP_TYPb, ... })  — the
//      classic UEFI / QEMU shape. The namespace builder records
//      this with `kind == Name` and aml_offset pointing at the
//      4-char "_S5_" NameString.
//
//   2. Method(_S5_, 0, NotSerialized) { Return(Package(4)
//      { SLP_TYPa, SLP_TYPb, ... }) }  — used by some consumer
//      firmware (notably older OEM-modified UEFIs). The namespace
//      builder records this with `kind == Method` and aml_offset
//      pointing at the 0x14 MethodOp byte.
//
// Returns true on a clean extract. On any shape deviation the
// caller stays in "shutdown unsupported" — we don't guess bits.
bool AmlReadS5(u8* slp_typa, u8* slp_typb)
{
    if (slp_typa == nullptr || slp_typb == nullptr)
        return false;
    const AmlNamespaceEntry* entry = AmlNamespaceFind("\\_S5_");
    if (entry == nullptr)
        entry = AmlNamespaceFind("\\_S5");
    if (entry == nullptr || (entry->kind != AmlObjectKind::Name && entry->kind != AmlObjectKind::Method))
        return false;

    const u8* aml = nullptr;
    u32 aml_len = 0;
    if (entry->source_table_idx == 0)
    {
        const u64 dsdt_phys = DsdtAddress();
        if (dsdt_phys == 0)
            return false;
        const u32 dsdt_len = DsdtLength();
        // SdtHeader is 36 bytes; refuse a header-only / truncated
        // table rather than underflowing the subtraction below.
        if (dsdt_len < 36)
            return false;
        const auto* hdr = static_cast<const u8*>(AcpiMapTable(dsdt_phys, dsdt_len));
        aml = hdr + 36; // skip SdtHeader
        aml_len = dsdt_len - 36;
    }
    else
    {
        const u32 idx = entry->source_table_idx - 1;
        if (idx >= SsdtCount())
            return false;
        const u64 ssdt_phys = SsdtAddress(idx);
        if (ssdt_phys == 0)
            return false;
        const u32 ssdt_len = SsdtLength(idx);
        if (ssdt_len < 36)
            return false;
        const auto* hdr = static_cast<const u8*>(AcpiMapTable(ssdt_phys, ssdt_len));
        aml = hdr + 36;
        aml_len = ssdt_len - 36;
    }

    // Overflow-safe bounds check — `aml_offset + 4` could wrap if
    // a corrupt entry stashed UINT32_MAX-3 in aml_offset.
    if (entry->aml_offset > aml_len || aml_len - entry->aml_offset < 4)
        return false;
    u32 p = 0;
    if (entry->kind == AmlObjectKind::Name)
    {
        p = entry->aml_offset + 4; // past the 4-char "_S5_" name
    }
    else
    {
        // Method-form: aml_offset points at MethodOp (0x14).
        // Layout: 0x14 PkgLength NameString MethodFlags TermList.
        // We need to land `p` on the PackageOp inside the
        // body's `Return(Package(...))`. Real OEM bodies in the
        // wild are tiny — a single Return(Package{...}) — so we
        // scan forward looking for the canonical sequence
        // ReturnOp (0xA4) immediately followed by PackageOp (0x12).
        // The match has to lie inside the method's PkgLength
        // span; we don't trust offsets past it.
        if (entry->aml_offset >= aml_len || aml[entry->aml_offset] != 0x14 /* MethodOp */)
            return false;
        u32 q = entry->aml_offset + 1;
        if (q >= aml_len)
            return false;
        // Decode PkgLength to compute the method's end.
        const u8 pkg_lead = aml[q];
        const u32 pkg_extra = pkg_lead >> 6;
        u32 pkg_len_local = pkg_lead & 0x3F;
        if (pkg_extra > 0)
        {
            // Multi-byte PkgLength: the leading nibble's low 4
            // bits become the bottom 4 bits of the length, then
            // the next pkg_extra bytes are appended high-order.
            pkg_len_local = pkg_lead & 0x0F;
            for (u32 k = 0; k < pkg_extra; ++k)
            {
                if (q + 1 + k >= aml_len)
                    return false;
                pkg_len_local |= static_cast<u32>(aml[q + 1 + k]) << (4 + k * 8);
            }
        }
        const u32 method_end_off = q + pkg_len_local;
        if (method_end_off > aml_len || method_end_off < q)
            return false;
        // Skip past PkgLength + NameString (4 bytes for "_S5_") +
        // MethodFlags (1 byte) to reach the body. NameString here
        // is unprefixed (no '\' or '^') because the namespace
        // builder validated it as 4 ASCII chars; consumer
        // firmware uses exactly that form for `_S5_`.
        u32 r = q + 1 + pkg_extra; // past PkgLength
        if (r + 4 + 1 > method_end_off)
            return false;
        r += 4; // past "_S5_"
        ++r;    // past MethodFlags
        // Scan body for ReturnOp (0xA4) followed by PackageOp (0x12).
        // 16-byte cap on scan span: real method bodies for _S5_ are
        // 8 bytes total; refusing anything longer keeps this from
        // becoming a foothold for malformed AML.
        u32 scan_end = method_end_off;
        if (scan_end - r > 16)
            scan_end = r + 16;
        u32 s = 0;
        bool found = false;
        for (u32 k = r; k + 1 < scan_end; ++k)
        {
            if (aml[k] == 0xA4 /* ReturnOp */ && aml[k + 1] == 0x12 /* PackageOp */)
            {
                s = k + 2; // past ReturnOp + PackageOp opcode
                found = true;
                break;
            }
        }
        if (!found)
            return false;
        p = s - 1; // back up so the existing PackageOp validation
                   // below sees the 0x12 byte.
    }
    if (p + 2 > aml_len || aml[p] != 0x12 /* PackageOp */)
        return false;
    ++p;
    // PkgLength: top two bits of the first byte = how many extra
    // bytes follow. For _S5 the package is tiny so usually just
    // 1 byte total.
    if (p >= aml_len)
        return false;
    const u8 pkg_lead = aml[p];
    const u32 pkg_extra = pkg_lead >> 6;
    p += 1 + pkg_extra;
    if (p + 1 > aml_len)
        return false;
    // NumElements (expect >= 2).
    if (aml[p++] < 2)
        return false;

    // Helper: decode a single AML byte-sized integer element.
    auto read_byte = [&](u8* out) -> bool
    {
        if (p >= aml_len)
            return false;
        const u8 op = aml[p++];
        if (op == 0x00)
        {
            *out = 0;
            return true;
        } // ZeroOp
        if (op == 0x01)
        {
            *out = 1;
            return true;
        } // OneOp
        if (op == 0x0A)
        {
            if (p >= aml_len)
                return false;
            *out = aml[p++];
            return true;
        } // BytePrefix
        return false; // Other encodings not supported in v0
    };

    if (!read_byte(slp_typa))
        return false;
    if (!read_byte(slp_typb))
        return false;
    return true;
}

u32 AmlRegionCount()
{
    return g_region_count;
}
const AmlRegionInfo* AmlRegionAt(u32 i)
{
    return i < g_region_count ? &g_regions[i] : nullptr;
}
const AmlRegionInfo* AmlRegionFind(const char* path)
{
    if (path == nullptr)
        return nullptr;
    for (u32 i = 0; i < g_region_count; ++i)
    {
        const char* a = g_regions[i].path;
        const char* b = path;
        while (*a != '\0' && *a == *b)
        {
            ++a;
            ++b;
        }
        if (*a == '\0' && *b == '\0')
            return &g_regions[i];
    }
    return nullptr;
}

u32 AmlFieldCount()
{
    return g_field_count;
}
const AmlFieldInfo* AmlFieldAt(u32 i)
{
    return i < g_field_count ? &g_fields[i] : nullptr;
}
const AmlFieldInfo* AmlFieldFind(const char* path)
{
    if (path == nullptr)
        return nullptr;
    for (u32 i = 0; i < g_field_count; ++i)
    {
        const char* a = g_fields[i].path;
        const char* b = path;
        while (*a != '\0' && *a == *b)
        {
            ++a;
            ++b;
        }
        if (*a == '\0' && *b == '\0')
            return &g_fields[i];
    }
    return nullptr;
}

namespace
{
// Map a recorded entry's source table and return the AML body (past
// the 36-byte SdtHeader) + its length. nullptr on unmappable.
const u8* MapSourceAml(u8 source_table_idx, u32* aml_len)
{
    u64 phys = 0;
    u32 len = 0;
    if (source_table_idx == 0)
    {
        phys = DsdtAddress();
        len = DsdtLength();
    }
    else
    {
        const u32 idx = source_table_idx - 1;
        if (idx >= SsdtCount())
            return nullptr;
        phys = SsdtAddress(idx);
        len = SsdtLength(idx);
    }
    if (phys == 0 || len < 36)
        return nullptr;
    const auto* hdr = static_cast<const u8*>(AcpiMapTable(phys, len));
    if (hdr == nullptr)
        return nullptr;
    *aml_len = len - 36;
    return hdr + 36;
}
} // namespace

bool AmlMethodBody(const AmlNamespaceEntry* entry, const u8** body, u32* body_len, u8* argc)
{
    if (entry == nullptr || entry->kind != AmlObjectKind::Method)
        return false;
    u32 aml_len = 0;
    const u8* aml = MapSourceAml(entry->source_table_idx, &aml_len);
    if (aml == nullptr)
        return false;
    const u32 off = entry->aml_offset;
    if (off >= aml_len || aml[off] != 0x14 /* MethodOp */)
        return false;
    u32 q = off + 1;
    u32 pkg_len = 0, pc = 0;
    if (!ReadPkgLength(aml + q, aml_len - q, &pkg_len, &pc))
        return false;
    if (pkg_len > aml_len - q)
        return false;
    // pkg_len < pc would push q past pkg_end and underflow
    // `pkg_end - q` — same class as the namespace-walk sites.
    if (pkg_len < pc)
        return false;
    const u32 pkg_end = q + pkg_len;
    q += pc;
    NameStringInfo ns;
    u32 nc = 0;
    if (!ReadNameString(aml + q, pkg_end - q, &ns, &nc))
        return false;
    q += nc;
    if (q >= pkg_end)
        return false;
    const u8 flags = aml[q++];
    *argc = flags & 0x07;
    *body = aml + q;
    *body_len = pkg_end - q;
    return true;
}

bool AmlNameValue(const AmlNamespaceEntry* entry, const u8** data, u32* data_len)
{
    if (entry == nullptr || entry->kind != AmlObjectKind::Name)
        return false;
    u32 aml_len = 0;
    const u8* aml = MapSourceAml(entry->source_table_idx, &aml_len);
    if (aml == nullptr)
        return false;
    const u32 off = entry->aml_offset;
    if (off >= aml_len || aml[off] != 0x08 /* NameOp */)
        return false;
    u32 q = off + 1;
    NameStringInfo ns;
    u32 nc = 0;
    if (!ReadNameString(aml + q, aml_len - q, &ns, &nc))
        return false;
    q += nc;
    if (q >= aml_len)
        return false;
    *data = aml + q;
    *data_len = aml_len - q;
    return true;
}

} // namespace duetos::acpi
