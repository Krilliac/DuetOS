// manifest.cpp — Win32 SxS assembly-manifest parser + PE resource
// extraction for RT_MANIFEST. Covers kernel/loader/manifest.h.
//
// The PE resource walker here is intentionally minimal — it only
// needs to locate RT_MANIFEST (type 24, ID 1 or 2) in the three-
// level resource directory. The full userland walker lives in
// userland/libs/common/pe_resources.h; we duplicate only the
// handful of lines needed so this TU stays freestanding (no
// dependency on the mapped-image assumption that pe_resources.h
// makes).
//
// The XML "parser" is a scanner: it seeks known attribute values
// and element text rather than building a DOM. Assembly manifests
// are machine-generated and tightly schematised, so this is
// sufficient and avoids the complexity of a real XML parser in
// kernel context.

#include "loader/manifest.h"

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;

// ---------------------------------------------------------------
// Byte-order helpers (PE is always little-endian)
// ---------------------------------------------------------------

u16 Le16(const u8* p)
{
    return u16(p[0]) | (u16(p[1]) << 8);
}
u32 Le32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

// ---------------------------------------------------------------
// Minimal string helpers (freestanding — no libc)
// ---------------------------------------------------------------

bool MemEq(const u8* a, const char* b, u64 n)
{
    for (u64 i = 0; i < n; ++i)
    {
        if (a[i] != static_cast<u8>(b[i]))
            return false;
    }
    return true;
}

u64 StrLen(const char* s)
{
    u64 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

// Case-insensitive ASCII compare for manifest attribute values.
u8 ToLower(u8 c)
{
    return (c >= 'A' && c <= 'Z') ? u8(c + 32) : c;
}

bool CiEq(const u8* buf, u64 buf_len, const char* lit)
{
    const u64 lit_len = StrLen(lit);
    if (buf_len != lit_len)
        return false;
    for (u64 i = 0; i < lit_len; ++i)
    {
        if (ToLower(buf[i]) != ToLower(static_cast<u8>(lit[i])))
            return false;
    }
    return true;
}

// ---------------------------------------------------------------
// Scan helpers for the XML manifest
// ---------------------------------------------------------------

// Find a byte sequence in [buf, buf+len). Returns offset or ~0.
u64 FindBytes(const u8* buf, u64 len, const char* needle, u64 needle_len)
{
    if (needle_len == 0 || needle_len > len)
        return ~u64(0);
    for (u64 i = 0; i <= len - needle_len; ++i)
    {
        if (MemEq(buf + i, needle, needle_len))
            return i;
    }
    return ~u64(0);
}

// Find next occurrence of `needle` starting from `start`.
u64 FindFrom(const u8* buf, u64 len, u64 start, const char* needle)
{
    if (start >= len)
        return ~u64(0);
    const u64 nlen = StrLen(needle);
    const u64 r = FindBytes(buf + start, len - start, needle, nlen);
    return (r == ~u64(0)) ? ~u64(0) : start + r;
}

// Extract the value of an XML attribute: given a position inside a
// tag, find `attr="value"` and return pointers to value start + len.
// Returns false if not found. Searches forward from `pos` up to
// the next '>' (end of tag).
bool ExtractAttr(const u8* buf, u64 len, u64 pos, const char* attr, const u8** val, u64* val_len)
{
    const u64 attr_len = StrLen(attr);
    // Find the end of the enclosing tag.
    u64 tag_end = pos;
    while (tag_end < len && buf[tag_end] != '>')
        ++tag_end;
    // Search for `attr="` within [pos, tag_end).
    for (u64 i = pos; i + attr_len + 2 < tag_end; ++i)
    {
        if (MemEq(buf + i, attr, attr_len) && buf[i + attr_len] == '=' && buf[i + attr_len + 1] == '"')
        {
            const u64 vstart = i + attr_len + 2;
            u64 vend = vstart;
            while (vend < len && buf[vend] != '"')
                ++vend;
            if (vend < len)
            {
                *val = buf + vstart;
                *val_len = vend - vstart;
                return true;
            }
        }
    }
    return false;
}

// Extract text content between >...</ closing-tag for a simple
// element. `open_end` is the position of the '>' that ends the
// opening tag. Returns false if the text is empty or contains
// nested tags.
bool ExtractText(const u8* buf, u64 len, u64 open_end, const u8** text, u64* text_len)
{
    if (open_end >= len)
        return false;
    const u64 tstart = open_end + 1;
    u64 tend = tstart;
    while (tend < len && buf[tend] != '<')
        ++tend;
    if (tend <= tstart || tend >= len)
        return false;
    // Trim leading/trailing whitespace.
    u64 a = tstart;
    u64 b = tend;
    while (a < b && (buf[a] == ' ' || buf[a] == '\t' || buf[a] == '\r' || buf[a] == '\n'))
        ++a;
    while (b > a && (buf[b - 1] == ' ' || buf[b - 1] == '\t' || buf[b - 1] == '\r' || buf[b - 1] == '\n'))
        --b;
    if (a >= b)
        return false;
    *text = buf + a;
    *text_len = b - a;
    return true;
}

// Find the '>' that closes the tag starting at `pos` (which should
// point at '<'). Handles self-closing tags. Returns ~0 if not found.
u64 FindTagEnd(const u8* buf, u64 len, u64 pos)
{
    for (u64 i = pos; i < len; ++i)
    {
        if (buf[i] == '>')
            return i;
    }
    return ~u64(0);
}

} // anonymous namespace

namespace duetos::core
{

// ---------------------------------------------------------------
// ParseManifestXml — scan the XML for known elements/attributes
// ---------------------------------------------------------------

ManifestInfo ParseManifestXml(const u8* xml, u64 len)
{
    ManifestInfo info{};
    if (xml == nullptr || len == 0)
        return info;

    // Verify this looks like an assembly manifest. The root element
    // must be <assembly ...>.
    const u64 asm_pos = FindFrom(xml, len, 0, "<assembly");
    if (asm_pos == ~u64(0))
        return info;

    info.has_manifest = true;

    // --- Requested execution level ---
    // <requestedExecutionLevel level="..." uiAccess="..."/>
    const u64 rel_pos = FindFrom(xml, len, 0, "requestedExecutionLevel");
    if (rel_pos != ~u64(0))
    {
        const u8* val = nullptr;
        u64 vlen = 0;
        if (ExtractAttr(xml, len, rel_pos, "level", &val, &vlen))
        {
            if (CiEq(val, vlen, "asInvoker"))
                info.execution_level = ManifestInfo::ExecutionLevel::AsInvoker;
            else if (CiEq(val, vlen, "highestAvailable"))
                info.execution_level = ManifestInfo::ExecutionLevel::HighestAvailable;
            else if (CiEq(val, vlen, "requireAdministrator"))
                info.execution_level = ManifestInfo::ExecutionLevel::RequireAdministrator;
        }
        if (ExtractAttr(xml, len, rel_pos, "uiAccess", &val, &vlen))
        {
            info.ui_access = CiEq(val, vlen, "true");
        }
    }

    // --- DPI awareness ---
    // <dpiAwareness>PerMonitorV2</dpiAwareness> takes precedence
    // over <dpiAware>true</dpiAware> when both are present.
    bool found_dpi_awareness = false;
    {
        const u64 da_pos = FindFrom(xml, len, 0, "<dpiAwareness");
        if (da_pos != ~u64(0))
        {
            const u64 gt = FindTagEnd(xml, len, da_pos);
            if (gt != ~u64(0))
            {
                const u8* text = nullptr;
                u64 tlen = 0;
                if (ExtractText(xml, len, gt, &text, &tlen))
                {
                    found_dpi_awareness = true;
                    if (CiEq(text, tlen, "PerMonitorV2") || CiEq(text, tlen, "PerMonitor, PerMonitorV2") ||
                        CiEq(text, tlen, "PerMonitorV2, PerMonitor"))
                    {
                        info.dpi_awareness = ManifestInfo::DpiAwareness::PerMonitorV2;
                    }
                    else if (CiEq(text, tlen, "PerMonitor"))
                    {
                        info.dpi_awareness = ManifestInfo::DpiAwareness::PerMonitorAware;
                    }
                    else if (CiEq(text, tlen, "system"))
                    {
                        info.dpi_awareness = ManifestInfo::DpiAwareness::SystemAware;
                    }
                    // "unaware" / unrecognised → Unaware (default)
                }
            }
        }
    }
    if (!found_dpi_awareness)
    {
        const u64 da_pos = FindFrom(xml, len, 0, "<dpiAware");
        if (da_pos != ~u64(0))
        {
            const u64 gt = FindTagEnd(xml, len, da_pos);
            if (gt != ~u64(0))
            {
                const u8* text = nullptr;
                u64 tlen = 0;
                if (ExtractText(xml, len, gt, &text, &tlen))
                {
                    // "true" → system-aware. "true/PM" or "True/PM"
                    // → per-monitor (legacy MSDN pattern).
                    if (CiEq(text, tlen, "true/pm") || CiEq(text, tlen, "True/PM"))
                        info.dpi_awareness = ManifestInfo::DpiAwareness::PerMonitorAware;
                    else if (CiEq(text, tlen, "true") || CiEq(text, tlen, "True"))
                        info.dpi_awareness = ManifestInfo::DpiAwareness::SystemAware;
                }
            }
        }
    }

    // --- Long-path awareness ---
    {
        const u64 lp_pos = FindFrom(xml, len, 0, "<longPathAware");
        if (lp_pos != ~u64(0))
        {
            const u64 gt = FindTagEnd(xml, len, lp_pos);
            if (gt != ~u64(0))
            {
                const u8* text = nullptr;
                u64 tlen = 0;
                if (ExtractText(xml, len, gt, &text, &tlen))
                {
                    info.long_path_aware = CiEq(text, tlen, "true");
                }
            }
        }
    }

    // --- SxS dependencies ---
    // Each <dependentAssembly> contains an <assemblyIdentity> with
    // a `name` attribute. Collect up to kMaxSxsDeps of them.
    {
        u64 search = 0;
        while (info.sxs_dep_count < ManifestInfo::kMaxSxsDeps)
        {
            const u64 dep_pos = FindFrom(xml, len, search, "<dependentAssembly");
            if (dep_pos == ~u64(0))
                break;

            // Find <assemblyIdentity inside this dependency block.
            const u64 end_dep = FindFrom(xml, len, dep_pos, "</dependentAssembly");
            const u64 bound = (end_dep != ~u64(0)) ? end_dep : len;
            const u64 id_pos = FindFrom(xml, len, dep_pos, "<assemblyIdentity");
            if (id_pos != ~u64(0) && id_pos < bound)
            {
                const u8* name_val = nullptr;
                u64 name_len = 0;
                if (ExtractAttr(xml, len, id_pos, "name", &name_val, &name_len))
                {
                    const u64 copy_len =
                        name_len < ManifestInfo::kSxsNameMax - 1 ? name_len : ManifestInfo::kSxsNameMax - 1;
                    char* dst = info.sxs_deps[info.sxs_dep_count];
                    for (u64 j = 0; j < copy_len; ++j)
                        dst[j] = static_cast<char>(name_val[j]);
                    dst[copy_len] = '\0';
                    ++info.sxs_dep_count;
                }
            }
            search = (end_dep != ~u64(0)) ? end_dep + 1 : bound;
        }
    }

    return info;
}

// ---------------------------------------------------------------
// PE resource directory walker — RT_MANIFEST extraction
// ---------------------------------------------------------------

// PE constants for the resource directory walk.
namespace
{

constexpr u32 kRtManifest = 24;
constexpr u32 kManifestIdExe = 1;
constexpr u32 kManifestIdDll = 2;

// Offsets within IMAGE_RESOURCE_DIRECTORY (16 bytes).
constexpr u64 kResDirNumberOfNamedEntries = 12;
constexpr u64 kResDirNumberOfIdEntries = 14;
constexpr u64 kResDirSize = 16;

// Each IMAGE_RESOURCE_DIRECTORY_ENTRY is 8 bytes.
constexpr u64 kResEntrySize = 8;

// IMAGE_RESOURCE_DATA_ENTRY (16 bytes).
// OffsetToData (RVA), Size, CodePage, Reserved.
constexpr u64 kResDataEntrySize = 16;

// RVA-to-file-offset conversion using the section table.
u64 RvaToFileOff(const u8* file, u64 file_len, u64 sec_base, u16 sec_count, u32 rva)
{
    for (u16 i = 0; i < sec_count; ++i)
    {
        const u64 sh = sec_base + u64(i) * 40;
        if (sh + 40 > file_len)
            return ~u64(0);
        const u32 va = Le32(file + sh + 12);
        const u32 raw_size = Le32(file + sh + 16);
        const u32 virt_size = Le32(file + sh + 8);
        const u32 extent = raw_size > virt_size ? raw_size : virt_size;
        if (rva >= va && extent > 0 && rva - va < extent)
        {
            const u32 raw_off = Le32(file + sh + 20);
            return u64(raw_off) + u64(rva - va);
        }
    }
    return ~u64(0);
}

// Find a resource entry with a given integer ID in a resource
// directory. Returns the OffsetToData/OffsetToDirectory field
// (the second DWORD of the entry), or ~0 on miss.
u64 FindResEntry(const u8* rsrc, u64 rsrc_len, u64 dir_off, u32 target_id)
{
    if (dir_off + kResDirSize > rsrc_len)
        return ~u64(0);
    const u16 named = Le16(rsrc + dir_off + kResDirNumberOfNamedEntries);
    const u16 id_entries = Le16(rsrc + dir_off + kResDirNumberOfIdEntries);
    // ID entries follow named entries.
    const u64 entry_base = dir_off + kResDirSize + u64(named) * kResEntrySize;
    for (u16 i = 0; i < id_entries; ++i)
    {
        const u64 eoff = entry_base + u64(i) * kResEntrySize;
        if (eoff + kResEntrySize > rsrc_len)
            return ~u64(0);
        const u32 id = Le32(rsrc + eoff);
        if (id == target_id)
            return Le32(rsrc + eoff + 4);
    }
    return ~u64(0);
}

} // anonymous namespace

ManifestInfo ParseManifestFromPe(const u8* file, u64 file_len)
{
    ManifestInfo info{};
    if (file == nullptr || file_len < 64)
        return info;

    // DOS header: e_lfanew at offset 0x3C.
    if (file[0] != 'M' || file[1] != 'Z')
        return info;
    const u32 pe_off = Le32(file + 0x3C);
    if (u64(pe_off) + 4 > file_len)
        return info;
    if (file[pe_off] != 'P' || file[pe_off + 1] != 'E' || file[pe_off + 2] != 0 || file[pe_off + 3] != 0)
        return info;

    // COFF header starts at pe_off + 4.
    const u64 coff = u64(pe_off) + 4;
    if (coff + 20 > file_len)
        return info;
    const u16 num_sections = Le16(file + coff + 2);
    const u16 opt_size = Le16(file + coff + 16);
    const u64 opt_base = coff + 20;
    if (opt_base + opt_size > file_len || opt_size < 2)
        return info;

    // Optional header magic: PE32 (0x10B) or PE32+ (0x20B).
    const u16 magic = Le16(file + opt_base);
    u64 data_dir_offset = 0;
    u32 num_rva_and_sizes = 0;
    if (magic == 0x20B)
    {
        // PE32+: NumberOfRvaAndSizes at offset 108, data dirs at 112.
        if (opt_size < 112)
            return info;
        num_rva_and_sizes = Le32(file + opt_base + 108);
        data_dir_offset = 112;
    }
    else if (magic == 0x10B)
    {
        // PE32: NumberOfRvaAndSizes at offset 92, data dirs at 96.
        if (opt_size < 96)
            return info;
        num_rva_and_sizes = Le32(file + opt_base + 92);
        data_dir_offset = 96;
    }
    else
    {
        return info;
    }

    // Resource directory is data directory index 2.
    if (num_rva_and_sizes <= 2)
        return info;
    const u64 rsrc_dd = opt_base + data_dir_offset + 2 * 8;
    if (rsrc_dd + 8 > file_len)
        return info;
    const u32 rsrc_rva = Le32(file + rsrc_dd);
    const u32 rsrc_size = Le32(file + rsrc_dd + 4);
    if (rsrc_rva == 0 || rsrc_size == 0)
        return info;

    // Convert the resource directory RVA to a file offset.
    const u64 sec_base = opt_base + opt_size;
    const u64 rsrc_file_off = RvaToFileOff(file, file_len, sec_base, num_sections, rsrc_rva);
    if (rsrc_file_off == ~u64(0) || rsrc_file_off + rsrc_size > file_len)
        return info;

    // We now have the resource directory at [rsrc_file_off, +rsrc_size).
    // Walk the three-level tree: Type -> Name/ID -> Language.
    const u8* rsrc = file + rsrc_file_off;
    const u64 rsrc_len = rsrc_size;

    // Level 1: find RT_MANIFEST (type 24).
    const u64 type_entry = FindResEntry(rsrc, rsrc_len, 0, kRtManifest);
    if (type_entry == ~u64(0))
        return info;

    // High bit set → subdirectory offset from rsrc base.
    if ((type_entry & 0x80000000u) == 0)
        return info;
    const u64 name_dir_off = type_entry & 0x7FFFFFFFu;

    // Level 2: find ID 1 (exe) first, then ID 2 (dll).
    u64 id_entry = FindResEntry(rsrc, rsrc_len, name_dir_off, kManifestIdExe);
    if (id_entry == ~u64(0))
        id_entry = FindResEntry(rsrc, rsrc_len, name_dir_off, kManifestIdDll);
    if (id_entry == ~u64(0))
        return info;

    // Level 3: language directory — take the first entry.
    u64 lang_dir_off = 0;
    if (id_entry & 0x80000000u)
    {
        lang_dir_off = id_entry & 0x7FFFFFFFu;
    }
    else
    {
        // Direct data entry (unusual but handle it).
        lang_dir_off = ~u64(0);
    }

    u64 data_entry_off = 0;
    if (lang_dir_off != ~u64(0))
    {
        // Read the first entry in the language directory.
        if (lang_dir_off + kResDirSize > rsrc_len)
            return info;
        const u16 lang_named = Le16(rsrc + lang_dir_off + kResDirNumberOfNamedEntries);
        const u16 lang_id_entries = Le16(rsrc + lang_dir_off + kResDirNumberOfIdEntries);
        if (lang_named + lang_id_entries == 0)
            return info;
        const u64 first_entry = lang_dir_off + kResDirSize;
        if (first_entry + kResEntrySize > rsrc_len)
            return info;
        const u32 entry_val = Le32(rsrc + first_entry + 4);
        if (entry_val & 0x80000000u)
            return info; // Subdirectory at level 4 — malformed.
        data_entry_off = entry_val;
    }
    else
    {
        data_entry_off = id_entry;
    }

    // Read the IMAGE_RESOURCE_DATA_ENTRY.
    if (data_entry_off + kResDataEntrySize > rsrc_len)
        return info;
    const u32 data_rva = Le32(rsrc + data_entry_off);
    const u32 data_size = Le32(rsrc + data_entry_off + 4);
    if (data_rva == 0 || data_size == 0)
        return info;

    // Convert the data RVA to a file offset.
    const u64 xml_off = RvaToFileOff(file, file_len, sec_base, num_sections, data_rva);
    if (xml_off == ~u64(0) || xml_off + data_size > file_len)
        return info;

    return ParseManifestXml(file + xml_off, data_size);
}

} // namespace duetos::core
