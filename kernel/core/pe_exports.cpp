/*
 * DuetOS — PE Export Address Table parser: implementation.
 *
 * Companion to pe_exports.h — see there for the public API
 * (`PeParseExports`, `PeExportLookupName`).
 *
 * WHAT
 *   Walks a PE's IMAGE_EXPORT_DIRECTORY and produces three
 *   parallel arrays the resolver uses: name-table, ordinal-
 *   table, EAT (RVAs). Distinguishes own-module entries from
 *   forwarders (`Dll.Func` / `Dll.#N` strings inside .edata).
 *
 * HOW
 *   `LeU16/32/64` byte-level readers (no packed-struct casts);
 *   header offsets hand-coded rather than pulled from <winnt.h>
 *   to keep the kernel self-contained. `PeExportLookupName` is
 *   a binary search over the (sorted) name table.
 */

#include "pe_exports.h"

#include "../arch/x86_64/serial.h"

namespace duetos::core
{

namespace
{

// ---- byte-level readers --------------------------------------------------
// Same contract as pe_loader.cpp's LE* helpers. PE Export
// Directory fields are 4-byte aligned on disk but we still read
// through u8 so an unaligned file pointer can't trap.
inline u16 LeU16(const u8* p)
{
    return u16(p[0]) | (u16(p[1]) << 8);
}
inline u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
inline u64 LeU64(const u8* p)
{
    return static_cast<u64>(LeU32(p)) | (static_cast<u64>(LeU32(p + 4)) << 32);
}

// ---- PE header constants we need for EAT parsing ------------------------
// These duplicate a handful of constants from pe_loader.cpp's
// anon namespace. Deliberately re-declared locally so the EAT
// parser stays usable without dragging in the full loader.
constexpr u16 kDosMagic = 0x5A4D;
constexpr u32 kPeSignature = 0x00004550;
constexpr u16 kMachineAmd64 = 0x8664;
constexpr u16 kOptMagicPe32Plus = 0x020B;
constexpr u64 kFileHeaderSize = 20;
constexpr u64 kOptHeaderNumberOfRvaAndSizes = 108;
constexpr u64 kOptHeaderDataDirectories = 112;
constexpr u64 kDataDirEntrySize = 8; // RVA + Size
constexpr u64 kSectionHeaderSize = 40;
constexpr u64 kSectionHeaderVirtualSize = 8;
constexpr u64 kSectionHeaderVirtualAddress = 12;
constexpr u64 kSectionHeaderSizeOfRawData = 16;
constexpr u64 kSectionHeaderPointerToRawData = 20;

// Export Directory is Data Directory index 0 (PE spec).
constexpr u64 kDirEntryExport = 0;

/*
 * IMAGE_EXPORT_DIRECTORY layout (40 bytes, PE32+):
 *
 *   0x00  u32 Characteristics
 *   0x04  u32 TimeDateStamp
 *   0x08  u16 MajorVersion
 *   0x0A  u16 MinorVersion
 *   0x0C  u32 Name                  (RVA of DLL name NUL-string)
 *   0x10  u32 Base                  (ordinal base)
 *   0x14  u32 NumberOfFunctions     (EAT size)
 *   0x18  u32 NumberOfNames         (ENT/EOT size)
 *   0x1C  u32 AddressOfFunctions    (RVA of u32[NumberOfFunctions] — EAT)
 *   0x20  u32 AddressOfNames        (RVA of u32[NumberOfNames]     — ENT)
 *   0x24  u32 AddressOfNameOrdinals (RVA of u16[NumberOfNames]     — EOT,
 *                                    biased: absolute ord = base + entry)
 */
constexpr u64 kExpDirName = 0x0C;
constexpr u64 kExpDirBase = 0x10;
constexpr u64 kExpDirNumberOfFunctions = 0x14;
constexpr u64 kExpDirNumberOfNames = 0x18;
constexpr u64 kExpDirAddressOfFunctions = 0x1C;
constexpr u64 kExpDirAddressOfNames = 0x20;
constexpr u64 kExpDirAddressOfOrdinals = 0x24;
constexpr u64 kExpDirSize = 0x28; // 40 bytes

// Max string length we will scan through when returning a
// borrowed C string. 512 is generous: real export names top out
// around 200 chars even for C++-mangled templates in MSVCP140.
constexpr u64 kMaxExportStringLen = 512;

// Walk an RVA back to a file offset using the section table.
// Returns u64(-1) on miss. Duplicated here so the EAT parser is
// independent of pe_loader.cpp; swapping to a shared helper is
// one rename when we consolidate in a later slice.
struct PeHeaderShape
{
    u64 opt_base;
    u16 opt_header_size;
    u64 section_base;
    u16 section_count;
    u32 num_rva_and_sizes;
};

bool ParsePeShape(const u8* file, u64 file_len, PeHeaderShape& out)
{
    if (file == nullptr || file_len < 0x40)
        return false;
    if (LeU16(file) != kDosMagic)
        return false;
    const u32 e_lfanew = LeU32(file + 0x3C);
    if (u64(e_lfanew) + 4 + kFileHeaderSize > file_len)
        return false;
    if (LeU32(file + e_lfanew) != kPeSignature)
        return false;
    const u8* fh = file + e_lfanew + 4;
    if (LeU16(fh + 0) != kMachineAmd64)
        return false;
    out.section_count = LeU16(fh + 2);
    out.opt_header_size = LeU16(fh + 16);
    out.opt_base = u64(e_lfanew) + 4 + kFileHeaderSize;
    if (out.opt_base + out.opt_header_size > file_len)
        return false;
    const u8* opt = file + out.opt_base;
    if (LeU16(opt) != kOptMagicPe32Plus)
        return false;
    if (out.opt_header_size < kOptHeaderNumberOfRvaAndSizes + 4)
        return false;
    out.num_rva_and_sizes = LeU32(opt + kOptHeaderNumberOfRvaAndSizes);
    out.section_base = out.opt_base + out.opt_header_size;
    const u64 sect_bytes = u64(out.section_count) * kSectionHeaderSize;
    if (out.section_base + sect_bytes > file_len)
        return false;
    return true;
}

u64 RvaToFile(const u8* file, const PeHeaderShape& h, u32 rva)
{
    for (u16 i = 0; i < h.section_count; ++i)
    {
        const u8* sec = file + h.section_base + u64(i) * kSectionHeaderSize;
        const u32 va = LeU32(sec + kSectionHeaderVirtualAddress);
        const u32 raw_size = LeU32(sec + kSectionHeaderSizeOfRawData);
        const u32 virt_size = LeU32(sec + kSectionHeaderVirtualSize);
        const u32 extent = raw_size > virt_size ? raw_size : virt_size;
        if (rva >= va && rva < va + extent)
        {
            const u32 raw_off = LeU32(sec + kSectionHeaderPointerToRawData);
            return u64(raw_off) + u64(rva - va);
        }
    }
    return ~u64(0);
}

// Return a validated borrowed C string at `file[off..]`, or
// nullptr if no NUL appears within kMaxExportStringLen bytes.
const char* CStringAt(const u8* file, u64 file_len, u64 off)
{
    if (off >= file_len)
        return nullptr;
    const u64 cap = (file_len - off) < kMaxExportStringLen ? (file_len - off) : kMaxExportStringLen;
    for (u64 i = 0; i < cap; ++i)
    {
        if (file[off + i] == 0)
            return reinterpret_cast<const char*>(file + off);
    }
    return nullptr;
}

// Case-sensitive strcmp with an explicit end-of-string guard.
// No stdlib in kernel space.
bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return a == b;
    while (*a && *b)
    {
        if (*a != *b)
            return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

} // namespace

const char* PeExportStatusName(PeExportStatus s)
{
    switch (s)
    {
    case PeExportStatus::Ok:
        return "Ok";
    case PeExportStatus::HeaderParseFailed:
        return "HeaderParseFailed";
    case PeExportStatus::NoExportDirectory:
        return "NoExportDirectory";
    case PeExportStatus::BadDirectoryRva:
        return "BadDirectoryRva";
    case PeExportStatus::BadNameRva:
        return "BadNameRva";
    case PeExportStatus::BadArrayRva:
        return "BadArrayRva";
    case PeExportStatus::TooManyExports:
        return "TooManyExports";
    }
    return "?";
}

PeExportStatus PeParseExports(const u8* file, u64 file_len, PeExports& out)
{
    PeHeaderShape h{};
    if (!ParsePeShape(file, file_len, h))
        return PeExportStatus::HeaderParseFailed;

    // Read data directory 0 (Export).
    const u64 dir_bytes = u64(h.num_rva_and_sizes) * kDataDirEntrySize;
    if (kOptHeaderDataDirectories + dir_bytes > h.opt_header_size)
        return PeExportStatus::HeaderParseFailed;
    if (kDirEntryExport >= h.num_rva_and_sizes)
        return PeExportStatus::NoExportDirectory;
    const u8* opt = file + h.opt_base;
    const u32 dir_rva = LeU32(opt + kOptHeaderDataDirectories + kDirEntryExport * kDataDirEntrySize + 0);
    const u32 dir_size = LeU32(opt + kOptHeaderDataDirectories + kDirEntryExport * kDataDirEntrySize + 4);
    if (dir_rva == 0 || dir_size == 0)
        return PeExportStatus::NoExportDirectory;
    // Spec: the directory payload is at least 40 bytes (the
    // fixed IMAGE_EXPORT_DIRECTORY struct). A smaller dir_size
    // is malformed.
    if (dir_size < kExpDirSize)
        return PeExportStatus::BadDirectoryRva;

    const u64 dir_off = RvaToFile(file, h, dir_rva);
    if (dir_off == ~u64(0) || dir_off + kExpDirSize > file_len)
        return PeExportStatus::BadDirectoryRva;

    const u8* dir = file + dir_off;
    const u32 name_rva = LeU32(dir + kExpDirName);
    const u32 base_ord = LeU32(dir + kExpDirBase);
    const u32 n_funcs = LeU32(dir + kExpDirNumberOfFunctions);
    const u32 n_names = LeU32(dir + kExpDirNumberOfNames);
    const u32 funcs_rva = LeU32(dir + kExpDirAddressOfFunctions);
    const u32 names_rva = LeU32(dir + kExpDirAddressOfNames);
    const u32 ords_rva = LeU32(dir + kExpDirAddressOfOrdinals);

    if (n_funcs > kPeExportsMax || n_names > kPeExportsMax)
        return PeExportStatus::TooManyExports;

    // Each of the three arrays must land inside the file.
    // NumberOfFunctions == 0 is technically legal (an empty DLL)
    // — in that case we still return Ok, but every lookup will
    // miss. The array-offset check is skipped when the count is
    // 0 since funcs_rva may legitimately be 0 too.
    u64 funcs_off = 0;
    if (n_funcs != 0)
    {
        funcs_off = RvaToFile(file, h, funcs_rva);
        if (funcs_off == ~u64(0) || funcs_off + u64(n_funcs) * 4 > file_len)
            return PeExportStatus::BadArrayRva;
    }
    u64 names_off = 0;
    u64 ords_off = 0;
    if (n_names != 0)
    {
        names_off = RvaToFile(file, h, names_rva);
        ords_off = RvaToFile(file, h, ords_rva);
        if (names_off == ~u64(0) || names_off + u64(n_names) * 4 > file_len)
            return PeExportStatus::BadArrayRva;
        if (ords_off == ~u64(0) || ords_off + u64(n_names) * 2 > file_len)
            return PeExportStatus::BadArrayRva;
    }

    // DLL name: nice-to-have, but a missing/invalid name isn't
    // fatal — we just report nullptr for the DLL name.
    u64 name_off = ~u64(0);
    if (name_rva != 0)
    {
        const u64 off = RvaToFile(file, h, name_rva);
        if (off != ~u64(0))
            name_off = off;
    }

    out.file = file;
    out.file_len = file_len;
    out.base_ordinal = base_ord;
    out.num_funcs = n_funcs;
    out.num_names = n_names;
    out.funcs_file_off = funcs_off;
    out.names_file_off = names_off;
    out.ords_file_off = ords_off;
    out.name_file_off = name_off;
    out.export_dir_lo = dir_rva;
    out.export_dir_hi = dir_rva + dir_size;
    return PeExportStatus::Ok;
}

const char* PeExportsDllName(const PeExports& exp)
{
    if (exp.name_file_off == ~u64(0))
        return nullptr;
    return CStringAt(exp.file, exp.file_len, exp.name_file_off);
}

// Given a name-table index (0..num_names-1), return the absolute
// ordinal the corresponding EOT entry points at. EOT values are
// 0-based indices into the EAT; adding base_ordinal yields the
// absolute ordinal the OS reports (what GetProcAddress compares
// against). Out-of-range indices fail gracefully.
static bool NameIdxToOrdinalIndex(const PeExports& exp, u32 name_idx, u32& out_eat_idx)
{
    if (name_idx >= exp.num_names)
        return false;
    const u16 eot = LeU16(exp.file + exp.ords_file_off + u64(name_idx) * 2);
    out_eat_idx = eot;
    return eot < exp.num_funcs;
}

// Populate `out` from EAT index `idx` + optional name. Name is
// nullptr when the EAT slot has no corresponding ENT entry
// (ordinal-only export).
static bool PopulateFromIndex(const PeExports& exp, u32 idx, const char* name, PeExport& out)
{
    if (idx >= exp.num_funcs)
        return false;
    const u32 rva = LeU32(exp.file + exp.funcs_file_off + u64(idx) * 4);
    if (rva == 0)
        return false; // PE spec: 0 = unused EAT slot.

    out.name = name;
    out.ordinal = exp.base_ordinal + idx;
    out.rva = rva;
    out.is_forwarder = false;
    out.forwarder = nullptr;

    if (rva >= exp.export_dir_lo && rva < exp.export_dir_hi)
    {
        // Forwarder — the RVA lies inside the export directory,
        // which is how real DLLs encode "this export is an alias
        // for AnotherDll.ActualName".
        PeHeaderShape h{};
        if (ParsePeShape(exp.file, exp.file_len, h))
        {
            const u64 off = RvaToFile(exp.file, h, rva);
            if (off != ~u64(0))
            {
                const char* fwd = CStringAt(exp.file, exp.file_len, off);
                if (fwd != nullptr)
                {
                    out.is_forwarder = true;
                    out.forwarder = fwd;
                }
            }
        }
    }
    return true;
}

bool PeExportAt(const PeExports& exp, u32 idx, PeExport& out)
{
    if (idx >= exp.num_funcs)
        return false;
    // Walk ENT to find a name for this EAT index. Worst-case O(num_names);
    // real DLLs keep num_names ~= num_funcs so this is fine at parse time.
    const char* name = nullptr;
    for (u32 n = 0; n < exp.num_names; ++n)
    {
        u32 eat_idx = 0;
        if (!NameIdxToOrdinalIndex(exp, n, eat_idx))
            continue;
        if (eat_idx == idx)
        {
            const u32 name_rva = LeU32(exp.file + exp.names_file_off + u64(n) * 4);
            PeHeaderShape h{};
            if (ParsePeShape(exp.file, exp.file_len, h))
            {
                const u64 off = RvaToFile(exp.file, h, name_rva);
                if (off != ~u64(0))
                    name = CStringAt(exp.file, exp.file_len, off);
            }
            break;
        }
    }
    return PopulateFromIndex(exp, idx, name, out);
}

bool PeExportLookupOrdinal(const PeExports& exp, u32 ordinal, PeExport& out)
{
    if (ordinal < exp.base_ordinal)
        return false;
    const u32 idx = ordinal - exp.base_ordinal;
    return PeExportAt(exp, idx, out);
}

// 3-way compare two NUL-terminated strings. Returns <0/0/>0 in
// the lexicographic ordering convention. Treats both nullptr as
// equal so a malformed ENT slot doesn't crash the search.
int StrCmp3(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return (a == b) ? 0 : (a == nullptr ? -1 : 1);
    while (*a && *b)
    {
        const int da = static_cast<unsigned char>(*a);
        const int db = static_cast<unsigned char>(*b);
        if (da != db)
            return da - db;
        ++a;
        ++b;
    }
    return static_cast<unsigned char>(*a) - static_cast<unsigned char>(*b);
}

bool PeExportLookupName(const PeExports& exp, const char* name, PeExport& out)
{
    if (name == nullptr || exp.num_names == 0)
        return false;
    PeHeaderShape h{};
    if (!ParsePeShape(exp.file, exp.file_len, h))
        return false;
    // Binary search. The PE spec requires the Export Name Table
    // (ENT) to be name-sorted in ASCII order, paired index-for-
    // index with the Export Ordinal Table (EOT). On a malformed
    // image with a bad name RVA at the midpoint, fall back to a
    // linear scan rather than mis-discarding half the table.
    auto load_name = [&](u32 idx) -> const char*
    {
        const u32 name_rva = LeU32(exp.file + exp.names_file_off + u64(idx) * 4);
        const u64 off = RvaToFile(exp.file, h, name_rva);
        if (off == ~u64(0))
            return nullptr;
        return CStringAt(exp.file, exp.file_len, off);
    };

    u32 lo = 0;
    u32 hi = exp.num_names;
    while (lo < hi)
    {
        const u32 mid = lo + (hi - lo) / 2;
        const char* cand = load_name(mid);
        if (cand == nullptr)
        {
            // Bad name RVA at mid — bail to linear scan to keep
            // the lookup correct on a malformed-but-otherwise-
            // valid image.
            for (u32 n = 0; n < exp.num_names; ++n)
            {
                const char* c = load_name(n);
                if (c == nullptr)
                    continue;
                if (!StrEq(c, name))
                    continue;
                u32 eat_idx = 0;
                if (!NameIdxToOrdinalIndex(exp, n, eat_idx))
                    return false;
                return PopulateFromIndex(exp, eat_idx, c, out);
            }
            return false;
        }
        const int cmp = StrCmp3(cand, name);
        if (cmp == 0)
        {
            u32 eat_idx = 0;
            if (!NameIdxToOrdinalIndex(exp, mid, eat_idx))
                return false;
            return PopulateFromIndex(exp, eat_idx, cand, out);
        }
        if (cmp < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return false;
}

void PeExportsReport(const PeExports& exp)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    SerialWrite("  exports: dll=\"");
    const char* dll = PeExportsDllName(exp);
    SerialWrite(dll ? dll : "<unknown>");
    SerialWrite("\" base=");
    SerialWriteHex(exp.base_ordinal);
    SerialWrite(" nfunc=");
    SerialWriteHex(exp.num_funcs);
    SerialWrite(" nname=");
    SerialWriteHex(exp.num_names);
    SerialWrite("\n");

    if (exp.num_funcs == 0)
        return;

    // Walk name-first so ordinal-only slots print without a
    // name (rather than scanning num_funcs slots for each of
    // num_names — same information, cheaper order).
    const u32 cap = exp.num_names < kPeExportsReportMax ? exp.num_names : kPeExportsReportMax;
    for (u32 n = 0; n < cap; ++n)
    {
        u32 eat_idx = 0;
        if (!NameIdxToOrdinalIndex(exp, n, eat_idx))
            continue;
        PeExport e{};
        if (!PeExportAt(exp, eat_idx, e))
            continue;
        SerialWrite("    [");
        SerialWriteHex(e.ordinal);
        SerialWrite("] ");
        SerialWrite(e.name ? e.name : "<ord>");
        if (e.is_forwarder)
        {
            SerialWrite(" -> forwarder=\"");
            SerialWrite(e.forwarder ? e.forwarder : "<bad>");
            SerialWrite("\"\n");
        }
        else
        {
            SerialWrite(" -> rva=");
            SerialWriteHex(e.rva);
            SerialWrite("\n");
        }
    }
    if (exp.num_names > cap)
    {
        SerialWrite("    (truncated at ");
        SerialWriteHex(cap);
        SerialWrite(" of ");
        SerialWriteHex(exp.num_names);
        SerialWrite(")\n");
    }
}

} // namespace duetos::core
