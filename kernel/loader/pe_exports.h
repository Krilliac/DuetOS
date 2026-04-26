#pragma once

#include "util/types.h"

/*
 * DuetOS PE/COFF Export Address Table (EAT) parser — stage 2 of
 * the Win32 DLL-loader track.
 *
 * Stage 1 (v0 — see `pe-subsystem-v0.md`) ran PEs with imports by
 * mapping a flat kernel-hosted stubs page and patching the IAT
 * directly from a `{dll, func} -> offset` static table. That
 * works for executables, but it stops the moment a PE wants to
 * call `GetProcAddress(..., "RegQueryValueW")` or loads a DLL
 * dynamically — there is no EAT to walk and no DLL image to
 * resolve names against.
 *
 * Stage 2 introduces a real EAT parser: given a PE file buffer
 * (typically a DLL, but any PE with a non-empty Export Directory
 * works), it validates IMAGE_EXPORT_DIRECTORY and exposes a
 * tight iteration + lookup API:
 *
 *   - Every export can be enumerated by function-table index.
 *   - Exports can be looked up by name (binary-searchable since
 *     PE stores the name-pointer and name-ordinal arrays in
 *     name-sorted order).
 *   - Exports can be looked up by ordinal (the EAT's native key).
 *   - Forwarder exports (whose RVA points back inside the Export
 *     Directory) are detected and yield a "forwarder string"
 *     (e.g. "NTDLL.RtlAllocateHeap") instead of a code RVA —
 *     callers either chain the resolve or defer to the DLL
 *     loader's export cache.
 *
 * This module is **parse only**. It does not load, map, or
 * otherwise touch an AddressSpace. The DLL loader (`dll_loader.h`)
 * sits on top of it and maps an image into memory; both are
 * independent so PeReport can cheaply dump exports without
 * allocating frames.
 *
 * All offsets returned as "file offsets" are into the input
 * buffer — callers hold it; this parser does not copy it.
 *
 * Context: any. No allocations, no locks. Safe to call at early
 * boot before the heap or AS machinery is up.
 */

namespace duetos::core
{

/// Status of a PeParseExports attempt.
enum class PeExportStatus : u8
{
    Ok = 0,
    HeaderParseFailed, // underlying PE header parse rejected the buffer
    NoExportDirectory, // IMAGE_DATA_DIRECTORY[0] is empty — not an error, just "nothing to parse"
    BadDirectoryRva,   // Export directory RVA does not land inside any section
    BadNameRva,        // The DLL name RVA is invalid
    BadArrayRva,       // One of EAT / ENT / EOT arrays lies outside the file
    TooManyExports,    // Exceeds our per-image budget (guard against hostile images)
};

const char* PeExportStatusName(PeExportStatus s);

/*
 * Parsed IMAGE_EXPORT_DIRECTORY.
 *
 * All `*_file_off` fields are offsets into the original file
 * buffer passed to PeParseExports — callers retain ownership of
 * that buffer for the lifetime of the table. The parser never
 * dereferences through an aligned (T*) cast; every element is
 * read back through the LE* helpers in pe_loader.cpp's sibling
 * style (and re-implemented here for isolation).
 *
 * `export_dir_lo` / `export_dir_hi` bound the RVA range the
 * export directory spans. A function-entry RVA that falls inside
 * this range is a forwarder — its value is an RVA to a
 * NUL-terminated "Dll.Function" / "Dll.#Ordinal" string rather
 * than a code entry point in the image itself.
 */
struct PeExports
{
    const u8* file; // borrowed — file contents
    u64 file_len;   // bytes

    u32 base_ordinal;   // first ordinal (= Base in IMAGE_EXPORT_DIRECTORY)
    u32 num_funcs;      // NumberOfFunctions — size of the EAT array
    u32 num_names;      // NumberOfNames    — size of ENT + EOT arrays
    u64 funcs_file_off; // file offset of the Export Address Table (u32 RVAs, num_funcs of them)
    u64 names_file_off; // file offset of the Export Name Table   (u32 RVAs, num_names of them)
    u64 ords_file_off;  // file offset of the Export Ordinal Table (u16 biased ordinals, num_names of them)
    u64 name_file_off;  // file offset of the DLL name string (NUL-terminated ASCII)

    u32 export_dir_lo; // Export Directory's RVA (inclusive)
    u32 export_dir_hi; // export_dir_lo + directory size (exclusive) — forwarder detection range
};

/// Maximum number of exports we tolerate in a single image.
/// MSVCP140 exports ~16k symbols; ntdll exports ~2.5k. 65536 is
/// comfortably above both and keeps the u16 ordinal space fully
/// representable. A PE advertising more than this is either
/// hostile or a real outlier; either way we refuse to walk it.
inline constexpr u32 kPeExportsMax = 65536;

/// Parse the Export Directory in `file`. Returns:
///   - Ok  — `out` is populated and the API below is safe to use.
///   - NoExportDirectory — the PE has no exports (legitimate for
///     executables). `out` left untouched; treat as "no API
///     surface".
///   - Any Bad*  — the image is malformed. Do not use `out`.
PeExportStatus PeParseExports(const u8* file, u64 file_len, PeExports& out);

/*
 * Export entry returned by the iteration / lookup API.
 *
 * Exactly one of (rva, forwarder) is populated:
 *   - `is_forwarder = false` + `rva` is the function's RVA
 *     inside the DLL's image (add to the DLL's load base to
 *     obtain the VA).
 *   - `is_forwarder = true`  + `forwarder` is a borrowed pointer
 *     into the file buffer (NUL-terminated "Dll.Func"/"Dll.#N"
 *     string). Valid for the lifetime of the file buffer.
 *
 * `name`  is the borrowed ASCII name pointer, or nullptr if the
 * entry is ordinal-only (EAT slot with no ENT entry pointing at
 * it).  `ordinal` is the absolute ordinal (= index +
 * base_ordinal).
 */
struct PeExport
{
    const char* name; // may be nullptr for ordinal-only exports
    u32 ordinal;      // absolute ordinal (base + index)
    u32 rva;          // in-image RVA (ignored when is_forwarder)
    bool is_forwarder;
    const char* forwarder;
};

/// Number of EAT slots (indexed 0 .. num_funcs-1). Some slots
/// may be empty (rva == 0) — the PE spec guarantees this is a
/// sentinel for "no export at this ordinal".
inline u32 PeExportsCount(const PeExports& exp)
{
    return exp.num_funcs;
}

/// Yield the export at ordinal-index `idx` (0-based into the
/// EAT, equivalent to absolute ordinal `exp.base_ordinal + idx`).
/// Returns true on success; false if idx is out of range or the
/// slot is empty.
bool PeExportAt(const PeExports& exp, u32 idx, PeExport& out);

/// Look up an export by absolute ordinal (NOT the EAT index).
/// Returns true on hit, false if the ordinal is outside
/// [base_ordinal, base_ordinal + num_funcs) or the EAT slot is
/// empty.
bool PeExportLookupOrdinal(const PeExports& exp, u32 ordinal, PeExport& out);

/// Look up an export by ASCII name. Case-sensitive, matching
/// MSVC `/EXPORT:` convention — `GetProcAddress` expects exact
/// case. Returns true on hit, false on miss (no such name in
/// the Export Name Table). Implemented as a binary search over
/// the name-sorted ENT (per PE spec); falls back to a linear
/// scan on a malformed name RVA at the midpoint so a single bad
/// slot can't mis-discard half the table.
bool PeExportLookupName(const PeExports& exp, const char* name, PeExport& out);

/// Resolve the DLL's own name as embedded in the Export
/// Directory. Returns a borrowed pointer into the file buffer,
/// or nullptr if the name RVA is out of bounds.
const char* PeExportsDllName(const PeExports& exp);

/// Dump a human-readable summary of the EAT to the serial log,
/// mirroring the shape of `ReportImports` in pe_loader.cpp:
///
///   exports: dll="kernel32.dll" base=1 nfunc=0x3e0 nname=0x3e0
///     [0x0001] ExitProcess -> rva=0x00112340
///     [0x0002] GetProcAddress -> rva=0x000FF120
///     ...
///     [0x01FB] NtClose -> forwarder="ntdll.NtClose"
///
/// At most kPeExportsReportMax entries are emitted to keep the
/// log bounded on a DLL with thousands of exports; the line
/// count at the end is always the true total.
void PeExportsReport(const PeExports& exp);

inline constexpr u32 kPeExportsReportMax = 32;

} // namespace duetos::core
