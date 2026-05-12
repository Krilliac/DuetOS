// DuetOS SMBIOS table walker C FFI — hand-written. Mirrors
// kernel/arch/x86_64/smbios_rust/src/lib.rs.
//
// The C++ caller at kernel/arch/x86_64/smbios.cpp does the
// PhysToVirt resolution, single-init guarding, and summary-cache
// write-back. This crate parses the entry-point anchor and walks
// the variable-length structure table over firmware-controlled
// bytes — slice-bounded, with checksum + double-NUL + string-cap
// validation that the v0 C++ implementation did NOT do.

#pragma once

#include "util/types.h"

namespace duetos::arch::smbios_rust
{

struct DuetosSmbiosEntryPoint
{
    u8 anchor_revision; // 2 = "_SM_", 3 = "_SM3_"
    u8 major_version;
    u8 minor_version;
    u8 _pad0;
    u64 table_phys;
    u32 table_length;
    u8 ok;
    u8 _pad1[3];
};

struct DuetosSmbiosStructure
{
    u8 struct_type;
    u8 formatted_length; // header `Length` byte, >= 4 on success
    u16 _pad0;
    u16 handle;
    u16 _pad1;
    u32 formatted_offset; // == input `off` on success
    u32 strings_offset;   // formatted_offset + formatted_length
    u32 end_offset;       // start of the next structure
    u8 ok;
    u8 _pad2[3];
};

struct DuetosSmbiosString
{
    u32 offset; // first byte of the resolved string within `buf`
    u32 length; // string length in bytes, NUL exclusive
    u8 ok;
    u8 _pad[3];
};

extern "C"
{
    /// Decode an SMBIOS entry-point structure. Validates the
    /// anchor signature (`_SM_` or `_SM3_`), the byte-additive
    /// checksum, the entry-point length, and a 1 MiB cap on the
    /// structure-table length. On success, writes the table's
    /// physical base + length and the SMBIOS major/minor into
    /// `*out`.
    bool duetos_smbios_parse_entry_point(const u8* buf, usize len, DuetosSmbiosEntryPoint* out);

    /// Decode one structure within the structure-table slice.
    /// `buf` is the whole table; `off` is the starting offset of
    /// the structure under decode. Walks the trailing-strings
    /// region until a double-NUL terminator is found (each entry
    /// capped at 1 KiB), so `end_offset` is the offset of the
    /// NEXT structure (or `len` for the end-of-table type=127
    /// sentinel).
    bool duetos_smbios_parse_structure(const u8* buf, usize len, usize off, DuetosSmbiosStructure* out);

    /// Resolve the 1-based `index`-th string inside a structure's
    /// strings region. `strings_off` + `end_off` must be the values
    /// `duetos_smbios_parse_structure` wrote to `strings_offset` /
    /// `end_offset`. Returns true on hit; sets `out->offset` +
    /// `out->length` to bound the validated NUL-terminated slice.
    bool duetos_smbios_read_string(const u8* buf, usize len, usize strings_off, usize end_off, u8 index,
                                   DuetosSmbiosString* out);
}

} // namespace duetos::arch::smbios_rust
