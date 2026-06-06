// DuetOS ACPI AML namespace-walker C FFI — hand-written. Mirrors
// kernel/acpi/aml_rust/src/lib.rs.
//
// The three record structs are LAYOUT-COMPATIBLE with the kernel's
// AmlNamespaceEntry / AmlRegionInfo / AmlFieldInfo (acpi/aml.h):
// the C++ caller passes its own global arrays reinterpreted as
// these, so the walker writes named-object records straight into
// the namespace table with no marshalling copy. aml.cpp carries
// static_asserts that the layouts match — a kernel-side struct
// change that breaks the mirror fails the build, not silently at
// runtime.

#pragma once

#include "util/types.h"

namespace duetos::acpi::rust
{

// Mirror of AmlNamespaceEntry (acpi/aml.h). kind / region-space are
// plain u8 here; the kernel side casts back to its enum class.
struct DuetosAmlEntry
{
    char path[64];
    u8 kind;
    u8 method_args;
    u8 source_table_idx;
    u8 _pad;
    u32 aml_offset;
};

// Mirror of AmlRegionInfo (acpi/aml.h).
struct DuetosAmlRegion
{
    char path[64];
    u8 space;
    u8 source_table_idx;
    u8 _pad[2];
    u64 base;
    u64 length;
};

// Mirror of AmlFieldInfo (acpi/aml.h).
struct DuetosAmlField
{
    char path[64];
    char region[64];
    u32 bit_offset;
    u32 bit_width;
    u8 access_bytes;
    u8 source_table_idx;
    u8 _pad[2];
};

extern "C"
{
    /// Walk one ACPI table's AML body and APPEND the named objects it
    /// declares to the caller's namespace / region / field arrays.
    ///
    /// `sdt` points at the whole table (including the 36-byte ACPI
    /// header); `total_len` is its length. `source_idx` is stamped
    /// into every record (0 = DSDT, N = SSDT[N-1]).
    ///
    /// Each `*_count` is in/out: the walker starts appending at the
    /// current count and stops at the matching `*_cap`. Bounds + a
    /// recursion-depth cap make a hostile table safe; the walker
    /// stops the current TermList on any byte it can't decode and
    /// resumes the parent at its PkgLength end, exactly as the former
    /// C++ walker did.
    void duetos_aml_walk_table(const u8* sdt, u32 total_len, u8 source_idx, DuetosAmlEntry* entries, u32 entries_cap,
                               u32* entries_count, DuetosAmlRegion* regions, u32 regions_cap, u32* regions_count,
                               DuetosAmlField* fields, u32 fields_cap, u32* fields_count);
}

} // namespace duetos::acpi::rust
