// DuetOS ACPI table walker C FFI — hand-written. Mirrors
// kernel/acpi/acpi_rust/src/lib.rs.
//
// Status: SKELETON. Currently no C++ caller.

#pragma once

#include "util/types.h"

namespace duetos::acpi::rust
{

struct DuetosAcpiRsdp
{
    u8 revision;
    u8 _pad0[3];
    u32 rsdt_address;
    u64 xsdt_address;
    u8 oem_id[6];
    u8 ok;
    u8 _pad1;
};

struct DuetosAcpiTableHeader
{
    u8 signature[4];
    u32 length;
    u8 revision;
    u8 checksum;
    u8 oem_id[6];
    u8 oem_table_id[8];
    u32 oem_revision;
    u8 creator_id[4];
    u32 creator_revision;
    u8 ok;
    u8 _pad[3];
};

extern "C"
{
    /// Probe + parse an ACPI RSDP. Returns true with `out->ok = 1`
    /// on signature + checksum pass. v1 (20 bytes) and v2 (36
    /// bytes) both accepted; `revision` selects which path.
    bool duetos_acpi_parse_rsdp(const u8* buf, usize len, DuetosAcpiRsdp* out);

    /// Parse a 36-byte ACPI table header. Validates signature
    /// length and the whole-table 8-bit additive checksum (the
    /// caller must pass `length` bytes that fit the table).
    bool duetos_acpi_parse_table_header(const u8* buf, usize len, DuetosAcpiTableHeader* out);
}

} // namespace duetos::acpi::rust
