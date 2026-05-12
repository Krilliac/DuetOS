// DuetOS ACPI table walker C FFI — hand-written. Mirrors
// kernel/acpi/acpi_rust/src/lib.rs.

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

struct DuetosAcpiMadtEntryHeader
{
    u8 entry_type;
    u8 length;
    u16 _pad;
    u8 ok;
    u8 _pad1[3];
};

struct DuetosAcpiFadt
{
    u32 firmware_ctrl;
    u32 dsdt;
    u16 sci_int;
    u16 _pad0;
    u32 smi_cmd;
    u32 pm1a_evt_blk;
    u32 pm1a_cnt_blk;
    u32 pm1b_cnt_blk;
    u32 pm_tmr_blk;
    u8 pm1_cnt_len;
    u8 _pad1[3];
    u32 flags;
    u8 reset_supported;
    u8 reset_address_space_id;
    u8 _pad2[2];
    u64 reset_address;
    u8 reset_value;
    u8 _pad3[3];
    u8 ok;
    u8 _pad4[3];
};

struct DuetosAcpiMcfgEntry
{
    u64 base_address;
    u16 segment_group;
    u8 start_bus;
    u8 end_bus;
    u32 _pad;
    u8 ok;
    u8 _pad2[7];
};

struct DuetosAcpiHpet
{
    u32 event_timer_block_id;
    u8 base_address_space_id;
    u8 _pad0[3];
    u64 base_address;
    u8 hpet_number;
    u8 _pad1;
    u16 main_counter_minimum;
    u8 page_protection_oem;
    u8 _pad2[3];
    u8 timer_count;
    u8 counter_width;
    u8 _pad3[2];
    u8 ok;
    u8 _pad4[7];
};

struct DuetosAcpiSratMemoryAffinity
{
    u32 proximity_domain;
    u32 _pad0;
    u64 base_address;
    u64 length;
    u32 flags;
    u8 enabled;
    u8 hot_pluggable;
    u8 non_volatile;
    u8 _pad1;
    u8 ok;
    u8 _pad2[7];
};

extern "C"
{
    /// Probe + parse an ACPI RSDP. v1 (20 bytes) and v2 (36 bytes)
    /// both accepted; `revision` selects which checksum path.
    bool duetos_acpi_parse_rsdp(const u8* buf, usize len, DuetosAcpiRsdp* out);

    /// Parse a 36-byte ACPI table header. Validates signature
    /// length and the whole-table 8-bit additive checksum.
    bool duetos_acpi_parse_table_header(const u8* buf, usize len, DuetosAcpiTableHeader* out);

    /// Decode one MADT entry header (type + length). `off` is the
    /// byte offset within `buf` of the entry's first byte.
    bool duetos_acpi_parse_madt_entry_header(const u8* buf, usize len, usize off, DuetosAcpiMadtEntryHeader* out);

    /// Decode the FADT body fields the kernel actually consumes
    /// (SCI vector, PM1 control block + length, flags, DSDT
    /// pointer, reset register / value). `buf` is the entire FADT
    /// table including the 36-byte ACPI header.
    bool duetos_acpi_parse_fadt(const u8* buf, usize len, DuetosAcpiFadt* out);

    /// Decode the `idx`-th MCFG entry. `buf` is the entire MCFG
    /// table including the 36-byte ACPI header.
    bool duetos_acpi_parse_mcfg_entry(const u8* buf, usize len, u32 idx, DuetosAcpiMcfgEntry* out);

    /// Decode the HPET description table.
    bool duetos_acpi_parse_hpet(const u8* buf, usize len, DuetosAcpiHpet* out);

    /// Decode an SRAT Memory Affinity subtable starting at `off`
    /// (entries are variable-length and chained by their `length`
    /// byte; caller advances the cursor).
    bool duetos_acpi_parse_srat_memory_affinity(const u8* buf, usize len, usize off, DuetosAcpiSratMemoryAffinity* out);
}

} // namespace duetos::acpi::rust
