// DuetOS exFAT metadata C FFI — hand-written. Mirrors
// kernel/fs/exfat_rust/src/lib.rs.

#pragma once

#include "util/types.h"

namespace duetos::fs::exfat
{

struct DuetosExfatBootSector
{
    u64 partition_offset;
    u64 volume_length;
    u32 fat_offset;
    u32 fat_length;
    u32 cluster_heap_offset;
    u32 cluster_count;
    u32 root_dir_first_cluster;
    u32 volume_serial;
    u8 bytes_per_sector_shift;
    u8 sectors_per_cluster_shift;
    u8 number_of_fats;
    u8 ok;
    u32 _pad;
};

struct DuetosExfatGeometry
{
    u32 bytes_per_sector;
    u32 sectors_per_cluster;
    u64 cluster_bytes;
    u8 ok;
    u8 _pad[7];
};

struct DuetosExfatDirEntry
{
    u8 attributes;
    u8 _pad0;
    u16 _pad1;
    u32 first_cluster;
    u64 size_bytes;
    u64 valid_data_len;
    u32 name_offset;
    u8 name_units;
    u8 _pad2[3];
    u8 slots_consumed;
    u8 _pad3[3];
    u8 ok;
    u8 _pad4[7];
};

extern "C"
{
    /// Probe + parse an exFAT VBR (Volume Boot Record). Returns
    /// true with `out->ok = 1` only if the OEM ID ("EXFAT   "),
    /// MBR signature, and shift fields all pass spec validation.
    bool duetos_exfat_parse_boot_sector(const u8* buf, usize len, DuetosExfatBootSector* out);

    /// Derive layout numbers (bytes/sector, sectors/cluster,
    /// cluster size in bytes) from a parsed boot sector. Returns
    /// false if `bs` is null, has `ok == 0`, or has shift fields
    /// outside the spec-permitted range.
    bool duetos_exfat_derive_geometry(const DuetosExfatBootSector* bs, DuetosExfatGeometry* out);

    /// Parse one dirent set starting at slot `start_idx` (32-byte
    /// slots) within `buf`. `buf_entries` is the number of slots
    /// in `buf`. Returns false on a hard parse error; returns true
    /// with `out->ok = 0` and `out->slots_consumed > 0` for "skip
    /// this many slots and try again" (deleted / non-File primary /
    /// orphan entry).
    bool duetos_exfat_parse_dirent_set(const u8* buf, usize len, u32 start_idx, u32 buf_entries,
                                       DuetosExfatDirEntry* out);

    /// Look up `cluster` in the FAT (4-byte LE per entry). Returns
    /// 0 on invalid input, 0xFFFFFFFF on end-of-chain (any value >=
    /// 0xFFFFFFF8 per spec), otherwise the next cluster index.
    u32 duetos_exfat_fat_chain_next(const u8* fat, usize fat_len, u32 cluster);
}

} // namespace duetos::fs::exfat
