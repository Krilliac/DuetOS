// DuetOS NTFS metadata C FFI — hand-written. Mirrors
// kernel/fs/ntfs_rust/src/lib.rs.
//
// The C++ wrapper in kernel/fs/ntfs.cpp delegates boot-sector parse,
// MFT record header decode, resident $FILE_NAME walk, and runlist
// (mapping-pairs) decode to this crate. UTF-16 → ASCII glyph
// filtering still lives in C++ (`util::Utf16CpToSafeAscii`) because
// the crate has no business pulling the project's glyph table in.

#pragma once

#include "util/types.h"

namespace duetos::fs::ntfs
{

struct DuetosNtfsBootSector
{
    u16 bytes_per_sector;
    u8 sectors_per_cluster;
    u8 _pad0;
    u64 total_sectors;
    u64 mft_lcn;
    u64 mft_mirror_lcn;
    i8 clusters_per_mft_record;
    i8 clusters_per_index_block;
    u8 _pad1[2];
    u64 volume_serial;
    u8 ok;
    u8 _pad2[7];
};

struct DuetosNtfsMftRecordHeader
{
    u16 first_attribute_offset;
    u16 flags;
    u8 in_use;
    u8 is_directory;
    u8 _pad[4];
    u8 ok;
    u8 _pad2[7];
};

struct DuetosNtfsFileNameSpan
{
    u32 utf16_offset;
    u8 utf16_units;
    u8 _pad[3];
    u8 ok;
    u8 _pad2[7];
};

struct DuetosNtfsRunlistEntry
{
    u64 length_clusters;
    u64 lcn;
    u8 is_sparse;
    u8 _pad[7];
    u32 bytes_consumed;
    u8 ok;
    u8 _pad2[3];
};

extern "C"
{
    /// Probe + parse an NTFS boot sector. Returns true with
    /// `out->ok = 1` only if the OEM ID ("NTFS    "), MBR signature
    /// (0x55 0xAA at offset 510), `bytes_per_sector` ∈ {256, 512,
    /// 1024, 2048, 4096}, and `sectors_per_cluster` ∈ {1, 2, 4, 8,
    /// 16, 32, 64, 128} all pass.
    bool duetos_ntfs_parse_boot_sector(const u8* buf, usize len, DuetosNtfsBootSector* out);

    /// Decode the BPB `clusters_per_mft_record` byte into a byte
    /// size. Positive: that many clusters per record. Negative N:
    /// record size = 2^(-N). Returns 0 on out-of-range shifts so
    /// the caller can reject.
    u32 duetos_ntfs_decode_mft_record_size(i8 raw, u32 bytes_per_cluster);

    /// Parse an MFT record header (the FILE signature + flags +
    /// first-attribute offset).
    bool duetos_ntfs_parse_mft_record_header(const u8* rec, usize rec_len, usize rec_size,
                                             DuetosNtfsMftRecordHeader* out);

    /// Walk an MFT record's attribute list and return the byte
    /// span of the first resident $FILE_NAME attribute's UTF-16
    /// name. Caller does the UTF-16 → ASCII translation.
    bool duetos_ntfs_find_resident_file_name(const u8* rec, usize rec_len, usize rec_size, DuetosNtfsFileNameSpan* out);

    /// Decode one mapping-pair runlist entry. `prev_lcn` is the
    /// running absolute LCN (pass 0 for the first call).
    /// `out->ok == 1` for a regular run, `out->ok == 0` with
    /// `out->bytes_consumed == 1` on the end-of-runlist terminator
    /// byte, `false` on a hard parse error.
    bool duetos_ntfs_parse_runlist_entry(const u8* buf, usize len, u64 prev_lcn, DuetosNtfsRunlistEntry* out);
}

} // namespace duetos::fs::ntfs
