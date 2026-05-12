// DuetOS NTFS metadata C FFI — hand-written. Mirrors
// kernel/fs/ntfs_rust/src/lib.rs.
//
// Status: SKELETON. Currently no C++ caller — see
// `wiki/reference/Roadmap.md` "Skeleton crates" for the trigger
// that flips this to production status.

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

extern "C"
{
    /// Probe + parse an NTFS boot sector. Returns true with
    /// `out->ok = 1` only if the OEM ID ("NTFS    "), MBR signature
    /// (0x55 0xAA at offset 510), `bytes_per_sector` ∈ {256, 512,
    /// 1024, 2048, 4096}, and `sectors_per_cluster` ∈ {1, 2, 4, 8,
    /// 16, 32, 64, 128} all pass.
    bool duetos_ntfs_parse_boot_sector(const u8* buf, usize len, DuetosNtfsBootSector* out);
}

} // namespace duetos::fs::ntfs
