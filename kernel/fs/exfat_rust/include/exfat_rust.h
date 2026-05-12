// DuetOS exFAT metadata C FFI — hand-written. Mirrors
// kernel/fs/exfat_rust/src/lib.rs.
//
// Status: SKELETON. Currently no C++ caller.

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

extern "C"
{
    /// Probe + parse an exFAT VBR (Volume Boot Record). Returns
    /// true with `out->ok = 1` only if the OEM ID ("EXFAT   "),
    /// MBR signature, and shift fields all pass spec validation.
    bool duetos_exfat_parse_boot_sector(const u8* buf, usize len, DuetosExfatBootSector* out);
}

} // namespace duetos::fs::exfat
