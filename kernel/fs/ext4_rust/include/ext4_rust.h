// DuetOS ext4 metadata C FFI — hand-written. Mirrors
// kernel/fs/ext4_rust/src/lib.rs.
//
// Status: SKELETON. Currently no C++ caller.

#pragma once

#include "util/types.h"

namespace duetos::fs::ext4
{

struct DuetosExt4Superblock
{
    u32 inodes_count;
    u32 blocks_count_lo;
    u32 free_blocks_count_lo;
    u32 free_inodes_count;
    u32 first_data_block;
    u32 log_block_size;
    u32 blocks_per_group;
    u32 inodes_per_group;
    u16 magic;
    u16 state;
    u32 rev_level;
    u32 feature_compat;
    u32 feature_incompat;
    u32 feature_ro_compat;
    u8 uuid[16];
    u8 ok;
    u8 _pad[7];
};

extern "C"
{
    /// Probe + parse an ext2/3/4 superblock. The on-disk
    /// superblock lives at offset 1024 of the volume; the caller
    /// passes the disk image starting at offset 0 (the function
    /// computes the offset internally).
    bool duetos_ext4_parse_superblock(const u8* buf, usize len, DuetosExt4Superblock* out);
}

} // namespace duetos::fs::ext4
