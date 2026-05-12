// DuetOS ext4 metadata C FFI — hand-written. Mirrors
// kernel/fs/ext4_rust/src/lib.rs.

#pragma once

#include "util/types.h"

namespace duetos::fs::ext4_rust
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
    u16 inode_size;
    u16 _pad0;
    u8 volume_name[16];
    u8 ok;
    u8 _pad[7];
};

struct DuetosExt4GroupDesc
{
    u32 block_bitmap_block;
    u32 inode_bitmap_block;
    u32 inode_table_block;
    u16 free_blocks_count;
    u16 free_inodes_count;
    u16 used_dirs_count;
    u16 _pad0;
    u8 ok;
    u8 _pad1[7];
};

struct DuetosExt4Inode
{
    u16 mode;
    u16 uid;
    u64 size_bytes;
    u32 atime;
    u32 ctime;
    u32 mtime;
    u16 gid;
    u16 links_count;
    u32 blocks_lo;
    u32 flags;
    u8 uses_extents;
    u8 _pad0;
    u16 block0_magic;
    u8 i_block[60];
    u8 ok;
    u8 _pad1[7];
};

struct DuetosExt4ExtentHeader
{
    u16 magic;
    u16 entries;
    u16 max;
    u16 depth;
    u32 generation;
    u8 ok;
    u8 _pad[7];
};

struct DuetosExt4Extent
{
    u32 logical_block;
    u16 length_blocks;
    u16 _pad0;
    u64 physical_block;
    u8 ok;
    u8 _pad1[7];
};

struct DuetosExt4ExtentIndex
{
    u32 logical_block;
    u64 leaf_block;
    u8 ok;
    u8 _pad[7];
};

struct DuetosExt4DirEntry
{
    u32 inode;
    u16 rec_len;
    u8 name_len;
    u8 file_type;
    u32 name_offset;
    u8 ok;
    u8 _pad[3];
};

extern "C"
{
    bool duetos_ext4_parse_superblock(const u8* buf, usize len, DuetosExt4Superblock* out);
    bool duetos_ext4_parse_group_desc0(const u8* buf, usize len, DuetosExt4GroupDesc* out);
    bool duetos_ext4_parse_inode(const u8* buf, usize len, u16 ino_size, u32 feature_ro_compat, DuetosExt4Inode* out);
    bool duetos_ext4_parse_extent_header(const u8* buf, usize len, DuetosExt4ExtentHeader* out);
    bool duetos_ext4_parse_extent_leaf(const u8* buf, usize len, u16 idx, DuetosExt4Extent* out);
    bool duetos_ext4_parse_extent_index(const u8* buf, usize len, u16 idx, DuetosExt4ExtentIndex* out);

    /// Parse one linux_dirent record. Returns the bytes consumed
    /// (rec_len) on success, 0 on a hard error. `out->ok == 1` for
    /// a real entry; `out->ok == 0` for a placeholder slot.
    u32 duetos_ext4_parse_dirent(const u8* block, usize block_len, u32 byte_off, DuetosExt4DirEntry* out);
}

} // namespace duetos::fs::ext4_rust
