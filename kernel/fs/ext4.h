#pragma once

#include "../core/result.h"
#include "../core/types.h"

/*
 * DuetOS — ext4 driver, v0 probe-only shell.
 *
 * Reads LBA 2 (the 1024-byte superblock offset) of a block handle,
 * validates the ext4 magic (0xEF53 at offset 0x38 of the
 * superblock = offset 1024+56), records a few self-describing
 * fields from the superblock (block size, UUID, label), and logs
 * the result. That's the extent of v0 — no inode walk, no
 * directory enumeration, no file read.
 *
 * Scope:
 *   - Magic probe. Confirms "this is an ext4 volume" without
 *     committing to any further parse.
 *   - One per-volume record in `g_volumes`.
 *
 * Not in scope (next slice):
 *   - Inode table walk, directory entries, file reads.
 *   - Block-group descriptor parsing.
 *   - Extents / block maps.
 *   - htree + journal awareness.
 *
 * Context: kernel. Safe from task context (BlockDeviceRead is
 * polling synchronous).
 */

namespace duetos::fs::ext4
{

inline constexpr u32 kMaxVolumes = 8;

// Magic value at superblock offset 0x38 (56). Stored
// little-endian. Any ext2/3/4 volume has the same magic — the
// `feature_incompat` flags distinguish them.
inline constexpr u16 kSuperblockMagic = 0xEF53;
inline constexpr u64 kSuperblockLba = 2; // 1024 bytes = 2 × 512-byte sectors

// Group descriptor (classic 32-byte; 64-bit FS has a 64-byte
// variant). We pull the low-half pointers and the free counters.
struct GroupDesc
{
    u32 block_bitmap_block;
    u32 inode_bitmap_block;
    u32 inode_table_block;
    u16 free_blocks_count;
    u16 free_inodes_count;
    u16 used_dirs_count;
};

// Subset of an ext4 inode. We pull mode + size + link count + a
// tag indicating whether the data area is an extent tree (ext4)
// or the legacy block-pointer array (ext2/3). The full 60-byte
// `i_block` area is retained so a directory / small-file walk
// can interpret it without re-reading the inode.
struct InodeInfo
{
    u16 mode; // file type in high 4 bits + perms
    u16 uid;
    u64 size_bytes; // i_size (low 32 + upper 32 when 64-bit)
    u32 atime;
    u32 ctime;
    u32 mtime;
    u16 gid;
    u16 links_count;
    u32 blocks_lo; // in 512-byte units
    u32 flags;
    bool uses_extents; // EXT4_EXTENTS_FL (0x80000) set
    u16 block0_magic;  // if uses_extents: low u16 of i_block[0] = 0xF30A
    u8 i_block[60];    // raw i_block area: extent tree or block ptrs
};

// Parsed ext4 directory entry.
struct Ext4DirEntry
{
    u32 inode;
    u8 file_type;   // 0=unknown, 1=reg, 2=dir, 3=chr, 4=blk, 5=fifo, 6=sock, 7=lnk
    char name[128]; // NUL-terminated; truncated for entries >127
};

inline constexpr u32 kMaxRootDirEntries = 32;

struct Volume
{
    u32 block_handle;
    u32 block_size; // 1024 << s_log_block_size
    u16 inode_size; // s_inode_size; 128 for ext2, 256 for ext3/4
    u64 inode_count;
    u64 block_count;
    u32 blocks_per_group;
    u32 inodes_per_group;
    u32 first_data_block; // 0 for 4KiB blocks, 1 for 1KiB
    u32 feature_compat;
    u32 feature_incompat;
    u32 feature_ro_compat;
    u32 rev_level;  // 0 = "good old", 1 = "dynamic"
    char label[17]; // s_volume_name + NUL

    bool group0_valid;
    GroupDesc group0;

    bool root_inode_valid;
    InodeInfo root_inode;

    u32 root_dir_entry_count;
    Ext4DirEntry root_dir_entries[kMaxRootDirEntries];
};

/// Probe the block device at `handle`. On success, allocates a
/// registry slot, fills its Volume record, logs it, and returns
/// the slot index. Errors:
///   IoError    — BlockDeviceRead failed.
///   NotFound   — magic mismatch (not an ext2/3/4 volume).
///   BadState   — volume registry full.
::duetos::core::Result<u32> Ext4Probe(u32 block_handle);

u32 Ext4VolumeCount();
const Volume* Ext4VolumeByIndex(u32 index);

/// Boot-time sweep: probe every discovered block device. Logs
/// the outcome for each.
void Ext4ScanAll();

} // namespace duetos::fs::ext4
