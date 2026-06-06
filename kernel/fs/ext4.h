#pragma once

#include "util/result.h"
#include "util/types.h"

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

/// Find the probed volume backed by `block_handle`, or nullptr if
/// no ext4 volume on that handle has been registered. Mirrors
/// `fat32::Fat32Volume` — the VFS backend lookup keys by handle.
const Volume* Ext4VolumeByHandle(u32 block_handle);

/// Read inode number `ino_num` (1-based, as on disk) from volume
/// `v` into `*out`. Walks the block-group descriptor table to find
/// the group, then the inode table within it, then parses the
/// record. Returns NotFound on a zero / out-of-range inode number,
/// IoError on a block-layer failure, InvalidArgument on geometry
/// skew (inode straddles two blocks — not yet handled).
///   GAP: assumes the inode record fits inside a single FS block
///   (inode_size <= block_size and the record doesn't straddle a
///   block boundary). True for every sane mkfs.ext4 layout; revisit
///   if a 1KiB-block + 256B-inode image ever lands an inode across
///   a block edge.
::duetos::core::Result<void> Ext4ReadInode(const Volume& v, u32 ino_num, InodeInfo* out);

/// Find a child named `name` directly under the root directory of
/// `v`, filling `*out` with its directory entry (inode number +
/// type + name). Returns NotFound if absent. Uses the cached
/// `root_dir_entries[]` snapshot populated at probe time, so this
/// is a linear scan over already-parsed entries.
///   GAP: htree (hashed) directories are not walked — a large dir
///   with the INDEX_FL flag set falls back to whatever linear
///   entries the leaf walk captured. Revisit when htree lands.
::duetos::core::Result<void> Ext4FindInRoot(const Volume& v, const char* name, Ext4DirEntry* out);

/// Find a child named `name` directly under the directory inode `dir`
/// (any directory, not just root), filling `*out` with its directory
/// entry. Reads `dir`'s data block-by-block via `Ext4ReadFile` and
/// scans the linux_dirent records, so it works for any extent-mapped
/// directory — this is what lets `VfsResolve` walk multi-component
/// paths (`/sub/file`). Returns NotFound if absent.
///   GAP: htree (hashed) directories are not walked — same limit as
///   Ext4FindInRoot. Names longer than the `Ext4DirEntry::name`
///   buffer (127 chars) cannot be matched.
::duetos::core::Result<void> Ext4FindInDir(const Volume& v, const InodeInfo& dir, const char* name, Ext4DirEntry* out);

/// Read up to `len` bytes of regular-file data starting at byte
/// `offset` from the extent-mapped inode `inode` on volume `v`.
/// Writes into `buf` and reports the byte count actually read via
/// `*out_read` (clamped to the file size). Returns InvalidArgument
/// for a non-extent inode or bad geometry, IoError on a block read
/// failure.
///   GAP: extents only — classic direct/indirect block maps
///   (ext2/3 layout, EXT4_EXTENTS_FL clear) are not read here. The
///   modern mkfs.ext4 default is extents, so the happy path is
///   covered; revisit for legacy images.
///   Depth>0 extent trees are followed: when the inode's extent
///   header has depth>0, the read path descends the interior index
///   nodes (one covering child per level, read into a dedicated
///   scratch buffer) until it reaches the covering leaf.
///   GAP: descent depth is capped at kMaxExtentDepth (16) — a tree
///   deeper than that (only reachable via corruption; real ext4
///   trees top out near 5 levels) is treated as a miss. depth>1 is
///   code-supported but the self-test only exercises depth-1.
::duetos::core::Result<void> Ext4ReadFile(const Volume& v, const InodeInfo& inode, u64 offset, void* buf, u64 len,
                                          u64* out_read);

/// Boot-time sweep: probe every discovered block device. Logs
/// the outcome for each.
void Ext4ScanAll();

/// Boot self-test: builds a minimal synthetic ext4 volume in a RAM
/// block device and drives probe → group-desc → root-inode →
/// root-dir enumerate → find file → extent file read with
/// assertions. Emits `[ext4-selftest] PASS (...)` on success;
/// `[ext4-selftest] FAIL (<phase>)` + a kBootSelftestFail probe on
/// failure. Lives in kernel/fs/ext4_selftest.cpp.
void Ext4SelfTest();

} // namespace duetos::fs::ext4
