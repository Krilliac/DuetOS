#pragma once

#include "../core/types.h"

/*
 * CustomOS — ext4 driver, v0 probe-only shell.
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

namespace customos::fs::ext4
{

inline constexpr u32 kMaxVolumes = 8;

// Magic value at superblock offset 0x38 (56). Stored
// little-endian. Any ext2/3/4 volume has the same magic — the
// `feature_incompat` flags distinguish them.
inline constexpr u16 kSuperblockMagic = 0xEF53;
inline constexpr u64 kSuperblockLba = 2; // 1024 bytes = 2 × 512-byte sectors

struct Volume
{
    u32 block_handle;
    u32 block_size; // 1024 << s_log_block_size
    u64 inode_count;
    u64 block_count;
    char label[17]; // s_volume_name + NUL
};

/// Probe the block device at `handle`. If the superblock magic
/// matches, populate a Volume record, log it, and return true
/// via `*out_index` = array slot. Returns false otherwise.
bool Ext4Probe(u32 block_handle, u32* out_index);

u32 Ext4VolumeCount();
const Volume* Ext4VolumeByIndex(u32 index);

/// Boot-time sweep: probe every discovered block device. Logs
/// the outcome for each.
void Ext4ScanAll();

} // namespace customos::fs::ext4
