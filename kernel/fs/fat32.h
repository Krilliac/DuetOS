#pragma once

#include "../core/types.h"

/*
 * CustomOS FAT32 driver — v0 (read-only BPB parse + root-dir walk).
 *
 * Scope:
 *   - Recognise a FAT32 volume by reading LBA 0 of a block-device
 *     handle, validating the BPB (bytes_per_sector, sectors_per_cluster,
 *     reserved + FAT counts, "FAT32" in fs_type, 0x55AA at 510/511).
 *   - Enumerate the root directory (cluster chain starting at
 *     BPB.root_cluster). v0 follows the chain through the FAT, so a
 *     multi-cluster root works even without LFN decoding. Only short
 *     8.3 names are reported; LFN (attr == 0x0F) entries are skipped.
 *   - Log one line per non-deleted, non-volume-label entry:
 *     name, attrs, first cluster, size.
 *
 * Not in scope (next slice):
 *   - File content read by cluster-chain walk. BlockDeviceRead into
 *     a caller buffer, bounded by the size field. Exposing it as a
 *     VFS mount-point is the one-after-that.
 *   - Long filename (LFN) decoding.
 *   - Subdirectory recursion (root-dir only for v0).
 *   - Writes.
 *
 * Context: kernel. Safe in task context (issues BlockDeviceRead,
 * which is polling-mode synchronous).
 */

namespace customos::fs::fat32
{

/// Max volumes we track. One per partition-block handle is plenty —
/// the block layer caps at 16, so 16 here matches.
inline constexpr u32 kMaxVolumes = 16;

/// Max directory entries we carry in a per-volume snapshot. Enough
/// for a handful of test files; real filesystems should enumerate
/// on demand (follow-up slice).
inline constexpr u32 kMaxDirEntries = 32;

/// A single parsed directory entry. Short 8.3 name only in v0 —
/// LFN fragments are skipped during the walk.
struct DirEntry
{
    char name[12];     // 8.3 format with one '.' + NUL, e.g. "HELLO.TXT\0"
    u8 attributes;     // FAT attribute byte (0x20 = ARCHIVE, 0x10 = DIR, etc.)
    u32 first_cluster; // 0 for entries with no cluster (zero-length file)
    u32 size_bytes;    // size field; 0 for directories
};

struct Volume
{
    u32 block_handle;
    u32 bytes_per_sector;
    u32 sectors_per_cluster;
    u32 reserved_sectors;
    u32 num_fats;
    u32 fat_size_sectors;
    u32 total_sectors;
    u32 root_cluster;
    u32 data_start_sector; // LBA (within the partition) of cluster 2
    u32 root_entry_count;  // filled count of root_entries below
    DirEntry root_entries[kMaxDirEntries];
};

/// Probe a block-device handle for a FAT32 volume. On success:
/// fills the volume registry, logs one summary line + one line per
/// root-dir entry, and writes `*out_index` with the new volume
/// slot. On any failure (bad BPB, unsupported geometry, I/O error)
/// returns false and logs a diagnostic.
bool Fat32Probe(u32 block_handle, u32* out_index);

u32 Fat32VolumeCount();
const Volume* Fat32Volume(u32 index);

/// Boot-time self-test. Calls `Fat32Probe` on every registered
/// block device; partitions that aren't FAT32 are expected to fail
/// and are logged as "not FAT32" (no failure shout). One PASS line
/// if the self-test found at least one volume AND that volume's
/// root contains at least one non-directory entry.
void Fat32SelfTest();

} // namespace customos::fs::fat32
