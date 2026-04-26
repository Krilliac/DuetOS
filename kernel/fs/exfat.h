#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — exFAT driver, v0 probe + root-directory walk.
 *
 * exFAT boot sector (sector 0) signature is "EXFAT   " (EXFAT +
 * 3 spaces) at offset 3. Unlike FAT32 and NTFS, exFAT uses a
 * much simpler boot record layout but still shares the 0x55AA
 * boot signature at offset 510.
 *
 * The root directory is a chain of 32-byte directory entries
 * starting at `first_cluster_of_root`. Each logical "file" is
 * made of a primary entry (type 0x85 File Directory Entry),
 * followed by a stream-extension entry (type 0xC0, carries
 * size + first-cluster + name length), followed by 1..17 file-
 * name entries (type 0xC1, each carries 15 UTF-16 chars). We
 * walk the root cluster only (no recursion) and parse each triad
 * into a `DirEntry` record.
 *
 * Scope:
 *   - Signature probe + boot-sector record.
 *   - Root-directory walk (first cluster only — a multi-cluster
 *     root would need the FAT walk, which is deferred).
 *   - Up to kMaxDirEntries entries captured per volume.
 *
 * Not in scope:
 *   - FAT-backed multi-cluster chain walk.
 *   - Writes.
 *   - Subdirectory recursion.
 *
 * Context: kernel, polling synchronous.
 */

namespace duetos::fs::exfat
{

inline constexpr u32 kMaxVolumes = 8;
inline constexpr u32 kMaxDirEntries = 32;
inline constexpr u64 kBootSectorLba = 0;

// exFAT directory-entry type bytes. The high bit distinguishes
// "in-use" (1) from "deleted" (0). Primary entry types share the
// 0x80..0xBF range; secondary (follow-up) entries use 0xC0..0xFF.
inline constexpr u8 kDirEntryEndOfDir = 0x00;
inline constexpr u8 kDirEntryFile = 0x85;
inline constexpr u8 kDirEntryStreamExt = 0xC0;
inline constexpr u8 kDirEntryFileName = 0xC1;

struct DirEntry
{
    char name[128];     // UTF-16 decoded to ASCII; non-ASCII -> '?'
    u8 attributes;      // FAT-style attribute byte (0x10 = DIR, 0x20 = ARCH)
    u32 first_cluster;  // first cluster of the file data
    u64 valid_data_len; // "valid" length (always <= size_bytes)
    u64 size_bytes;     // file size
};

struct Volume
{
    u32 block_handle;
    u64 partition_offset_bytes;
    u64 volume_length_sectors;
    u32 fat_offset_sectors;
    u32 cluster_heap_offset_sectors;
    u32 cluster_count;
    u32 first_cluster_of_root;
    u8 bytes_per_sector_shift;    // log2
    u8 sectors_per_cluster_shift; // log2
    u32 root_entry_count;         // count of parsed root entries
    DirEntry root_entries[kMaxDirEntries];
};

/// Probe the block device at `handle`. On success returns the
/// registry slot index; errors as for Ext4Probe.
::duetos::core::Result<u32> ExfatProbe(u32 block_handle);
u32 ExfatVolumeCount();
const Volume* ExfatVolumeByIndex(u32 index);
void ExfatScanAll();

} // namespace duetos::fs::exfat
