#pragma once

#include "../core/result.h"
#include "../core/types.h"

/*
 * DuetOS — NTFS driver, v0 probe + $MFT system-record walk.
 *
 * Reads LBA 0 (the boot sector) of a block device and validates
 * the NTFS signature: "NTFS    " at offset 3 plus 0x55AA at offset
 * 510. Records bytes-per-sector, sectors-per-cluster, the MFT LCN,
 * and `clusters_per_mft_record` (signed byte at offset 0x40 of the
 * BPB — if positive, clusters per record; if negative, log2 of
 * byte-size per record).
 *
 * After probe, we walk the first kMaxMftRecords entries of the MFT
 * itself (records 0..15 are "$MFT", "$MFTMirr", "$LogFile",
 * "$Volume", "$AttrDef", "$" (root dir), "$Bitmap", "$Boot",
 * "$BadClus", "$Secure", "$UpCase", "$Extend", ...). For each
 * record we validate the "FILE" signature, find the first
 * $FILE_NAME attribute (type 0x30), and decode its UTF-16 name to
 * ASCII for logging.
 *
 * Scope:
 *   - Signature probe + handful of boot-sector fields.
 *   - System-record name enumeration ($MFT, $MFTMirr, ..., root).
 *
 * Not in scope:
 *   - Update-sequence-array fixup (names live below the sector
 *     boundary that fixup would rewrite, so our read is safe; a
 *     $DATA run list or INDEX_ALLOCATION probe would need fixup).
 *   - $INDEX_ROOT / $INDEX_ALLOCATION traversal (root-directory
 *     enumeration proper).
 *   - File data attribute reads.
 *   - Compressed / sparse / encrypted attributes; $LogFile; USN
 *     journal.
 *
 * Context: kernel, polling-synchronous block reads only.
 */

namespace duetos::fs::ntfs
{

inline constexpr u32 kMaxVolumes = 8;
inline constexpr u32 kMaxMftRecords = 16;
inline constexpr u64 kBootSectorLba = 0;

// File record "FILE" signature, little-endian u32.
inline constexpr u32 kFileRecordMagic = 0x454C4946; // 'FILE'

struct MftEntry
{
    u32 record_num;
    bool in_use;
    bool is_directory;
    char name[128]; // UTF-16 decoded to ASCII; non-ASCII -> '?'
};

struct Volume
{
    u32 block_handle;
    u16 bytes_per_sector;
    u8 sectors_per_cluster;
    i8 clusters_per_mft_record; // raw signed byte from BPB @ 0x40
    u32 mft_record_size;        // decoded byte size (typically 1024)
    u64 total_sectors;
    u64 mft_lcn; // logical cluster number of $MFT
    u32 system_record_count;
    MftEntry system_records[kMaxMftRecords];
};

/// Probe the block device at `handle`. On success returns the
/// registry slot index; errors as for Ext4Probe.
::duetos::core::Result<u32> NtfsProbe(u32 block_handle);
u32 NtfsVolumeCount();
const Volume* NtfsVolumeByIndex(u32 index);
void NtfsScanAll();

} // namespace duetos::fs::ntfs
