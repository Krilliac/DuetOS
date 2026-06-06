#pragma once

#include "util/result.h"
#include "util/types.h"

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
 *   - MFT-record-by-index read with USA (update-sequence-array)
 *     fixup applied (NtfsReadMftRecord).
 *   - $DATA resolution for a regular file: resident value, plus a
 *     basic single-run non-resident value via the Rust runlist
 *     decoder (NtfsResolveData / NtfsReadFile).
 *   - Root-directory enumeration via the resident $INDEX_ROOT
 *     ($I30) index entries (NtfsEnumerateRoot / NtfsFindInRoot).
 *
 * GAP (not in scope):
 *   - $INDEX_ALLOCATION b-trees: a directory whose $I30 index
 *     overflows INDEX_ROOT into non-resident INDEX_ALLOCATION
 *     blocks is only enumerated for the resident slice. This applies
 *     at every directory level of a multi-component path walk
 *     (NtfsEnumerateDir / NtfsFindInDir), not just the root.
 *   - Multi-run / compressed / sparse / encrypted $DATA: the
 *     non-resident decoder follows the FIRST data run only.
 *   - Alternate data streams (named $DATA), reparse points /
 *     symlinks, $LogFile / $UsnJrnl replay, writes.
 *   - Unicode collation edge cases (names are decoded UTF-16 →
 *     safe ASCII via util::Utf16CpToSafeAscii).
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

// NTFS attribute type codes the read path cares about.
inline constexpr u32 kAttrTypeFileName = 0x30;  // $FILE_NAME
inline constexpr u32 kAttrTypeData = 0x80;      // $DATA
inline constexpr u32 kAttrTypeIndexRoot = 0x90; // $INDEX_ROOT
inline constexpr u32 kAttrTypeEnd = 0xFFFFFFFF; // attribute-list terminator

// Largest MFT record we will read into scratch (covers the common
// 1024-byte record plus the 4096-byte modern variant).
inline constexpr u32 kMaxMftRecordSize = 4096;

// Largest directory we enumerate from a resident $INDEX_ROOT.
inline constexpr u32 kMaxDirEntries = 32;
// Largest single-run non-resident file we read back (one scratch
// cluster-run; the resident-$DATA happy path is much smaller).
inline constexpr u32 kMaxFileReadBytes = 4096;

struct MftEntry
{
    u32 record_num;
    bool in_use;
    bool is_directory;
    char name[128]; // UTF-16 decoded to ASCII; non-ASCII -> '?'
};

// One enumerated directory entry from a resident $INDEX_ROOT.
struct DirEntry
{
    u64 mft_reference; // target MFT record number (low 48 bits)
    bool is_directory;
    char name[128]; // UTF-16 decoded to ASCII; non-ASCII -> '?'
};

// Resolved $DATA location for a regular file. `resident` data lives
// inline in the MFT record (small files); otherwise the first data
// run is described by (first_lcn, run_clusters) and `size_bytes` is
// the real (allocated-or-initialised) data length.
struct DataLocation
{
    bool valid;
    bool resident;
    u64 size_bytes;
    // Resident-only: byte offset of the value within the MFT record.
    u32 resident_offset;
    // Non-resident-only: first run's start LCN + length in clusters.
    u64 first_lcn;
    u64 run_clusters;
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

/// Find the probed volume backed by `block_handle`, or nullptr if no
/// NTFS volume on that handle has been registered. Mirrors
/// `ext4::Ext4VolumeByHandle` — the VFS backend lookup keys by handle.
const Volume* NtfsVolumeByHandle(u32 block_handle);
void NtfsScanAll();

/// Read MFT record number `record_num` from volume `v` into `out`
/// (which must hold at least `v.mft_record_size` bytes) and apply the
/// update-sequence-array (USA) fixup. Returns InvalidArgument on bad
/// geometry, IoError on a block read failure, Corrupt on a bad "FILE"
/// signature or an inconsistent fixup.
::duetos::core::Result<void> NtfsReadMftRecord(const Volume& v, u64 record_num, u8* out);

/// Resolve the unnamed $DATA attribute of a (already fixed-up) MFT
/// record. Fills `*out` with either a resident value pointer-offset
/// or the first non-resident data run. Returns NotFound if the record
/// has no unnamed $DATA, Corrupt on a malformed attribute.
///   GAP: follows the FIRST data run of a non-resident value only;
///   multi-run / compressed / sparse / encrypted $DATA is not mapped.
::duetos::core::Result<void> NtfsResolveData(const Volume& v, const u8* rec, DataLocation* out);

/// Enumerate the directory whose MFT record is `dir_record_num` on
/// volume `v` from its resident $INDEX_ROOT ($I30) index. Writes up to
/// `kMaxDirEntries` entries into `out_entries[]` and reports the count
/// via `*out_count`. Used at every level of a multi-component walk.
///   GAP: resident INDEX_ROOT only — entries that spilled into a
///   non-resident $INDEX_ALLOCATION b-tree are not walked. Applies at
///   every directory level, not just the root.
///   NOTE: non-reentrant — decodes through a module-static scratch
///   buffer, so each level's DirEntry results (value copies) must be
///   consumed before the next NtfsEnumerateDir / NtfsFindInDir call.
::duetos::core::Result<void> NtfsEnumerateDir(const Volume& v, u64 dir_record_num, DirEntry* out_entries, u32 cap,
                                              u32* out_count);

/// Enumerate the root directory ($Root, MFT record 5) of volume `v`.
/// Thin wrapper over NtfsEnumerateDir(v, 5, ...); same GAP applies.
::duetos::core::Result<void> NtfsEnumerateRoot(const Volume& v, DirEntry* out_entries, u32 cap, u32* out_count);

/// Find a child named `name` directly under the directory whose MFT
/// record is `dir_record_num` on `v`, filling `*out` with its directory
/// entry. Returns NotFound if absent. Re-enumerates the resident index
/// per call (no cache). The descend primitive for a component walk: the
/// returned `mft_reference` is the next level's `dir_record_num`.
::duetos::core::Result<void> NtfsFindInDir(const Volume& v, u64 dir_record_num, const char* name, DirEntry* out);

/// Find a child named `name` directly under the root directory of
/// `v`, filling `*out` with its directory entry. Returns NotFound if
/// absent. Thin wrapper over NtfsFindInDir(v, 5, ...).
::duetos::core::Result<void> NtfsFindInRoot(const Volume& v, const char* name, DirEntry* out);

/// Read up to `len` bytes of regular-file data starting at byte
/// `offset` from `data` (a resolved $DATA location) on volume `v`.
/// `rec` is the fixed-up MFT record that backs a resident value.
/// Reports the byte count read via `*out_read` (clamped to the data
/// size). Returns IoError on a block read failure.
///   GAP: single-run non-resident $DATA only — see NtfsResolveData.
::duetos::core::Result<void> NtfsReadFile(const Volume& v, const u8* rec, const DataLocation& data, u64 offset,
                                          void* buf, u64 len, u64* out_read);

/// Boot self-test: builds a minimal synthetic NTFS volume in a RAM
/// block device and drives probe → root enumerate → read-file-back
/// with assertions. Emits `[ntfs-selftest] PASS (...)` on success;
/// `[ntfs-selftest] FAIL (<phase>)` + a kBootSelftestFail probe on
/// failure. Lives in kernel/fs/ntfs_selftest.cpp.
void NtfsSelfTest();

} // namespace duetos::fs::ntfs
