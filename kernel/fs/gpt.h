#pragma once

#include "util/types.h"

/*
 * DuetOS GPT partition parser — v0.
 *
 * Reads the Protective MBR + primary GPT header + partition entry
 * array from a block device and records every non-empty partition.
 * No mount logic and no filesystem probing — this module's job is
 * strictly "turn a disk handle into a list of (first_lba, last_lba,
 * type_guid, name) tuples" so the next stage (FAT32 mount) can pick
 * a partition and hand it to the filesystem driver.
 *
 * Scope limits (v0):
 *   - Primary header only. If the primary is corrupt the parse
 *     fails rather than falling back to the backup at the last
 *     LBA. Disks in that state are either brand-new or already
 *     hosed; either way, manual intervention is appropriate.
 *   - 128 partition entries × 128 bytes (the UEFI spec's canonical
 *     layout — every mkfs / fdisk / parted variant produces this).
 *     Custom entry sizes are rejected.
 *   - No MBR fallback. Non-GPT disks log "not a GPT disk" and
 *     return false; modern SSDs ship GPT, legacy MBR-only disks
 *     are out of scope until a real workload needs one.
 *   - CRC32-IEEE validation on both header and entry array.
 *     Header CRC covers the header with the CRC field zeroed.
 *     Entries CRC covers num_entries * entry_size bytes.
 *
 * Context: kernel. Safe to call from task context; issues block
 * I/O which is currently polling-mode synchronous.
 */

namespace duetos::fs::gpt
{

/// Size of a GPT GUID in bytes. Binary form — byte order is little-
/// endian for the first three fields (u32, u16, u16) and big-endian
/// for the last two (u8[2], u8[6]) per UEFI spec §5.3.1. We store
/// them raw and compare byte-wise; string rendering is deferred to
/// a future `GptFormatGuid`.
inline constexpr u32 kGuidBytes = 16;

/// Partition name length in UTF-16 code units. Stored as raw bytes
/// (144 bytes total) in the entry; this field reports the code-
/// unit count. v0 does NOT decode UTF-16 — we store the raw bytes.
inline constexpr u32 kPartitionNameChars = 36;

/// Max partitions we record per disk. Real disks rarely exceed 8;
/// 16 covers the ESP + swap + root + home + data pattern with
/// plenty of headroom.
inline constexpr u32 kMaxPartitionsPerDisk = 16;

/// Max disks we can track. One per block device is plenty —
/// `kMaxDevices` in the block layer is 16, matching.
inline constexpr u32 kMaxDisks = 8;

struct Partition
{
    u64 first_lba;
    u64 last_lba; // inclusive per UEFI spec
    u64 attributes;
    u8 type_guid[kGuidBytes];
    u8 unique_guid[kGuidBytes];
    // UTF-16LE partition name, NUL-padded. Not decoded in v0 —
    // higher layers that want a printable name decode on demand.
    u8 name_utf16le[kPartitionNameChars * 2];
};

struct Disk
{
    u32 block_handle;
    u32 partition_count; // non-empty entries
    u64 disk_sector_count;
    u32 sector_size;
    u8 disk_guid[kGuidBytes];
    Partition partitions[kMaxPartitionsPerDisk];
};

/// Parse the GPT on `block_handle`. On success, `*out_index` receives
/// the index of the newly-registered Disk record and the function
/// returns true. On any failure — unreadable MBR, missing 0xAA55,
/// missing "EFI PART" magic, CRC mismatch, out-of-range LBAs — the
/// function logs a diagnostic and returns false.
///
/// Idempotent: probing the same handle twice registers a second
/// Disk record. Callers decide whether to retry.
bool GptProbe(u32 block_handle, u32* out_index);

/// Total disks successfully probed. Handles `0 .. count-1` are valid.
u32 GptDiskCount();

/// Accessor. Returns nullptr on out-of-range index.
const Disk* GptDisk(u32 index);

/// Boot-time self-test: walk every block device, call `GptProbe`
/// on each, log the result. No PASS/FAIL since non-GPT disks are
/// a legitimate state for ramtest0; the LOG is the signal.
void GptSelfTest();

} // namespace duetos::fs::gpt
