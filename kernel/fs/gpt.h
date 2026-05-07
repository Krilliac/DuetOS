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
/// them raw and compare byte-wise; string rendering goes through
/// `FormatGuid` below.
inline constexpr u32 kGuidBytes = 16;

/// Length of a canonical mixed-endian GUID string (8-4-4-4-12 hex
/// + 4 hyphens), without the trailing NUL.
inline constexpr u32 kGuidStringLen = 36;

/// Render a 16-byte GUID as a mixed-endian hex string into
/// `out_buf` (≥ kGuidStringLen + 1 bytes — the helper writes a
/// trailing '\0'). Layout matches what mkfs / parted print:
/// the first three fields are little-endian-decoded, the last
/// two are big-endian. Output is uppercase hex with hyphens at
/// the canonical positions (8-4-4-4-12). No-op (writes "" if
/// buf_cap > 0) on null pointers or undersized buffers.
void FormatGuid(const u8 guid[kGuidBytes], char* out_buf, u32 buf_cap);

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

/// One partition's worth of input to `GptInitDisk`. Caller fills
/// type_guid + unique_guid (must come from the entropy pool — the
/// disk-installer plan mandates a freshly-random unique GUID per
/// partition), the inclusive LBA range, attributes (typically 0),
/// and the UTF-16LE name padded to 72 bytes.
struct PartitionSpec
{
    const u8* type_guid;   // 16 bytes
    const u8* unique_guid; // 16 bytes
    u64 first_lba;
    u64 last_lba; // inclusive
    u64 attributes;
    const u8* name_utf16le; // 72 bytes (kPartitionNameChars × 2), zero-padded
};

/// Lay down a fresh GPT on `block_handle`: PMBR at LBA 0, primary
/// header at LBA 1, primary entries array at LBA 2..33, partition
/// data area, backup entries at LBA N-33..N-2, backup header at
/// LBA N-1. Header + entries-array CRC32s are computed and stored
/// per UEFI 2.10 §5.3.
///
/// Pre-conditions:
///   - The handle is writable (`BlockDeviceIsWritable`).
///   - `disk_sector_count >= 67` (1 PMBR + 1 header + 32 entries +
///     1 data + 32 backup entries + 1 backup header — minimum
///     viable disk).
///   - `part_count <= kCanonicalPartitionCount` (128).
///   - Every `parts[i].first_lba >= 34` and `last_lba <= disk_sector_count - 34`.
///   - `disk_guid` is a 16-byte buffer containing a freshly-random GUID.
///
/// **DESTRUCTIVE.** This is the disk-installer's GPT-write entry
/// point — calling it on a disk with existing data overwrites
/// the partition table. Caller is responsible for the user-
/// confirmation step (`disk-installer-plan.md` mandates a typed
/// "ERASE" confirmation before reaching here).
///
/// Returns true on success; false (with a one-line klog reason)
/// on any precondition violation or block-write failure.
bool GptInitDisk(u32 block_handle, u64 disk_sector_count, const u8 disk_guid[kGuidBytes], const PartitionSpec* parts,
                 u32 part_count);

inline constexpr u32 kCanonicalPartitionCount = 128;
inline constexpr u32 kCanonicalEntryBytes = 128;

/// DuetOS-private partition type GUID for crash-dump regions.
/// Picked so the printable bytes spell "DUETOSCRAS H_DUMP" — a
/// disk-installer that lays down GPT can mark a 4 MiB tail
/// partition with this type, and the panic-time dump path will
/// discover it via GptFindCrashDumpRegion instead of trusting
/// the last 4 MiB of the namespace to be unused.
///
/// Bytes are stored as an UEFI-canonical mixed-endian GUID:
///   44554554-4F53-4352-4153-485F44554D50
/// Field 1 (u32) and field 2/3 (u16) appear little-endian on
/// disk; fields 4/5 are byte-arrays that appear big-endian.
inline constexpr u8 kDuetCrashDumpTypeGuid[kGuidBytes] = {
    0x54, 0x45, 0x55, 0x44,             // u32 LE: 0x44554554
    0x53, 0x4F,                         // u16 LE: 0x4F53
    0x52, 0x43,                         // u16 LE: 0x4352
    0x41, 0x53,                         // u8[2] BE: 0x41 0x53
    0x48, 0x5F, 0x44, 0x55, 0x4D, 0x50, // u8[6] BE: 0x48 0x5F 0x44 0x55 0x4D 0x50
};

/// Search every probed Disk for a partition whose type_guid
/// matches kDuetCrashDumpTypeGuid AND whose block_handle equals
/// `block_handle`. On hit, fills *first_lba_out and *sector_count_out
/// with the partition's inclusive LBA range expressed as base + count
/// and returns true. On miss returns false; callers fall back to a
/// driver-private "tail of namespace" reservation.
bool GptFindCrashDumpRegion(u32 block_handle, u64* first_lba_out, u64* sector_count_out);

} // namespace duetos::fs::gpt
