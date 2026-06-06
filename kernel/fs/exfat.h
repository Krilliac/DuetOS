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
 *   - Root-directory file mutation: write-in-place, append/grow,
 *     create, truncate. Mirrors the proven FAT32 write path
 *     (kernel/fs/fat32_write.cpp + fat32_create.cpp): allocate
 *     free clusters, chain them through the FAT (4-byte LE
 *     entries, EOC == 0xFFFFFFFF), flip the allocation-bitmap
 *     bits, then plant / patch the File (0x85) + Stream-Extension
 *     (0xC0) + FileName (0xC1) dirent set with a correct
 *     SetChecksum and NameHash.
 *
 * Not in scope (precise GAPs annotated at the call sites):
 *   - Subdirectory targets — create/append/truncate operate on
 *     the ROOT directory's first cluster only.
 *   - Up-case-table-aware name hashing — v0 up-cases ASCII
 *     a-z → A-Z only; the on-disk Up-case Table dirent is not
 *     parsed, so names with non-ASCII letters hash with their raw
 *     code units (still self-consistent on our own volumes).
 *   - Defragmentation / contiguous (NoFatChain) allocation — every
 *     file we create is FAT-chained.
 *   - TexFAT (the transactional safe-FAT second FAT) — volumes
 *     with NumberOfFats == 2 get only FAT #1 maintained.
 *
 * Context: kernel, polling synchronous.
 */

namespace duetos::fs::exfat
{

inline constexpr u32 kMaxVolumes = 8;
inline constexpr u32 kMaxDirEntries = 32;
inline constexpr u64 kBootSectorLba = 0;

/// DuetOS-ownership marker for an exFAT volume: the VolumeSerialNumber
/// field (VBR offset 0x64) stamped to this exact value by the DuetOS
/// exFAT formatter. It is the exFAT analogue of fat32::kDuetOsVolumeId
/// (same value, same intent) — the single signal `ExfatProbe` uses to
/// tell a volume DuetOS formatted from a foreign one (a Windows / macOS
/// SD card, a USB stick). exFAT carries its volume label in a root-dir
/// entry (type 0x83), not the boot sector, so — unlike FAT32, which
/// requires BOTH a serial and a label — the serial alone is the marker
/// here; a 1-in-2^32 accidental collision is acceptable under this
/// threat model. (Not a security boundary: a disk that deliberately
/// forges the serial can still be adopted — the threat model is
/// accidental corruption of the user's own Windows/macOS data, not a
/// hostile disk. Mirrors the FAT32 adoption gate landed in 7bb94062.)
inline constexpr u32 kDuetOsVolumeSerial = 0xCAFEBABE;

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
    u32 volume_serial;            // VBR VolumeSerialNumber (offset 0x64)
    u8 bytes_per_sector_shift;    // log2
    u8 sectors_per_cluster_shift; // log2
    u32 root_entry_count;         // count of parsed root entries
    DirEntry root_entries[kMaxDirEntries];
};

/// True iff `v` carries the DuetOS-ownership marker (VolumeSerialNumber
/// == kDuetOsVolumeSerial). Used by `ExfatProbe` to decide whether to
/// adopt the volume into the registry. A foreign exFAT volume returns
/// false and is never registered at boot, so its (root-dir) write paths
/// can never reach a partition DuetOS does not own. Safe to call with
/// v == nullptr (returns false).
bool ExfatVolumeIsDuetOsOwned(const Volume* v);

/// Probe the block device at `handle`. On success returns the
/// registry slot index; errors as for Ext4Probe. A volume that parses
/// as exFAT but lacks the DuetOS-ownership marker is recognised and
/// logged but NOT registered (returns ErrorCode::NotFound) — inert by
/// default, mirroring the FAT32 adoption gate (commit 7bb94062).
::duetos::core::Result<u32> ExfatProbe(u32 block_handle);
u32 ExfatVolumeCount();
const Volume* ExfatVolumeByIndex(u32 index);
void ExfatScanAll();

// ---------------------------------------------------------------
// Write path (root directory only — see header GAP list). All take
// a non-const Volume* because a successful create/append/truncate
// refreshes the cached root snapshot (root_entries / root_entry_count)
// so a follow-up read sees the new state without a re-probe. They
// fail with -1 / false on a read-only device, full disk, I/O error,
// or a target outside the supported (root-dir, FAT-chained) shape.
// ---------------------------------------------------------------

/// Look up `name` (case-insensitive 8.3-or-long, as decoded into
/// DirEntry.name) in the cached root snapshot. Returns nullptr on
/// miss. Pointer is into the volume's snapshot — stable until the
/// next mutating call refreshes it.
const DirEntry* ExfatFindInRoot(const Volume* v, const char* name);

/// Overwrite `len` bytes at byte offset `offset` inside `e`. NO
/// size change, NO allocation — `offset + len` MUST be <=
/// `e->size_bytes`. Full clusters inside the span are written
/// directly; head/tail partial clusters are read-modify-written.
/// Returns bytes written (== len on success) or -1.
i64 ExfatWriteInPlace(const Volume* v, const DirEntry* e, u64 offset, const void* buf, u64 len);

/// Append `len` bytes to the end of a root-dir file, allocating and
/// chaining clusters as needed, flipping the allocation-bitmap
/// bits, and patching the on-disk Stream-Extension entry's
/// valid_data_len + data_length fields. Returns bytes appended
/// (== len) or -1.
i64 ExfatAppendInRoot(Volume* v, const char* name, const void* buf, u64 len);

/// Create a new file in the root directory with `name` and initial
/// content. Allocates content clusters, plants the File +
/// Stream-Extension + FileName dirent set (attr = 0x20 ARCHIVE)
/// with a valid SetChecksum + NameHash. Returns the new size on
/// success, -1 on a full root cluster, duplicate name, name too
/// long for the per-volume dirent budget, or I/O error.
i64 ExfatCreateInRoot(Volume* v, const char* name, const void* buf, u64 len);

/// Truncate a root-dir file to `new_size`. Grows (zero-fill) via
/// the append path, shrinks by trimming the cluster chain + freeing
/// the bitmap bits, or no-ops when equal. Returns the new size or -1.
i64 ExfatTruncateInRoot(Volume* v, const char* name, u64 new_size);

/// Boot self-test: builds a synthetic exFAT volume in a RAM block
/// device and drives the write path (create -> find -> write-in-place
/// -> append -> truncate) with read-back verification. Emits a single
/// `[exfat-selftest] PASS (...)` line on success; a FAIL line + a
/// kBootSelftestFail probe on any failed assertion. Registered on the
/// boot self-test list (see kernel/core/boot_bringup.cpp).
void ExfatSelfTest();

} // namespace duetos::fs::exfat
