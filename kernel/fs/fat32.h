#pragma once

#include "util/types.h"

/*
 * DuetOS FAT32 driver — v0 (read-only BPB parse + root-dir walk).
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

namespace duetos::fs::fat32
{

/// Max volumes we track. One per partition-block handle is plenty —
/// the block layer caps at 16, so 16 here matches.
inline constexpr u32 kMaxVolumes = 16;

/// Max directory entries we carry in a per-volume snapshot. Enough
/// for a handful of test files; real filesystems should enumerate
/// on demand (follow-up slice).
inline constexpr u32 kMaxDirEntries = 32;

/// A single parsed directory entry. `name` carries either the
/// LFN-decoded long name (when a valid LFN sequence preceded the
/// SFN in the directory) or the 8.3 short name. UTF-16 codepoints
/// outside ASCII are replaced with '?' in v0 — no UTF-8 yet.
struct DirEntry
{
    char name[128];    // either long name or 8.3, NUL-terminated
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

/// Case-insensitive lookup for an 8.3 name in the volume's root
/// snapshot. `name` is the human-form "HELLO.TXT" (as emitted by
/// Fat32Probe into DirEntry.name), NOT the raw 11-byte spaced
/// form. Returns nullptr on miss.
const DirEntry* Fat32FindInRoot(const Volume* v, const char* name);

/// Multi-component path lookup. `path` is interpreted relative
/// to the volume root; a leading '/' is tolerated. Components are
/// separated by '/', each matched case-insensitively against the
/// 8.3 name. Empty / "/" yields a synthesised "root" DirEntry.
///
/// On success fills `*out` and returns true. `out` is caller-
/// owned storage, not a pointer into the volume; this path walks
/// beyond the cached root snapshot, so no stable pointer exists.
///
/// Out scope (this slice): LFN decoding; symlinks. A miss on any
/// component short-circuits and returns false.
bool Fat32LookupPath(const Volume* v, const char* path, DirEntry* out);

/// Enumerate a directory's entries into `out[0..cap-1]`, starting
/// at `first_cluster`. Returns the number of filled entries. LFN
/// fragments, deleted slots, volume-label entries, and the "."
/// / ".." synthetic entries are skipped.
u32 Fat32ListDirByCluster(const Volume* v, u32 first_cluster, DirEntry* out, u32 cap);

/// Read up to `max` bytes of a file's contents into `out`. Returns
/// the number of bytes actually written (0..file.size_bytes), or
/// -1 on any I/O failure. Safe to call with max==0 (trivially
/// returns 0). Follows the cluster chain through the FAT; no
/// caching, no prefetch — a fresh BlockDeviceRead per cluster.
///
/// Bounded: caps at 65536 clusters (256 MiB at 4 KiB cluster), so
/// a corrupt chain that self-loops can't spin forever. Bounded
/// loop also protects against the compiler-noticed infinite-loop
/// undefined-behaviour warnings clang emits at -O3.
i64 Fat32ReadFile(const Volume* v, const DirEntry* e, void* out, u64 max);

/// Offset-aware read for syscall-driven cursors. Reads up to `len`
/// bytes starting at byte `offset` into `out`. Returns the number
/// of bytes copied (0 at EOF, capped to file size - offset), or
/// -1 on I/O failure. Walks the cluster chain to skip past
/// `offset`, then resumes the standard cluster-by-cluster read
/// path. Used by the Win32 file syscalls' `DoFileRead` to back
/// FAT32-routed handles whose `cursor` advances per call.
i64 Fat32ReadAt(const Volume* v, const DirEntry* e, u64 offset, void* out, u64 len);

/// Callback signature for Fat32ReadFileStream. `data` points into
/// internal scratch — valid only for the duration of the call.
/// Returning false stops the stream cleanly.
using ReadChunkCb = bool (*)(const u8* data, u64 len, void* ctx);

/// Stream a file's contents cluster-by-cluster, calling `cb` once
/// per cluster with the valid byte count (trimmed to the file's
/// size on the last cluster). Good for piping to the console or
/// a network socket without needing to allocate a size-of-file
/// buffer. Returns true on clean completion OR when cb stops the
/// walk; false on I/O error.
bool Fat32ReadFileStream(const Volume* v, const DirEntry* e, ReadChunkCb cb, void* ctx);

/// Overwrite `len` bytes at byte offset `offset` inside the file
/// described by `e`. NO size change, NO new cluster allocation —
/// `offset + len` MUST be <= `e->size_bytes`. Returns the number
/// of bytes written (== len on success), or -1 on validation /
/// I/O error.
///
/// Implementation:
///   - Walks the cluster chain from `first_cluster` to find the
///     starting cluster for `offset`.
///   - For any cluster whose byte range is fully inside [offset,
///     offset+len), writes the caller's buffer directly (full-
///     cluster transfer, no read-modify-write).
///   - For partial clusters (head / tail), reads the cluster,
///     patches the bytes in place, writes back.
///   - Issues writes through BlockDeviceWrite on the volume's
///     partition handle. The backing driver (AHCI WRITE_DMA_EXT
///     today) must be writable; NvmeBlockWrite has always been.
///
/// Out of scope in this slice: extending a file, creating a new
/// file, allocating free clusters, FAT mirror updates for the
/// allocation-table itself (the only FAT entries we touch are
/// read-only). FSInfo is not updated.
i64 Fat32WriteInPlace(const Volume* v, const DirEntry* e, u64 offset, const void* buf, u64 len);

/// Append `len` bytes to the END of a file that lives in the root
/// directory. Allocates free clusters as needed, chains them to
/// the existing tail, writes the caller's bytes into them, and
/// patches the on-disk directory entry's size field in place.
/// Returns the number of bytes appended (== len on success), or
/// -1 on validation / allocation / I/O failure.
///
/// Mutates BOTH FAT copies to keep the mirror in sync. Does NOT
/// update FSInfo (free_count / next_free are only hints; Linux
/// and Windows rebuild them on mount if stale). Does NOT support
/// appending to a zero-size file in v0 — use Fat32WriteInPlace
/// for existing content, Fat32AppendInRoot once the file already
/// has one cluster.
///
/// Only root-dir files are supported in v0; extending a file in
/// a subdirectory needs the directory's entry LBA handed in,
/// which the path walker doesn't yet expose. Follow-up slice.
i64 Fat32AppendInRoot(const Volume* v, const char* name, const void* buf, u64 len);

/// Create a new file in the root directory with the given name
/// and initial content. `name` may be a "NAME.EXT" form (up to
/// 8 + 3 chars, case-insensitive) or a bare "NAME" with no dot.
/// Anything that can't fit in the 8.3 SFN encoding (longer than
/// 8 base or 3 extension, or containing forbidden chars) is
/// rejected with -1. No LFN is emitted in v0 — callers get
/// the 8.3 form preserved verbatim.
///
/// Behavior:
///   - Finds the first unused directory slot (0x00 end-of-dir or
///     0xE5 deleted) in the root cluster chain.
///   - If bytes != nullptr && len > 0: allocates one or more
///     clusters, writes the content, chains them, and records
///     first_cluster + size in the directory entry.
///   - Writes the SFN record (attributes = 0x20 = ARCHIVE).
///   - Does NOT support subdirectory targets, LFN emission, or
///     root-cluster-full growth. A filled root dir returns -1.
///
/// Returns the file's new size on success, -1 on failure.
/// Duplicate-name detection: returns -1 if a non-deleted entry
/// with the same 8.3 already exists.
i64 Fat32CreateInRoot(const Volume* v, const char* name, const void* buf, u64 len);

/// Delete a file from the root directory. Finds the entry by
/// name, marks the SFN record's first byte to 0xE5 (FAT's
/// deleted marker), frees the entire cluster chain by writing
/// 0 to each entry in both FAT copies. Refreshes the cached
/// root snapshot.
///
/// Returns true on success, false if the file is not found or
/// I/O fails mid-way. On partial failure the on-disk state MAY
/// be inconsistent — v0 has no journaling.
bool Fat32DeleteInRoot(const Volume* v, const char* name);

/// Truncate a root-dir file to `new_size` bytes. Three cases:
///   - new_size == current: no-op, returns 0.
///   - new_size >  current: equivalent to Fat32AppendInRoot of
///     (new_size - current) zero bytes.
///   - new_size <  current: walks the chain to the cluster
///     containing byte (new_size - 1), marks it EOC, frees all
///     subsequent clusters. If new_size == 0, also releases
///     first_cluster and zeros that field in the directory
///     entry. Updates size in place.
///
/// Returns the new size on success, -1 on failure.
i64 Fat32TruncateInRoot(const Volume* v, const char* name, u64 new_size);

// ---------------------------------------------------------------
// Path-based CRUD. These walk the path's parent directory, then
// perform the same operation the InRoot versions do but against
// any directory cluster, not just the root. `path` is
// volume-relative (leading '/' tolerated). All fail with -1 /
// false if an intermediate component doesn't exist, isn't a
// directory, or the parent directory is unwritable (v0 rejects
// growth of a full-cluster directory).
// ---------------------------------------------------------------

i64 Fat32CreateAtPath(const Volume* v, const char* path, const void* buf, u64 len);
bool Fat32DeleteAtPath(const Volume* v, const char* path);
i64 Fat32TruncateAtPath(const Volume* v, const char* path, u64 new_size);
i64 Fat32AppendAtPath(const Volume* v, const char* path, const void* buf, u64 len);

/// Create a new directory at `path`. The parent directory must
/// exist; the basename must not collide with an existing entry.
/// Seeds the new directory with the required "." and ".." self
/// / parent entries per spec, then plants an attr=0x10 directory
/// entry in the parent (with LFN fragments emitted when the
/// basename doesn't fit 8.3).
///
/// Returns true on success, false on validation / allocation /
/// I/O error.
bool Fat32MkdirAtPath(const Volume* v, const char* path);

/// Remove an empty directory at `path`. Refuses if the directory
/// still contains any entries beyond the "." / ".." self and
/// parent records. Frees the directory's cluster chain and marks
/// the parent's entry (+ any LFN fragments that precede it)
/// deleted.
///
/// Returns true on success. false on "not a directory", "not
/// empty", "not found", or I/O error.
bool Fat32RmdirAtPath(const Volume* v, const char* path);

/// Boot-time self-test. Calls `Fat32Probe` on every registered
/// block device; partitions that aren't FAT32 are expected to fail
/// and are logged as "not FAT32" (no failure shout). PASS
/// criterion: at least one volume's root contains a file AND
/// the seed file HELLO.TXT reads back exactly as the image-
/// builder wrote it.
void Fat32SelfTest();

} // namespace duetos::fs::fat32
