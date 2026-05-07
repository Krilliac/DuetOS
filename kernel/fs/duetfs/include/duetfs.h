// DuetFS C FFI — hand-written. Mirrors kernel/fs/duetfs/src/ffi.rs.
//
// Bindgen / cbindgen are forbidden — the contract is readable here
// and verified at compile time on the C++ side.
//
// One descriptor (`Device`) covers both memory- and kernel-block-
// handle backends. Construct a Device, hand it to a duetfs_* call,
// drop it. The Rust crate never retains the descriptor or the
// callbacks across calls.

#pragma once

#include "util/types.h"

namespace duetos::fs::duetfs
{

// ----------------------------------------------------------------
// Constants — kept in lockstep with kernel/fs/duetfs/src/format.rs
// ----------------------------------------------------------------
inline constexpr u32 kKindUnused = 0;
inline constexpr u32 kKindFile = 1;
inline constexpr u32 kKindDir = 2;

inline constexpr u32 kBlockSize = 4096;
inline constexpr u32 kNodeSize = 256;
inline constexpr u32 kRootNodeId = 0;

/// Magic identifying a DuetFS superblock — bytes "DuetFS01"
/// little-endian (byte 0 = 'D' = 0x44, byte 7 = '1' = 0x31).
/// Magic stayed across v1→v2; only the version field bumps.
inline constexpr u64 kMagic = 0x3130534674657544ull;
inline constexpr u32 kVersion = 3; // v2 (multi-extent + SB CRC)
inline constexpr u32 kMaxInlineExtents = 8;

// ----------------------------------------------------------------
// Status codes
// ----------------------------------------------------------------
inline constexpr u32 kStatusOk = 0;
inline constexpr u32 kStatusInvalid = 1;
inline constexpr u32 kStatusNotFound = 2;
inline constexpr u32 kStatusNotADir = 3;
inline constexpr u32 kStatusNotAFile = 4;
inline constexpr u32 kStatusNameTooLong = 5;
inline constexpr u32 kStatusNameExists = 6;
inline constexpr u32 kStatusDirNotEmpty = 7;
inline constexpr u32 kStatusNoSpaceData = 8;
inline constexpr u32 kStatusNoSpaceNodes = 9;
inline constexpr u32 kStatusIo = 10;
inline constexpr u32 kStatusReadOnly = 11;
inline constexpr u32 kStatusNoSpaceExtents = 12;
inline constexpr u32 kStatusCorrupt = 13;

// ----------------------------------------------------------------
// Device descriptor
// ----------------------------------------------------------------
using BlockReadFn = i32 (*)(void* cookie, u32 lba, u8* dst);
using BlockWriteFn = i32 (*)(void* cookie, u32 lba, const u8* src);

struct Device
{
    void* cookie;
    u32 block_count;
    u32 read_only; // 0 = writable, 1 = read-only
    BlockReadFn read;
    BlockWriteFn write;
};

// ----------------------------------------------------------------
// Lookup result
// ----------------------------------------------------------------
struct LookupResult
{
    u32 kind; // kKind* or 0xFFFFFFFF on miss
    u32 node_id;
    u32 size_bytes;
    u32 child_count;
};
inline constexpr u32 kKindMiss = 0xFFFFFFFFu;

/// fsck output. `repaired = 1` iff the on-disk bitmap was
/// rewritten. `sb_crc_mismatch = 1` if the superblock's stored
/// CRC didn't match the computed one (informational; CRC failure
/// already causes Fs::open to return kStatusCorrupt before fsck
/// can even run).
struct FsckReport
{
    u32 leaked_blocks;
    u32 missing_blocks;
    u32 orphan_nodes;
    u32 bad_extents;
    u32 repaired;
    u32 sb_crc_mismatch;
};

// ----------------------------------------------------------------
// FFI surface
// ----------------------------------------------------------------
extern "C"
{
    /// Probe a device for a DuetFS v1 superblock. Returns 1 if valid,
    /// 0 otherwise. Cheap — only inspects block 0.
    u32 duetfs_probe(const Device* dev);

    /// Format a fresh DuetFS image on the device. Wipes the
    /// superblock + bitmap + node table, then creates the root dir.
    /// Returns kStatusOk or an error code.
    u32 duetfs_mkfs(const Device* dev);

    /// Resolve `path` (NUL-terminated, kernel buffer, bounded by
    /// `path_max`) against the FS. On success fills `*out` and
    /// returns kStatusOk. On miss / corruption / bad args returns a
    /// non-zero status code and `out->kind == kKindMiss`.
    u32 duetfs_lookup(const Device* dev, const u8* path, usize path_max, LookupResult* out);

    /// Read up to `dst_max` bytes of `node_id`'s file contents into
    /// `dst` starting at `offset`. On success writes the actual byte
    /// count to `*out_copied` (may be 0 on EOF, < dst_max on partial)
    /// and returns kStatusOk.
    u32 duetfs_read_file(const Device* dev, u32 node_id, u32 offset, void* dst, usize dst_max, usize* out_copied);

    /// Write `src_max` bytes from `src` to `node_id` starting at
    /// `offset`. Auto-grows the file (realloc + copy) if the write
    /// extends past the current extent. On success writes the byte
    /// count to `*out_written`.
    u32 duetfs_write_at(const Device* dev, u32 node_id, u32 offset, const void* src, usize src_max, usize* out_written);

    /// Create a file (kind=kKindFile) or directory (kind=kKindDir)
    /// at `path`. The parent must already exist. On success writes
    /// the new node id to `*out_node_id`.
    u32 duetfs_create_path(const Device* dev, const u8* path, usize path_max, u32 kind, u32* out_node_id);

    /// Remove `path`. Refuses to remove a non-empty directory
    /// (kStatusDirNotEmpty) or a missing path (kStatusNotFound).
    u32 duetfs_unlink_path(const Device* dev, const u8* path, usize path_max);

    /// Set a file's logical size to `new_size`, growing or shrinking
    /// the underlying extent as needed. Grow allocates additional
    /// blocks; shrink does NOT free extent blocks (free-on-shrink
    /// lands in a follow-up slice).
    u32 duetfs_truncate(const Device* dev, u32 node_id, u32 new_size);

    /// Walk the metadata, recompute the should-be bitmap, and
    /// optionally repair (rewrite the on-disk bitmap + SB).
    /// Returns kStatusOk on success and fills *out with counts.
    u32 duetfs_fsck(const Device* dev, u32 repair, FsckReport* out);
}

} // namespace duetos::fs::duetfs
