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
inline constexpr u32 kKindSymlink = 3;

inline constexpr u32 kBlockSize = 4096;
inline constexpr u32 kNodeSize = 256;
inline constexpr u32 kRootNodeId = 0;

/// Magic identifying a DuetFS superblock — bytes "DuetFS01"
/// little-endian (byte 0 = 'D' = 0x44, byte 7 = '1' = 0x31).
/// Magic stayed across v1→v8; only the version field bumps.
inline constexpr u64 kMagic = 0x3130534674657544ull;
inline constexpr u32 kVersion = 8; // v8 (xattrs / ACLs)
inline constexpr u32 kXattrNameMax = 255;
inline constexpr u32 kXattrValueMax = 1024;
inline constexpr u32 kJournalLba = 7;
inline constexpr u32 kJournalBlocks = 8;
inline constexpr u32 kSnapshotLba = 15;
inline constexpr u32 kSnapshotBlocks = 7;
inline constexpr u32 kDataLba = 22;
inline constexpr u32 kSaltBytes = 16;
inline constexpr u32 kXtsKeyBytes = 64;
inline constexpr u32 kEncryptedNo = 0;
inline constexpr u32 kEncryptedAesXts256 = 1;
inline constexpr u32 kMaxInlineExtents = 8;
inline constexpr u32 kSymlinkTargetMax = 1024;

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
inline constexpr u32 kStatusNotASymlink = 14;
inline constexpr u32 kStatusXdevLink = 15;
inline constexpr u32 kStatusSymlinkLoop = 16;

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
    u32 block_crc_mismatch;
    u32 link_count_mismatch;
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
    /// `path_max`) against the FS. POSIX-`lstat`-style — symbolic
    /// links at intermediate components are followed transparently,
    /// but a path landing on a symlink returns the symlink node
    /// (kind == kKindSymlink) so the caller can call `readlink`.
    /// Cyclic / over-deep symlink chains surface as
    /// `kStatusSymlinkLoop`. On miss / corruption / bad args
    /// returns a non-zero status code and `out->kind == kKindMiss`.
    u32 duetfs_lookup(const Device* dev, const u8* path, usize path_max, LookupResult* out);

    /// Like `duetfs_lookup` but follows the final component too
    /// (POSIX-`stat`-style). A path landing on a symlink returns
    /// the resolved target. Returns `kStatusSymlinkLoop` on cyclic
    /// chains, `kStatusNotFound` if the target does not exist.
    u32 duetfs_lookup_follow(const Device* dev, const u8* path, usize path_max, LookupResult* out);

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

    /// Walk the metadata, recompute the should-be bitmap, verify
    /// per-block CRCs, and optionally repair (rewrite the on-disk
    /// bitmap + CRC table + SB).
    u32 duetfs_fsck(const Device* dev, u32 repair, FsckReport* out);

    /// Create a symbolic link at `path` pointing at `target`.
    /// `target` is stored verbatim in the symlink node's first
    /// extent (capped at kSymlinkTargetMax bytes). Resolution
    /// through the symlink lives in lookup_path's caller — v3
    /// stops at the symlink and hands its kind back; the caller
    /// re-resolves with the target.
    u32 duetfs_create_symlink(const Device* dev, const u8* path, usize path_max, const u8* target, usize target_max,
                              u32* out_node_id);

    /// Read a symlink's target into `dst`. Same shape as
    /// duetfs_read_file but errors with kStatusNotASymlink if the
    /// node isn't a symlink.
    u32 duetfs_readlink(const Device* dev, u32 node_id, void* dst, usize dst_max, usize* out_copied);

    /// Create a hard link at `new_path` to the inode at
    /// `existing_path`. v3 caveat: the new dirent shares the
    /// target's existing name (its last component MUST equal
    /// the target's name); a separate dirent table lands later.
    u32 duetfs_link(const Device* dev, const u8* existing_path, usize existing_max, const u8* new_path, usize new_max);

    /// Read a raw 4096-byte block at `lba` from the device. Bypasses
    /// the FS layer — used by the journal self-test to verify
    /// post-replay block contents. `dst` must point at a buffer of
    /// at least kBlockSize bytes.
    u32 duetfs_block_read(const Device* dev, u32 lba, u8* dst);

    /// Apply a single (target_lba, payload) write atomically through
    /// the journal. `payload` is a kernel-space pointer to a
    /// kBlockSize-byte buffer. On success the target LBA holds the
    /// new bytes and the journal is empty; on failure the FS is left
    /// in its pre-call state (or, after the next mount's replay,
    /// brought there).
    u32 duetfs_journal_apply(const Device* dev, u32 target_lba, const u8* payload);

    /// Test-only: stage + commit a single (target_lba, payload)
    /// through the journal AND skip the apply step. Used by the
    /// self-test to simulate a torn write between the commit fsync
    /// and the apply-to-target step. The next call that re-opens
    /// the FS (any Fs::open path) replays the txn.
    u32 duetfs_journal_inject_for_test(const Device* dev, u32 target_lba, const u8* payload);

    /// Read the journal descriptor's `state` field. 0 = empty
    /// (clean), 1 = committed (replay pending), 0xFFFFFFFFu = read
    /// error. Diagnostic — Fs::open replays before returning, so a
    /// well-formed mount always reports 0.
    u32 duetfs_journal_state(const Device* dev);

    /// Argon2id KDF. Derives a 64-byte key (kXtsKeyBytes) into
    /// `out_key` from `password` + `salt` and the (m, t, p) costs.
    /// kStatusInvalid for null pointers / empty inputs / out-of-
    /// range params. Default v6 params: m=4096 KiB, t=3, p=1.
    u32 duetfs_kdf_argon2id(const u8* password, usize password_len, const u8* salt, usize salt_len, u32 m_cost_kib,
                            u32 t_cost, u32 p_cost, u8* out_key);

    /// Encrypt `buf` (kBlockSize bytes) in place using AES-256-XTS.
    /// `key` is 64 bytes (data || tweak). `sector` is the FS LBA
    /// — the XTS tweak is derived from it.
    u32 duetfs_xts_encrypt_block(const u8* key, u64 sector, u8* buf);

    /// Decrypt `buf` (kBlockSize bytes) in place. Inverse of
    /// duetfs_xts_encrypt_block.
    u32 duetfs_xts_decrypt_block(const u8* key, u64 sector, u8* buf);

    /// Format `dev` as an encrypted DuetFS volume. The caller MUST
    /// already wrap the underlying storage with AES-XTS in/out
    /// callbacks — mkfs writes every metadata block via the wrapper.
    /// `salt` (kSaltBytes) and the (m, t, p) cost params get
    /// persisted in the SB; the SB itself stays plaintext so a
    /// future mounter can read these fields before having the key.
    u32 duetfs_mkfs_encrypted(const Device* dev, const u8* salt, usize salt_len, u32 m_cost_kib, u32 t_cost,
                              u32 p_cost);

    /// Read the SB's encryption metadata without mounting. `dev` is
    /// the RAW (unwrapped) device. Returns kStatusOk + fills the
    /// outs on a recognised v6 SB; kStatusInvalid otherwise. Used
    /// by the C++ side to learn salt + cost params before deriving
    /// the key. `salt_buf_len` MUST be >= kSaltBytes.
    u32 duetfs_read_encryption_meta(const Device* dev, u32* out_encrypted, u32* out_m_cost, u32* out_t_cost,
                                    u32* out_p_cost, u8* out_salt, usize salt_buf_len);

    /// LZ4 compress `src_len` bytes from `src` into `dst`. Output is
    /// a size-prefixed LZ4 frame (u32-le uncompressed length header +
    /// LZ4 bytes). Caller sizes `dst_max` via `duetfs_lz4_compress_bound`.
    u32 duetfs_lz4_compress(const u8* src, usize src_len, u8* dst, usize dst_max, usize* out_len);

    /// LZ4 decompress a size-prefixed frame from `src` into `dst`.
    /// `dst_max` MUST be >= the original uncompressed length.
    u32 duetfs_lz4_decompress(const u8* src, usize src_len, u8* dst, usize dst_max, usize* out_len);

    /// Worst-case output size for duetfs_lz4_compress on an input of
    /// `n` bytes (includes the 4-byte size prefix). Cheap (no I/O).
    usize duetfs_lz4_compress_bound(usize n);

    /// Take a snapshot of the live FS metadata. Pins every block
    /// the live allocator currently considers in-use; allocations
    /// after this call skip pinned blocks. `ts_ns` is opaque —
    /// stored in the SB for diagnostic display ("snapshot taken
    /// N seconds ago"). Returns kStatusOk or an error code.
    u32 duetfs_snapshot_create(const Device* dev, u64 ts_ns);

    /// Restore the snapshot slot on top of the live metadata. The
    /// FS returns to exactly the state captured by the most recent
    /// duetfs_snapshot_create. Idempotent.
    u32 duetfs_snapshot_restore(const Device* dev);

    /// Snapshot presence. 0 = absent, 1 = present, 0xFFFFFFFFu =
    /// read error / corrupt SB.
    u32 duetfs_snapshot_present(const Device* dev);

    /// Set / replace `name`'s value on the node at `path`. Allocates
    /// the per-node xattr block on first set; rewrites in place on
    /// subsequent calls. `name_len` <= kXattrNameMax (255);
    /// `value_len` <= kXattrValueMax (1024). Use a name like
    /// "system.posix_acl_access" for an ACL.
    u32 duetfs_xattr_set(const Device* dev, const u8* path, usize path_max, const u8* name, usize name_len,
                         const u8* value, usize value_len);

    /// Read `name`'s value on the node at `path` into `dst`. Writes
    /// the full value length to `*out_len` (may exceed `dst_max` —
    /// caller probes for size by passing a 0-byte dst).
    u32 duetfs_xattr_get(const Device* dev, const u8* path, usize path_max, const u8* name, usize name_len, u8* dst,
                         usize dst_max, usize* out_len);

    /// List xattr names on the node at `path` as a NUL-separated
    /// stream in `dst`. Writes the bytes-needed to `*out_len`.
    u32 duetfs_xattr_list(const Device* dev, const u8* path, usize path_max, u8* dst, usize dst_max, usize* out_len);

    /// Remove `name`'s entry on the node at `path`. Returns
    /// kStatusNotFound if no such xattr exists; frees the xattr
    /// block if the last entry is removed.
    u32 duetfs_xattr_remove(const Device* dev, const u8* path, usize path_max, const u8* name, usize name_len);
}

} // namespace duetos::fs::duetfs
