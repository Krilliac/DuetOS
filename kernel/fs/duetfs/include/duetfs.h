// DuetFS C FFI — hand-written.
//
// This header is the contract between the C++ kernel and the Rust
// `duetfs` crate. It MUST stay in lockstep with `kernel/fs/duetfs/
// src/ffi.rs`. Bindgen / cbindgen are not used — the contract is
// readable here and verified at compile time on the C++ side.
//
// Lifetime / ownership:
//   - The kernel owns the image bytes. Every call passes them in;
//     the crate never retains the pointer across calls.
//   - All functions are NUL- / NULL-tolerant — passing 0 / NULL
//     yields a "miss" result (0 / no-bytes-written), never UB.
//   - Returned data references in `duetfs_lookup` are by-value;
//     callers never need to free anything from the crate.
//
// Build:
//   - The crate is a `staticlib` linked into the kernel.
//   - `panic = abort` — a Rust panic calls `duetos_rust_panic`
//     (kernel-provided) which routes to klog + halts the box.
//
// Lineage: clean-room rewrite inspired by RedoxFS
// (https://github.com/redox-os/redoxfs, MIT). The on-disk format
// is a small subset designed for this v0 slice.

#pragma once

#include "util/types.h"

namespace duetos::fs::duetfs
{

inline constexpr u32 kKindUnused = 0;
inline constexpr u32 kKindFile = 1;
inline constexpr u32 kKindDir = 2;

inline constexpr u32 kBlockSize = 4096;
inline constexpr u32 kNodeSize = 256;
inline constexpr u32 kNodesPerBlock = kBlockSize / kNodeSize; // 16
inline constexpr u32 kRootNodeId = 0;
inline constexpr u32 kKindMiss = 0xFFFFFFFFu;

/// Magic identifying a DuetFS v0 superblock — bytes "DuetFS00"
/// little-endian (byte 0 = 'D' = 0x44, byte 7 = '0' = 0x30).
inline constexpr u64 kMagic = 0x3030534674657544ull;

/// Result of a successful path resolve. Layout is mirrored in
/// `kernel/fs/duetfs/src/ffi.rs`'s `DuetFsLookupResult`. The C++
/// side static_asserts the size + offsets match.
struct LookupResult
{
    u32 kind;        // kKind*
    u32 node_id;     // node table index
    u32 size_bytes;  // file size (or dir child_count × 4)
    u32 child_count; // dirs only; 0 for files
};

extern "C"
{
    /// Probe `image[0..len]` for a DuetFS superblock. 1 if valid, 0
    /// otherwise. Cheap — only inspects the first block.
    u32 duetfs_probe(const u8* image, usize len);

    /// Resolve `path` (NUL-terminated, kernel buffer, bounded by
    /// `path_max`) against the image. On success, fills `*out` and
    /// returns 1. On miss / corruption / bad args returns 0 and leaves
    /// `out->kind == kKindMiss`.
    ///
    /// Path-shape rules: leading '/' optional, "." skipped, ".."
    /// rejected, empty components ("//") tolerated. Mirrors the global
    /// VFS resolver semantics in kernel/fs/vfs.h.
    u32 duetfs_lookup(const u8* image, usize len, const u8* path, usize path_max, LookupResult* out);

    /// Read up to `dst_max` bytes of `node_id`'s file contents into
    /// `dst`, starting at `offset`. Returns the number of bytes copied
    /// — 0 on miss / non-file / out-of-range (a short read at EOF
    /// returns the truncated count, not 0). Caller-owned `dst`.
    usize duetfs_read_file(const u8* image, usize len, u32 node_id, u32 offset, void* dst, usize dst_max);
}

} // namespace duetos::fs::duetfs
