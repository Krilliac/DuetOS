#pragma once

#include "util/types.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"

/*
 * DuetOS VFS — v0.
 *
 * "VFS" is generous: today the only backend is ramfs (kernel/fs/ramfs.h),
 * and this header's only responsibility is path resolution starting
 * from an explicit root. The abstraction is shaped so the day a real
 * disk-backed FS lands, the lookup primitive doesn't change — only
 * the leaf "read the bytes" path opens up.
 *
 * The path-resolution rules are deliberately strict and jail-friendly:
 *
 *   - Every resolution starts from a caller-supplied root. There is
 *     NO ambient "global filesystem root". A process's root is
 *     `Process::root` (which the kernel picks at spawn based on
 *     the process's trust level).
 *
 *   - Absolute paths ("/foo/bar") are resolved from the root.
 *     Relative paths ("foo/bar") are resolved from the root.
 *     There is no concept of a per-process "cwd" yet — every path
 *     is root-relative. That's a feature: a sandboxed process
 *     literally cannot name anything outside its root.
 *
 *   - ".." is REJECTED, not interpreted as "parent directory".
 *     Allowing ".." to climb would break sandbox containment the
 *     moment the sandbox root is embedded inside a richer tree.
 *     v0 stays safe-by-default; a future "canonical resolve" can
 *     add ".." with explicit anchoring at the process root.
 *
 *   - "." is accepted and skipped.
 *
 *   - Trailing slashes are tolerated.
 *
 *   - Empty components (consecutive slashes, "//") are tolerated
 *     and skipped.
 *
 *   - Lookups never follow a symlink — we don't have symlinks. If
 *     we ever do, a symlink that points outside the jail root
 *     must resolve through the caller's root, not the kernel's.
 *
 *   - Lookups that walk through a file-typed node fail (can't
 *     `cd` into a regular file).
 *
 * Return value is a const pointer to the resolved node, or nullptr
 * if any component is missing / rejected / malformed. Callers MUST
 * NOT mutate the returned node (everything lives in .rodata today).
 *
 * Context: kernel. Safe at any interrupt level — pure pointer walk
 * over constinit data.
 */

namespace duetos::fs
{

struct MountEntry;

/// Resolve `path` starting from `root`. `path` may begin with '/'
/// (absolute against root) or not (relative to root, same effect).
/// Returns the resolved node, or nullptr on any failure.
///
/// `path` must be a kernel-pointer NUL-terminated string. Syscall
/// handlers that accept user-supplied paths MUST first CopyFromUser
/// into a kernel buffer before calling this — VfsLookup does not
/// touch user memory.
///
/// `path_max` bounds the number of bytes we'll scan from `path`
/// before declaring it malformed. Kept explicit (rather than strlen)
/// so a missing NUL doesn't run off into adjacent data.
const RamfsNode* VfsLookup(const RamfsNode* root, const char* path, u64 path_max);

/// Comprehensive self-test of the path resolver against the seeded
/// ramfs trees. Asserts every documented behaviour: positive lookups,
/// jail containment (sandbox root cannot see trusted paths), ".."
/// rejection, "." pass-through, empty-component tolerance, trailing
/// slash tolerance, walk-through-file rejection, null/zero-length
/// guards, and path_max truncation. Panics on any failure.
///
/// Runs at boot from kernel_main, before address-space isolation
/// brings up ring 3 — a VFS regression here is fatal because every
/// later subsystem (sandboxing, file syscalls) layers on these rules.
void VfsSelfTest();

// =====================================================================
// Generic VFS node + cross-mount resolver (Stage 6 second slice).
//
// `VfsLookup` above is ramfs-only by signature: it returns a
// `RamfsNode*` and walks a ramfs tree from a given root. That's
// enough for sandbox enforcement and the constinit trees, but it
// cannot answer "what does `/disk/0/SUB/INNER.TXT` resolve to?"
// because that path crosses a FAT32 mount point — the file lives
// in a different backend.
//
// `VfsResolve` is the cross-mount sibling. It returns a tagged
// `VfsNode` so callers can hold "the resolved thing" without
// caring which backend produced it. Two backends ship today —
// Ramfs (constinit trees + the per-process root) and Fat32
// (registered via `VfsMount` at boot for every probed volume).
// New backends register a `VfsBackendOps` table in `mount.cpp`
// and `VfsResolve` dispatches through `VfsBackendForFsType`.
//
// The `VfsLookup` API is preserved verbatim for ramfs-only
// callers — sandbox enforcement, syscall path resolution against
// `Process::root` — so the two coexist while the fleet of
// callers migrates.
// =====================================================================

enum class VfsBackend : u8
{
    Invalid = 0, ///< default-constructed / "miss" sentinel
    Ramfs = 1,
    Fat32 = 2,
    DuetFs = 3,
    RamVol = 4, ///< frame-backed writable RAM volume (fs::RamVol*, mounted at /run)
};

/// Resolved node — backend-tagged. Storage is by-value so the
/// caller doesn't have to track lifetime against a backend's
/// internal table; the FAT32 entry is a snapshot copy (mirrors
/// `Fat32LookupPath`'s caller-owned-out shape).
struct VfsNode
{
    VfsBackend backend;
    /// Ramfs-backed nodes — pointer into the constinit ramfs tree.
    /// Stable for the kernel's lifetime.
    const RamfsNode* ramfs;
    /// FAT32-backed nodes — volume index + a snapshotted DirEntry.
    /// `fat32_volume_idx` indexes into `fs::fat32::Fat32Volume(...)`;
    /// `fat32_entry` carries the resolved entry by value.
    u32 fat32_volume_idx;
    fat32::DirEntry fat32_entry;
    /// DuetFS-backed nodes — mount block_handle (used to rebuild a
    /// `duetfs::Device` via `DeviceForMountHandle`) plus a snapshot
    /// of the node's id / kind / size / child_count from the
    /// LookupResult. The crate's id is stable across calls within
    /// the same FS, so the snapshot survives any number of
    /// subsequent reads / writes from the same caller.
    u32 duetfs_block_handle;
    u32 duetfs_node_id;
    u32 duetfs_kind;
    u32 duetfs_size_bytes;
    u32 duetfs_child_count;
    /// RamVol-backed nodes — the absolute in-volume path snapshot
    /// (e.g. "/run/foo"). RamVol is path-addressed and its node
    /// structs are module-private, so the path IS the stable
    /// handle; reads re-resolve via fs::RamVolRead/Stat. NUL-term.
    char ramvol_path[192];
};

/// True when `n` is a real resolved node (backend != Invalid).
bool VfsNodeIsValid(const VfsNode& n);

/// True when `n` represents a directory in its backend.
bool VfsNodeIsDir(const VfsNode& n);

/// True when `n` represents a regular file in its backend.
bool VfsNodeIsFile(const VfsNode& n);

/// Size of a file-backed node, 0 for directories / invalid nodes.
u64 VfsNodeSize(const VfsNode& n);

/// True when `mount_point` may be crossed from `root`. The trusted
/// boot root owns the global mount namespace; sandbox/custom roots
/// only see mounts whose mount point is explicitly materialised as a
/// ramfs directory inside that root. This keeps mount visibility as a
/// namespace policy instead of baking synthetic mount directories into
/// the immutable ramfs tree.
bool VfsMountVisibleFromRoot(const RamfsNode* root, const char* mount_point);

/// Format the canonical FAT-style auto-mount point for a volume index
/// (`/disk/<idx>`). Returns false when the destination is null, too
/// small, or the decimal index cannot fit. Kept beside mount visibility
/// so direct FAT32 paths and routing-layer paths use the same spelling.
bool VfsFormatDiskMountPoint(u32 idx, char* dst, u64 dst_cap);

/// Resolve `path` to the longest visible non-ramfs mount for `root`.
/// Hidden mount points are skipped instead of shadowing shorter
/// visible mounts or root-local ramfs paths. `path_max` bounds the
/// scan exactly like `VfsLookup`; the resolver never walks past it
/// looking for a NUL. `out_subpath` receives the in-mount absolute
/// tail (`/` when `path == mount_point`).
const MountEntry* VfsMountResolveVisible(const RamfsNode* root, const char* path, u64 path_max,
                                         const char** out_subpath);

/// Cross-mount path resolver. Walks `path` starting from `root`
/// (a ramfs root, typically `Process::root`). When the path's
/// longest visible mount-prefix matches a non-ramfs mount, the
/// resolver dispatches to that backend's lookup with the in-mount
/// subpath. Hidden global mounts are ignored for this root, so they
/// do not shadow shorter visible mounts or root-local ramfs files.
/// Returns a `VfsNode` with `backend = Invalid` on miss / malformed
/// path.
///
/// Same path-resolution rules as `VfsLookup` — leading-slash
/// optional, `..` rejected, `.` skipped, empty components
/// tolerated. The mount-prefix check considers the path verbatim
/// (it does NOT chase ramfs symlinks first), but the per-process
/// namespace gate still decides whether that global mount is visible
/// to this root.
///
/// Ramfs mounts in the registry are ignored by the dispatcher —
/// the explicit `root` argument is authoritative for the ramfs
/// view (so sandbox roots stay sandbox roots even when any global
/// mount is registered).
VfsNode VfsResolve(const RamfsNode* root, const char* path, u64 path_max);

/// Cross-mount resolver self-test. Runs AFTER FAT32 auto-mount
/// has registered each probed volume (`/disk/<idx>` mount points
/// with `FsType::Fat32`). Asserts a `/disk/0/HELLO.TXT` resolve
/// hits the FAT32 backend, surfaces the right size, and that
/// missing paths under the same mount return Invalid. SKIPs
/// gracefully on systems with no FAT32 volume so the test stays
/// no-op on QEMU runs without an attached disk image.
void VfsResolveCrossMountSelfTest();

} // namespace duetos::fs
