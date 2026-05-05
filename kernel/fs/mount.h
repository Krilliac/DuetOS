#pragma once

#include "util/types.h"

/*
 * DuetOS — VFS mount registry, v0 (Stage 6 first slice).
 *
 * A "mount" pairs a backing block device + filesystem type with a
 * mount point in the kernel's path namespace. v0 is BOOKKEEPING
 * ONLY — VfsMount records the binding so the shell (and later
 * VfsLookup) can enumerate active mounts, but lookups themselves
 * still go through the constinit ramfs trees. Teaching VfsLookup
 * to switch backends at a mount point is the Stage 6 second
 * slice; the registry has to land first because a mount point is
 * a prerequisite for the routing slice.
 *
 * The first real consumer is the kernel shell: `mount` lists
 * active mounts; `mount /dev/sda1 /mnt/disk` registers a binding.
 *
 * Context: kernel. Init runs at boot before the first VfsLookup
 * call. The table is a fixed-size flat array — kMaxMounts
 * entries — with linear-scan add / lookup. No locking yet
 * because the only mutator paths are boot init + the kernel
 * shell, both single-threaded today; SMP / multi-process mount
 * will need a spinlock around the table.
 */

namespace duetos::fs
{

inline constexpr u32 kMaxMounts = 16;

/// Filesystem backend. Stage 6 first slice ships only the type tag;
/// the routing slice adds the per-type lookup vtable.
enum class FsType : u32
{
    Ramfs = 0,
    Fat32 = 1,
    Ext4 = 2,
    Ntfs = 3,
};

const char* FsTypeName(FsType t);

/// Opaque mount identifier handed back from `VfsMount`.
using MountId = u32;
inline constexpr MountId kInvalidMountId = 0xFFFFFFFFu;

struct MountEntry
{
    char mount_point[64]; // canonical absolute path, NUL-terminated
    FsType fs_type;
    u32 block_handle; // block-layer handle, 0 for ramfs / synth
    u32 mount_seq;    // monotonic sequence id (mount events ever recorded)
    bool in_use;
};

/// Register a new mount. Validates the mount point (must start with
/// '/', non-empty, fits in MountEntry::mount_point), the fs type,
/// and the block handle (must be non-zero for non-ramfs types).
/// Refuses to mount on top of an existing mount (caller must
/// VfsUmount first). Returns the assigned MountId or
/// kInvalidMountId on failure.
MountId VfsMount(const char* mount_point, FsType fs_type, u32 block_handle);

/// Drop a mount. Returns true on success, false if the id is
/// unknown or already free.
bool VfsUmount(MountId id);

/// Number of currently-active mounts.
u32 VfsMountCount();

/// Enumerate every active mount. Stops early if the callback
/// returns false. Safe to call from any context — the table is
/// not modified during the walk.
using VfsMountEnumCb = bool (*)(const MountEntry& entry, MountId id, void* cookie);
void VfsMountEnumerate(VfsMountEnumCb cb, void* cookie);

/// Find a mount by its mount-point path. Exact-match only —
/// "/mnt/disk" won't match "/mnt/disk/sub". Returns nullptr if
/// no entry. Pointer is stable until the matching VfsUmount call.
const MountEntry* VfsMountFind(const char* mount_point);

/// Boot-time self-test: register, enumerate, find, unmount and
/// assert each step. Panics on mismatch. Cheap and runs once.
void VfsMountSelfTest();

} // namespace duetos::fs
