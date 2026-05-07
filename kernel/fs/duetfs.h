#pragma once

#include "fs/duetfs/include/duetfs.h"
#include "util/types.h"

/*
 * DuetFS — kernel-side adapter for the Rust crate at
 * kernel/fs/duetfs/. The crate exposes its FFI through
 * kernel/fs/duetfs/include/duetfs.h; this header layers the
 * kernel-facing concerns on top:
 *
 *   - Device-builder helpers (memory + block-handle backed).
 *   - The kernel-side mount table integration
 *     (DuetFsBoot mounts the boot RAM disk at /duetfs).
 *   - The boot self-test (DuetFsSelfTest).
 *
 * Lineage: clean-room rewrite inspired by RedoxFS
 * (https://github.com/redox-os/redoxfs, MIT). v1 ships persistent
 * write path + mount integration; the on-disk format
 * documentation lives in wiki/filesystem/DuetFS.md.
 */

namespace duetos::fs::duetfs
{

/// Build a Device that stores data in a kernel-owned byte buffer.
/// `buf` must remain valid for the full call chain that uses the
/// returned Device. `len` must be a multiple of kBlockSize.
Device MakeMemoryDevice(u8* buf, usize len, bool read_only);

/// Build a Device whose I/O routes to a kernel block-device handle
/// (registered in kernel/drivers/storage/block.h). Sector
/// translation lives inside this adapter — the Rust crate always
/// sees 4 KiB blocks. `block_handle` must be a valid handle whose
/// sector_size divides 4096.
Device MakeBlockHandleDevice(u32 block_handle);

/// True when `block_handle`'s underlying device holds a valid
/// DuetFS v1 superblock. Cheap — issues one block read.
bool ProbeBlockHandle(u32 block_handle);

/// Boot-time DuetFS bring-up:
///   1. Create the in-memory boot volume (kBootImageBytes in .bss).
///   2. mkfs it + seed /etc/version + mount at /duetfs.
///   3. Walk every kernel block-device handle. For each handle
///      that's not a partition view and is at least kMinDiskBlocks
///      blocks: probe — if the device already holds a v2 DuetFS
///      superblock, mount it at /disks/duetfs<N>; if it's blank
///      (probe fails), do nothing (we never auto-mkfs a real
///      device, that's a destructive operation that requires an
///      explicit user command).
///
/// On failure of step 1/2, panics with subsystem `duetfs/boot`.
/// Steps 3+ log + skip on failure (never panic — a misbehaving
/// disk shouldn't take down the boot).
u32 DuetFsBoot();

/// Boot-time self-test. Runs after DuetFsBoot. Exercises:
///   1. probe — accepts the boot-mounted FS
///   2. mkfs round-trip on a separate scratch RAM disk
///   3. create file, write, read back
///   4. create dir, nested file, lookup, read
///   5. unlink (file + dir), DirNotEmpty rejection
///   6. truncate (grow + shrink)
///
/// Panics on any failure with `duetfs/selftest`.
void DuetFsSelfTest();

/// Size of the boot-time DuetFS image (256 KiB = 64 blocks).
inline constexpr u32 kBootImageBlocks = 64;
inline constexpr u32 kBootImageBytes = kBootImageBlocks * kBlockSize;

/// Minimum block count for an existing kernel block device to be
/// considered as a candidate DuetFS volume during the boot probe.
/// 7 blocks is the minimum a v2 image can occupy (1 SB + 1 bitmap
/// + 4 node table + 1 data block).
inline constexpr u32 kMinDiskBlocks = 7;

/// Sentinel block_handle stored in the mount table for the
/// memory-backed boot volume (the real kernel block-device
/// handles are 0..kBlockHandleInvalid-1, so this collides with
/// nothing).
inline constexpr u32 kBootHandleSentinel = 0xFFFFFFFFu;

/// Block handle of the boot DuetFS volume after DuetFsBoot ran.
/// Returns 0xFFFFFFFFu before boot.
u32 BootHandle();

/// Build a `Device` for the mount table's `block_handle` field.
/// Used by the VFS routing layer in mount.cpp's `DuetFsLookup`.
/// For the boot sentinel, points at the .bss-resident boot image;
/// for any other handle, wraps the kernel block-device.
Device DeviceForMountHandle(u32 block_handle);

} // namespace duetos::fs::duetfs
