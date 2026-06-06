#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS block device layer — v0.
 *
 * A uniform interface above every backend that exposes sector-
 * addressable storage: the RAM-backed test device today, plus
 * NVMe / AHCI when those land. Higher layers (GPT parser,
 * filesystem drivers, a future VFS mount path) go through this
 * interface and never talk to a specific driver.
 *
 * Design:
 *   - Synchronous I/O. A call returns when the sectors have
 *     been read / written (or on error). Polling-style for v0;
 *     an async variant can be added as an alternate entry point
 *     when a driver actually benefits from it (NVMe completion
 *     IRQ, AHCI command slot parallelism).
 *   - Flat registry. `BlockDeviceRegister` hands out handles
 *     (opaque `u32`) indexing into a fixed-size table. No
 *     dynamic allocation inside the layer itself.
 *   - Driver-supplied vtable. Backends implement `Ops` and
 *     hand in a `void* cookie` they own. The layer does not
 *     own the backend's state.
 *
 * Invariants:
 *   - `lba + count <= sector_count`. Violating it is a
 *     programming error; callers get -1 back and a log line.
 *   - `buffer` is kernel-virtual and large enough to hold
 *     `count * sector_size` bytes. No driver checks this; a
 *     short buffer will corrupt kernel memory.
 *   - DMA backends assume `buffer` is a direct-map pointer
 *     (PhysToVirt return-value shape). Stack buffers work on
 *     the RAM backend but not on hardware backends — document
 *     per-driver.
 *
 * Sector size: each device reports its native size. Most SSDs
 * are 512-byte-emulated; NVMe may report 4096. Callers use the
 * reported size, never hardcode 512.
 */

namespace duetos::drivers::storage
{

inline constexpr u32 kBlockHandleInvalid = 0xFFFFFFFFu;

struct BlockOps;

/// Opaque descriptor a driver hands to `BlockDeviceRegister`.
/// The layer copies this into its registry — the pointer does
/// not need to outlive the call.
struct BlockDesc
{
    /// Short name for log lines: "ram0", "nvme0n1", etc.
    /// Caller-owned; must outlive the registered entry.
    const char* name;
    /// Vtable pointer. See `BlockOps` below.
    const BlockOps* ops;
    /// Driver-private cookie handed back to ops on every call.
    void* cookie;
    /// Native sector size in bytes. Typically 512 or 4096.
    u32 sector_size;
    /// Total addressable sector count.
    u64 sector_count;
};

/// Back-end implementation vtable. Each driver provides one
/// static instance and passes its address to `BlockDeviceRegister`.
struct BlockOps
{
    /// Read `count` sectors starting at `lba` into `buf`.
    /// Returns 0 on success, -1 on any failure (bounds, device
    /// not ready, hardware error). The layer validates bounds
    /// before dispatch, so drivers only need to handle device-
    /// specific errors.
    i32 (*read)(void* cookie, u64 lba, u32 count, void* buf);
    /// Write `count` sectors starting at `lba` from `buf`.
    /// Same return contract as `read`. May be nullptr on
    /// read-only devices — the layer returns -1 without
    /// calling through.
    i32 (*write)(void* cookie, u64 lba, u32 count, const void* buf);
    /// Optional flush hook. Returns 0 on success, -1 on any
    /// failure. May be nullptr — the layer treats absent flush
    /// as "nothing to flush" and returns 0 without calling
    /// through. Filesystem drivers call this at commit points
    /// (fsync, journal close) so the device persists any
    /// in-flight writes before the call returns.
    i32 (*flush)(void* cookie);
    /// Optional discard hook — tells the device that the given
    /// LBA range no longer holds caller-meaningful data (file
    /// unlink, freed cluster, freed inode block). On NVMe the
    /// backend issues a Dataset Management Deallocate command
    /// (opcode 0x09 with the AD bit); on AHCI it's DATA SET
    /// MANAGEMENT with feature TRIM (0x06 / feature 0x01); on
    /// virtio-blk it's VIRTIO_BLK_T_DISCARD. Optional because
    /// non-SSD backends (RAM disk, spinning HDD without TRIM
    /// support) have nothing useful to do. Absent discard = the
    /// block layer returns 0 without calling through, mirroring
    /// the flush contract. Returns 0 on success, -1 on failure.
    i32 (*discard)(void* cookie, u64 lba, u32 count);
};

/// Register a backend. Returns a stable handle for the life of
/// the kernel, or `kBlockHandleInvalid` if the registry is
/// full. The registry is flat-array; kMaxDevices is small
/// (enough for every SSD / SATA port on a typical desktop
/// plus a handful of virtual devices).
u32 BlockDeviceRegister(const BlockDesc& desc);

/// Total registered device count. Handles `0 .. count-1` are
/// valid. Stays constant for the kernel's lifetime (no
/// deregistration in v0).
u32 BlockDeviceCount();

/// Device-info accessors. Safe to call with any handle; on an
/// invalid handle the string accessors return "<invalid>" and
/// the numeric accessors return 0.
const char* BlockDeviceName(u32 handle);
u32 BlockDeviceSectorSize(u32 handle);
u64 BlockDeviceSectorCount(u32 handle);
bool BlockDeviceIsWritable(u32 handle);

/// True when `handle` is a partition-view block device created by
/// `PartitionBlockDeviceCreate` (LBA-translation wrapper over a
/// parent disk). Useful for callers (e.g. runtime health checks)
/// that need to reason about raw-disk LBAs and should ignore
/// partition-relative LBA 0/1.
bool BlockDeviceIsPartition(u32 handle);

/// Read `count` sectors starting at `lba` into `buf`. Returns
/// 0 on success, -1 on failure. The layer bounds-checks lba +
/// count against sector_count before dispatch.
i32 BlockDeviceRead(u32 handle, u64 lba, u32 count, void* buf);

/// Result-shaped sibling of `BlockDeviceRead`. Maps the legacy
/// -1 return to `ErrorCode::IoError`; success is `Result<void>`.
inline ::duetos::core::Result<void> TryBlockDeviceRead(u32 handle, u64 lba, u32 count, void* buf)
{
    if (BlockDeviceRead(handle, lba, count, buf) < 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::IoError};
    return {};
}

/// Symmetric write. Returns -1 on read-only devices or on
/// out-of-range lba. Write-guard rules are consulted before
/// dispatch: a write covering any sensitive LBA gets logged
/// (Advisory mode) or refused with -1 (Deny mode).
i32 BlockDeviceWrite(u32 handle, u64 lba, u32 count, const void* buf);

/// Result-shaped sibling of `BlockDeviceWrite`. `-1` becomes
/// `IoError`. A more specific code (PermissionDenied when the
/// write-guard denies, BadState for read-only devices) is a
/// follow-up once `BlockDeviceWrite` itself returns a typed
/// failure internally.
inline ::duetos::core::Result<void> TryBlockDeviceWrite(u32 handle, u64 lba, u32 count, const void* buf)
{
    if (BlockDeviceWrite(handle, lba, count, buf) < 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::IoError};
    return {};
}

/// Flush any in-flight writes on `handle`. Returns 0 on success
/// (including when the backend has no flush op — the layer
/// treats absent as a no-op success), -1 on failure. Filesystem
/// drivers call this at commit points so the device persists
/// before the call returns.
i32 BlockDeviceFlush(u32 handle);

/// Hint to the device that sectors [lba, lba+count) no longer
/// hold caller-meaningful data. Called when a filesystem frees
/// blocks (unlink, truncate-shrink, mkfs). The block layer
/// bounds-checks and consults the write-guard before dispatch —
/// a discard touching a guarded LBA is denied just like a write.
/// Returns 0 on success (including no-op success when the
/// backend doesn't implement discard), -1 on failure.
///
/// The discard is a HINT: every backend is free to drop it on
/// the floor. Callers must NOT assume the bytes read back as
/// zero (NVMe DSM Deallocate may return either the old bytes
/// or all-zeros, controller's choice; AHCI TRIM is similar).
i32 BlockDeviceDiscard(u32 handle, u64 lba, u32 count);

/// True iff the backend behind `handle` exposes a non-null
/// discard hook. Filesystem drivers query this to decide whether
/// to attempt batch trim at all — saves the loop overhead on
/// backends that wouldn't do anything with the hint.
bool BlockDeviceSupportsDiscard(u32 handle);

/// Saturating counters surfacing the block layer's discard
/// activity since boot. `Issued` counts every accepted
/// BlockDeviceDiscard call (including no-op-success on backends
/// without a discard hook); `Sectors` counts the total sectors
/// the FS layer asked us to deallocate. Useful for triage when
/// a "did my fstrim actually run?" question comes up — and for
/// the storage selftest to verify a hint round-trips at least
/// once on every boot.
u64 BlockDiscardIssuedCount();
u64 BlockDiscardSectorsHinted();

// -------------------------------------------------------------------
// Write-guard for sensitive LBAs.
//
// Blocks writes to MBR (LBA 0), GPT primary header (LBA 1),
// and any range explicitly armed by a caller. The gate applies
// at the `BlockDeviceWrite` boundary so every backend (AHCI,
// NVMe, RAM) is covered. A bootkit that writes via any of
// those channels now hits the deny.
//
// Modes:
//   Off      — no gating. Default at boot until armed.
//   Advisory — log every sensitive-LBA write, let it through.
//   Deny     — refuse every sensitive-LBA write; return -1.
//              Flipped on by the health subsystem after any
//              security-critical finding, or manually via the
//              `blockguard deny` shell command.
// -------------------------------------------------------------------

enum class WriteGuardMode : u8
{
    Off = 0,
    Advisory,
    Deny,
};

/// Current write-guard mode. Cheap read.
WriteGuardMode BlockWriteGuardMode();

/// Flip the guard mode. Logs the transition.
void BlockWriteGuardSetMode(WriteGuardMode m);

/// Arm a rule: writes to [first_lba, first_lba + count) on
/// `handle` (or kBlockHandleInvalid for "every device") are
/// subject to the current guard mode. Up to 32 rules cached.
void BlockWriteGuardAddRule(u32 handle, u64 first_lba, u32 count, const char* tag);

/// How many writes have been refused since boot.
u64 BlockWriteGuardDenyCount();

// -------------------------------------------------------------------
// Owned-region write chokepoint (allow-list, the inverse of the
// deny-list above).
//
// The incident class behind wiki/security/Hardware-Safety.md was a
// write to a disk DuetOS does not own. Ownership is checked per-call-
// site today (Fat32VolumeIsDuetOsOwned, GptCrashDumpRegionSane); this
// chokepoint converts that into one enforced property: register the
// LBA regions DuetOS owns, and `DiskRegionIsOwned` is the single
// predicate every persistent write can be routed through. A write that
// is not FULLY contained in a registered owned region is, under the
// owned-write enforcement mode, refused at the `BlockDeviceWrite`
// boundary — so a new writer cannot reach a foreign region even if it
// skips the per-call-site adoption check.
//
// Default mode is Off (no behaviour change): the mechanism + registry
// are in place and exercised by the self-test, but flipping the default
// to Deny needs every legitimate writer (FAT32 system volume, crash-dump
// partition, the disk installer's target) to register its owned region
// first — see the Roadmap follow-up.
// -------------------------------------------------------------------

/// Register an LBA region [first_lba, first_lba+count) on `handle`
/// (or kBlockHandleInvalid for "every device") as DuetOS-owned and thus
/// writable. Up to 16 regions cached.
void BlockOwnedRegionAdd(u32 handle, u64 first_lba, u64 count, const char* tag);


/// True iff [lba, lba+count) is FULLY contained in some registered
/// owned region for `handle`. The single ownership predicate the write
/// chokepoint routes through.
bool DiskRegionIsOwned(u32 handle, u64 lba, u32 count);

/// Owned-write enforcement mode (reuses the WriteGuardMode tri-state):
///   Off      — no owned-region check (default).
///   Advisory — log a write outside any owned region, let it through.
///   Deny     — refuse a write outside any owned region (return -1).
WriteGuardMode BlockOwnedWriteMode();
void BlockOwnedWriteSetMode(WriteGuardMode m);

/// How many writes the owned-write chokepoint has refused since boot.
u64 BlockOwnedWriteDenyCount();

/// Boot self-test of the owned-region predicate + the Deny-mode write
/// refusal (containment, straddle, wrong-handle, wildcard; a RAM-disk
/// allowed/denied write pair). Panics on failure; emits one
/// "[block-owned-selftest] PASS" line.
void BlockOwnedRegionSelfTest();

// ---------------------------------------------------------------
// Backends
// ---------------------------------------------------------------

/// Stand up a RAM-backed block device of `sector_count` sectors
/// of `sector_size` bytes each. Sectors are kernel-heap-backed
/// (KMalloc); the device is writable. Returns the block handle
/// on success or kBlockHandleInvalid on OOM / bad params.
///
/// Intended as the canonical test backend for the rest of the
/// storage stack. Cheap enough to stand up multiple instances
/// for unit tests of higher layers (GPT parser, FAT32) once
/// they land.
u32 RamBlockDeviceCreate(const char* name, u32 sector_size, u64 sector_count);

/// Stand up a partition view over an existing parent block
/// device. Sector I/O on the returned handle addresses LBA 0
/// .. (last_lba - first_lba); each call translates to
/// (first_lba + lba) on the parent. Writable iff the parent
/// is writable — the wrapper routes writes through without
/// caching the flag.
///
/// The partition view does NOT own the parent; the parent's
/// lifetime must cover the view's (kernel lifetime in v0 —
/// no deregistration). `name` must outlive the registered
/// entry (typically a static string or the GPT parser's
/// per-disk name table).
///
/// Constraints: first_lba <= last_lba, last_lba < parent's
/// sector_count. Any violation returns kBlockHandleInvalid.
u32 PartitionBlockDeviceCreate(const char* name, u32 parent_handle, u64 first_lba, u64 last_lba);

/// Init: logs "[block] layer online" and resets the registry
/// to empty. Safe to call multiple times; only the first call
/// has effect.
void BlockLayerInit();

/// Boot-time self-test: creates a 64-sector, 512-byte RAM
/// device, writes a distinctive pattern at LBA 0 and LBA 63,
/// reads them back, verifies. Prints one PASS/FAIL line to
/// COM1. Called from main.cpp right after BlockLayerInit.
void BlockLayerSelfTest();

} // namespace duetos::drivers::storage
