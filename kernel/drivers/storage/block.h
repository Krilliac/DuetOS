#pragma once

#include "../../core/types.h"

/*
 * CustomOS block device layer — v0.
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

namespace customos::drivers::storage
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

/// Read `count` sectors starting at `lba` into `buf`. Returns
/// 0 on success, -1 on failure. The layer bounds-checks lba +
/// count against sector_count before dispatch.
i32 BlockDeviceRead(u32 handle, u64 lba, u32 count, void* buf);

/// Symmetric write. Returns -1 on read-only devices or on
/// out-of-range lba. Write-guard rules are consulted before
/// dispatch: a write covering any sensitive LBA gets logged
/// (Advisory mode) or refused with -1 (Deny mode).
i32 BlockDeviceWrite(u32 handle, u64 lba, u32 count, const void* buf);

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

} // namespace customos::drivers::storage
