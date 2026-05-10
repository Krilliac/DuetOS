#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — disk installer orchestration, v0.
 *
 * Drives the destructive sequence that turns a blank block device
 * into a DuetOS-bootable layout:
 *
 *   1. Lay down a fresh GPT (PMBR + headers + entries)
 *   2. Format two FAT32 partitions (ESP + system)
 *   3. Reserve a tail crash-dump partition typed
 *      `kDuetCrashDumpTypeGuid` so the panic-time NVMe / AHCI dump
 *      path can find it via `GptFindCrashDumpRegion` instead of
 *      trusting the last 4 MiB of the namespace to be unused
 *   4. Mount ESP at /esp, system at /system, and seed
 *      /esp/EFI/BOOT/grub.cfg with a chainload stub pointing at
 *      /system/boot/duetos-kernel.elf
 *
 * Bootloader-bytes copy (writing a real `BOOTX64.EFI` and
 * `duetos-kernel.elf` into the freshly-formatted ESP) is a
 * follow-on slice — it requires either embedding the running
 * kernel image into the ramfs (a build-time bootstrap problem)
 * or pulling them from an out-of-band source (USB / network).
 * v0 lays down the ESP + the chainload stub so the layout is
 * correct; the operator stages the bootloader in a separate step.
 *
 * Pre-conditions enforced by `Install`:
 *   - block handle is registered + writable
 *   - disk_sector_count >= kMinInstallSectors (~100 MiB at 512B —
 *     ESP + min-system + crash-dump + GPT overhead)
 *   - caller already passed the user-typed "INSTALL" confirmation
 *
 * Side effects:
 *   - DESTRUCTIVE write to LBAs 0..33 + N-33..N-1 (GPT)
 *   - DESTRUCTIVE write to ESP partition payload (FAT32 BPB + FATs
 *     + root-cluster zero)
 *   - DESTRUCTIVE write to system partition payload (same shape)
 *   - Crash-dump partition payload is *not* zeroed — the panic-time
 *     writer overwrites whatever's there on first use
 *   - Two new entries materialise in the block layer + the VFS
 *     mount registry: /esp and /system
 *
 * Context: kernel. Synchronous (polling block I/O); blocking is
 * acceptable in a shell-driven flow but not from an IRQ handler.
 */

namespace duetos::fs::installer
{

inline constexpr u64 kEspSectors = 131072;     // 64 MiB ESP (ample for kernel + grub.cfg + multiple kernels)
inline constexpr u64 kCrashDumpSectors = 8192; // 4 MiB crash-dump tail

// Smallest system-partition span we accept. FAT32 spec floor is
// 65525 clusters; Fat32Format itself rejects partitions under
// 65536 sectors (32 MiB at 512B sectors).
inline constexpr u64 kMinSystemSectors = 65536;

// GPT overhead: 1 PMBR + 1 primary header + 32 primary entries +
// 1 backup header + 32 backup entries = 67 reserved sectors.
inline constexpr u64 kGptOverheadSectors = 67;

// Smallest disk we'll install onto. Computed so the constants
// stay self-consistent: bumping kEspSectors / kCrashDumpSectors /
// kMinSystemSectors automatically lifts the floor.
inline constexpr u64 kMinInstallSectors = kEspSectors + kMinSystemSectors + kCrashDumpSectors + kGptOverheadSectors;

/// Result of an install attempt. `disk_handle` is the parent block
/// handle the install ran against; `esp_handle` and `system_handle`
/// are the freshly-created partition block handles, both mounted at
/// `/esp` and `/system` respectively. On failure all three handles
/// remain at the boot state and no destructive writes are committed
/// — `Install` validates pre-conditions before touching the disk.
struct Report
{
    u32 disk_handle;
    u32 esp_handle;
    u32 esp_mount_id;
    u32 system_handle;
    u32 system_mount_id;
    u64 esp_first_lba;
    u64 esp_last_lba;
    u64 system_first_lba;
    u64 system_last_lba;
    u64 crashdump_first_lba;
    u64 crashdump_last_lba;
};

enum class Status : u32
{
    Ok = 0,
    InvalidHandle = 1,
    NotWritable = 2,
    DiskTooSmall = 3,
    GptInitFailed = 4,
    PartitionRegisterFailed = 5,
    EspFormatFailed = 6,
    SystemFormatFailed = 7,
    EspMountFailed = 8,
    SystemMountFailed = 9,
    EspGrubCfgWriteFailed = 10,
};

const char* StatusName(Status s);

/// Run the install pipeline against `block_handle`. Returns
/// `Status::Ok` and fills `*out_report` on success. On any failure
/// returns the matching status, leaves `*out_report` untouched, and
/// logs a one-line `core::Log` reason. Caller is responsible for
/// having already verified the user-typed "INSTALL" confirmation
/// token before reaching here.
///
/// `use_duetfs_system` selects the filesystem laid down on the
/// system partition: false (default) → FAT32 (familiar tooling
/// elsewhere can read it), true → DuetFS (journalled writes,
/// CRC-checked blocks, encryption / compression / snapshots
/// available). The ESP is always FAT32 (UEFI-spec-mandated).
Status Install(u32 block_handle, bool use_duetfs_system, Report* out_report);

/// Pure-math layout planner — given `disk_sectors`, fills in the
/// inclusive LBA ranges Install would assign for ESP / system /
/// crash-dump (matching the main pipeline's layout). Returns
/// `Status::Ok` and populates `*out_report`'s six LBA fields if
/// the disk is large enough; returns `Status::DiskTooSmall`
/// otherwise. Other Report fields stay at their boot state. Used
/// by the boot-time self-test to assert the layout math against
/// known disk sizes without touching block I/O.
Status PlanLayout(u64 disk_sectors, Report* out_report);

/// Boot-time self-test: exercises the layout planner against
/// canonical disk sizes (just-too-small, just-large-enough,
/// 1 GB, 1 TB) and asserts the resulting LBA ranges are sane
/// (non-overlapping, monotonic, system >= 65536 sectors,
/// crash-dump = kCrashDumpSectors, ESP = kEspSectors). Panics on
/// any mismatch. Cheap — runs once at boot.
void InstallerSelfTest();

} // namespace duetos::fs::installer
