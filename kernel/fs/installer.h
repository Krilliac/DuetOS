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
 *   4. Stage BOOTX64.EFI (embedded blob) at the UEFI removable-
 *      media path, stage the embedded kernel ELF (when
 *      DUETOS_INSTALLER_KERNEL_EMBED is ON) into the inactive A/B
 *      slot on the ESP with read-back validation, and persist the
 *      boot-slot state + generated grub.cfg (`PersistSlotState`)
 *   5. Mount ESP at /esp, system at /system
 *
 * When the kernel-ELF embed is OFF, the slot staging is skipped
 * and the operator stages kernel bytes out-of-band (USB /
 * network); the generated grub.cfg's legacy menuentry still
 * points at /system/boot/duetos-kernel.elf.
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

namespace duetos::fs::fat32
{
struct Volume;
}
namespace duetos::fs::boot_slot
{
struct State;
}

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
    u32 staged_slot; // boot_slot::Slot (as u32) the embedded kernel ELF was staged into on the
                     // ESP; 0 (kInvalid) when no kernel was embedded or staging failed.
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

// ---------------------------------------------------------------
// FAT32-backed boot-slot persistence. boot_slot itself is FS-
// agnostic (callback-based SaveVia/LoadVia); these two helpers are
// the single FAT32 bridge every persist site shares — the
// installer at install time, the heartbeat after MarkHealthyNow,
// and the `bootslot` shell commands.
// ---------------------------------------------------------------

/// Locate the FAT32 volume that carries the boot-slot state file
/// (the ESP the installer laid down). Falls back to volume 0 — the
/// QEMU/dev scratch volume — when no registered volume has the
/// file yet, so a dev boot still persists somewhere LoadVia-able.
/// Returns nullptr when no FAT32 volume is registered at all.
const fat32::Volume* FindBootSlotVolume();

/// Persist `state` to `/boot/duetos-slot.cfg` on `vol` via
/// `boot_slot::SaveVia` + the FAT32 bounded-write tier (same-size
/// in-place overwrite, else delete + create), then regenerate
/// `/boot/grub/grub.cfg` from the same state — when the volume has
/// a `/boot/grub` directory (i.e. it is an ESP) — so GRUB's
/// `set default` always tracks the state machine. Flushes the
/// volume on success. Returns false on any write failure.
bool PersistSlotState(const fat32::Volume* vol, const boot_slot::State& state);

} // namespace duetos::fs::installer
