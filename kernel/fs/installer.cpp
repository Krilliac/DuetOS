/*
 * DuetOS — disk installer orchestration, v0.
 *
 * Companion to installer.h. Drives the GPT-init + FAT32-format +
 * mount + ESP-stub-write sequence that turns a blank block device
 * into a DuetOS-bootable layout. Bootloader-bytes copy is a
 * separate slice (build-time bootstrap problem); v0 lays down the
 * partition table and the filesystem skeletons so the layout is
 * correct.
 *
 * Failure semantics: every step before the GPT write is purely
 * validation; the disk is not touched until we've gated on
 * writability + size. After the GPT write the disk is committed
 * and a partial failure leaves an inconsistent state that the
 * operator must repair (or re-run the installer). The Status
 * codes in installer.h let callers report exactly which stage
 * tripped.
 */

#include "fs/installer.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/storage/block.h"
#include "fs/boot_slot.h"
#include "fs/duetfs.h"
#include "fs/duetfs/include/duetfs.h"
#include "fs/fat32.h"
#include "fs/gpt.h"
#include "fs/mount.h"
#include "fs/ramfs.h"
#include "log/klog.h"
#include "util/random.h"

namespace duetos::fs::installer
{
namespace
{

namespace storage = drivers::storage;
namespace gpt = fs::gpt;

// EFI System Partition: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
constexpr u8 kEspTypeGuid[gpt::kGuidBytes] = {
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
};

// Microsoft Basic Data: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7. Used
// for the system partition because Windows + Linux fdisk both
// recognise it; a DuetOS-private system-partition GUID would force
// every external tool that wants to read our disk to know our type.
constexpr u8 kSystemTypeGuid[gpt::kGuidBytes] = {
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
};

void FillRandomGuid(u8 out[gpt::kGuidBytes])
{
    const u64 lo = duetos::core::RandomU64();
    const u64 hi = duetos::core::RandomU64();
    for (u32 i = 0; i < 8; ++i)
        out[i] = static_cast<u8>(lo >> (i * 8));
    for (u32 i = 0; i < 8; ++i)
        out[8 + i] = static_cast<u8>(hi >> (i * 8));
    // Stamp UUID v4 + RFC 4122 variant bits so external tooling
    // recognises this as a randomly-generated GUID rather than
    // entropy-soup.
    out[7] = static_cast<u8>((out[7] & 0x0F) | 0x40);
    out[8] = static_cast<u8>((out[8] & 0x3F) | 0x80);
}

// UTF-16LE encode a 7-bit ASCII label into a 72-byte zero-padded
// buffer (kPartitionNameChars = 36). Caller-supplied label must be
// NUL-terminated; characters past 35 are truncated.
void Utf16LePartitionName(const char* label, u8 out[72])
{
    for (u32 i = 0; i < 72; ++i)
        out[i] = 0;
    for (u32 i = 0; label[i] != '\0' && i < 35; ++i)
    {
        out[i * 2] = static_cast<u8>(label[i]);
        out[i * 2 + 1] = 0;
    }
}

// /system/boot/.duetos-installed sentinel. Operators can read it
// from another OS to confirm the disk really did go through the
// installer rather than being half-formatted by some other tool.
constexpr char kSystemSentinelPayload[] = "DuetOS installer v0 — system partition initialised\n"
                                          "Layout: /esp (ESP, FAT32), /system (Microsoft Basic Data, FAT32).\n"
                                          "Crash-dump partition reserved with kDuetCrashDumpTypeGuid.\n";

// Write `len` bytes at `path`, replacing any existing file. A
// same-size replace goes through Fat32WriteInPlace (pure data-
// cluster overwrite — no FAT mutation, no remove/create window);
// anything else is delete-then-create through the bounded-write
// tier.
// GAP: delete + create is non-atomic — a power cut between the two
// leaves the path absent until the next persist; FAT32 v0 has no
// rename-over-existing to close the window.
bool WriteFileReplacing(const fat32::Volume* vol, const char* path, const void* buf, u64 len)
{
    if (vol == nullptr || path == nullptr || buf == nullptr || len == 0)
        return false;
    fat32::DirEntry existing;
    if (fat32::Fat32LookupPath(vol, path, &existing))
    {
        if (static_cast<u64>(existing.size_bytes) == len)
            return fat32::Fat32WriteInPlace(vol, &existing, 0, buf, len) == static_cast<i64>(len);
        if (!fat32::Fat32DeleteAtPath(vol, path))
            return false;
    }
    return fat32::Fat32CreateAtPath(vol, path, buf, len) == static_cast<i64>(len);
}

// Stage a kernel image into a slot path on the ESP and validate
// the on-disk artifact: directory entry size must match and a
// chunked read-back must compare byte-for-byte against the source.
// Polling block I/O — fine in the shell-driven install flow.
bool StageSlotKernel(const fat32::Volume* vol, const char* path, const u8* bytes, u64 len)
{
    if (path == nullptr || bytes == nullptr || len == 0)
        return false;
    if (!WriteFileReplacing(vol, path, bytes, len))
        return false;
    fat32::DirEntry entry;
    if (!fat32::Fat32LookupPath(vol, path, &entry) || static_cast<u64>(entry.size_bytes) != len)
        return false;
    u8 chunk[4096];
    u64 off = 0;
    while (off < len)
    {
        const u64 want = (len - off < sizeof(chunk)) ? (len - off) : sizeof(chunk);
        if (fat32::Fat32ReadAt(vol, &entry, off, chunk, want) != static_cast<i64>(want))
            return false;
        for (u64 i = 0; i < want; ++i)
        {
            if (chunk[i] != bytes[off + i])
                return false;
        }
        off += want;
    }
    return true;
}

bool WriteEspBootSkeleton(const fat32::Volume* vol)
{
    if (vol == nullptr)
        return false;
    if (!fat32::Fat32MkdirAtPath(vol, "/EFI"))
        return false;
    if (!fat32::Fat32MkdirAtPath(vol, "/EFI/BOOT"))
        return false;
    if (!fat32::Fat32MkdirAtPath(vol, "/boot"))
        return false;
    if (!fat32::Fat32MkdirAtPath(vol, "/boot/grub"))
        return false;
    // Drop the embedded BOOTX64.EFI bytes at the canonical UEFI
    // fall-back removable-media path. UEFI firmware that boots a
    // removable disk without an explicit boot variable looks for
    // \EFI\BOOT\BOOTX64.EFI; this is what makes the freshly-
    // installed disk actually boot on real hardware. Bytes come
    // from the in-kernel ramfs blob populated at build time by
    // kernel/CMakeLists.txt's BOOTX64.EFI embed step.
    const u8* efi_bytes = RamfsBootX64EfiBytes();
    const u64 efi_len = RamfsBootX64EfiSize();
    if (efi_bytes != nullptr && efi_len > 0)
    {
        if (fat32::Fat32CreateAtPath(vol, "/EFI/BOOT/BOOTX64.EFI", efi_bytes, efi_len) != static_cast<i64>(efi_len))
            return false;
    }
    return true;
}

bool WriteSystemSentinel(const fat32::Volume* vol)
{
    if (vol == nullptr)
        return false;
    if (!fat32::Fat32MkdirAtPath(vol, "/boot"))
        return false;
    const u64 sentinel_len = sizeof(kSystemSentinelPayload) - 1;
    if (fat32::Fat32CreateAtPath(vol, "/boot/.duetos-installed", kSystemSentinelPayload, sentinel_len) !=
        static_cast<i64>(sentinel_len))
        return false;
    // Optional kernel.elf write. Bytes come from the .incbin blob
    // in kernel_elf_blob.S, which is the stage-1 kernel ELF when
    // the build option DUETOS_INSTALLER_KERNEL_EMBED is ON. When
    // it's OFF, RamfsKernelElfSize() returns 0 and we skip — the
    // generated grub.cfg's legacy menuentry points at this path,
    // so the operator stages the bytes from an out-of-band source
    // (USB / network) before first install-target boot.
    const u8* kern_bytes = RamfsKernelElfBytes();
    const u64 kern_len = RamfsKernelElfSize();
    if (kern_bytes != nullptr && kern_len > 0)
    {
        if (fat32::Fat32CreateAtPath(vol, "/boot/duetos-kernel.elf", kern_bytes, kern_len) !=
            static_cast<i64>(kern_len))
            return false;
    }
    return true;
}

} // namespace

const fat32::Volume* FindBootSlotVolume()
{
    namespace bs = fs::boot_slot;
    for (u32 i = 0; i < fat32::Fat32VolumeCount(); ++i)
    {
        const fat32::Volume* v = fat32::Fat32Volume(i);
        fat32::DirEntry entry;
        if (v != nullptr && fat32::Fat32LookupPath(v, bs::kSlotStateFilePath, &entry))
            return v;
    }
    return fat32::Fat32Volume(0);
}

bool PersistSlotState(const fat32::Volume* vol, const boot_slot::State& state)
{
    namespace bs = fs::boot_slot;
    if (vol == nullptr)
        return false;
    struct Ctx
    {
        const fat32::Volume* vol;
    } ctx{vol};
    auto save_fn = +[](void* c, const u8* buf, u64 len) -> bool
    {
        auto* x = static_cast<Ctx*>(c);
        return WriteFileReplacing(x->vol, bs::kSlotStateFilePath, buf, len);
    };
    if (!bs::SaveVia(save_fn, &ctx, state))
    {
        core::Log(core::LogLevel::Warn, "fs/installer", "boot-slot persist: state-file write failed");
        return false;
    }
    // Regenerate grub.cfg so `set default` tracks the new state.
    // Only volumes that carry a /boot/grub directory (the ESP the
    // installer laid down) get a cfg; the QEMU/dev scratch volume
    // persists the state file alone.
    fat32::DirEntry grub_dir;
    if (fat32::Fat32LookupPath(vol, "/boot/grub", &grub_dir))
    {
        u8 cfg[bs::kGrubCfgCapacity];
        const u64 cfg_len = bs::GrubCfgGenerate(state, cfg, sizeof(cfg));
        if (cfg_len == 0 || !WriteFileReplacing(vol, bs::kGrubCfgPath, cfg, cfg_len))
        {
            core::Log(core::LogLevel::Warn, "fs/installer", "boot-slot persist: grub.cfg regenerate failed");
            return false;
        }
    }
    return fat32::Fat32Sync(vol);
}

const char* StatusName(Status s)
{
    switch (s)
    {
    case Status::Ok:
        return "Ok";
    case Status::InvalidHandle:
        return "InvalidHandle";
    case Status::NotWritable:
        return "NotWritable";
    case Status::DiskTooSmall:
        return "DiskTooSmall";
    case Status::GptInitFailed:
        return "GptInitFailed";
    case Status::PartitionRegisterFailed:
        return "PartitionRegisterFailed";
    case Status::EspFormatFailed:
        return "EspFormatFailed";
    case Status::SystemFormatFailed:
        return "SystemFormatFailed";
    case Status::EspMountFailed:
        return "EspMountFailed";
    case Status::SystemMountFailed:
        return "SystemMountFailed";
    case Status::EspGrubCfgWriteFailed:
        return "EspGrubCfgWriteFailed";
    }
    return "?";
}

Status Install(u32 block_handle, bool use_duetfs_system, Report* out_report)
{
    if (out_report == nullptr)
        return Status::InvalidHandle;

    if (block_handle >= storage::BlockDeviceCount())
    {
        core::Log(core::LogLevel::Warn, "fs/installer", "Install: block handle out of range");
        return Status::InvalidHandle;
    }
    if (!storage::BlockDeviceIsWritable(block_handle))
    {
        core::Log(core::LogLevel::Warn, "fs/installer", "Install: block handle not writable");
        return Status::NotWritable;
    }
    const u64 disk_sectors = storage::BlockDeviceSectorCount(block_handle);
    Report layout{};
    const Status plan = PlanLayout(disk_sectors, &layout);
    if (plan != Status::Ok)
    {
        core::Log(core::LogLevel::Warn, "fs/installer", "Install: layout planner refused this disk size");
        return plan;
    }
    const u64 esp_first = layout.esp_first_lba;
    const u64 esp_last = layout.esp_last_lba;
    const u64 sys_first = layout.system_first_lba;
    const u64 sys_last = layout.system_last_lba;
    const u64 crash_first = layout.crashdump_first_lba;
    const u64 crash_last = layout.crashdump_last_lba;

    u8 disk_guid[gpt::kGuidBytes];
    u8 esp_unique[gpt::kGuidBytes];
    u8 sys_unique[gpt::kGuidBytes];
    u8 crash_unique[gpt::kGuidBytes];
    FillRandomGuid(disk_guid);
    FillRandomGuid(esp_unique);
    FillRandomGuid(sys_unique);
    FillRandomGuid(crash_unique);

    u8 esp_name[72];
    u8 sys_name[72];
    u8 crash_name[72];
    Utf16LePartitionName("DuetOS ESP", esp_name);
    Utf16LePartitionName("DuetOS System", sys_name);
    Utf16LePartitionName("DuetOS CrashDump", crash_name);

    gpt::PartitionSpec specs[3];
    specs[0].type_guid = kEspTypeGuid;
    specs[0].unique_guid = esp_unique;
    specs[0].first_lba = esp_first;
    specs[0].last_lba = esp_last;
    specs[0].attributes = 0;
    specs[0].name_utf16le = esp_name;

    specs[1].type_guid = use_duetfs_system ? gpt::kDuetFsTypeGuid : kSystemTypeGuid;
    specs[1].unique_guid = sys_unique;
    specs[1].first_lba = sys_first;
    specs[1].last_lba = sys_last;
    specs[1].attributes = 0;
    specs[1].name_utf16le = sys_name;

    specs[2].type_guid = gpt::kDuetCrashDumpTypeGuid;
    specs[2].unique_guid = crash_unique;
    specs[2].first_lba = crash_first;
    specs[2].last_lba = crash_last;
    specs[2].attributes = 0;
    specs[2].name_utf16le = crash_name;

    if (!gpt::GptInitDisk(block_handle, disk_sectors, disk_guid, specs, 3))
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: GptInitDisk failed");
        return Status::GptInitFailed;
    }

    // Re-probe to refresh the in-memory Disk record + register
    // partitions in the block layer for FAT32 to format. Without
    // this, the next Fat32Format call would touch raw whole-disk
    // LBAs instead of partition-relative LBAs.
    u32 gpt_idx = 0;
    if (!gpt::GptProbe(block_handle, &gpt_idx))
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: re-probe of fresh GPT failed");
        return Status::GptInitFailed;
    }

    const u32 esp_handle = storage::PartitionBlockDeviceCreate("install_esp", block_handle, esp_first, esp_last);
    const u32 sys_handle = storage::PartitionBlockDeviceCreate("install_sys", block_handle, sys_first, sys_last);
    const u32 crash_handle =
        storage::PartitionBlockDeviceCreate("install_crash", block_handle, crash_first, crash_last);
    if (esp_handle == storage::kBlockHandleInvalid || sys_handle == storage::kBlockHandleInvalid ||
        crash_handle == storage::kBlockHandleInvalid)
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: PartitionBlockDeviceCreate failed");
        return Status::PartitionRegisterFailed;
    }

    if (!fat32::Fat32Format(esp_handle, kEspSectors))
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: Fat32Format(ESP) failed");
        return Status::EspFormatFailed;
    }
    if (use_duetfs_system)
    {
        // DuetFS chose for the system partition. Adapter cookies up
        // a Device that points at the partition block handle, then
        // mkfs lays down a fresh DuetFS image.
        const duetfs::Device sys_dev = duetfs::MakeBlockHandleDevice(sys_handle);
        if (sys_dev.read == nullptr || sys_dev.write == nullptr || sys_dev.block_count == 0 || sys_dev.read_only != 0)
        {
            core::Log(core::LogLevel::Error, "fs/installer", "Install: DuetFS adapter rejected the partition handle");
            return Status::SystemFormatFailed;
        }
        const u32 mkfs_st = duetfs::duetfs_mkfs(&sys_dev);
        if (mkfs_st != duetfs::kStatusOk)
        {
            core::Log(core::LogLevel::Error, "fs/installer", "Install: duetfs_mkfs(system) failed");
            return Status::SystemFormatFailed;
        }
        if (duetfs::duetfs_probe(&sys_dev) == 0)
        {
            core::Log(core::LogLevel::Error, "fs/installer", "Install: DuetFS post-format probe rejected");
            return Status::SystemFormatFailed;
        }
    }
    else
    {
        if (!fat32::Fat32Format(sys_handle, sys_last - sys_first + 1))
        {
            core::Log(core::LogLevel::Error, "fs/installer", "Install: Fat32Format(system) failed");
            return Status::SystemFormatFailed;
        }
    }

    u32 esp_vol_idx = 0;
    if (!fat32::Fat32Probe(esp_handle, &esp_vol_idx))
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: ESP probe after format failed");
        return Status::EspFormatFailed;
    }
    if (!use_duetfs_system)
    {
        u32 sys_vol_idx = 0;
        if (!fat32::Fat32Probe(sys_handle, &sys_vol_idx))
        {
            core::Log(core::LogLevel::Error, "fs/installer", "Install: system probe after format failed");
            return Status::SystemFormatFailed;
        }
        if (!WriteSystemSentinel(fat32::Fat32Volume(sys_vol_idx)))
        {
            // Sentinel is informational; format succeeded so we
            // don't unwind. Log loud.
            core::Log(core::LogLevel::Warn, "fs/installer", "Install: system sentinel write failed (continuing)");
        }
    }
    // DuetFS sentinel write is left as a follow-on — DuetFS
    // create_path needs an absolute-path NUL-terminated buffer
    // routed through the Rust ABI, which the installer doesn't
    // currently wrap. The duetfs_probe success above is the
    // strong proof that the partition is initialised; the sentinel
    // is cosmetic.

    namespace bs = fs::boot_slot;
    const fat32::Volume* esp_vol = fat32::Fat32Volume(esp_vol_idx);
    if (!WriteEspBootSkeleton(esp_vol))
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: ESP boot-skeleton write failed");
        return Status::EspGrubCfgWriteFailed;
    }

    // A/B slot staging. The freshly-laid disk starts from the
    // canonical Default state (active = A); the embedded kernel —
    // when the build carries one — is staged into the INACTIVE
    // slot, validated by byte-for-byte read-back, and only then
    // does BeginInstall flip `pending` so the first boot tries it
    // (with the legacy system-partition entry as GRUB fallback).
    bs::State slot_state = bs::Default();
    bs::Slot staged = bs::Slot::kInvalid;
    const u8* slot_kern_bytes = RamfsKernelElfBytes();
    const u64 slot_kern_len = RamfsKernelElfSize();
    if (slot_kern_bytes != nullptr && slot_kern_len > 0)
    {
        const bs::Slot target = bs::Other(slot_state.active);
        if (StageSlotKernel(esp_vol, bs::SlotKernelPath(target), slot_kern_bytes, slot_kern_len))
        {
            slot_state = bs::BeginInstall(slot_state, target);
            staged = target;
        }
        else
        {
            // Non-fatal: the legacy menuentry (system-partition
            // kernel) still boots the disk. State stays Default so
            // GRUB never defaults to an empty slot.
            core::Log(core::LogLevel::Warn, "fs/installer",
                      "Install: slot-kernel stage/validate failed — legacy entry remains the boot path");
        }
    }
    if (!PersistSlotState(esp_vol, slot_state))
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: ESP grub.cfg/slot-state write failed");
        return Status::EspGrubCfgWriteFailed;
    }

    const MountId esp_mount = VfsMount("/esp", FsType::Fat32, esp_handle);
    if (esp_mount == kInvalidMountId)
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: VfsMount(/esp) failed");
        return Status::EspMountFailed;
    }
    const FsType sys_fs_type = use_duetfs_system ? FsType::DuetFs : FsType::Fat32;
    const MountId sys_mount = VfsMount("/system", sys_fs_type, sys_handle);
    if (sys_mount == kInvalidMountId)
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: VfsMount(/system) failed");
        return Status::SystemMountFailed;
    }

    out_report->disk_handle = block_handle;
    out_report->esp_handle = esp_handle;
    out_report->esp_mount_id = esp_mount;
    out_report->system_handle = sys_handle;
    out_report->system_mount_id = sys_mount;
    out_report->esp_first_lba = esp_first;
    out_report->esp_last_lba = esp_last;
    out_report->system_first_lba = sys_first;
    out_report->system_last_lba = sys_last;
    out_report->crashdump_first_lba = crash_first;
    out_report->crashdump_last_lba = crash_last;
    out_report->staged_slot = static_cast<u32>(staged);

    core::Log(core::LogLevel::Info, "fs/installer", "Install: complete");
    return Status::Ok;
}

Status PlanLayout(u64 disk_sectors, Report* out_report)
{
    if (out_report == nullptr)
        return Status::InvalidHandle;
    if (disk_sectors < kMinInstallSectors)
        return Status::DiskTooSmall;

    // Layout (sector indices, inclusive, 512-byte sectors):
    //   PMBR + primary header + entries: 0..33
    //   ESP                           : 34..(34 + ESP - 1)
    //   System                        : ESP_end+1..(crashdump_first - 1)
    //   Crash-dump                    : (last_usable - crashdump + 1)..last_usable
    //   Backup entries + header       : (disk_end - 33)..(disk_end - 1)
    //
    // System partition takes "everything else" so the user gets
    // every spare sector. On a 100 MiB disk the system gets ~32
    // MiB; on a 1 TB disk the system gets ~999.9 GB.
    const u64 first_usable = 34;
    const u64 last_usable = disk_sectors - 34; // inclusive — UEFI 5.3.2

    const u64 esp_first = first_usable;
    const u64 esp_last = esp_first + kEspSectors - 1;

    const u64 crash_last = last_usable;
    const u64 crash_first = crash_last - kCrashDumpSectors + 1;

    const u64 sys_first = esp_last + 1;
    const u64 sys_last = crash_first - 1;

    if (sys_first > sys_last || sys_last - sys_first + 1 < kMinSystemSectors)
        return Status::DiskTooSmall;

    out_report->esp_first_lba = esp_first;
    out_report->esp_last_lba = esp_last;
    out_report->system_first_lba = sys_first;
    out_report->system_last_lba = sys_last;
    out_report->crashdump_first_lba = crash_first;
    out_report->crashdump_last_lba = crash_last;
    return Status::Ok;
}

namespace
{

void AssertOrPanic(bool cond, const char* msg)
{
    if (!cond)
    {
        core::Log(core::LogLevel::Error, "fs/installer", msg);
        core::Panic("fs/installer", msg);
    }
}

bool LayoutOk(const Report& r)
{
    return r.esp_first_lba <= r.esp_last_lba && r.esp_last_lba < r.system_first_lba &&
           r.system_first_lba <= r.system_last_lba && r.system_last_lba < r.crashdump_first_lba &&
           r.crashdump_first_lba <= r.crashdump_last_lba;
}

} // namespace

void InstallerSelfTest()
{
    // Just-too-small: kMinInstallSectors - 1 must refuse.
    {
        Report r{};
        const Status s = PlanLayout(kMinInstallSectors - 1, &r);
        AssertOrPanic(s == Status::DiskTooSmall, "selftest: undersized disk should refuse");
    }
    // Just-large-enough: kMinInstallSectors must succeed and produce a
    // sane layout.
    {
        Report r{};
        const Status s = PlanLayout(kMinInstallSectors, &r);
        AssertOrPanic(s == Status::Ok, "selftest: kMinInstallSectors should succeed");
        AssertOrPanic(LayoutOk(r), "selftest: 100 MiB layout malformed");
        AssertOrPanic(r.esp_last_lba - r.esp_first_lba + 1 == kEspSectors, "selftest: ESP did not match kEspSectors");
        AssertOrPanic(r.crashdump_last_lba - r.crashdump_first_lba + 1 == kCrashDumpSectors,
                      "selftest: crash-dump did not match kCrashDumpSectors");
        AssertOrPanic(r.system_last_lba - r.system_first_lba + 1 >= kMinSystemSectors,
                      "selftest: system partition under FAT32 floor");
    }
    // 1 GiB disk (2 097 152 sectors at 512B): ESP + crash-dump fixed,
    // system absorbs the rest.
    {
        Report r{};
        const Status s = PlanLayout(2097152ULL, &r);
        AssertOrPanic(s == Status::Ok, "selftest: 1 GiB disk should succeed");
        AssertOrPanic(LayoutOk(r), "selftest: 1 GiB layout malformed");
        AssertOrPanic(r.system_last_lba - r.system_first_lba + 1 > 65536,
                      "selftest: 1 GiB system partition implausibly small");
    }
    // 1 TiB disk (2 147 483 648 sectors at 512B): same shape, much
    // larger system partition. Sanity-check the system span is on
    // the order of the disk.
    {
        Report r{};
        const Status s = PlanLayout(2147483648ULL, &r);
        AssertOrPanic(s == Status::Ok, "selftest: 1 TiB disk should succeed");
        AssertOrPanic(LayoutOk(r), "selftest: 1 TiB layout malformed");
        const u64 sys_span = r.system_last_lba - r.system_first_lba + 1;
        AssertOrPanic(sys_span > 2000000000ULL, "selftest: 1 TiB system partition shrunk");
    }
    // Null-out: must reject without writing.
    {
        const Status s = PlanLayout(2097152ULL, nullptr);
        AssertOrPanic(s == Status::InvalidHandle, "selftest: null report must refuse");
    }
    arch::SerialWrite("[fs/installer] self-test OK (PlanLayout: 100 MiB / 1 GiB / 1 TiB / undersized refused)\n");
}

} // namespace duetos::fs::installer
