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

// /esp/EFI/BOOT/grub.cfg payload. Tells GRUB (or a chainloaded
// stage-2 like rEFInd) where to find the kernel ELF on the system
// partition. The bootloader bytes themselves are NOT laid down by
// v0 of the installer — that's a follow-on slice. Until then the
// stub is a marker the operator can sanity-check by reading the
// freshly-formatted ESP from another OS.
constexpr char kGrubCfgPayload[] = "set timeout=3\n"
                                   "set default=0\n"
                                   "menuentry \"DuetOS\" {\n"
                                   "    insmod fat\n"
                                   "    set root=(hd0,gpt2)\n"
                                   "    multiboot2 /boot/duetos-kernel.elf\n"
                                   "    boot\n"
                                   "}\n"
                                   "# DuetOS installer v0 stub. Bootloader bytes (BOOTX64.EFI +\n"
                                   "# duetos-kernel.elf) are staged separately — see\n"
                                   "# wiki/reference/Daily-Driver-Readiness.md, Tier 0.\n";

// /system/boot/.duetos-installed sentinel. Operators can read it
// from another OS to confirm the disk really did go through the
// installer rather than being half-formatted by some other tool.
constexpr char kSystemSentinelPayload[] = "DuetOS installer v0 — system partition initialised\n"
                                          "Layout: /esp (ESP, FAT32), /system (Microsoft Basic Data, FAT32).\n"
                                          "Crash-dump partition reserved with kDuetCrashDumpTypeGuid.\n";

bool WriteEspGrubStub(const fat32::Volume* vol)
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
    const u64 cfg_len = sizeof(kGrubCfgPayload) - 1;
    if (fat32::Fat32CreateAtPath(vol, "/boot/grub/grub.cfg", kGrubCfgPayload, cfg_len) != static_cast<i64>(cfg_len))
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
    // grub.cfg already on the freshly-formatted ESP points at this
    // path, so the operator stages the bytes from an out-of-band
    // source (USB / network) before first install-target boot.
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

    if (!WriteEspGrubStub(fat32::Fat32Volume(esp_vol_idx)))
    {
        core::Log(core::LogLevel::Error, "fs/installer", "Install: ESP grub.cfg write failed");
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
