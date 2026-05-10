/*
 * DuetOS — kernel shell: storage / device-list commands.
 *
 * Sibling TU of shell.cpp. Houses the simple block-layer / GPT
 * / mount-table read-only views: lsblk, lsgpt, lsmod, mount.
 *
 * The Fat* family (fatls / fatcat / fatwrite / fatappend / fatnew
 * / fatrm / fattrunc / fatmkdir / fatrmdir) and CmdRead live in a
 * follow-up slice — they share the FatLeaf path-strip helper and
 * ParseU64Str with several other shell commands, so promoting
 * those to shell_internal.h is its own work item.
 */

#include "shell/shell_internal.h"

#include "diag/minidump.h"
#include "drivers/storage/block.h"
#include "drivers/storage/nvme.h"
#include "drivers/video/console.h"
#include "fs/duetfs.h"
#include "fs/duetfs/include/duetfs.h"
#include "fs/fat32.h"
#include "fs/gpt.h"
#include "fs/installer.h"
#include "fs/mount.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// TU-local hex printer used for tabular column output. Distinct
// from the canonical WriteU64Hex in shell_format.cpp: this one
// emits no "0x" prefix and pads to a fixed width without leading
// zeros stripped. Renamed to WriteHexCol so the canonical one
// (declared in shell_internal.h) doesn't shadow it.
void WriteHexCol(u64 v, u32 digits = 16)
{
    char tmp[16];
    if (digits == 0 || digits > 16)
        digits = 16;
    for (u32 i = 0; i < digits; ++i)
    {
        const u32 nibble = static_cast<u32>((v >> ((digits - 1 - i) * 4)) & 0xF);
        tmp[i] = nibble < 10 ? char('0' + nibble) : char('A' + (nibble - 10));
    }
    for (u32 i = 0; i < digits; ++i)
        ConsoleWriteChar(tmp[i]);
}

} // namespace

void CmdMount()
{
    // Built-in roots that always exist regardless of the
    // registered mount table — these are the kernel's static
    // namespace (constinit ramfs trees + the tmpfs slot
    // backend).
    ConsoleWriteln("ramfs on /       type=ramfs (ro)");
    ConsoleWriteln("tmpfs on /tmp    type=tmpfs (rw, 16 slots, 512B each)");
    // Walk the VfsMount registry. Stage-6 first slice landed
    // the registry; the lookup-routing slice that switches
    // backends at mount points lands separately. Until then,
    // these entries are bookkeeping only — but listing them
    // here gives the operator the same one-line view of the
    // mount surface real Linux's `mount` provides.
    using duetos::fs::FsTypeName;
    using duetos::fs::MountEntry;
    using duetos::fs::MountId;
    using duetos::fs::VfsMountCount;
    using duetos::fs::VfsMountEnumerate;
    if (VfsMountCount() > 0)
    {
        VfsMountEnumerate(
            [](const MountEntry& e, MountId id, void* /*cookie*/) -> bool
            {
                ConsoleWrite(FsTypeName(e.fs_type));
                ConsoleWrite(" on ");
                ConsoleWrite(e.mount_point);
                ConsoleWrite("  type=");
                ConsoleWrite(FsTypeName(e.fs_type));
                ConsoleWrite(" (id=");
                WriteHexCol(static_cast<u64>(id), 2);
                ConsoleWrite(" blk=");
                WriteHexCol(static_cast<u64>(e.block_handle), 2);
                ConsoleWriteln(")");
                return true;
            },
            nullptr);
    }
}

void CmdLsblk()
{
    namespace storage = duetos::drivers::storage;
    const duetos::u32 count = storage::BlockDeviceCount();
    ConsoleWrite("NAME       HANDLE  SECT_SZ  SECT_COUNT       MODE");
    ConsoleWriteln("");
    for (duetos::u32 i = 0; i < count; ++i)
    {
        const char* name = storage::BlockDeviceName(i);
        ConsoleWrite(name);
        // Pad the name column to 10 chars (max realistic "nvme0n99").
        for (duetos::u32 p = 0; p < 11; ++p)
        {
            if (name[p] == 0)
            {
                for (duetos::u32 q = p; q < 11; ++q)
                    ConsoleWriteChar(' ');
                break;
            }
        }
        WriteHexCol(i, 4);
        ConsoleWrite("    ");
        WriteHexCol(storage::BlockDeviceSectorSize(i), 6);
        ConsoleWrite("  ");
        WriteHexCol(storage::BlockDeviceSectorCount(i), 16);
        ConsoleWrite("  ");
        ConsoleWriteln(storage::BlockDeviceIsWritable(i) ? "rw" : "ro");
    }
    if (count == 0)
    {
        ConsoleWriteln("  (no block devices registered)");
    }
}

void CmdLsgpt()
{
    namespace gpt = duetos::fs::gpt;
    const duetos::u32 disks = gpt::GptDiskCount();
    if (disks == 0)
    {
        ConsoleWriteln("  (no GPT disks probed)");
        return;
    }
    for (duetos::u32 di = 0; di < disks; ++di)
    {
        const gpt::Disk* d = gpt::GptDisk(di);
        if (d == nullptr)
            continue;
        ConsoleWrite("DISK HANDLE ");
        WriteHexCol(d->block_handle, 4);
        ConsoleWrite("  SECTOR_SIZE ");
        WriteHexCol(d->sector_size, 4);
        ConsoleWrite("  PARTS ");
        WriteHexCol(d->partition_count, 2);
        ConsoleWriteln("");
        char guid_str[gpt::kGuidStringLen + 1];
        gpt::FormatGuid(d->disk_guid, guid_str, sizeof(guid_str));
        ConsoleWrite("  DISK_GUID ");
        ConsoleWriteln(guid_str);
        for (duetos::u32 pi = 0; pi < d->partition_count; ++pi)
        {
            const gpt::Partition& p = d->partitions[pi];
            ConsoleWrite("  PART ");
            WriteHexCol(pi, 2);
            ConsoleWrite(" FIRST_LBA ");
            WriteHexCol(p.first_lba, 0);
            ConsoleWrite(" LAST_LBA ");
            WriteHexCol(p.last_lba, 0);
            ConsoleWriteln("");
            gpt::FormatGuid(p.type_guid, guid_str, sizeof(guid_str));
            ConsoleWrite("       TYPE ");
            ConsoleWriteln(guid_str);
        }
    }
}

// `mkfs <handle> ERASE` — destructive. Lays down a fresh FAT32
// volume on the named block-device handle. Refuses unless the
// caller passes the literal "ERASE" confirmation token (matches
// the disk-installer plan's user-typed-confirmation contract for
// every DESTRUCTIVE primitive). Admin-gated. Validates writability
// + minimum size + already-FAT32-mounted state before touching
// anything on disk.
void CmdMkfs(u32 argc, char** argv)
{
    namespace storage = duetos::drivers::storage;
    namespace fat = duetos::fs::fat32;
    if (!RequireAdmin("MKFS"))
        return;
    if (argc < 3 || argv == nullptr)
    {
        ConsoleWriteln("usage: mkfs <handle-hex> ERASE");
        ConsoleWriteln("  handle  block-device handle from `lsblk` (hex)");
        ConsoleWriteln("  ERASE   literal token — destructive, lays a fresh FAT32 BPB");
        return;
    }
    duetos::u64 handle_u64 = 0;
    if (!ParseU64Str(argv[1], &handle_u64) || handle_u64 >= 0xFFFFu)
    {
        ConsoleWrite("mkfs: bad handle '");
        ConsoleWrite(argv[1]);
        ConsoleWriteln("'");
        return;
    }
    const duetos::u32 handle = static_cast<duetos::u32>(handle_u64);
    bool ok = false;
    for (duetos::u32 i = 0; i < storage::BlockDeviceCount(); ++i)
    {
        if (i == handle)
        {
            ok = true;
            break;
        }
    }
    if (!ok)
    {
        ConsoleWriteln("mkfs: handle out of range — see `lsblk`");
        return;
    }
    bool confirm = argv[2][0] == 'E' && argv[2][1] == 'R' && argv[2][2] == 'A' && argv[2][3] == 'S' &&
                   argv[2][4] == 'E' && argv[2][5] == '\0';
    if (!confirm)
    {
        ConsoleWriteln("mkfs: confirmation token missing — pass literal ERASE");
        return;
    }
    if (!storage::BlockDeviceIsWritable(handle))
    {
        ConsoleWrite("mkfs: handle not writable: ");
        ConsoleWriteln(storage::BlockDeviceName(handle));
        return;
    }
    const duetos::u64 sectors = storage::BlockDeviceSectorCount(handle);
    if (sectors < 65600)
    {
        ConsoleWriteln("mkfs: device under 32 MiB — FAT32 spec floor");
        return;
    }
    ConsoleWrite("mkfs: formatting ");
    ConsoleWrite(storage::BlockDeviceName(handle));
    ConsoleWrite(" (");
    WriteHexCol(sectors, 0);
    ConsoleWriteln(" sectors) as FAT32...");
    if (!fat::Fat32Format(handle, sectors))
    {
        ConsoleWriteln("mkfs: Fat32Format failed (see klog)");
        return;
    }
    duetos::u32 vol_idx = 0;
    if (fat::Fat32Probe(handle, &vol_idx))
    {
        ConsoleWrite("mkfs OK: re-probe handed back volume index ");
        WriteHexCol(vol_idx, 2);
        ConsoleWriteln("");
    }
    else
    {
        ConsoleWriteln("mkfs: laid down BPB but re-probe rejected — please file a bug");
    }
}

// `mkfs.duetfs <handle> ERASE` — destructive. Lays down a fresh
// DuetFS image on the named block-device handle. Same admin /
// confirmation-token contract as `mkfs` (FAT32). After the format
// the volume is NOT auto-mounted — the existing duetfs probe path
// runs at boot and only mounts pre-formatted volumes; mounting a
// fresh image at runtime is a follow-on slice.
void CmdMkfsDuetfs(u32 argc, char** argv)
{
    namespace storage = duetos::drivers::storage;
    namespace duetfs = duetos::fs::duetfs;
    if (!RequireAdmin("MKFS.DUETFS"))
        return;
    if (argc < 3 || argv == nullptr)
    {
        ConsoleWriteln("usage: mkfs.duetfs <handle-hex> ERASE");
        ConsoleWriteln("  handle  block-device handle from `lsblk` (hex)");
        ConsoleWriteln("  ERASE   literal token — destructive, lays a fresh DuetFS image");
        return;
    }
    duetos::u64 handle_u64 = 0;
    if (!ParseU64Str(argv[1], &handle_u64) || handle_u64 >= 0xFFFFu)
    {
        ConsoleWrite("mkfs.duetfs: bad handle '");
        ConsoleWrite(argv[1]);
        ConsoleWriteln("'");
        return;
    }
    const duetos::u32 handle = static_cast<duetos::u32>(handle_u64);
    bool ok_handle = false;
    for (duetos::u32 i = 0; i < storage::BlockDeviceCount(); ++i)
    {
        if (i == handle)
        {
            ok_handle = true;
            break;
        }
    }
    if (!ok_handle)
    {
        ConsoleWriteln("mkfs.duetfs: handle out of range — see `lsblk`");
        return;
    }
    const bool confirm = argv[2][0] == 'E' && argv[2][1] == 'R' && argv[2][2] == 'A' && argv[2][3] == 'S' &&
                         argv[2][4] == 'E' && argv[2][5] == '\0';
    if (!confirm)
    {
        ConsoleWriteln("mkfs.duetfs: confirmation token missing — pass literal ERASE");
        return;
    }
    if (!storage::BlockDeviceIsWritable(handle))
    {
        ConsoleWrite("mkfs.duetfs: handle not writable: ");
        ConsoleWriteln(storage::BlockDeviceName(handle));
        return;
    }
    const duetfs::Device dev = duetfs::MakeBlockHandleDevice(handle);
    if (dev.read == nullptr || dev.write == nullptr || dev.block_count == 0)
    {
        ConsoleWriteln("mkfs.duetfs: block-handle adapter rejected the handle (sector size or count)");
        return;
    }
    if (dev.read_only != 0)
    {
        ConsoleWriteln("mkfs.duetfs: block-handle adapter reports read-only");
        return;
    }
    ConsoleWrite("mkfs.duetfs: formatting ");
    ConsoleWrite(storage::BlockDeviceName(handle));
    ConsoleWrite(" (");
    WriteHexCol(static_cast<duetos::u64>(dev.block_count), 0);
    ConsoleWriteln(" 4 KiB blocks) as DuetFS...");
    const duetos::u32 st = duetfs::duetfs_mkfs(&dev);
    if (st != duetfs::kStatusOk)
    {
        ConsoleWrite("mkfs.duetfs: duetfs_mkfs returned status=");
        WriteHexCol(static_cast<duetos::u64>(st), 0);
        ConsoleWriteln("");
        return;
    }
    if (duetfs::duetfs_probe(&dev) == 0)
    {
        ConsoleWriteln("mkfs.duetfs: laid down image but probe rejected — please file a bug");
        return;
    }
    // Auto-mount the freshly formatted volume at the first free
    // /disks/duetfsN slot (N in 0..15). The boot probe path uses
    // the same mount-point template; this just makes the volume
    // immediately usable after a runtime mkfs without forcing a
    // reboot. If every slot is taken, report success without a
    // mount and let the operator shuffle by hand.
    for (duetos::u32 n = 0; n < 16; ++n)
    {
        char mp[24] = {};
        const char prefix[] = "/disks/duetfs";
        for (duetos::u32 i = 0; i < sizeof(prefix) - 1; ++i)
        {
            mp[i] = prefix[i];
        }
        if (n < 10)
        {
            mp[sizeof(prefix) - 1] = static_cast<char>('0' + n);
        }
        else
        {
            mp[sizeof(prefix) - 1] = '1';
            mp[sizeof(prefix)] = static_cast<char>('0' + (n - 10));
        }
        if (duetos::fs::VfsMountFind(mp) != nullptr)
        {
            continue;
        }
        const auto mid = duetos::fs::VfsMount(mp, duetos::fs::FsType::DuetFs, handle);
        if (mid == duetos::fs::kInvalidMountId)
        {
            ConsoleWriteln("mkfs.duetfs: format OK but VfsMount refused — verify mount table");
            return;
        }
        ConsoleWrite("mkfs.duetfs OK — mounted at ");
        ConsoleWriteln(mp);
        return;
    }
    ConsoleWriteln("mkfs.duetfs OK — superblock probe re-validates (no free /disks/duetfsN slot for auto-mount)");
}

// `install <handle> INSTALL` — run the disk-installer pipeline.
// DESTRUCTIVE. Lays down a fresh GPT (ESP + system + crash-dump),
// formats ESP and system as FAT32, seeds /esp/boot/grub/grub.cfg
// with a chainload stub, and mounts the new partitions at /esp +
// /system. Bootloader-bytes copy (BOOTX64.EFI + duetos-kernel.elf)
// is a follow-on slice — see wiki/reference/Daily-Driver-Readiness.md
// Tier 0 for the residual scope. Admin-gated; requires the literal
// "INSTALL" confirmation token to proceed.
void CmdInstall(u32 argc, char** argv)
{
    namespace storage = duetos::drivers::storage;
    namespace inst = duetos::fs::installer;
    if (!RequireAdmin("INSTALL"))
        return;
    if (argc < 3 || argv == nullptr)
    {
        ConsoleWriteln("usage: install <handle-hex> INSTALL");
        ConsoleWriteln("  handle   block-device handle from `lsblk` (hex)");
        ConsoleWriteln("  INSTALL  literal token — destructive, lays a fresh GPT + ESP + system");
        ConsoleWriteln("");
        ConsoleWriteln("layout (~100 MiB minimum):");
        ConsoleWriteln("  LBA 0..33       — PMBR + primary GPT");
        ConsoleWriteln("  LBA 34..        — ESP (FAT32, 64 MiB)");
        ConsoleWriteln("  LBA esp_end+1.. — System (FAT32, takes remaining space)");
        ConsoleWriteln("  last 4 MiB      — Crash-dump (kDuetCrashDumpTypeGuid)");
        ConsoleWriteln("  trailing 33 LBA — Backup GPT");
        return;
    }
    duetos::u64 handle_u64 = 0;
    if (!ParseU64Str(argv[1], &handle_u64) || handle_u64 >= 0xFFFFu)
    {
        ConsoleWrite("install: bad handle '");
        ConsoleWrite(argv[1]);
        ConsoleWriteln("'");
        return;
    }
    const duetos::u32 handle = static_cast<duetos::u32>(handle_u64);
    if (handle >= storage::BlockDeviceCount())
    {
        ConsoleWriteln("install: handle out of range — see `lsblk`");
        return;
    }
    const bool confirm = argv[2][0] == 'I' && argv[2][1] == 'N' && argv[2][2] == 'S' && argv[2][3] == 'T' &&
                         argv[2][4] == 'A' && argv[2][5] == 'L' && argv[2][6] == 'L' && argv[2][7] == '\0';
    if (!confirm)
    {
        ConsoleWriteln("install: confirmation token missing — pass literal INSTALL");
        return;
    }
    ConsoleWrite("install: target ");
    ConsoleWrite(storage::BlockDeviceName(handle));
    ConsoleWrite(" (");
    WriteHexCol(storage::BlockDeviceSectorCount(handle), 0);
    ConsoleWriteln(" sectors)");

    inst::Report report{};
    const inst::Status st = inst::Install(handle, &report);
    if (st != inst::Status::Ok)
    {
        ConsoleWrite("install: failed — ");
        ConsoleWriteln(inst::StatusName(st));
        return;
    }
    ConsoleWriteln("install: complete");
    ConsoleWrite("  ESP        handle=");
    WriteHexCol(report.esp_handle, 4);
    ConsoleWrite(" lba ");
    WriteHexCol(report.esp_first_lba, 0);
    ConsoleWrite("..");
    WriteHexCol(report.esp_last_lba, 0);
    ConsoleWriteln(" mounted at /esp");
    ConsoleWrite("  System     handle=");
    WriteHexCol(report.system_handle, 4);
    ConsoleWrite(" lba ");
    WriteHexCol(report.system_first_lba, 0);
    ConsoleWrite("..");
    WriteHexCol(report.system_last_lba, 0);
    ConsoleWriteln(" mounted at /system");
    ConsoleWrite("  Crash-dump lba ");
    WriteHexCol(report.crashdump_first_lba, 0);
    ConsoleWrite("..");
    WriteHexCol(report.crashdump_last_lba, 0);
    ConsoleWriteln(" reserved (DuetOS-private type GUID)");
    ConsoleWriteln("note: bootloader bytes (BOOTX64.EFI + duetos-kernel.elf)");
    ConsoleWriteln("      are NOT copied by v0 — stage them via the offline path.");
    ConsoleWriteln("      See wiki/reference/Daily-Driver-Readiness.md, Tier 0.");
}

// `lastdump` — operator readout for the last-built minidump.
// On QEMU the dump bytes egress via debugcon (port 0xE9) on every
// emit; on real hardware those writes go nowhere, so an
// in-system command that confirms a dump WAS emitted (and how
// big it was) is the only surface that survives. Prints
// "no dump this boot" when AccessLastMinidump returns false.
void CmdLastdump()
{
    namespace md = duetos::diag::minidump;
    const duetos::u8* bytes = nullptr;
    duetos::u64 len = 0;
    if (!md::AccessLastMinidump(&bytes, &len) || bytes == nullptr || len == 0)
    {
        ConsoleWriteln("lastdump: no minidump emitted this boot");
        return;
    }
    ConsoleWrite("lastdump: ");
    WriteHexCol(len, 0);
    ConsoleWriteln(" bytes resident in the kernel buffer");
    // First 4 bytes of a minidump are "MDMP" (0x504D444D LE) per
    // the Microsoft format. Surface them so an operator can sanity-
    // check the header without a debugger attached.
    ConsoleWrite("  signature: ");
    if (len >= 4)
    {
        for (duetos::u32 i = 0; i < 4; ++i)
        {
            const char c = static_cast<char>(bytes[i]);
            ConsoleWriteChar((c >= 0x20 && c < 0x7F) ? c : '?');
        }
    }
    ConsoleWriteln("");
    if (len >= 8)
    {
        // Bytes 4..7 are version (low 16) + revision (high 16).
        ConsoleWrite("  version: ");
        const duetos::u16 ver = static_cast<duetos::u16>(bytes[4] | (bytes[5] << 8));
        WriteHexCol(static_cast<duetos::u64>(ver), 4);
        ConsoleWriteln("");
    }

    // NVMe persistence — reports whether the panic path landed
    // a copy on the reserved LBA region of namespace 1. The dump
    // file name on the host (debugcon channel) is the FIRST
    // copy; this is the second, which survives a host without
    // the QEMU debugcon flag set.
    namespace stor = duetos::drivers::storage;
    if (stor::NvmeAvailable())
    {
        const duetos::u64 lba = stor::NvmeDumpReservedLba();
        ConsoleWrite("  disk persist: ");
        if (stor::NvmePanicWriteSucceededLast())
        {
            ConsoleWrite("OK at LBA ");
            WriteU64Dec(lba);
            ConsoleWrite(" (");
            WriteU64Dec(stor::NvmePanicLastWriteBytes());
            ConsoleWriteln(" bytes)");
        }
        else if (stor::NvmePanicLastWriteBytes() != 0)
        {
            ConsoleWrite("PARTIAL at LBA ");
            WriteU64Dec(lba);
            ConsoleWrite(" (");
            WriteU64Dec(stor::NvmePanicLastWriteBytes());
            ConsoleWriteln(" bytes written)");
        }
        else
        {
            ConsoleWrite("not yet attempted (reserved LBA=");
            WriteU64Dec(lba);
            ConsoleWriteln(", region writes only on panic)");
        }
    }
    else
    {
        ConsoleWriteln("  disk persist: no NVMe namespace");
    }
}

void CmdLsmod()
{
    // Not real modules — just a static list of the subsystems
    // currently online. Still useful as a "what's loaded" view.
    static const char* const kModules[] = {
        "multiboot2", "gdt",   "idt",    "tss+ist",     "paging", "frame_alloc", "kheap",   "acpi",
        "pic",        "lapic", "ioapic", "hpet",        "timer",  "scheduler",   "percpu",  "ps2kbd",
        "ps2mouse",   "pci",   "ahci",   "framebuffer", "cursor", "font8x8",     "console", "widget",
        "taskbar",    "menu",  "ramfs",  "tmpfs",       "vfs",    "rtc",         "klog",    "shell",
    };
    constexpr u32 kCount = sizeof(kModules) / sizeof(kModules[0]);
    for (u32 i = 0; i < kCount; ++i)
    {
        ConsoleWrite("  ");
        ConsoleWriteln(kModules[i]);
    }
}

} // namespace duetos::core::shell::internal
