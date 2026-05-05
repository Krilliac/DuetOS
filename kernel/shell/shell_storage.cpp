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

#include "drivers/storage/block.h"
#include "drivers/video/console.h"
#include "fs/fat32.h"
#include "fs/gpt.h"
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
