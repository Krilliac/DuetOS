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

#include "shell_internal.h"

#include "../drivers/storage/block.h"
#include "../drivers/video/console.h"
#include "../fs/gpt.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// TU-local hex printer. The shell.cpp copy is the canonical
// definition; duplicated here so this file is self-contained
// without dragging the parent's anon namespace into the build.
void WriteU64Hex(u64 v, u32 digits = 16)
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
    // Show every mounted backend. v0: ramfs at /, tmpfs at
    // /tmp. Real mount table lands with multi-backend VFS.
    ConsoleWriteln("ramfs on /       type=ramfs (ro)");
    ConsoleWriteln("tmpfs on /tmp    type=tmpfs (rw, 16 slots, 512B each)");
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
        WriteU64Hex(i, 4);
        ConsoleWrite("    ");
        WriteU64Hex(storage::BlockDeviceSectorSize(i), 6);
        ConsoleWrite("  ");
        WriteU64Hex(storage::BlockDeviceSectorCount(i), 16);
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
        WriteU64Hex(d->block_handle, 4);
        ConsoleWrite("  SECTOR_SIZE ");
        WriteU64Hex(d->sector_size, 4);
        ConsoleWrite("  PARTS ");
        WriteU64Hex(d->partition_count, 2);
        ConsoleWriteln("");
        for (duetos::u32 pi = 0; pi < d->partition_count; ++pi)
        {
            const gpt::Partition& p = d->partitions[pi];
            ConsoleWrite("  PART ");
            WriteU64Hex(pi, 2);
            ConsoleWrite(" FIRST_LBA ");
            WriteU64Hex(p.first_lba, 0);
            ConsoleWrite(" LAST_LBA ");
            WriteU64Hex(p.last_lba, 0);
            ConsoleWriteln("");
            ConsoleWrite("       TYPE ");
            // Canonical mixed-endian GUID rendering.
            static constexpr int kOrder[] = {3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15};
            for (int k = 0; k < 20; ++k)
            {
                const int idx = kOrder[k];
                if (idx < 0)
                {
                    ConsoleWriteChar('-');
                }
                else
                {
                    const duetos::u8 b = p.type_guid[idx];
                    const char hi = (b >> 4) < 10 ? char('0' + (b >> 4)) : char('A' + (b >> 4) - 10);
                    const char lo = (b & 0xF) < 10 ? char('0' + (b & 0xF)) : char('A' + (b & 0xF) - 10);
                    ConsoleWriteChar(hi);
                    ConsoleWriteChar(lo);
                }
            }
            ConsoleWriteln("");
        }
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
