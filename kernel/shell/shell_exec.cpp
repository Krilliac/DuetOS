/*
 * DuetOS — kernel shell: executable + low-level read commands.
 *
 * Sibling TU of shell.cpp. Houses the operator-facing windows
 * onto the kernel's loader machinery + the raw block-device peek:
 *
 *   linuxexec   read ELF from FAT32, hand to SpawnElfLinux
 *   exec        validate + dump load plan + SpawnElfFile
 *   readelf     pure decode of an ELF64 header + program headers
 *   read        BlockDeviceRead one sector + hexdump
 *   translate   subsystems::translation hit table
 *
 * TU-private helpers (LeU16 / LeU32 / LeU64 / ElfTypeName /
 * ElfMachineName / ElfPtypeName) stay in this file's anon
 * namespace.
 */

#include "shell/shell_internal.h"

#include "drivers/storage/block.h"
#include "drivers/video/console.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "mm/address_space.h"
#include "subsystems/translation/translate.h"
#include "loader/elf_loader.h"
#include "proc/process.h"
#include "proc/ring3_smoke.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// Little-endian u16/u32/u64 readers — the ELF parser walks raw
// bytes, so we don't rely on alignment or struct packing.
u16 LeU16(const u8* p)
{
    return u16(p[0]) | (u16(p[1]) << 8);
}
u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
u64 LeU64(const u8* p)
{
    u64 lo = LeU32(p);
    u64 hi = LeU32(p + 4);
    return lo | (hi << 32);
}

const char* ElfTypeName(u16 t)
{
    switch (t)
    {
    case 0:
        return "NONE";
    case 1:
        return "REL";
    case 2:
        return "EXEC";
    case 3:
        return "DYN (shared or PIE)";
    case 4:
        return "CORE";
    default:
        return "OTHER";
    }
}

const char* ElfMachineName(u16 m)
{
    switch (m)
    {
    case 0x00:
        return "none";
    case 0x03:
        return "x86 (i386)";
    case 0x28:
        return "arm";
    case 0x3E:
        return "x86_64";
    case 0xB7:
        return "aarch64";
    case 0xF3:
        return "riscv";
    default:
        return "unknown";
    }
}

const char* ElfPtypeName(u32 t)
{
    switch (t)
    {
    case 0:
        return "NULL";
    case 1:
        return "LOAD";
    case 2:
        return "DYNAMIC";
    case 3:
        return "INTERP";
    case 4:
        return "NOTE";
    case 5:
        return "SHLIB";
    case 6:
        return "PHDR";
    case 7:
        return "TLS";
    case 0x6474E550:
        return "GNU_EH_FRAME";
    case 0x6474E551:
        return "GNU_STACK";
    case 0x6474E552:
        return "GNU_RELRO";
    default:
        return "OTHER";
    }
}

} // namespace

void CmdLinuxexec(u32 argc, char** argv)
{
    namespace fat = duetos::fs::fat32;
    if (argc < 2)
    {
        ConsoleWriteln("LINUXEXEC: USAGE: LINUXEXEC PATH");
        return;
    }
    const char* path = argv[1];
    if (const char* leaf = FatLeaf(path); leaf != nullptr && *leaf != '\0')
    {
        path = leaf;
    }
    else if (path[0] == '/')
    {
        ++path;
    }
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        ConsoleWriteln("LINUXEXEC: FAT32 NOT MOUNTED");
        return;
    }
    fat::DirEntry entry;
    if (!fat::Fat32LookupPath(v, path, &entry))
    {
        ConsoleWrite("LINUXEXEC: NO SUCH FILE: ");
        ConsoleWriteln(path);
        return;
    }
    if (entry.attributes & 0x10)
    {
        ConsoleWriteln("LINUXEXEC: PATH IS A DIRECTORY");
        return;
    }
    static u8 elf_buf[16384];
    const i64 n = fat::Fat32ReadFile(v, &entry, elf_buf, sizeof(elf_buf));
    if (n <= 0)
    {
        ConsoleWriteln("LINUXEXEC: READ ERROR OR EMPTY");
        return;
    }
    const u64 pid = duetos::core::SpawnElfLinux("linuxexec", elf_buf, static_cast<u64>(n), duetos::core::CapSetEmpty(),
                                                duetos::fs::RamfsSandboxRoot(),
                                                /*frame_budget=*/16, duetos::core::kTickBudgetSandbox);
    if (pid == 0)
    {
        ConsoleWriteln("LINUXEXEC: SPAWNELFLINUX FAILED");
        return;
    }
    ConsoleWrite("LINUXEXEC: SPAWNED PID=");
    WriteU64Dec(pid);
    ConsoleWrite(" PATH=");
    ConsoleWriteln(path);
}

void CmdTranslate()
{
    namespace tx = duetos::subsystems::translation;
    const auto& linux = tx::LinuxHitsRead();
    const auto& native = tx::NativeHitsRead();
    ConsoleWriteln("TRANSLATION UNIT HIT TABLE");
    ConsoleWriteln("  DIR     NR     HITS");
    for (u32 i = 0; i < 1024; ++i)
    {
        if (linux.buckets[i] == 0)
            continue;
        ConsoleWrite("  linux   0x");
        WriteU64Hex(i, 3);
        ConsoleWrite("  ");
        WriteU64Dec(linux.buckets[i]);
        ConsoleWriteln("");
    }
    for (u32 i = 0; i < 1024; ++i)
    {
        if (native.buckets[i] == 0)
            continue;
        ConsoleWrite("  native  0x");
        WriteU64Hex(i, 3);
        ConsoleWrite("  ");
        WriteU64Dec(native.buckets[i]);
        ConsoleWriteln("");
    }
    ConsoleWriteln("-- end --");
}

void CmdRead(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("READ: USAGE: READ HANDLE LBA [COUNT]");
        ConsoleWriteln("      (count in sectors, default 1, max = 4096/sector_size)");
        return;
    }
    namespace storage = duetos::drivers::storage;
    u64 handle_u64 = 0;
    u64 lba = 0;
    u64 count = 1;
    if (!ParseU64Str(argv[1], &handle_u64) || handle_u64 >= 0x100000000ULL)
    {
        ConsoleWriteln("READ: BAD HANDLE");
        return;
    }
    if (!ParseU64Str(argv[2], &lba))
    {
        ConsoleWriteln("READ: BAD LBA");
        return;
    }
    if (argc >= 4 && !ParseU64Str(argv[3], &count))
    {
        ConsoleWriteln("READ: BAD COUNT");
        return;
    }
    const u32 handle = static_cast<u32>(handle_u64);
    const u32 ssize = storage::BlockDeviceSectorSize(handle);
    if (ssize == 0)
    {
        ConsoleWriteln("READ: INVALID HANDLE (no such block device)");
        return;
    }
    const u32 max_count = 4096u / ssize;
    if (count == 0 || count > max_count)
    {
        ConsoleWrite("READ: COUNT OUT OF RANGE (max ");
        WriteU64Hex(max_count, 0);
        ConsoleWriteln(")");
        return;
    }
    static u8 buf[4096];
    for (u64 i = 0; i < 4096; ++i)
        buf[i] = 0;
    if (storage::BlockDeviceRead(handle, lba, static_cast<u32>(count), buf) != 0)
    {
        ConsoleWriteln("READ: DRIVER RETURNED ERROR");
        return;
    }
    const u32 bytes = static_cast<u32>(count) * ssize;
    ConsoleWrite("READ ");
    WriteU64Hex(bytes, 0);
    ConsoleWrite(" BYTES FROM HANDLE ");
    WriteU64Hex(handle, 0);
    ConsoleWrite(" LBA ");
    WriteU64Hex(lba, 0);
    ConsoleWriteln(":");
    for (u32 row = 0; row < bytes; row += 16)
    {
        WriteU64Hex(row, 8);
        ConsoleWrite("  ");
        for (u32 i = 0; i < 16; ++i)
        {
            if (row + i < bytes)
                WriteU64Hex(buf[row + i], 2);
            else
                ConsoleWrite("  ");
            ConsoleWriteChar(' ');
            if (i == 7)
                ConsoleWriteChar(' ');
        }
        ConsoleWrite(" |");
        for (u32 i = 0; i < 16 && row + i < bytes; ++i)
        {
            const char c = static_cast<char>(buf[row + i]);
            ConsoleWriteChar((c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        ConsoleWriteln("|");
    }
}

void CmdExec(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("EXEC: USAGE: EXEC PATH   (dry-run ELF loader)");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("EXEC: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    const u8* file = reinterpret_cast<const u8*>(scratch);
    const duetos::core::ElfStatus st = duetos::core::ElfValidate(file, n);
    if (st != duetos::core::ElfStatus::Ok)
    {
        ConsoleWrite("EXEC: INVALID ELF: ");
        ConsoleWriteln(duetos::core::ElfStatusName(st));
        return;
    }
    ConsoleWrite("EXEC: OK. ENTRY = ");
    WriteU64Hex(duetos::core::ElfEntry(file));
    ConsoleWriteChar('\n');
    ConsoleWriteln("LOAD PLAN:");
    ConsoleWriteln("  VADDR             FILESZ    MEMSZ     FLAGS   FILE-OFFSET");
    struct Cookie
    {
        u32 count;
    };
    Cookie cookie{0};
    const u32 visited = duetos::core::ElfForEachPtLoad(
        file, n,
        [](const duetos::core::ElfSegment& seg, void* ck)
        {
            auto* c = static_cast<Cookie*>(ck);
            ++c->count;
            ConsoleWrite("  ");
            WriteU64Hex(seg.vaddr);
            ConsoleWrite("  ");
            WriteU64Hex(seg.filesz, 8);
            ConsoleWrite("  ");
            WriteU64Hex(seg.memsz, 8);
            ConsoleWrite("  ");
            ConsoleWriteChar((seg.flags & duetos::core::kElfPfR) ? 'R' : '-');
            ConsoleWriteChar((seg.flags & duetos::core::kElfPfW) ? 'W' : '-');
            ConsoleWriteChar((seg.flags & duetos::core::kElfPfX) ? 'X' : '-');
            ConsoleWrite("     ");
            WriteU64Hex(seg.file_offset, 8);
            ConsoleWriteChar('\n');
        },
        &cookie);
    ConsoleWrite("EXEC: ");
    WriteU64Dec(visited);
    ConsoleWriteln(" PT_LOAD SEGMENTS.");

    const u64 new_pid =
        duetos::core::SpawnElfFile(argv[1], file, n, duetos::core::CapSetTrusted(), duetos::fs::RamfsTrustedRoot(),
                                   duetos::mm::kFrameBudgetTrusted, duetos::core::kTickBudgetTrusted);
    if (new_pid == 0)
    {
        ConsoleWriteln("EXEC: SPAWN FAILED (OOM or bad ELF layout).");
        return;
    }
    ConsoleWrite("EXEC: SPAWN pid=");
    WriteU64Dec(new_pid);
    ConsoleWriteln(" queued.");
    ConsoleWriteln("EXEC: (use `ps` to observe, kernel log for entry line.)");
}

void CmdReadelf(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("READELF: USAGE: READELF PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("READELF: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    if (n < 64)
    {
        ConsoleWriteln("READELF: FILE TOO SMALL FOR AN ELF HEADER");
        return;
    }
    const u8* b = reinterpret_cast<const u8*>(scratch);
    if (!(b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'))
    {
        ConsoleWriteln("READELF: NOT AN ELF FILE (BAD MAGIC)");
        return;
    }
    const u8 ei_class = b[4];
    const u8 ei_data = b[5];
    if (ei_class != 2)
    {
        ConsoleWriteln("READELF: NOT ELF64 (ei_class != 2)");
        return;
    }
    if (ei_data != 1)
    {
        ConsoleWriteln("READELF: NOT LITTLE-ENDIAN (ei_data != 1)");
        return;
    }
    ConsoleWriteln("-- ELF HEADER --");
    ConsoleWrite("  CLASS:      ELF64\n");
    ConsoleWrite("  DATA:       LSB\n");
    ConsoleWrite("  VERSION:    ");
    WriteU64Dec(b[6]);
    ConsoleWriteChar('\n');
    ConsoleWrite("  OSABI:      ");
    WriteU64Dec(b[7]);
    ConsoleWriteChar('\n');
    const u16 e_type = LeU16(b + 16);
    ConsoleWrite("  TYPE:       ");
    WriteU64Hex(e_type, 4);
    ConsoleWrite("  (");
    ConsoleWrite(ElfTypeName(e_type));
    ConsoleWriteln(")");
    const u16 e_machine = LeU16(b + 18);
    ConsoleWrite("  MACHINE:    ");
    WriteU64Hex(e_machine, 4);
    ConsoleWrite("  (");
    ConsoleWrite(ElfMachineName(e_machine));
    ConsoleWriteln(")");
    const u64 e_entry = LeU64(b + 24);
    ConsoleWrite("  ENTRY:      ");
    WriteU64Hex(e_entry);
    ConsoleWriteChar('\n');
    const u64 e_phoff = LeU64(b + 32);
    const u64 e_shoff = LeU64(b + 40);
    ConsoleWrite("  PHOFF:      ");
    WriteU64Dec(e_phoff);
    ConsoleWrite("   SHOFF: ");
    WriteU64Dec(e_shoff);
    ConsoleWriteChar('\n');
    const u16 e_phentsize = LeU16(b + 54);
    const u16 e_phnum = LeU16(b + 56);
    const u16 e_shentsize = LeU16(b + 58);
    const u16 e_shnum = LeU16(b + 60);
    ConsoleWrite("  PHDRS:      ");
    WriteU64Dec(e_phnum);
    ConsoleWrite(" x ");
    WriteU64Dec(e_phentsize);
    ConsoleWrite(" bytes");
    ConsoleWriteChar('\n');
    ConsoleWrite("  SHDRS:      ");
    WriteU64Dec(e_shnum);
    ConsoleWrite(" x ");
    WriteU64Dec(e_shentsize);
    ConsoleWrite(" bytes");
    ConsoleWriteChar('\n');

    if (e_phnum == 0 || e_phentsize < 56 || e_phoff == 0)
    {
        return;
    }
    ConsoleWriteln("-- PROGRAM HEADERS --");
    ConsoleWriteln("   TYPE       FLAGS  OFFSET           VADDR            FILESZ    MEMSZ     ALIGN");
    for (u16 i = 0; i < e_phnum; ++i)
    {
        const u64 off = e_phoff + static_cast<u64>(i) * e_phentsize;
        if (off + 56 > n)
        {
            ConsoleWriteln("  <TRUNCATED>");
            break;
        }
        const u8* p = b + off;
        const u32 p_type = LeU32(p + 0);
        const u32 p_flags = LeU32(p + 4);
        const u64 p_offset = LeU64(p + 8);
        const u64 p_vaddr = LeU64(p + 16);
        const u64 p_filesz = LeU64(p + 32);
        const u64 p_memsz = LeU64(p + 40);
        const u64 p_align = LeU64(p + 48);
        ConsoleWrite("  ");
        const char* tn = ElfPtypeName(p_type);
        ConsoleWrite(tn);
        for (u32 k = 0; k < 12; ++k)
        {
            if (tn[k] == '\0')
            {
                for (u32 j = k; j < 12; ++j)
                    ConsoleWriteChar(' ');
                break;
            }
        }
        ConsoleWriteChar((p_flags & 4) ? 'R' : '-');
        ConsoleWriteChar((p_flags & 2) ? 'W' : '-');
        ConsoleWriteChar((p_flags & 1) ? 'X' : '-');
        ConsoleWrite("    ");
        WriteU64Hex(p_offset);
        ConsoleWrite(" ");
        WriteU64Hex(p_vaddr);
        ConsoleWrite(" ");
        WriteU64Hex(p_filesz, 8);
        ConsoleWrite("  ");
        WriteU64Hex(p_memsz, 8);
        ConsoleWrite("  ");
        WriteU64Hex(p_align, 5);
        ConsoleWriteChar('\n');
    }
}

} // namespace duetos::core::shell::internal
