#pragma once

/*
 * DuetOS — minimal ELF64 types for the UEFI loader, Phase B.
 *
 * The kernel has its own ELF parser in `kernel/loader/`, but we
 * deliberately don't include from there: the UEFI loader compiles
 * with `--target=x86_64-unknown-windows` (PE/COFF, MS x64 ABI)
 * while the kernel compiles ELF/SysV. Sharing headers across the
 * boundary is asking for ABI confusion the moment one side adds a
 * `[[gnu::sysv_abi]]`-style attribute. The loader-side type is
 * 100 lines and exists only to validate + walk the kernel image
 * the firmware just gave us.
 *
 * Reference: System V ABI, x86_64 supplement (1.0), §4.
 *            "ELF-64 Object File Format" (Levine, 2.1).
 *
 * Phase B.1 scope:
 *   - Elf64_Ehdr (file header) — validation only.
 *   - Constants for e_ident / e_class / e_data / e_machine /
 *     e_type so the loader can reject non-x86_64 binaries early.
 *
 * Phase B.2 will add:
 *   - Elf64_Phdr (program headers) — segment iteration + load.
 *   - PT_LOAD constants + PF_X/W/R flags.
 */

namespace duetos::boot::uefi::elf
{

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;
using s32 = signed int;
using s64 = signed long long;

using Elf64_Addr = u64;
using Elf64_Off = u64;
using Elf64_Half = u16;
using Elf64_Word = u32;
using Elf64_Sword = s32;
using Elf64_Xword = u64;
using Elf64_Sxword = s64;

// e_ident byte indices.
inline constexpr int EI_MAG0 = 0;
inline constexpr int EI_MAG1 = 1;
inline constexpr int EI_MAG2 = 2;
inline constexpr int EI_MAG3 = 3;
inline constexpr int EI_CLASS = 4;
inline constexpr int EI_DATA = 5;
inline constexpr int EI_VERSION = 6;
inline constexpr int EI_NIDENT = 16;

// ELF magic.
inline constexpr u8 ELFMAG0 = 0x7F;
inline constexpr u8 ELFMAG1 = 'E';
inline constexpr u8 ELFMAG2 = 'L';
inline constexpr u8 ELFMAG3 = 'F';

// e_ident[EI_CLASS]
inline constexpr u8 ELFCLASSNONE = 0;
inline constexpr u8 ELFCLASS32 = 1;
inline constexpr u8 ELFCLASS64 = 2;

// e_ident[EI_DATA]
inline constexpr u8 ELFDATANONE = 0;
inline constexpr u8 ELFDATA2LSB = 1; // little-endian (x86_64 always)
inline constexpr u8 ELFDATA2MSB = 2;

// e_type
inline constexpr Elf64_Half ET_NONE = 0;
inline constexpr Elf64_Half ET_REL = 1;
inline constexpr Elf64_Half ET_EXEC = 2;
inline constexpr Elf64_Half ET_DYN = 3;

// e_machine — only x86_64 is accepted.
inline constexpr Elf64_Half EM_X86_64 = 62;

struct Elf64_Ehdr
{
    u8 e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
};

static_assert(sizeof(Elf64_Ehdr) == 64, "Elf64_Ehdr must be 64 bytes");

} // namespace duetos::boot::uefi::elf
