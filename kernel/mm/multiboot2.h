#pragma once

#include "../core/types.h"

/*
 * Multiboot2 information structure — the subset we actually consume.
 *
 * Full spec at https://www.gnu.org/software/grub/manual/multiboot2/; this
 * header declares only the tags the frame allocator needs to read today
 * (end tag, memory map). Others get parsed past via their `size` field.
 *
 * All structures are tightly packed and laid out exactly as GRUB places
 * them in memory; do NOT reorder fields.
 */

namespace customos::mm
{

inline constexpr u32 kMultibootTagEnd = 0;
inline constexpr u32 kMultibootTagMmap = 6;
inline constexpr u32 kMultibootTagAcpiOld = 14; // RSDP v1 (20 bytes) embedded
inline constexpr u32 kMultibootTagAcpiNew = 15; // RSDP v2 (36 bytes) embedded

inline constexpr u32 kMmapTypeAvailable = 1;
inline constexpr u32 kMmapTypeReserved = 2;
inline constexpr u32 kMmapTypeAcpiReclaimable = 3;
inline constexpr u32 kMmapTypeAcpiNvs = 4;
inline constexpr u32 kMmapTypeBadRam = 5;

struct [[gnu::packed]] MultibootInfoHeader
{
    u32 total_size;
    u32 reserved;
    // Tags follow, 8-byte aligned.
};

struct [[gnu::packed]] MultibootTagHeader
{
    u32 type;
    u32 size;
};

struct [[gnu::packed]] MultibootMmapEntry
{
    u64 base_addr;
    u64 length;
    u32 type;
    u32 reserved;
};

struct [[gnu::packed]] MultibootMmapTag
{
    u32 type;          // = kMultibootTagMmap
    u32 size;          // includes header + all entries
    u32 entry_size;    // typically 24
    u32 entry_version; // 0
    // MultibootMmapEntry entries follow.
};

} // namespace customos::mm
