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
inline constexpr u32 kMultibootTagFramebuffer = 8; // linear FB info from GRUB
inline constexpr u32 kMultibootTagAcpiOld = 14;    // RSDP v1 (20 bytes) embedded
inline constexpr u32 kMultibootTagAcpiNew = 15;    // RSDP v2 (36 bytes) embedded

inline constexpr u32 kMmapTypeAvailable = 1;
inline constexpr u32 kMmapTypeReserved = 2;
inline constexpr u32 kMmapTypeAcpiReclaimable = 3;
inline constexpr u32 kMmapTypeAcpiNvs = 4;
inline constexpr u32 kMmapTypeBadRam = 5;

// Framebuffer types per Multiboot2 §3.6.12. We only consume "direct
// RGB" (type 1). "EGA text" (type 2) and "indexed palette" (type 0)
// exist on legacy hardware and are skipped by the FB driver.
inline constexpr u8 kFramebufferTypeIndexed = 0;
inline constexpr u8 kFramebufferTypeRgb = 1;
inline constexpr u8 kFramebufferTypeEgaText = 2;

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

// Framebuffer info tag (type 8) — the common prefix across every
// framebuffer_type. We only care about RGB (type == 1); the variable-
// length "colour info" trailer for indexed / EGA-text framebuffers is
// intentionally omitted here since we don't consume it.
struct [[gnu::packed]] MultibootFramebufferTag
{
    u32 type;           // = kMultibootTagFramebuffer
    u32 size;
    u64 addr;           // physical address of framebuffer
    u32 pitch;          // bytes per scanline
    u32 width;          // pixels
    u32 height;         // pixels
    u8 bpp;             // bits per pixel
    u8 framebuffer_type;
    u16 reserved;
    // Colour-info trailer follows, shape depends on framebuffer_type.
};

} // namespace customos::mm
