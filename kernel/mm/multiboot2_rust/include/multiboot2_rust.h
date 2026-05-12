// DuetOS Multiboot2 walker C FFI — hand-written. Mirrors
// kernel/mm/multiboot2_rust/src/lib.rs.
//
// The C++ caller at kernel/mm/frame_allocator.cpp pre-materialises
// the info pointer via the direct map, then hands a bounded byte
// slice to this crate. Rust owns every cursor advance and every
// mmap-entry size arithmetic.

#pragma once

#include "util/types.h"

namespace duetos::mm::multiboot2_rust
{

// Mirror of the Rust-side `pub const` constants.
constexpr u32 MULTIBOOT_TAG_END = 0;
constexpr u32 MULTIBOOT_TAG_CMDLINE = 1;
constexpr u32 MULTIBOOT_TAG_MMAP = 6;
constexpr u32 MULTIBOOT_TAG_FRAMEBUFFER = 8;
constexpr u32 MULTIBOOT_TAG_ACPI_OLD = 14;
constexpr u32 MULTIBOOT_TAG_ACPI_NEW = 15;
constexpr u32 MULTIBOOT_TAG_HOP_CAP = 256;

struct DuetosMultibootInfoHeader
{
    u32 total_size;
    u32 reserved;
    u8 ok;
    u8 _pad[7];
};

struct DuetosMultibootTag
{
    u32 tag_type;
    u32 size; // >= 8 on success
    u32 offset;
    u32 next_offset; // 8-byte aligned, bounded to slice
    u8 ok;
    u8 _pad[7];
};

struct DuetosMultibootMmap
{
    u32 entry_size;    // typically 24
    u32 entry_version; // 0 in v0
    u32 entries_offset;
    u32 entries_byte_len;
    u8 ok;
    u8 _pad[7];
};

struct DuetosMultibootMmapEntry
{
    u64 base_addr;
    u64 length;
    u32 entry_type;
    u32 reserved;
    u8 ok;
    u8 _pad[7];
};

extern "C"
{
    /// Validate the 8-byte Multiboot2 info header. On success the
    /// caller knows `[buf, buf + total_size)` is a self-bounded
    /// region it can iterate tags in.
    bool duetos_multiboot2_parse_header(const u8* buf, usize len, DuetosMultibootInfoHeader* out);

    /// Decode one tag header at offset `off`. Returns the tag's
    /// type, size, and the aligned-up next-tag offset.
    bool duetos_multiboot2_next_tag(const u8* buf, usize len, usize off, DuetosMultibootTag* out);

    /// Decode the mmap-tag fixed prefix (entry_size + entry_version)
    /// and return the byte range that holds the variable-length
    /// entry array.
    bool duetos_multiboot2_parse_mmap(const u8* buf, usize len, usize off, u32 tag_size, DuetosMultibootMmap* out);

    /// Decode one mmap entry at offset `off`. Rejects base+length
    /// arithmetic overflow.
    bool duetos_multiboot2_parse_mmap_entry(const u8* buf, usize len, usize off, DuetosMultibootMmapEntry* out);
}

} // namespace duetos::mm::multiboot2_rust
